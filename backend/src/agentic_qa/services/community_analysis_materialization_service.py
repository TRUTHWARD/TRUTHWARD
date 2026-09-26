# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
import re
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    CandidateGraphBuildRun,
    CanonicalExecutionGraph,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphVersion,
    ChangeSetRecord,
    Execution,
    ExecutionTask,
    ImpactResultRecord,
    RequirementChangeSetRecord,
    RequirementIntakeDraft,
    RequirementIntakePreview,
    RequirementVersion,
    TestPlan,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import ensure_trace
from agentic_qa.schemas.change_sets import RequirementChangeSetIngestRequest
from agentic_qa.schemas.candidate_graph import CandidateBuildRequest
from agentic_qa.schemas.community_analysis import CommunityAnalysisMaterializeRequest
from agentic_qa.schemas.execution_graph import (
    CreateCanonicalPathRequest,
    CreateGraphEdgeRequest,
    CreateGraphIdentityRequest,
    CreateGraphNodeRequest,
    CreateGraphVersionRequest,
    GraphDisplayMetadata,
    PathStepInput,
    StableGraphRef,
)
from agentic_qa.schemas.impact_analysis import (
    IMPACT_ALGORITHM_VERSION,
    ImpactResultContract,
)
from agentic_qa.schemas.selective_replay import (
    ReplayPlanBudget,
    SelectiveReplayRequest,
)
from agentic_qa.services.change_set_service import ChangeSetService
from agentic_qa.services.candidate_graph_query_service import CandidateGraphError
from agentic_qa.services.candidate_graph_service import CandidateGraphService
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
)
from agentic_qa.services.coverage_readiness_service import CoverageReadinessService
from agentic_qa.services.execution_graph_service import ExecutionGraphService
from agentic_qa.services.execution_service import ExecutionService
from agentic_qa.services.graph_coverage_service import GraphCoverageService
from agentic_qa.services.scope_service import (
    ScopeAuthorizationError,
    ScopeAuthorizationService,
)
from agentic_qa.services.traceability_service import TraceabilityService


_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,159}$")
_MAX_REQUIREMENT_NODES = 100
_MAX_EXECUTION_TASKS = 250


class CommunityAnalysisMaterializationError(ValueError):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.field = field


class CommunityAnalysisMaterializationService:
    """Materialize bounded Community coverage projections from persisted facts.

    The chain creates immutable/read-only analysis facts only.  It never promotes
    a Graph, creates an Approval or Gate, writes Memory/CI, starts an Execution,
    retries a task, or calls a model, Tool, or Connector.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def materialize(
        self,
        project_id: UUID,
        payload: CommunityAnalysisMaterializeRequest,
        context: ServiceContext,
        *,
        lifecycle_trigger: bool = False,
    ) -> dict[str, Any]:
        if "coverage.materialize" not in set(context.user.capabilities):
            raise CommunityAnalysisMaterializationError(
                "COMMUNITY_ANALYSIS_CAPABILITY_REQUIRED",
                status_code=403,
                field="coverage.materialize",
            )
        try:
            scope = ScopeAuthorizationService(self.db).resolve_project(
                project_id,
                context,
                write=not lifecycle_trigger,
            )
        except ScopeAuthorizationError as exc:
            raise CommunityAnalysisMaterializationError(
                "COMMUNITY_ANALYSIS_PROJECT_NOT_FOUND"
                if exc.status_code == 404
                else "COMMUNITY_ANALYSIS_PROJECT_WRITE_FORBIDDEN",
                status_code=exc.status_code,
                field=exc.field,
            ) from exc

        requirement = self._requirement(project_id, payload.requirementVersionId)
        execution, plan = self._execution(
            project_id,
            requirement,
            payload.executionId,
        )
        if requirement is None and plan is not None and plan.requirement_version_id is not None:
            requirement = self.db.get(RequirementVersion, plan.requirement_version_id)

        stages: list[dict[str, Any]] = []
        change_set_id: UUID | None = None
        graph: CanonicalExecutionGraph | None = None
        graph_version: CanonicalExecutionGraphVersion | None = None
        coverage_snapshot_id: UUID | None = None
        coverage_proof_ref: dict[str, Any] | None = None
        impact_result_id: UUID | None = None
        replay_plan_id: UUID | None = None
        candidate_observation = self._candidate_observation_status(
            "not_applicable",
            "CANDIDATE_OBSERVATION_INPUTS_MISSING",
        )

        if requirement is None:
            stages.append(self._blocked("change_set", "REQUIREMENT_VERSION_MISSING"))
        else:
            change_set_id, stage = self._materialize_change_set(project_id, requirement, context)
            stages.append(stage)

        if execution is None or plan is None:
            stages.append(self._blocked("graph", "BASE_EXECUTION_MISSING"))
        elif requirement is None:
            stages.append(self._blocked("graph", "REQUIREMENT_VERSION_MISSING"))
        else:
            graph, graph_version, graph_stage = self._materialize_graph(
                project_id,
                requirement,
                execution,
                plan,
                context,
            )
            stages.append(graph_stage)

        if execution is not None and graph is not None:
            candidate_observation = self._materialize_candidate_observation(
                project_id,
                execution,
                graph,
                context,
            )

        if requirement is None or execution is None or graph is None or graph_version is None:
            stages.append(self._blocked("coverage", "COVERAGE_INPUTS_MISSING"))
        else:
            coverage_snapshot_id, coverage_proof_ref, stage = self._materialize_coverage(
                project_id,
                requirement,
                execution,
                graph,
                graph_version,
                context,
            )
            stages.append(stage)

        if change_set_id is None or graph is None or graph_version is None:
            stages.append(self._blocked("impact", "IMPACT_INPUTS_MISSING"))
        else:
            impact_result_id, stage = self._materialize_impact(
                project_id,
                change_set_id,
                graph,
                graph_version,
                context,
            )
            stages.append(stage)

        if (
            impact_result_id is None
            or coverage_snapshot_id is None
            or execution is None
            or plan is None
        ):
            stages.append(self._blocked("selective_replay", "REPLAY_INPUTS_MISSING"))
        else:
            replay_plan_id, stage = self._materialize_replay(
                project_id,
                impact_result_id,
                coverage_snapshot_id,
                execution,
                plan,
                context,
            )
            stages.append(stage)

        stages.append(
            self._ready("proof", ref=coverage_proof_ref)
            if coverage_proof_ref
            else self._blocked("proof", "COVERAGE_PROOF_UNAVAILABLE")
        )
        complete = all(stage["status"] == "ready" for stage in stages)
        audit = write_audit_log(
            self.db,
            context.user.id,
            "community.analysis.materialize",
            "project",
            str(project_id),
            context.request_id,
            context.trace_id,
            {
                "projectId": str(project_id),
                "scopeDecisionRef": scope.decision_ref,
                "lifecycleTrigger": lifecycle_trigger,
                "complete": complete,
                "stageStatus": {item["id"]: item["status"] for item in stages},
                "candidateObservationStatus": candidate_observation["status"],
                "candidateObservationReasonCode": candidate_observation["reasonCode"],
                "productionApplied": False,
                "executionCreated": False,
            },
        )
        self.db.commit()
        readiness = CoverageReadinessService(self.db).project_readiness(project_id, context)
        return {
            "schemaVersion": "community.analysis-materialization.v1",
            "projectId": str(project_id),
            "requirementVersionId": str(requirement.id) if requirement else None,
            "executionId": str(execution.id) if execution else None,
            "complete": complete,
            "nonAuthoritative": True,
            "productionApplied": False,
            "executionCreated": False,
            "modelInvoked": False,
            "approvalCreated": False,
            "gateWritten": False,
            "memoryWritten": False,
            "externalWritePerformed": False,
            "candidateObservation": candidate_observation,
            "lifecycleTrigger": lifecycle_trigger,
            "stages": stages,
            "auditRef": f"audit://logs/{audit.id}",
            "readiness": readiness,
        }

    def _materialize_candidate_observation(
        self,
        project_id: UUID,
        execution: Execution,
        graph: CanonicalExecutionGraph,
        context: ServiceContext,
    ) -> dict[str, Any]:
        if "graph.candidate.observe" not in set(context.user.capabilities):
            return self._candidate_observation_status(
                "not_applicable",
                "CANDIDATE_OBSERVATION_CAPABILITY_REQUIRED",
            )
        existing_id = self.db.scalar(
            select(CandidateGraphBuildRun.id)
            .where(
                CandidateGraphBuildRun.project_id == project_id,
                CandidateGraphBuildRun.graph_id == graph.id,
                CandidateGraphBuildRun.execution_id == execution.id,
                CandidateGraphBuildRun.status == "completed",
            )
            .order_by(CandidateGraphBuildRun.created_at.desc())
            .limit(1)
        )
        try:
            result = CandidateGraphService(self.db).build_community_observation(
                project_id,
                CandidateBuildRequest(
                    graphId=graph.id,
                    executionId=execution.id,
                    config={
                        "includeModelSuggestions": False,
                        "maxActions": 1_000,
                        "confidenceFloor": 0.05,
                    },
                ),
                context,
            )
        except CandidateGraphError as exc:
            if exc.code == "CANDIDATE_AUTHORITATIVE_ACTIONS_NOT_FOUND":
                return self._candidate_observation_status(
                    "not_applicable",
                    "CANDIDATE_SEMANTIC_TRACE_MISSING",
                )
            return self._candidate_observation_status("failed", exc.code)
        except Exception:
            self.db.rollback()
            return self._candidate_observation_status(
                "failed",
                "CANDIDATE_OBSERVATION_FAILED",
            )
        build_id = str(result["buildId"])
        return {
            **self._candidate_observation_status("ready", None),
            "buildId": build_id,
            "graphId": str(graph.id),
            "candidateVersionId": str(result["candidateVersionId"]),
            "deduplicated": existing_id is not None and str(existing_id) == build_id,
        }

    @staticmethod
    def _candidate_observation_status(
        status: str,
        reason_code: str | None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "buildId": None,
            "graphId": None,
            "candidateVersionId": None,
            "reasonCode": reason_code,
            "deduplicated": False,
            "nonAuthoritative": True,
            "modelInvoked": False,
            "promotionPerformed": False,
            "gateWritten": False,
            "memoryWritten": False,
            "externalWritePerformed": False,
        }

    def _materialize_change_set(
        self,
        project_id: UUID,
        requirement: RequirementVersion,
        context: ServiceContext,
    ) -> tuple[UUID | None, dict[str, Any]]:
        try:
            existing = self.db.scalar(
                select(RequirementChangeSetRecord)
                .where(RequirementChangeSetRecord.head_requirement_version_id == requirement.id)
                .order_by(RequirementChangeSetRecord.change_set_id.desc())
                .limit(1)
            )
            if existing is not None:
                return existing.change_set_id, self._ready(
                    "change_set",
                    record_id=existing.change_set_id,
                    deduplicated=True,
                )
            base = self._previous_requirement(project_id, requirement)
            source_hash = canonical_hash(requirement.source_ref).removeprefix("sha256:")
            result = ChangeSetService(self.db).materialize_requirement_analysis(
                project_id,
                RequirementChangeSetIngestRequest(
                    sourceId=f"requirement://sources/{source_hash}",
                    revision=f"v{requirement.version_no}-{requirement.content_hash[-16:]}",
                    baseRequirementVersionId=base.id if base else None,
                    headRequirementVersionId=requirement.id,
                ),
                context,
            )
            record_id = UUID(str(result["changeSetId"]))
            return record_id, self._ready(
                "change_set",
                record_id=record_id,
                deduplicated=bool(result.get("deduplicated")),
            )
        except Exception as exc:  # stage failures are projected, not hidden
            self.db.rollback()
            return None, self._failed("change_set", exc)

    def _materialize_graph(
        self,
        project_id: UUID,
        requirement: RequirementVersion,
        execution: Execution,
        plan: TestPlan,
        context: ServiceContext,
    ) -> tuple[
        CanonicalExecutionGraph | None,
        CanonicalExecutionGraphVersion | None,
        dict[str, Any],
    ]:
        try:
            service = ExecutionGraphService(self.db)
            version = next(
                (
                    item
                    for item in self.db.scalars(
                        select(CanonicalExecutionGraphVersion)
                        .where(CanonicalExecutionGraphVersion.project_id == project_id)
                        .order_by(
                            CanonicalExecutionGraphVersion.created_at.desc(),
                            CanonicalExecutionGraphVersion.id.desc(),
                        )
                    )
                    if str(item.metadata_json.get("communityExecutionId") or "")
                    == str(execution.id)
                    and str(item.metadata_json.get("requirementVersionId") or "")
                    == str(requirement.id)
                ),
                None,
            )
            if version is not None:
                graph = self.db.get(CanonicalExecutionGraph, version.graph_id)
                if graph is None:
                    raise ValueError("COMMUNITY_ANALYSIS_GRAPH_NOT_FOUND")
            else:
                identity = service.create_draft_graph(
                    CreateGraphIdentityRequest(
                        projectId=project_id,
                        environmentId=plan.environment_id,
                        graphKey="community-analysis",
                        name="Community coverage analysis",
                        description="Non-authoritative execution-to-requirement analysis projection.",
                        idempotencyKey=(
                            f"community-analysis-graph:{project_id}:"
                            f"{plan.environment_id or 'project'}"
                        ),
                        metadata={
                            "communityProjection": True,
                            "nonAuthoritative": True,
                            "productionApplied": False,
                        },
                    ),
                    context,
                )
                graph = self.db.get(CanonicalExecutionGraph, UUID(str(identity["graphId"])))
                if graph is None:
                    raise ValueError("COMMUNITY_ANALYSIS_GRAPH_NOT_FOUND")
                parent = self.db.scalar(
                    select(CanonicalExecutionGraphVersion)
                    .where(CanonicalExecutionGraphVersion.graph_id == graph.id)
                    .order_by(CanonicalExecutionGraphVersion.version_number.desc())
                    .limit(1)
                )
                version_result = service.create_draft_version(
                    project_id,
                    CreateGraphVersionRequest(
                        graphId=graph.id,
                        parentVersionId=parent.id if parent else None,
                        source="observed",
                        sourceRefs=[
                            StableGraphRef(
                                type="requirement",
                                ref=f"requirement://versions/{requirement.id}",
                                contentHash=requirement.content_hash,
                            ),
                            StableGraphRef(
                                type="execution",
                                ref=f"execution://executions/{execution.id}",
                            ),
                        ],
                        applicability={
                            "environmentId": str(plan.environment_id)
                            if plan.environment_id
                            else None,
                        },
                        idempotencyKey=f"community-analysis-version:{execution.id}",
                        metadata={
                            "communityProjection": True,
                            "nonAuthoritative": True,
                            "productionApplied": False,
                            "communityExecutionId": str(execution.id),
                            "requirementVersionId": str(requirement.id),
                        },
                    ),
                    context,
                )
                version = self.db.get(
                    CanonicalExecutionGraphVersion,
                    UUID(str(version_result["version"]["versionId"])),
                )
                if version is None:
                    raise ValueError("COMMUNITY_ANALYSIS_GRAPH_VERSION_NOT_FOUND")
            truncated = self._populate_graph(
                service,
                project_id,
                graph,
                version,
                requirement,
                execution,
                plan,
                context,
            )
            return (
                graph,
                version,
                self._ready(
                    "graph",
                    record_id=version.id,
                    ref={"graphId": str(graph.id), "graphVersionId": str(version.id)},
                    issues=[
                        {"code": "COMMUNITY_ANALYSIS_GRAPH_INPUT_TRUNCATED", "severity": "warning"}
                    ]
                    if truncated
                    else [],
                ),
            )
        except Exception as exc:
            self.db.rollback()
            return None, None, self._failed("graph", exc)

    def _populate_graph(
        self,
        service: ExecutionGraphService,
        project_id: UUID,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        requirement: RequirementVersion,
        execution: Execution,
        plan: TestPlan,
        context: ServiceContext,
    ) -> bool:
        requirement_items = TraceabilityService(self.db)._active_requirement_items(
            requirement.id,
            requirement_scope=plan.requirement_scope or None,
        )
        if not requirement_items:
            raise ValueError("COMMUNITY_ANALYSIS_REQUIREMENT_ITEMS_EMPTY")
        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution.id)
                .order_by(
                    ExecutionTask.priority.asc(),
                    ExecutionTask.created_at.asc(),
                    ExecutionTask.id.asc(),
                )
            )
        )
        if not tasks:
            raise ValueError("COMMUNITY_ANALYSIS_EXECUTION_TASKS_MISSING")
        truncated = (
            len(requirement_items) > _MAX_REQUIREMENT_NODES or len(tasks) > _MAX_EXECUTION_TASKS
        )
        requirement_items = requirement_items[:_MAX_REQUIREMENT_NODES]
        tasks = tasks[:_MAX_EXECUTION_TASKS]
        risk = getattr(plan.risk_level, "value", str(plan.risk_level))
        risk = risk if risk in {"low", "medium", "high"} else "medium"
        requirement_nodes: list[UUID] = []
        lock_version = version.lock_version
        for index, item in enumerate(requirement_items, start=1):
            response = service.create_node(
                project_id,
                graph.id,
                version.id,
                CreateGraphNodeRequest(
                    clientKey=f"requirement:{index}",
                    semanticKey=f"requirement:{index}",
                    nodeType="requirement",
                    display=GraphDisplayMetadata(label=str(item.get("text") or item["id"])[:255]),
                    attributes={
                        "requirementItemId": str(item["id"]),
                        "version": requirement.version_no,
                        "acceptanceCriterionIds": [],
                    },
                    externalRefs=[
                        StableGraphRef(
                            type="requirement",
                            ref=f"requirement://versions/{requirement.id}",
                            contentHash=requirement.content_hash,
                        )
                    ],
                    riskLevel=risk,
                    source="observed",
                    confidence=1.0,
                    versionLockVersion=lock_version,
                ),
                context,
            )
            requirement_nodes.append(UUID(str(response["node"]["nodeId"])))
            lock_version = int(response["version"]["lockVersion"])

        domain_nodes: dict[str, UUID] = {}
        for task in tasks:
            domain = getattr(task.domain, "value", str(task.domain))
            if domain in domain_nodes:
                continue
            response = service.create_node(
                project_id,
                graph.id,
                version.id,
                CreateGraphNodeRequest(
                    clientKey=f"capability:{domain}",
                    semanticKey=f"capability:{domain}",
                    nodeType="capability",
                    display=GraphDisplayMetadata(label=f"{domain} regression"[:255]),
                    attributes={"capabilityKey": f"{domain}.regression", "domain": domain},
                    riskLevel=risk,
                    source="observed",
                    confidence=0.9,
                    versionLockVersion=lock_version,
                ),
                context,
            )
            domain_nodes[domain] = UUID(str(response["node"]["nodeId"]))
            lock_version = int(response["version"]["lockVersion"])

        for requirement_index, requirement_node in enumerate(requirement_nodes, start=1):
            for domain, capability_node in domain_nodes.items():
                response = service.create_edge(
                    project_id,
                    graph.id,
                    version.id,
                    CreateGraphEdgeRequest(
                        clientKey=f"contains:{requirement_index}:{domain}",
                        edgeType="contains",
                        sourceNodeId=requirement_node,
                        targetNodeId=capability_node,
                        riskLevel=risk,
                        source="observed",
                        confidence=0.9,
                        versionLockVersion=lock_version,
                    ),
                    context,
                )
                lock_version = int(response["version"]["lockVersion"])

        execution_ref = StableGraphRef(
            type="execution",
            ref=f"execution://executions/{execution.id}",
        )
        for index, task in enumerate(tasks, start=1):
            domain = getattr(task.domain, "value", str(task.domain))
            node_response = service.create_node(
                project_id,
                graph.id,
                version.id,
                CreateGraphNodeRequest(
                    clientKey=f"test:{index}",
                    semanticKey=f"test:{task.id}",
                    nodeType="test",
                    display=GraphDisplayMetadata(label=str(task.task_type)[:255]),
                    attributes={
                        "testKind": domain,
                        "testCaseRef": f"execution-task://{task.id}",
                    },
                    externalRefs=[
                        StableGraphRef(type="test", ref=f"test://execution-tasks/{task.id}"),
                        execution_ref,
                    ],
                    riskLevel=risk,
                    source="observed",
                    confidence=0.9,
                    versionLockVersion=lock_version,
                ),
                context,
            )
            test_node = UUID(str(node_response["node"]["nodeId"]))
            lock_version = int(node_response["version"]["lockVersion"])
            edge_response = service.create_edge(
                project_id,
                graph.id,
                version.id,
                CreateGraphEdgeRequest(
                    clientKey=f"verifies:{index}",
                    edgeType="verifies",
                    sourceNodeId=test_node,
                    targetNodeId=domain_nodes[domain],
                    riskLevel=risk,
                    source="observed",
                    confidence=0.9,
                    versionLockVersion=lock_version,
                ),
                context,
            )
            lock_version = int(edge_response["version"]["lockVersion"])
            path_response = service.create_path(
                project_id,
                graph.id,
                version.id,
                CreateCanonicalPathRequest(
                    clientKey=f"path:{index}",
                    pathKey=f"execution:{task.id}",
                    name=str(task.task_type)[:255],
                    description="Observed execution task projection; not a promoted canonical path.",
                    entryNodeId=test_node,
                    exitNodeId=test_node,
                    riskLevel=risk,
                    applicability={"domain": domain},
                    evidenceRefs=[execution_ref],
                    source="observed",
                    confidence=0.9,
                    steps=[
                        PathStepInput(
                            clientKey=f"step:{index}",
                            order=1,
                            nodeId=test_node,
                            evidenceRefs=[execution_ref],
                        )
                    ],
                    versionLockVersion=lock_version,
                ),
                context,
            )
            lock_version = int(path_response["version"]["lockVersion"])
        self.db.expire(version)
        return truncated

    def _materialize_coverage(
        self,
        project_id: UUID,
        requirement: RequirementVersion,
        execution: Execution,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        context: ServiceContext,
    ) -> tuple[UUID | None, dict[str, Any] | None, dict[str, Any]]:
        try:
            result = GraphCoverageService(self.db).compute(
                project_id=project_id,
                graph_id=graph.id,
                graph_version_id=version.id,
                requirement_version_id=requirement.id,
                execution_id=execution.id,
                context=context,
                materialize_gaps=False,
            )
            snapshot_id = UUID(str(result["snapshotId"]))
            proof_ref = result.get("coverageProofRef")
            return (
                snapshot_id,
                proof_ref,
                self._ready(
                    "coverage",
                    record_id=snapshot_id,
                    ref=proof_ref,
                    deduplicated=bool(result.get("deduplicated")),
                ),
            )
        except Exception as exc:
            self.db.rollback()
            return None, None, self._failed("coverage", exc)

    def _materialize_impact(
        self,
        project_id: UUID,
        change_set_id: UUID,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        context: ServiceContext,
    ) -> tuple[UUID | None, dict[str, Any]]:
        try:
            result = self._persist_community_impact(
                project_id=project_id,
                change_set_id=change_set_id,
                graph=graph,
                version=version,
                context=context,
            )
            result_id = UUID(str(result["impactResultId"]))
            return result_id, self._ready(
                "impact",
                record_id=result_id,
                deduplicated=bool(result.get("deduplicated")),
                issues=[{"code": "COMMUNITY_ANALYSIS_REVIEW_REQUIRED", "severity": "warning"}]
                if result.get("reviewRequired")
                else [],
            )
        except Exception as exc:
            self.db.rollback()
            return None, self._failed("impact", exc)

    def _persist_community_impact(
        self,
        *,
        project_id: UUID,
        change_set_id: UUID,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        context: ServiceContext,
    ) -> dict[str, Any]:
        """Persist a conservative deterministic projection without the full command path."""

        scope = ScopeAuthorizationService(self.db).resolve_project(project_id, context)
        change_set = self.db.scalar(
            select(ChangeSetRecord).where(
                ChangeSetRecord.id == change_set_id,
                ChangeSetRecord.tenant_id == scope.tenant_id,
                ChangeSetRecord.workspace_id == scope.workspace_id,
                ChangeSetRecord.project_id == project_id,
            )
        )
        if change_set is None:
            raise ValueError("COMMUNITY_ANALYSIS_CHANGE_SET_NOT_FOUND")
        if (
            graph.project_id != project_id
            or graph.tenant_id != scope.tenant_id
            or graph.workspace_id != scope.workspace_id
            or version.graph_id != graph.id
            or version.project_id != project_id
            or version.tenant_id != scope.tenant_id
            or version.workspace_id != scope.workspace_id
            or version.is_frozen
            or version.source != "observed"
        ):
            raise ValueError("COMMUNITY_ANALYSIS_OBSERVED_GRAPH_REQUIRED")

        input_fingerprint = canonical_hash(
            {
                "schemaVersion": "community.deterministic-impact-input.v1",
                "changeSetId": str(change_set.id),
                "changeSetFingerprint": change_set.fingerprint,
                "graphId": str(graph.id),
                "graphVersionId": str(version.id),
                "graphContentHash": version.content_hash,
                "algorithmVersion": IMPACT_ALGORITHM_VERSION,
                "mode": "community-observed-conservative",
            }
        )
        acquire_transaction_advisory_lock(
            self.db,
            "community-impact-materialization",
            f"{scope.tenant_id}:{scope.workspace_id}:{project_id}:{input_fingerprint}",
        )
        existing = self.db.scalar(
            select(ImpactResultRecord).where(
                ImpactResultRecord.tenant_id == scope.tenant_id,
                ImpactResultRecord.workspace_id == scope.workspace_id,
                ImpactResultRecord.project_id == project_id,
                ImpactResultRecord.input_fingerprint == input_fingerprint,
            )
        )
        if existing is not None:
            projection = dict(existing.result_snapshot)
            projection["deduplicated"] = True
            return ImpactResultContract.model_validate(projection).model_dump(mode="json")

        nodes = list(
            self.db.scalars(
                select(CanonicalExecutionGraphNode)
                .where(
                    CanonicalExecutionGraphNode.version_id == version.id,
                    CanonicalExecutionGraphNode.graph_id == graph.id,
                    CanonicalExecutionGraphNode.tenant_id == scope.tenant_id,
                    CanonicalExecutionGraphNode.workspace_id == scope.workspace_id,
                    CanonicalExecutionGraphNode.project_id == project_id,
                )
                .order_by(CanonicalExecutionGraphNode.id.asc())
            )
        )
        paths = list(
            self.db.scalars(
                select(CanonicalExecutionGraphPath)
                .where(
                    CanonicalExecutionGraphPath.version_id == version.id,
                    CanonicalExecutionGraphPath.graph_id == graph.id,
                    CanonicalExecutionGraphPath.tenant_id == scope.tenant_id,
                    CanonicalExecutionGraphPath.workspace_id == scope.workspace_id,
                    CanonicalExecutionGraphPath.project_id == project_id,
                )
                .order_by(CanonicalExecutionGraphPath.id.asc())
            )
        )
        graph_ref = {"type": "ceg_graph", "ref": graph.graph_ref, "contentHash": None}
        version_ref = {
            "type": "ceg_graph_version",
            "ref": version.version_ref,
            "contentHash": version.content_hash,
        }
        change_ref = {
            "type": "change_set",
            "ref": f"change-set://{change_set.id}",
            "contentHash": change_set.fingerprint,
        }
        evidence_refs = [change_ref, version_ref]

        def propagation(
            entity_type: str, entity_ref: str, confidence: float
        ) -> list[dict[str, Any]]:
            return [
                {
                    "order": 0,
                    "entityType": entity_type,
                    "entityRef": entity_ref,
                    "viaRelation": None,
                    "direction": "seed",
                    "confidence": confidence,
                    "evidenceRefs": evidence_refs,
                }
            ]

        capability_nodes = [item for item in nodes if item.node_type == "capability"]
        test_nodes = [item for item in nodes if item.node_type == "test"]
        impacted_capabilities = []
        for node in capability_nodes:
            entity_ref = str(node.attributes_json.get("capabilityKey") or node.node_ref)
            confidence = min(float(node.confidence), 0.9)
            impacted_capabilities.append(
                {
                    "entityType": "capability",
                    "entityRef": entity_ref,
                    "label": str(node.display_metadata.get("label") or entity_ref)[:255],
                    "riskLevel": self._impact_risk(node.risk_level),
                    "confidence": confidence,
                    "mappingSource": "graph_propagation",
                    "evidenceRefs": evidence_refs,
                    "propagationPath": propagation("capability", entity_ref, confidence),
                }
            )
        impacted_paths = []
        for path in paths:
            confidence = min(float(path.confidence), 0.9)
            impacted_paths.append(
                {
                    "pathId": str(path.id),
                    "pathRef": path.path_ref,
                    "name": path.name,
                    "riskLevel": self._impact_risk(path.risk_level),
                    "confidence": confidence,
                    "evidenceRefs": evidence_refs,
                    "propagationPath": propagation("path", path.path_ref, confidence),
                }
            )
        impacted_tests = []
        for node in test_nodes:
            test_ref = str(node.attributes_json.get("testCaseRef") or node.node_ref)
            confidence = min(float(node.confidence), 0.9)
            impacted_tests.append(
                {
                    "testRef": test_ref,
                    "testKind": str(node.attributes_json.get("testKind") or "observed"),
                    "riskLevel": self._impact_risk(node.risk_level),
                    "confidence": confidence,
                    "evidenceRefs": evidence_refs,
                    "propagationPath": propagation("test", test_ref, confidence),
                }
            )

        result_id = uuid4()
        created_at = datetime.now(UTC)
        ensure_trace(self.db, None, "community.impact.materialize", context.trace_id)
        audit = write_audit_log(
            self.db,
            context.user.id,
            "community.impact.materialize",
            "impact_result",
            str(result_id),
            context.request_id,
            context.trace_id,
            {
                "projectId": str(project_id),
                "changeSetId": str(change_set.id),
                "graphVersionId": str(version.id),
                "inputFingerprint": input_fingerprint,
                "nonAuthoritative": True,
                "reviewRequired": True,
                "modelInvoked": False,
                "approvalCreated": False,
                "productionApplied": False,
            },
        )
        audit_ref = {
            "type": "audit_log",
            "ref": f"audit://logs/{audit.id}",
            "contentHash": None,
        }
        mapping_snapshot_hash = canonical_hash([])
        uncertainty = {
            "code": "COMMUNITY_OBSERVED_GRAPH_NON_AUTHORITATIVE",
            "areaType": "graph",
            "areaRef": version.version_ref,
            "messageKey": "impact.uncertainty.communityObservedGraph",
            "riskLevel": "medium",
            "evidenceRefs": [version_ref],
            "reviewRequired": True,
        }
        replay_snapshot = {
            "schemaVersion": "community.impact-replay-snapshot.v1",
            "inputFingerprint": input_fingerprint,
            "changeSetRefs": [change_ref],
            "graphRef": graph_ref,
            "graphVersionRef": version_ref,
            "mappingSnapshotHash": mapping_snapshot_hash,
            "modelInvocationRefs": [],
            "approvalRefs": [],
            "nonAuthoritative": True,
            "productionApplied": False,
        }
        result = {
            "schemaVersion": "phase8.impact-result.v1",
            "impactResultId": str(result_id),
            "projectId": str(project_id),
            "status": "partial",
            "inputFingerprint": input_fingerprint,
            "deduplicated": False,
            "riskLevel": self._aggregate_impact_risk([*capability_nodes, *test_nodes, *paths]),
            "confidence": 0.75,
            "changeSetRefs": [change_ref],
            "graphRef": graph_ref,
            "graphVersionRef": version_ref,
            "graphStaleness": "unknown",
            "graphAssessmentRef": None,
            "mappingSnapshotHash": mapping_snapshot_hash,
            "mappingVersionRefs": [],
            "algorithmVersion": IMPACT_ALGORITHM_VERSION,
            "modelInvocationRefs": [],
            "guardrailEventRefs": [],
            "impactedCapabilities": impacted_capabilities,
            "impactedPaths": impacted_paths,
            "impactedTests": impacted_tests,
            "impactedRiskDomains": [],
            "unknownAreas": [uncertainty],
            "recommendedFallbacks": [
                {
                    "code": "GRAPH_REFRESH_REQUIRED",
                    "reason": "Observed Community graph is non-authoritative and requires review.",
                    "recommendedAction": "graph_refresh",
                }
            ],
            "aiSuggestions": [],
            "reviewRequired": True,
            "approvalRef": None,
            "truncated": False,
            "visitedNodeCount": len(nodes),
            "traceId": context.trace_id,
            "auditRefs": [audit_ref],
            "replaySnapshot": replay_snapshot,
            "createdAt": created_at,
        }
        validated = ImpactResultContract.model_validate(result).model_dump(mode="json")
        record = ImpactResultRecord(
            id=result_id,
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=project_id,
            change_set_ids=[str(change_set.id)],
            graph_id=graph.id,
            graph_version_id=version.id,
            graph_assessment_id=None,
            graph_staleness="unknown",
            input_fingerprint=input_fingerprint,
            mapping_snapshot_hash=mapping_snapshot_hash,
            mapping_version_refs=[],
            algorithm_version=IMPACT_ALGORITHM_VERSION,
            model_invocation_refs=[],
            status="partial",
            risk_level=validated["riskLevel"],
            confidence=Decimal("0.75"),
            review_required=True,
            approval_id=None,
            truncated=False,
            visited_node_count=len(nodes),
            result_snapshot=validated,
            replay_snapshot=replay_snapshot,
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
            created_at=created_at,
        )
        self.db.add(record)
        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            recovered = self.db.scalar(
                select(ImpactResultRecord).where(
                    ImpactResultRecord.tenant_id == scope.tenant_id,
                    ImpactResultRecord.workspace_id == scope.workspace_id,
                    ImpactResultRecord.project_id == project_id,
                    ImpactResultRecord.input_fingerprint == input_fingerprint,
                )
            )
            if recovered is None:
                raise ValueError("COMMUNITY_ANALYSIS_IMPACT_CONFLICT") from exc
            projection = dict(recovered.result_snapshot)
            projection["deduplicated"] = True
            return ImpactResultContract.model_validate(projection).model_dump(mode="json")
        return validated

    @staticmethod
    def _impact_risk(value: object) -> str:
        risk = getattr(value, "value", value)
        return str(risk) if str(risk) in {"low", "medium", "high"} else "medium"

    @classmethod
    def _aggregate_impact_risk(cls, items: list[object]) -> str:
        risks = [cls._impact_risk(getattr(item, "risk_level", "medium")) for item in items]
        if "high" in risks:
            return "high"
        if "medium" in risks:
            return "medium"
        return "low" if risks else "medium"

    def _materialize_replay(
        self,
        project_id: UUID,
        impact_result_id: UUID,
        coverage_snapshot_id: UUID,
        execution: Execution,
        plan: TestPlan,
        context: ServiceContext,
    ) -> tuple[UUID | None, dict[str, Any]]:
        try:
            task_count = len(
                list(
                    self.db.scalars(
                        select(ExecutionTask.id).where(ExecutionTask.execution_id == execution.id)
                    )
                )
            )
            if not task_count:
                raise ValueError("COMMUNITY_ANALYSIS_EXECUTION_TASKS_MISSING")
            result = ExecutionService(self.db).materialize_community_selective_replay_plan(
                project_id,
                SelectiveReplayRequest(
                    schemaVersion="phase8.selective-replay-request.v1",
                    impactResultId=impact_result_id,
                    baseExecutionId=execution.id,
                    coverageSnapshotId=coverage_snapshot_id,
                    environmentId=plan.environment_id,
                    budget=ReplayPlanBudget(
                        maxTests=min(task_count, 10_000),
                        maxEstimatedSeconds=min(max(task_count * 60, 60), 86_400),
                        overflowBehavior="conservative_fallback",
                    ),
                    confidenceThreshold=0.75,
                    ttlMinutes=60,
                    idempotencyKey=(
                        f"community-replay:{impact_result_id}:{coverage_snapshot_id}:{execution.id}"
                    ),
                ),
                context,
            )
            plan_id = UUID(str(result["planId"]))
            return plan_id, self._ready(
                "selective_replay",
                record_id=plan_id,
                deduplicated=bool(result.get("deduplicated")),
                issues=[
                    {"code": str(code), "severity": "warning"}
                    for code in (result.get("fallback") or {}).get("reasonCodes") or []
                ],
            )
        except Exception as exc:
            self.db.rollback()
            return None, self._failed("selective_replay", exc)

    def _requirement(
        self,
        project_id: UUID,
        requirement_version_id: UUID | None,
    ) -> RequirementVersion | None:
        if requirement_version_id is not None:
            requirement = self.db.get(RequirementVersion, requirement_version_id)
            if requirement is None or not self._belongs_to_project(project_id, requirement.id):
                raise CommunityAnalysisMaterializationError(
                    "COMMUNITY_ANALYSIS_REQUIREMENT_NOT_FOUND",
                    status_code=404,
                    field="requirementVersionId",
                )
            return requirement
        version_ids = {
            item
            for item in self.db.scalars(
                select(TestPlan.requirement_version_id).where(
                    TestPlan.project_id == project_id,
                    TestPlan.requirement_version_id.is_not(None),
                )
            )
            if item is not None
        }
        version_ids.update(
            item
            for item in self.db.scalars(
                select(RequirementIntakePreview.linked_requirement_version_id)
                .join(
                    RequirementIntakeDraft,
                    RequirementIntakeDraft.id == RequirementIntakePreview.draft_id,
                )
                .where(
                    RequirementIntakeDraft.project_id == project_id,
                    RequirementIntakePreview.linked_requirement_version_id.is_not(None),
                )
            )
            if item is not None
        )
        versions = [self.db.get(RequirementVersion, item) for item in version_ids]
        resolved = [item for item in versions if item is not None]
        return (
            max(resolved, key=lambda item: (item.created_at, item.version_no, str(item.id)))
            if resolved
            else None
        )

    def _previous_requirement(
        self,
        project_id: UUID,
        head: RequirementVersion,
    ) -> RequirementVersion | None:
        candidates = list(
            self.db.scalars(
                select(RequirementVersion)
                .where(
                    RequirementVersion.source_ref == head.source_ref,
                    RequirementVersion.version_no < head.version_no,
                )
                .order_by(RequirementVersion.version_no.desc())
            )
        )
        return next(
            (item for item in candidates if self._belongs_to_project(project_id, item.id)),
            None,
        )

    def _belongs_to_project(self, project_id: UUID, requirement_version_id: UUID) -> bool:
        if (
            self.db.scalar(
                select(TestPlan.id).where(
                    TestPlan.project_id == project_id,
                    TestPlan.requirement_version_id == requirement_version_id,
                )
            )
            is not None
        ):
            return True
        return (
            self.db.scalar(
                select(RequirementIntakePreview.id)
                .join(
                    RequirementIntakeDraft,
                    RequirementIntakeDraft.id == RequirementIntakePreview.draft_id,
                )
                .where(
                    RequirementIntakeDraft.project_id == project_id,
                    RequirementIntakePreview.linked_requirement_version_id
                    == requirement_version_id,
                )
            )
            is not None
        )

    def _execution(
        self,
        project_id: UUID,
        requirement: RequirementVersion | None,
        execution_id: UUID | None,
    ) -> tuple[Execution | None, TestPlan | None]:
        if execution_id is not None:
            execution = self.db.get(Execution, execution_id)
            plan = self.db.get(TestPlan, execution.plan_id) if execution else None
            if (
                execution is None
                or plan is None
                or plan.project_id != project_id
                or (requirement is not None and plan.requirement_version_id != requirement.id)
            ):
                raise CommunityAnalysisMaterializationError(
                    "COMMUNITY_ANALYSIS_EXECUTION_NOT_FOUND",
                    status_code=404,
                    field="executionId",
                )
            return execution, plan
        statement = (
            select(Execution)
            .join(TestPlan, TestPlan.id == Execution.plan_id)
            .join(ExecutionTask, ExecutionTask.execution_id == Execution.id)
            .where(TestPlan.project_id == project_id)
        )
        if requirement is not None:
            statement = statement.where(TestPlan.requirement_version_id == requirement.id)
        execution = self.db.scalar(
            statement.order_by(Execution.created_at.desc(), Execution.id.desc()).limit(1)
        )
        return execution, self.db.get(TestPlan, execution.plan_id) if execution else None

    @staticmethod
    def _ready(
        stage_id: str,
        *,
        record_id: UUID | None = None,
        ref: Any = None,
        deduplicated: bool = False,
        issues: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        return {
            "id": stage_id,
            "status": "ready",
            "recordId": str(record_id) if record_id else None,
            "ref": ref,
            "deduplicated": deduplicated,
            "issues": issues or [],
        }

    @staticmethod
    def _blocked(stage_id: str, code: str) -> dict[str, Any]:
        return {
            "id": stage_id,
            "status": "blocked",
            "recordId": None,
            "ref": None,
            "deduplicated": False,
            "issues": [{"code": code, "severity": "blocking"}],
        }

    @staticmethod
    def _failed(stage_id: str, exc: Exception) -> dict[str, Any]:
        candidate = str(getattr(exc, "code", "") or str(exc))
        code = candidate if _REASON_CODE.fullmatch(candidate) else "COMMUNITY_ANALYSIS_STAGE_FAILED"
        return {
            "id": stage_id,
            "status": "failed",
            "recordId": None,
            "ref": None,
            "deduplicated": False,
            "issues": [{"code": code, "severity": "blocking"}],
        }


__all__ = [
    "CommunityAnalysisMaterializationError",
    "CommunityAnalysisMaterializationService",
]

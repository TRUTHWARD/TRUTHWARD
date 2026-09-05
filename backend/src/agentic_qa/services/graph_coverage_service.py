# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterable, cast as type_cast
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import TaskStatus
from agentic_qa.domain.models import (
    CanonicalExecutionGraph,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
    CanonicalExecutionGraphVersion,
    CoverageProofBundleRecord,
    Execution,
    ExecutionArtifact,
    ExecutionMetric,
    ExecutionTask,
    GraphCoverageSnapshot,
        RawFindingRecord,
        RequirementVersion,
        TestPlan,
        TraceabilitySnapshotRecord,
)
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.schemas.graph_coverage import (
    GraphCoverageGap,
    GraphCoverageInput,
    GraphCoverageItem,
    GraphCoverageMetric,
    GraphCoverageResult,
    TraceabilityChain,
    TraceabilityLink,
    TraceabilityProjection,
    TraceabilityRef,
    TraceabilitySegment,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import ensure_trace, record_span
from agentic_qa.services.common import ServiceContext, canonical_hash
from agentic_qa.services.execution_graph_hash import (
    build_graph_topology_hash,
    build_graph_topology_material,
)
from agentic_qa.services.execution_graph_service import ExecutionGraphError, ExecutionGraphService
from agentic_qa.services.graph_staleness_service import GraphStalenessService
from agentic_qa.services.traceability_service import TraceabilityService


GRAPH_COVERAGE_ALGORITHM_VERSION = "graph-coverage.v1"
DIMENSION_ORDER = (
    "requirement",
    "canonical_path",
    "node",
    "risk",
    "change_impact",
)
CHAIN_STAGES = (
    "requirement",
    "capability",
    "code",
    "graph_path",
    "test",
    "execution",
    "evidence",
    "finding",
    "gate",
    "replay",
)
RISK_WEIGHT = {"low": 1, "medium": 3, "high": 9}
STATUS_RANK = {
    "covered": 0,
    "excluded": 0,
    "partial": 1,
    "uncovered": 2,
    "unknown": 3,
}


class GraphCoverageError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


class GraphCoverageService:
    """Extends the existing Traceability/Coverage authority with CEG dimensions."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def compute(
        self,
        *,
        project_id: UUID,
        graph_id: UUID,
        graph_version_id: UUID,
        requirement_version_id: UUID,
        execution_id: UUID | None,
        context: ServiceContext,
        materialize_gaps: bool = False,
    ) -> dict[str, Any]:
        self._require_capability(context, "coverage.read")
        return self._compute(
            project_id=project_id,
            graph_id=graph_id,
            graph_version_id=graph_version_id,
            requirement_version_id=requirement_version_id,
            execution_id=execution_id,
            context=context,
            materialize_gaps=materialize_gaps,
        )

    def _compute(
        self,
        *,
        project_id: UUID,
        graph_id: UUID,
        graph_version_id: UUID,
        requirement_version_id: UUID,
        execution_id: UUID | None,
        context: ServiceContext,
        materialize_gaps: bool,
    ) -> dict[str, Any]:
        scope = self._scope(project_id, context)
        graph = self._graph(scope, graph_id)
        version = self._version(scope, graph, graph_version_id)
        requirement = self.db.get(RequirementVersion, requirement_version_id)
        if requirement is None:
            raise GraphCoverageError("GRAPH_COVERAGE_REQUIREMENT_VERSION_NOT_FOUND", status_code=404)
        execution, plan = self._execution_context(scope, requirement, execution_id)
        # Coverage-proof bundles and the final snapshot both reference the
        # request trace.  Establish that parent before either authority can
        # flush a child row; SQLite can hide this ordering bug, PostgreSQL
        # correctly enforces it.
        ensure_trace(
            self.db,
            execution_id=execution.id if execution else None,
            root_span_name="graph.coverage.compute",
            trace_id=context.trace_id,
        )
        if execution is not None and plan is not None:
            TraceabilityService(self.db).ensure_requirement_execution_chain(
                requirement_version_id=requirement.id,
                test_plan_id=plan.id,
                execution_id=execution.id,
                requirement_scope=plan.requirement_scope or None,
            )
        nodes, edges, paths, steps = self._topology(version)
        topology_hash = build_graph_topology_hash(
            build_graph_topology_material(
                nodes=nodes,
                edges=edges,
                paths=paths,
                steps=steps,
            )
        )
        assessment_projection = GraphStalenessService(self.db).version_projection(
            version,
            expose_change_refs="evidence.read" in set(context.user.capabilities),
        )
        assessment = assessment_projection["assessment"]
        staleness_status = str(assessment.get("status") or "unknown")
        relation_scope = self._relation_scope(requirement.id, plan)
        relation_graph = TraceabilityService(self.db)._load_scope_graph(relation_scope)
        source_state = self._source_state(
            nodes=nodes,
            edges=edges,
            paths=paths,
            steps=steps,
            relation_graph=relation_graph,
            execution=execution,
            assessment=assessment,
        )
        source_state_hash = canonical_hash(source_state)
        expose_evidence = "evidence.read" in set(context.user.capabilities)
        coverage_proof_record = self._coverage_proof_authority(
            requirement,
            plan,
            context,
        )
        coverage_proof_ref = self._coverage_proof_ref(coverage_proof_record)
        projection = self._traceability_projection(
            graph=graph,
            version=version,
            requirement=requirement,
            execution=execution,
            nodes=nodes,
            edges=edges,
            paths=paths,
            steps=steps,
            relation_graph=relation_graph,
            assessment=assessment,
            expose_evidence=expose_evidence,
        )
        input_contract = GraphCoverageInput(
            schemaVersion="phase8.graph-coverage-input.v1",
            algorithmVersion=GRAPH_COVERAGE_ALGORITHM_VERSION,
            tenantId=scope.tenant_id,
            workspaceId=scope.workspace_id,
            projectId=scope.project.id,
            graphId=graph.id,
            graphVersionId=version.id,
            graphContentHash=version.content_hash,
            requirementVersionId=requirement.id,
            requirementContentHash=requirement.content_hash,
            executionId=execution.id if execution else None,
            stalenessStatus=type_cast(Any, staleness_status),
            stalenessAssessmentRef=assessment.get("assessmentRef") or (
                f"graph-staleness-assessment://assessments/{assessment['assessmentId']}"
                if assessment.get("assessmentId")
                else None
            ),
            stalenessAssessmentHash=assessment.get("assessmentHash"),
            topologyHash=topology_hash,
            sourceStateHash=source_state_hash,
            coverageProofRef=coverage_proof_ref,
            changeRefs=[
                self._ref("graph_edge", edge.id, ref=edge.edge_ref)
                for edge in edges
                if edge.edge_type in {"changes", "affects"}
            ],
            sourceRefs=[
                *self._projection_source_refs(
                    version, requirement, execution, assessment, expose_evidence
                ),
                coverage_proof_ref,
            ],
        )
        input_payload = validate_contract(
            "graph-coverage-input", input_contract.model_dump(mode="json")
        )
        input_fingerprint = canonical_hash(input_payload)
        existing = self.db.scalar(
            select(GraphCoverageSnapshot).where(
                GraphCoverageSnapshot.tenant_id == scope.tenant_id,
                GraphCoverageSnapshot.workspace_id == scope.workspace_id,
                GraphCoverageSnapshot.input_fingerprint == input_fingerprint,
            )
        )
        if existing is not None:
            if materialize_gaps and execution is not None:
                self.materialize_gap_candidates(
                    execution.id,
                    dict(existing.result_snapshot),
                )
                self.materialize_gate_metrics(execution.id, dict(existing.result_snapshot))
            return self._snapshot_projection(existing, deduplicated=True)

        metrics = self._coverage_metrics(
            staleness_status=staleness_status,
            nodes=nodes,
            edges=edges,
            paths=paths,
            steps=steps,
            relation_graph=relation_graph,
            execution=execution,
            projection=projection,
            expose_evidence=expose_evidence,
        )
        gaps = self._gaps(metrics, version, requirement, execution)
        status = self._overall_status(metrics)
        computed_at = self._deterministic_computed_at(
            version, requirement, execution, assessment
        )
        snapshot_ref = f"graph-coverage://snapshots/{input_fingerprint.removeprefix('sha256:')}"
        snapshot_hash = canonical_hash(
            {
                "algorithmVersion": GRAPH_COVERAGE_ALGORITHM_VERSION,
                "inputFingerprint": input_fingerprint,
                "status": status,
                "metrics": [item.model_dump(mode="json") for item in metrics],
                "gaps": [item.model_dump(mode="json") for item in gaps],
                "traceabilityProjection": projection.model_dump(mode="json"),
            }
        )
        result = GraphCoverageResult(
            schemaVersion="phase8.graph-coverage-result.v1",
            computedAt=computed_at,
            algorithmVersion=GRAPH_COVERAGE_ALGORITHM_VERSION,
            inputFingerprint=input_fingerprint,
            snapshotRef=snapshot_ref,
            snapshotHash=snapshot_hash,
            coverageProofRef=coverage_proof_ref,
            status=type_cast(Any, status),
            metrics=metrics,
            gaps=gaps,
            rawFindingRefs=[
                {
                    "rawRef": gap.rawFindingRef,
                    "dedupeKey": gap.dedupeKey,
                    "gapId": gap.gapId,
                }
                for gap in gaps
            ],
            findingCandidates=[dict(gap.findingCandidate) for gap in gaps],
            normalizedFindingRefs=[],
            traceabilityProjection=projection,
            replayable=True,
            frontendAuthoritative=False,
        )
        result_payload = validate_contract(
            "graph-coverage-result", result.model_dump(mode="json")
        )
        record = GraphCoverageSnapshot(
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=scope.project.id,
            graph_id=graph.id,
            graph_version_id=version.id,
            coverage_proof_bundle_id=coverage_proof_record.id,
            requirement_version_id=requirement.id,
            execution_id=execution.id if execution else None,
            staleness_assessment_id=(
                UUID(str(assessment["assessmentId"]))
                if assessment.get("assessmentId")
                else None
            ),
            algorithm_version=GRAPH_COVERAGE_ALGORITHM_VERSION,
            input_fingerprint=input_fingerprint,
            snapshot_ref=snapshot_ref,
            snapshot_hash=snapshot_hash,
            status=status,
            input_snapshot=input_payload,
            result_snapshot=result_payload,
            coverage_proof_ref=coverage_proof_ref.model_dump(mode="json"),
            traceability_snapshot=projection.model_dump(mode="json"),
            metric_snapshot=[item.model_dump(mode="json") for item in metrics],
            gap_snapshot=[item.model_dump(mode="json") for item in gaps],
            raw_finding_refs=list(result_payload["rawFindingRefs"]),
            normalized_finding_refs=[],
            replay_refs=[],
            trace_id=UUID(context.trace_id),
            computed_at=computed_at,
        )
        self.db.add(record)
        self.db.flush()
        record_span(
            self.db,
            context.trace_id,
            "graph.coverage.compute",
            "orchestrator-service",
            attributes={
                "graphVersionId": str(version.id),
                "requirementVersionId": str(requirement.id),
                "coverageProofBundleId": str(coverage_proof_record.id),
                "executionId": str(execution.id) if execution else None,
                "algorithmVersion": GRAPH_COVERAGE_ALGORITHM_VERSION,
                "inputFingerprint": input_fingerprint,
                "snapshotHash": snapshot_hash,
                "status": status,
            },
        )
        write_audit_log(
            self.db,
            context.user.id,
            "graph.coverage.snapshot",
            "graph_coverage_snapshot",
            str(record.id),
            context.request_id,
            context.trace_id,
            {
                "projectId": str(scope.project.id),
                "graphVersionId": str(version.id),
                "requirementVersionId": str(requirement.id),
                "executionId": str(execution.id) if execution else None,
                "algorithmVersion": GRAPH_COVERAGE_ALGORITHM_VERSION,
                "inputFingerprint": input_fingerprint,
                "snapshotHash": snapshot_hash,
                "status": status,
                "gapCount": len(gaps),
                "approvalRequired": False,
            },
            execution_id=execution.id if execution else None,
        )
        if materialize_gaps and execution is not None:
            self.materialize_gap_candidates(execution.id, result_payload)
            self.materialize_gate_metrics(execution.id, result_payload)
        self.db.flush()
        return self._snapshot_projection(record, deduplicated=False)

    def get_snapshot(
        self,
        snapshot_id: UUID,
        *,
        project_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "coverage.read")
        scope = self._scope(project_id, context)
        record = self.db.scalar(
            select(GraphCoverageSnapshot).where(
                GraphCoverageSnapshot.id == snapshot_id,
                GraphCoverageSnapshot.tenant_id == scope.tenant_id,
                GraphCoverageSnapshot.workspace_id == scope.workspace_id,
                GraphCoverageSnapshot.project_id == scope.project.id,
            )
        )
        if record is None:
            raise GraphCoverageError("GRAPH_COVERAGE_SNAPSHOT_NOT_FOUND", status_code=404)
        return self._snapshot_projection(record, deduplicated=True)

    def latest_for_execution(self, execution_id: UUID) -> dict[str, Any] | None:
        record = self._latest_execution_snapshot_record(execution_id)
        return dict(record.result_snapshot) if record else None

    def materialize_for_execution(
        self,
        execution_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any] | None:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise GraphCoverageError("GRAPH_COVERAGE_EXECUTION_NOT_FOUND", status_code=404)
        plan = self.db.get(TestPlan, execution.plan_id)
        graph_version_id = self._graph_version_id_from_execution(execution, plan)
        if graph_version_id is None or plan is None or plan.project_id is None or plan.requirement_version_id is None:
            return None
        version = self.db.get(CanonicalExecutionGraphVersion, graph_version_id)
        if version is None:
            raise GraphCoverageError("GRAPH_COVERAGE_GRAPH_VERSION_NOT_FOUND", status_code=404)
        # This is an internal Domain Service lifecycle hook, not a user-facing
        # coverage query. Authorization has already happened at the execution
        # boundary, so it must not depend on the caller also holding coverage.read.
        return self._compute(
            project_id=plan.project_id,
            graph_id=version.graph_id,
            graph_version_id=version.id,
            requirement_version_id=plan.requirement_version_id,
            execution_id=execution.id,
            context=context,
            materialize_gaps=True,
        )

    def materialize_gap_candidates(
        self,
        execution_id: UUID,
        result_payload: dict[str, Any],
    ) -> list[RawFindingRecord]:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise GraphCoverageError("GRAPH_COVERAGE_EXECUTION_NOT_FOUND", status_code=404)
        persisted: list[RawFindingRecord] = []
        for candidate in result_payload.get("findingCandidates") or []:
            dedupe_key = str(candidate["dedupeKey"])
            existing = self.db.scalar(
                select(RawFindingRecord).where(
                    RawFindingRecord.execution_id == execution_id,
                    RawFindingRecord.dedupe_key == dedupe_key,
                )
            )
            if existing is not None:
                persisted.append(existing)
                continue
            row = RawFindingRecord(
                id=uuid4(),
                execution_id=execution_id,
                task_id=None,
                source="system",
                category="reliability",
                severity=str(candidate["severity"]),
                title=str(candidate["title"]),
                summary=str(candidate["summary"]),
                confidence=Decimal(str(candidate["confidence"])),
                dedupe_key=dedupe_key,
                raw_ref=str(candidate["rawRef"]),
                location=dict(candidate["location"]),
                evidence=list(candidate["evidence"]),
                metadata_json={
                    **dict(candidate.get("metadata") or {}),
                    "domain": "functional",
                    "coverageGap": True,
                    "normalizeRequired": True,
                    "writesGate": False,
                },
            )
            self.db.add(row)
            self.db.flush()
            persisted.append(row)
        return persisted

    def materialize_gate_metrics(
        self,
        execution_id: UUID,
        result_payload: dict[str, Any],
    ) -> list[ExecutionMetric]:
        persisted: list[ExecutionMetric] = []
        snapshot_ref = str(result_payload["snapshotRef"])
        snapshot_hash = str(result_payload["snapshotHash"])
        for metric in result_payload.get("metrics") or []:
            metric_name = f"graph_coverage.{metric['dimension']}"
            matching = list(
                self.db.scalars(
                    select(ExecutionMetric).where(
                        ExecutionMetric.execution_id == execution_id,
                        ExecutionMetric.metric_name == metric_name,
                    )
                )
            )
            existing = next(
                (
                    item
                    for item in matching
                    if item.metadata_json.get("graphCoverageSnapshotHash") == snapshot_hash
                ),
                None,
            )
            if existing is not None:
                persisted.append(existing)
                continue
            ratio = metric.get("partialCreditRatio")
            row = ExecutionMetric(
                id=uuid4(),
                execution_id=execution_id,
                task_id=None,
                metric_name=metric_name,
                metric_value=Decimal(str(ratio if ratio is not None else 0.0)),
                metric_unit="ratio",
                threshold_value=None,
                baseline_value=None,
                metadata_json={
                    "source": "graph_coverage",
                    "domain": "functional",
                    "graphCoverageSnapshotRef": snapshot_ref,
                    "graphCoverageSnapshotHash": snapshot_hash,
                    "graphCoverageStatus": metric["status"],
                    "unknown": int(metric["unknown"]),
                    "excluded": int(metric["excluded"]),
                    "rawMetricRef": snapshot_ref,
                },
            )
            self.db.add(row)
            self.db.flush()
            persisted.append(row)
        return persisted

    def _coverage_metrics(
        self,
        *,
        staleness_status: str,
        nodes: list[CanonicalExecutionGraphNode],
        edges: list[CanonicalExecutionGraphEdge],
        paths: list[CanonicalExecutionGraphPath],
        steps: list[CanonicalExecutionGraphPathStep],
        relation_graph: dict[str, list[Any]],
        execution: Execution | None,
        projection: TraceabilityProjection,
        expose_evidence: bool,
    ) -> list[GraphCoverageMetric]:
        steps_by_path: dict[UUID, list[CanonicalExecutionGraphPathStep]] = defaultdict(list)
        path_ids_by_node: dict[UUID, set[UUID]] = defaultdict(set)
        for step in steps:
            steps_by_path[step.path_id].append(step)
            path_ids_by_node[step.node_id].add(step.path_id)

        test_asset_ids_by_node = {
            node.id: self._test_asset_ids(node)
            for node in nodes
            if node.node_type == "test"
        }
        execution_status_by_test = self._test_execution_statuses(
            relation_graph,
            execution,
        )
        path_items: list[GraphCoverageItem] = []
        for path in paths:
            applicability_status, applicability_reason = self._path_applicability(path)
            if applicability_status == "excluded":
                path_items.append(
                    self._item(
                        "canonical_path",
                        path.id,
                        path.path_ref,
                        "excluded",
                        [applicability_reason],
                        path.risk_level,
                    )
                )
                continue
            test_ids = {
                test_id
                for step in steps_by_path.get(path.id, [])
                for test_id in test_asset_ids_by_node.get(step.node_id, set())
            }
            status, reasons, evidence = self._path_execution_status(
                test_ids,
                execution_status_by_test,
                execution,
                expose_evidence=expose_evidence,
            )
            if staleness_status != "fresh":
                status = "unknown"
                reasons = [f"GRAPH_COVERAGE_GRAPH_{staleness_status.upper()}"]
            path_items.append(
                self._item(
                    "canonical_path",
                    path.id,
                    path.path_ref,
                    status,
                    reasons,
                    path.risk_level,
                    evidence,
                )
            )
        path_item_by_id = {
            UUID(item.entityRef.id): item
            for item in path_items
        }

        node_items: list[GraphCoverageItem] = []
        for node in nodes:
            memberships = [path_item_by_id[item] for item in path_ids_by_node.get(node.id, set())]
            if not memberships:
                status, reasons = "uncovered", ["GRAPH_COVERAGE_NODE_NOT_IN_CANONICAL_PATH"]
            else:
                status = max((item.status for item in memberships), key=lambda item: STATUS_RANK[item])
                reasons = sorted({reason for item in memberships for reason in item.reasonCodes})
            if staleness_status != "fresh" and status != "excluded":
                status = "unknown"
                reasons = [f"GRAPH_COVERAGE_GRAPH_{staleness_status.upper()}"]
            node_items.append(
                self._item("graph_node", node.id, node.node_ref, status, reasons, node.risk_level)
            )

        requirement_nodes = [item for item in nodes if item.node_type == "requirement"]
        requirement_items: list[GraphCoverageItem] = []
        if not requirement_nodes:
            requirement_items.append(
                self._item(
                    "requirement_version",
                    projection.requirementVersionId,
                    projection.requirementVersionRef,
                    "unknown",
                    ["GRAPH_COVERAGE_REQUIREMENT_NODE_MISSING"],
                    "high",
                )
            )
        else:
            node_item_map = {item.entityRef.id: item for item in node_items}
            for node in requirement_nodes:
                item = node_item_map[str(node.id)]
                requirement_items.append(
                    self._item(
                        "requirement",
                        node.id,
                        node.node_ref,
                        item.status,
                        item.reasonCodes,
                        node.risk_level,
                        item.evidenceRefs,
                    )
                )

        risk_items = [
            GraphCoverageItem(
                entityRef=item.entityRef,
                status=item.status,
                reasonCodes=item.reasonCodes,
                evidenceRefs=item.evidenceRefs,
                riskLevel=item.riskLevel,
                weight=RISK_WEIGHT[item.riskLevel or "low"],
            )
            for item in path_items
            if item.status != "excluded"
        ]
        impacted_ids = {
            edge.target_node_id
            for edge in edges
            if edge.edge_type in {"changes", "affects"}
        }
        node_item_map = {item.entityRef.id: item for item in node_items}
        change_items = [
            GraphCoverageItem(
                entityRef=node_item_map[str(node_id)].entityRef,
                status=node_item_map[str(node_id)].status,
                reasonCodes=node_item_map[str(node_id)].reasonCodes,
                evidenceRefs=node_item_map[str(node_id)].evidenceRefs,
                riskLevel=node_item_map[str(node_id)].riskLevel,
                weight=RISK_WEIGHT[node_item_map[str(node_id)].riskLevel or "low"],
            )
            for node_id in sorted(impacted_ids, key=str)
            if str(node_id) in node_item_map
        ]
        return [
            self._metric("requirement", requirement_items),
            self._metric("canonical_path", path_items),
            self._metric("node", node_items),
            self._metric("risk", risk_items, weighted=True),
            self._metric("change_impact", change_items, weighted=True),
        ]

    def _traceability_projection(
        self,
        *,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        requirement: RequirementVersion,
        execution: Execution | None,
        nodes: list[CanonicalExecutionGraphNode],
        edges: list[CanonicalExecutionGraphEdge],
        paths: list[CanonicalExecutionGraphPath],
        steps: list[CanonicalExecutionGraphPathStep],
        relation_graph: dict[str, list[Any]],
        assessment: dict[str, Any],
        expose_evidence: bool,
    ) -> TraceabilityProjection:
        node_by_id = {item.id: item for item in nodes}
        steps_by_path: dict[UUID, list[CanonicalExecutionGraphPathStep]] = defaultdict(list)
        for step in steps:
            steps_by_path[step.path_id].append(step)
        links: list[TraceabilityLink] = []
        link_ids_by_path: dict[UUID, list[str]] = defaultdict(list)
        for edge in sorted(edges, key=lambda item: (item.edge_type, str(item.id))):
            source = node_by_id[edge.source_node_id]
            target = node_by_id[edge.target_node_id]
            link = self._link(
                self._node_ref(source),
                self._node_ref(target),
                edge.edge_type,
                self._ref("graph_edge", edge.id, ref=edge.edge_ref),
                self._graph_relation_status(edge.review_status, assessment),
                self._stable_refs(edge.audit_refs, expose_evidence),
            )
            links.append(link)
        for path in paths:
            path_ref = self._ref("canonical_path", path.id, ref=path.path_ref, label=path.name)
            for step in sorted(steps_by_path.get(path.id, []), key=lambda item: item.step_order):
                link = self._link(
                    path_ref,
                    self._node_ref(node_by_id[step.node_id]),
                    "contains_step",
                    self._ref("graph_path_step", step.id, ref=step.step_ref),
                    "system_verified",
                    self._stable_refs(step.evidence_refs, expose_evidence),
                )
                links.append(link)
                link_ids_by_path[path.id].append(link.linkId)
        typed_links = self._typed_traceability_links(relation_graph, expose_evidence)
        links.extend(typed_links)
        typed_link_ids = [item.linkId for item in typed_links]
        chains: list[TraceabilityChain] = []
        missing: list[dict[str, Any]] = []
        for path in paths:
            path_nodes = [
                node_by_id[item.node_id]
                for item in sorted(steps_by_path.get(path.id, []), key=lambda item: item.step_order)
            ]
            segments = self._chain_segments(
                requirement,
                path,
                path_nodes,
                relation_graph,
                execution,
                expose_evidence,
            )
            reasons = sorted({reason for segment in segments for reason in segment.reasonCodes})
            complete = all(segment.status in {"available", "not_applicable"} for segment in segments)
            material = {
                "pathId": str(path.id),
                "segments": [segment.model_dump(mode="json") for segment in segments],
            }
            chain = TraceabilityChain(
                chainId=f"trace-chain:{canonical_hash(material).removeprefix('sha256:')}",
                canonicalPathRef=self._ref("canonical_path", path.id, ref=path.path_ref, label=path.name),
                segments=segments,
                linkIds=[*link_ids_by_path[path.id], *typed_link_ids],
                complete=complete,
                reasonCodes=reasons,
            )
            chains.append(chain)
            if not complete:
                missing.append(
                    {
                        "canonicalPathId": str(path.id),
                        "reasonCodes": reasons,
                        "blocksCoverage": True,
                    }
                )
        staleness_status = str(assessment.get("status") or "unknown")
        return TraceabilityProjection(
            schemaVersion="phase8.graph-traceability-projection.v1",
            generatedAt=self._deterministic_computed_at(version, requirement, execution, assessment),
            tenantId=version.tenant_id,
            workspaceId=version.workspace_id,
            projectId=version.project_id,
            graphId=graph.id,
            graphVersionId=version.id,
            graphVersionRef=version.version_ref,
            graphContentHash=version.content_hash,
            graphStatus=version.status.value,
            stalenessStatus=type_cast(Any, staleness_status),
            stalenessAssessmentRef=(
                f"graph-staleness-assessment://assessments/{assessment['assessmentId']}"
                if assessment.get("assessmentId")
                else None
            ),
            stalenessAssessmentHash=assessment.get("assessmentHash"),
            requirementVersionId=requirement.id,
            requirementVersionRef=f"requirement://versions/{requirement.id}",
            requirementContentHash=requirement.content_hash,
            executionId=execution.id if execution else None,
            links=sorted(links, key=lambda item: item.linkId),
            chains=sorted(chains, key=lambda item: item.chainId),
            missingLinks=missing,
            sourceRefs=self._projection_source_refs(
                version, requirement, execution, assessment, expose_evidence
            ),
            evidenceRefsRedacted=not expose_evidence,
        )

    def _chain_segments(
        self,
        requirement: RequirementVersion,
        path: CanonicalExecutionGraphPath,
        path_nodes: list[CanonicalExecutionGraphNode],
        relation_graph: dict[str, list[Any]],
        execution: Execution | None,
        expose_evidence: bool,
    ) -> list[TraceabilitySegment]:
        refs: dict[str, list[TraceabilityRef]] = {stage: [] for stage in CHAIN_STAGES}
        refs["requirement"].append(
            self._ref("requirement_version", requirement.id, ref=f"requirement://versions/{requirement.id}")
        )
        refs["graph_path"].append(
            self._ref("canonical_path", path.id, ref=path.path_ref, label=path.name)
        )
        for node in path_nodes:
            if node.node_type == "requirement":
                refs["requirement"].append(self._node_ref(node))
            elif node.node_type == "capability":
                refs["capability"].append(self._node_ref(node))
            elif node.node_type == "code":
                refs["code"].append(self._node_ref(node))
            elif node.node_type == "test":
                refs["test"].append(self._node_ref(node))
        test_ids = {
            test_id
            for node in path_nodes
            if node.node_type == "test"
            for test_id in self._test_asset_ids(node)
        }
        tasks = [
            relation
            for relation in relation_graph["test_case_execution_tasks"]
            if relation.test_case_id in test_ids
            and (execution is None or relation.execution_task_id in self._execution_task_ids(execution.id))
        ]
        task_ids = {item.execution_task_id for item in tasks}
        refs["test"].extend(
            self._ref("test_asset", item, ref=f"test://assets/{item}")
            for item in sorted(test_ids, key=str)
        )
        refs["execution"].extend(
            self._ref("execution_task", item, ref=f"execution-task://tasks/{item}")
            for item in sorted(task_ids, key=str)
        )
        artifact_relations = [
            item
            for item in relation_graph["execution_task_evidence_artifacts"]
            if item.execution_task_id in task_ids
        ]
        artifact_ids = {item.evidence_artifact_id for item in artifact_relations}
        refs["evidence"].extend(
            self._evidence_ref(item, expose_evidence)
            for item in sorted(artifact_ids, key=str)
        )
        raw_relations = [
            item for item in relation_graph["evidence_raw_findings"]
            if item.evidence_artifact_id in artifact_ids
        ]
        raw_ids = {item.raw_finding_id for item in raw_relations}
        normalized_relations = [
            item for item in relation_graph["raw_normalized_findings"]
            if item.raw_finding_id in raw_ids
        ]
        finding_ids = {item.normalized_finding_id for item in normalized_relations}
        refs["finding"].extend(
            self._ref("finding", item, ref=f"finding://findings/{item}")
            for item in sorted(finding_ids, key=str)
        )
        gate_relations = [
            item for item in relation_graph["normalized_finding_gate_decisions"]
            if item.normalized_finding_id in finding_ids
        ]
        gate_ids = {item.gate_decision_id for item in gate_relations}
        refs["gate"].extend(
            self._ref("gate_decision", item, ref=f"gate://decisions/{item}")
            for item in sorted(gate_ids, key=str)
        )
        replay_relations = [
            item for item in relation_graph["gate_decision_replay_exports"]
            if item.gate_decision_id in gate_ids
        ]
        refs["replay"].extend(
            self._ref("replay_export", item.replay_export_id)
            for item in replay_relations
        )
        segments: list[TraceabilitySegment] = []
        for stage in CHAIN_STAGES:
            stage_refs = self._dedupe_refs(refs[stage])
            if stage_refs:
                status = "available"
                reason_codes: list[str] = []
            elif stage in {"finding", "gate", "replay"} and execution is None:
                status = "not_applicable"
                reason_codes = ["GRAPH_TRACEABILITY_EXECUTION_CONTEXT_NOT_REQUESTED"]
            else:
                status = "unavailable"
                reason_codes = [f"GRAPH_TRACEABILITY_{stage.upper()}_REF_MISSING"]
            segments.append(
                TraceabilitySegment(
                    stage=type_cast(Any, stage),
                    refs=stage_refs,
                    status=type_cast(Any, status),
                    reasonCodes=reason_codes,
                )
            )
        return segments

    def _typed_traceability_links(
        self,
        relation_graph: dict[str, list[Any]],
        expose_evidence: bool,
    ) -> list[TraceabilityLink]:
        traceability = TraceabilityService(self.db)
        links: list[TraceabilityLink] = []
        for table, relations in relation_graph.items():
            for relation in relations:
                view = traceability._relation_view(table, relation)
                source = self._ref(view.sourceType, view.sourceId)
                target = self._ref(view.targetType, view.targetId)
                evidence_refs: list[TraceabilityRef] = []
                if view.sourceType == "evidence_artifact":
                    evidence_refs.append(self._evidence_ref(UUID(view.sourceId), expose_evidence))
                if view.targetType == "evidence_artifact":
                    evidence_refs.append(self._evidence_ref(UUID(view.targetId), expose_evidence))
                links.append(
                    self._link(
                        source,
                        target,
                        view.relationType,
                        self._ref("traceability_relation", view.id or "unknown"),
                        view.status.value,
                        evidence_refs,
                    )
                )
        return links

    def _gaps(
        self,
        metrics: list[GraphCoverageMetric],
        version: CanonicalExecutionGraphVersion,
        requirement: RequirementVersion,
        execution: Execution | None,
    ) -> list[GraphCoverageGap]:
        gaps: list[GraphCoverageGap] = []
        for metric in metrics:
            for item in metric.items:
                if item.status not in {"partial", "uncovered", "unknown"}:
                    continue
                reason = item.reasonCodes[0] if item.reasonCodes else "GRAPH_COVERAGE_GAP"
                gap_material = {
                    "algorithmVersion": GRAPH_COVERAGE_ALGORITHM_VERSION,
                    "graphVersionId": str(version.id),
                    "requirementVersionId": str(requirement.id),
                    "executionId": str(execution.id) if execution else None,
                    "dimension": metric.dimension,
                    "entity": item.entityRef.model_dump(mode="json"),
                    "status": item.status,
                    "reason": reason,
                }
                gap_hash = canonical_hash(gap_material).removeprefix("sha256:")
                raw_ref = f"graph-coverage://gaps/{gap_hash}"
                severity = self._gap_severity(metric.dimension, item)
                evidence = item.evidenceRefs or [
                    self._ref(
                        "graph_version",
                        version.id,
                        ref=version.version_ref,
                        content_hash=version.content_hash,
                    )
                ]
                evidence_payload = [
                    {
                        "type": "artifact_ref" if ref.type == "evidence_artifact" else "external_ref",
                        "ref": ref.ref or f"{ref.type}://{ref.id}",
                        "contentHash": ref.contentHash,
                    }
                    for ref in evidence
                ]
                dedupe = f"graph-coverage:{gap_hash}"
                candidate = {
                    "source": "system",
                    "category": "reliability",
                    "severity": severity,
                    "title": f"Graph coverage gap: {metric.dimension}",
                    "summary": f"{item.entityRef.type} {item.entityRef.id} is {item.status}: {reason}",
                    "confidence": 1.0 if item.status != "unknown" else 0.5,
                    "dedupeKey": dedupe,
                    "rawRef": raw_ref,
                    "location": {
                        "kind": "service",
                        "service": "graph-coverage",
                        "graphVersionId": str(version.id),
                        "dimension": metric.dimension,
                        "entityType": item.entityRef.type,
                        "entityId": item.entityRef.id,
                    },
                    "evidence": evidence_payload,
                    "metadata": {
                        "gapId": f"coverage-gap:{gap_hash}",
                        "reasonCode": reason,
                        "status": item.status,
                        "dimension": metric.dimension,
                        "entityType": item.entityRef.type,
                        "entityId": item.entityRef.id,
                        "algorithmVersion": GRAPH_COVERAGE_ALGORITHM_VERSION,
                        "artifactIdsByUri": {
                            str(payload["ref"]): ref.id
                            for ref, payload in zip(evidence, evidence_payload, strict=True)
                            if ref.type == "evidence_artifact"
                        },
                    },
                }
                gaps.append(
                    GraphCoverageGap(
                        gapId=f"coverage-gap:{gap_hash}",
                        dimension=metric.dimension,
                        entityRef=item.entityRef,
                        status=type_cast(Any, item.status),
                        reasonCode=reason,
                        severity=type_cast(Any, severity),
                        evidenceRefs=evidence,
                        rawFindingRef=raw_ref,
                        dedupeKey=dedupe,
                        findingCandidate=candidate,
                    )
                )
        return sorted(gaps, key=lambda item: item.gapId)

    def _test_execution_statuses(
        self,
        relation_graph: dict[str, list[Any]],
        execution: Execution | None,
    ) -> dict[UUID, list[tuple[ExecutionTask, list[ExecutionArtifact | None]]]]:
        result: dict[
            UUID,
            list[tuple[ExecutionTask, list[ExecutionArtifact | None]]],
        ] = defaultdict(list)
        execution_task_ids = self._execution_task_ids(execution.id) if execution else set()
        artifacts_by_task: dict[UUID, list[ExecutionArtifact | None]] = defaultdict(list)
        artifact_relations = relation_graph["execution_task_evidence_artifacts"]
        artifact_ids = {item.evidence_artifact_id for item in artifact_relations}
        artifacts = {
            item.id: item
            for item in self.db.scalars(select(ExecutionArtifact).where(ExecutionArtifact.id.in_(artifact_ids)))
        } if artifact_ids else {}
        for relation in artifact_relations:
            artifact = artifacts.get(relation.evidence_artifact_id)
            # The typed relation remains an input fact even when retention has
            # removed/expired its target. Preserve that absence as unknown
            # instead of silently downgrading it to ordinary no-evidence.
            artifacts_by_task[relation.execution_task_id].append(artifact)
        for relation in relation_graph["test_case_execution_tasks"]:
            if execution is not None and relation.execution_task_id not in execution_task_ids:
                continue
            task = self.db.get(ExecutionTask, relation.execution_task_id)
            if task is not None:
                result[relation.test_case_id].append((task, artifacts_by_task[task.id]))
        return result

    def _path_execution_status(
        self,
        test_ids: set[UUID],
        statuses: dict[
            UUID,
            list[tuple[ExecutionTask, list[ExecutionArtifact | None]]],
        ],
        execution: Execution | None,
        *,
        expose_evidence: bool,
    ) -> tuple[str, list[str], list[TraceabilityRef]]:
        if not test_ids:
            return "uncovered", ["GRAPH_COVERAGE_PATH_TEST_MAPPING_MISSING"], []
        records = [record for test_id in test_ids for record in statuses.get(test_id, [])]
        if not records:
            if execution is not None and execution.status in {
                TaskStatus.QUEUED,
                TaskStatus.RUNNING,
                TaskStatus.ANALYZING,
            }:
                return "unknown", ["GRAPH_COVERAGE_EXECUTION_IN_PROGRESS"], []
            return "uncovered", ["GRAPH_COVERAGE_TEST_NOT_EXECUTED"], []
        evidence = [
            self._ref(
                "evidence_artifact",
                artifact.id,
                ref=(artifact.redacted_uri or artifact.uri) if expose_evidence else None,
                status=artifact.redaction_status,
                redacted=not expose_evidence,
            )
            for _, artifacts in records
            for artifact in artifacts
            if artifact is not None
        ]
        retention_unavailable = any(
            artifact is None
            or (
                artifact.expires_at is not None
                and self._aware(artifact.expires_at) <= datetime.now(timezone.utc)
            )
            for _, artifacts in records
            for artifact in artifacts
        )
        if retention_unavailable:
            return "unknown", ["GRAPH_COVERAGE_EVIDENCE_RETENTION_UNAVAILABLE"], evidence
        completed_with_evidence = [
            task for task, artifacts in records
            if task.status == TaskStatus.COMPLETED
            and any(artifact is not None for artifact in artifacts)
        ]
        if len(completed_with_evidence) == len(records):
            return "covered", [], evidence
        if any(task.status in {TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.ANALYZING} for task, _ in records):
            return "unknown", ["GRAPH_COVERAGE_EXECUTION_IN_PROGRESS"], evidence
        if evidence:
            return "partial", ["GRAPH_COVERAGE_TEST_FAILED_OR_SKIPPED_WITH_PARTIAL_EVIDENCE"], evidence
        return "uncovered", ["GRAPH_COVERAGE_EXECUTION_EVIDENCE_MISSING"], evidence

    @staticmethod
    def _metric(dimension: str, items: list[GraphCoverageItem], *, weighted: bool = False) -> GraphCoverageMetric:
        counts = {status: sum(item.status == status for item in items) for status in STATUS_RANK}
        applicable = counts["covered"] + counts["partial"] + counts["uncovered"]
        unknown = counts["unknown"]
        coverage_ratio = None if applicable == 0 or unknown else counts["covered"] / applicable
        partial_credit_ratio = (
            None
            if applicable == 0 or unknown
            else (counts["covered"] + 0.5 * counts["partial"]) / applicable
        )
        weighted_ratio: float | None = None
        if weighted and applicable and not unknown:
            denominator = sum(item.weight for item in items if item.status not in {"excluded", "unknown"})
            numerator = sum(
                item.weight * (1.0 if item.status == "covered" else 0.5 if item.status == "partial" else 0.0)
                for item in items
                if item.status not in {"excluded", "unknown"}
            )
            weighted_ratio = numerator / denominator if denominator else None
        if unknown:
            status = "unknown"
        elif not items or applicable == 0:
            status = "not_applicable"
        elif counts["uncovered"] == 0 and counts["partial"] == 0:
            status = "covered"
        elif counts["covered"] or counts["partial"]:
            status = "partial"
        else:
            status = "uncovered"
        exclusions = [
            {
                "entityType": item.entityRef.type,
                "entityId": item.entityRef.id,
                "reasonCodes": item.reasonCodes,
            }
            for item in items
            if item.status == "excluded"
        ]
        return GraphCoverageMetric(
            dimension=type_cast(Any, dimension),
            total=len(items),
            applicable=applicable,
            covered=counts["covered"],
            partial=counts["partial"],
            uncovered=counts["uncovered"],
            excluded=counts["excluded"],
            unknown=unknown,
            coverageRatio=coverage_ratio,
            partialCreditRatio=partial_credit_ratio,
            weightedCoverageRatio=weighted_ratio,
            status=type_cast(Any, status),
            denominatorExplanation=(
                "applicable = covered + partial + uncovered; excluded and unknown are outside "
                "the numeric denominator; any unknown makes ratios unavailable"
            ),
            exclusionReasons=exclusions,
            items=items,
        )

    @staticmethod
    def _overall_status(metrics: list[GraphCoverageMetric]) -> str:
        statuses = {item.status for item in metrics if item.dimension != "change_impact" or item.total}
        if "unknown" in statuses:
            return "unknown"
        if not statuses or statuses == {"not_applicable"}:
            return "not_applicable"
        if statuses <= {"covered", "not_applicable"}:
            return "covered"
        if "covered" in statuses or "partial" in statuses:
            return "partial"
        return "uncovered"

    @staticmethod
    def _gap_severity(dimension: str, item: GraphCoverageItem) -> str:
        if item.status == "unknown":
            return "high"
        if dimension in {"requirement", "change_impact"} or item.riskLevel == "high":
            return "high"
        if item.status == "uncovered" or item.riskLevel == "medium":
            return "medium"
        return "low"

    @staticmethod
    def _path_applicability(path: CanonicalExecutionGraphPath) -> tuple[str, str]:
        applicability = dict(path.applicability or {})
        if applicability.get("excluded") is True or applicability.get("applicable") is False:
            return "excluded", str(applicability.get("reasonCode") or "GRAPH_COVERAGE_PATH_EXCLUDED")
        return "applicable", "GRAPH_COVERAGE_PATH_APPLICABLE"

    def _source_state(
        self,
        *,
        nodes: list[Any],
        edges: list[Any],
        paths: list[Any],
        steps: list[Any],
        relation_graph: dict[str, list[Any]],
        execution: Execution | None,
        assessment: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "topology": build_graph_topology_material(nodes=nodes, edges=edges, paths=paths, steps=steps),
            "relations": self._relation_state_rows(relation_graph),
            "execution": (
                {
                    "id": str(execution.id),
                    "status": execution.status.value,
                    "stage": execution.stage.value,
                    "endedAt": execution.ended_at.isoformat() if execution.ended_at else None,
                    "tasks": [
                        {
                            "id": str(task.id),
                            "status": task.status.value,
                            "stage": task.stage.value if task.stage else None,
                            "updatedAt": task.updated_at.isoformat() if task.updated_at else None,
                        }
                        for task in self.db.scalars(
                            select(ExecutionTask)
                            .where(ExecutionTask.execution_id == execution.id)
                            .order_by(ExecutionTask.id)
                        )
                    ],
                    "artifacts": [
                        {
                            "id": str(artifact.id),
                            "taskId": str(artifact.task_id) if artifact.task_id else None,
                            "type": artifact.artifact_type.value,
                            "uri": artifact.redacted_uri or artifact.uri,
                            "redactionStatus": artifact.redaction_status,
                            "expiresAt": artifact.expires_at.isoformat() if artifact.expires_at else None,
                        }
                        for artifact in self.db.scalars(
                            select(ExecutionArtifact)
                            .where(ExecutionArtifact.execution_id == execution.id)
                            .order_by(ExecutionArtifact.id)
                        )
                    ],
                }
                if execution
                else None
            ),
            "assessment": {
                "status": assessment.get("status"),
                "hash": assessment.get("assessmentHash"),
            },
        }

    def _relation_state_rows(
        self,
        relation_graph: dict[str, list[Any]],
    ) -> list[dict[str, Any]]:
        service = TraceabilityService(self.db)
        rows: list[dict[str, Any]] = []
        for table, relations in sorted(relation_graph.items()):
            for relation in sorted(relations, key=lambda value: str(value.id)):
                view = service._relation_view(table, relation)
                rows.append(
                    {
                        "table": table,
                        "id": str(relation.id),
                        "sourceId": view.sourceId,
                        "targetId": view.targetId,
                        "relationType": view.relationType,
                        "status": view.status.value,
                        "createdAt": relation.created_at.isoformat() if relation.created_at else None,
                        "validatedAt": (
                            relation.validated_at.isoformat()
                            if relation.validated_at is not None
                            else None
                        ),
                        "invalidatedAt": (
                            relation.invalidated_at.isoformat()
                            if relation.invalidated_at is not None
                            else None
                        ),
                    }
                )
        return rows

    @staticmethod
    def _graph_relation_status(review_status: str, assessment: dict[str, Any]) -> str:
        if str(assessment.get("status") or "unknown") in {"stale", "suspect"}:
            return "stale"
        if str(assessment.get("status") or "unknown") == "invalid":
            return "invalid"
        if str(assessment.get("status") or "unknown") == "unknown":
            return "unknown"
        if review_status in {"pending_review", "rejected"}:
            return "unknown" if review_status == "pending_review" else "invalid"
        return "system_verified"

    def _link(
        self,
        source: TraceabilityRef,
        target: TraceabilityRef,
        relation_type: str,
        authority: TraceabilityRef,
        status: str,
        evidence_refs: list[TraceabilityRef],
    ) -> TraceabilityLink:
        material = {
            "source": source.model_dump(mode="json"),
            "target": target.model_dump(mode="json"),
            "relationType": relation_type,
            "authority": authority.model_dump(mode="json"),
        }
        return TraceabilityLink(
            linkId=f"trace-link:{canonical_hash(material).removeprefix('sha256:')}",
            source=source,
            target=target,
            relationType=relation_type,
            authority=authority,
            status=type_cast(Any, status),
            evidenceRefs=evidence_refs,
        )

    @staticmethod
    def _item(
        entity_type: str,
        entity_id: object,
        ref: str | None,
        status: str,
        reasons: list[str],
        risk_level: str | None,
        evidence: list[TraceabilityRef] | None = None,
    ) -> GraphCoverageItem:
        return GraphCoverageItem(
            entityRef=TraceabilityRef(type=entity_type, id=str(entity_id), ref=ref),
            status=type_cast(Any, status),
            reasonCodes=reasons,
            evidenceRefs=evidence or [],
            riskLevel=type_cast(Any, risk_level),
            weight=RISK_WEIGHT.get(risk_level or "low", 1),
        )

    @staticmethod
    def _ref(
        ref_type: str,
        ref_id: object,
        *,
        ref: str | None = None,
        label: str | None = None,
        status: str | None = None,
        content_hash: str | None = None,
        redacted: bool = False,
    ) -> TraceabilityRef:
        return TraceabilityRef(
            type=ref_type,
            id=str(ref_id),
            ref=ref,
            label=label,
            status=status,
            contentHash=content_hash,
            available=True,
            unavailableReason=None,
            redacted=redacted,
        )

    def _node_ref(self, node: CanonicalExecutionGraphNode) -> TraceabilityRef:
        return self._ref(
            f"graph_{node.node_type}",
            node.id,
            ref=node.node_ref,
            label=str(node.display_metadata.get("label") or node.semantic_key),
            status=node.source,
        )

    def _evidence_ref(self, artifact_id: UUID, expose_evidence: bool) -> TraceabilityRef:
        artifact = self.db.get(ExecutionArtifact, artifact_id)
        if artifact is None:
            return TraceabilityRef(
                type="evidence_artifact",
                id=str(artifact_id),
                available=False,
                unavailableReason="GRAPH_TRACEABILITY_EVIDENCE_REF_UNAVAILABLE",
                redacted=not expose_evidence,
            )
        if (
            artifact.expires_at is not None
            and self._aware(artifact.expires_at) <= datetime.now(timezone.utc)
        ):
            return TraceabilityRef(
                type="evidence_artifact",
                id=str(artifact_id),
                available=False,
                unavailableReason="GRAPH_TRACEABILITY_EVIDENCE_RETENTION_UNAVAILABLE",
                redacted=True,
            )
        ref = artifact.redacted_uri or artifact.uri if expose_evidence else None
        return self._ref(
            "evidence_artifact",
            artifact.id,
            ref=ref,
            status=artifact.redaction_status,
            redacted=not expose_evidence,
        )

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    def _stable_refs(self, refs: Iterable[dict[str, Any]], expose: bool) -> list[TraceabilityRef]:
        return [
            self._ref(
                str(item.get("type") or "evidence"),
                str(item.get("id") or item.get("ref") or index),
                ref=str(item.get("ref")) if expose and item.get("ref") else None,
                content_hash=item.get("contentHash"),
                redacted=not expose,
            )
            for index, item in enumerate(refs)
            if isinstance(item, dict)
        ]

    @staticmethod
    def _dedupe_refs(refs: Iterable[TraceabilityRef]) -> list[TraceabilityRef]:
        result: dict[tuple[str, str], TraceabilityRef] = {}
        for ref in refs:
            result[(ref.type, ref.id)] = ref
        return [result[key] for key in sorted(result)]

    @staticmethod
    def _test_asset_ids(node: CanonicalExecutionGraphNode) -> set[UUID]:
        values: set[str] = set()
        candidate = node.attributes_json.get("testCaseRef")
        if candidate:
            values.add(str(candidate))
        for ref in node.external_refs or []:
            if ref.get("type") == "test":
                values.add(str(ref.get("ref") or ""))
        result: set[UUID] = set()
        for value in values:
            raw = value.removeprefix("test://assets/")
            try:
                result.add(UUID(raw))
            except ValueError:
                continue
        return result

    def _execution_task_ids(self, execution_id: UUID) -> set[UUID]:
        return set(
            self.db.scalars(
                select(ExecutionTask.id).where(ExecutionTask.execution_id == execution_id)
            )
        )

    def _projection_source_refs(
        self,
        version: CanonicalExecutionGraphVersion,
        requirement: RequirementVersion,
        execution: Execution | None,
        assessment: dict[str, Any],
        expose: bool,
    ) -> list[TraceabilityRef]:
        refs = [
            self._ref("graph_version", version.id, ref=version.version_ref, content_hash=version.content_hash),
            self._ref(
                "requirement_version",
                requirement.id,
                ref=f"requirement://versions/{requirement.id}",
                content_hash=requirement.content_hash,
            ),
        ]
        if execution:
            refs.append(self._ref("execution", execution.id, ref=f"execution://executions/{execution.id}"))
        if assessment.get("assessmentId"):
            refs.append(
                self._ref(
                    "graph_staleness_assessment",
                    assessment["assessmentId"],
                    ref=(
                        f"graph-staleness-assessment://assessments/{assessment['assessmentId']}"
                        if expose
                        else None
                    ),
                    content_hash=assessment.get("assessmentHash"),
                    redacted=not expose,
                )
            )
        return refs

    @staticmethod
    def _deterministic_computed_at(
        version: CanonicalExecutionGraphVersion,
        requirement: RequirementVersion,
        execution: Execution | None,
        assessment: dict[str, Any],
    ) -> datetime:
        values = [version.frozen_at, version.updated_at, requirement.created_at]
        if execution:
            values.extend([execution.ended_at, execution.updated_at, execution.created_at])
        if assessment.get("assessedAt"):
            values.append(datetime.fromisoformat(str(assessment["assessedAt"])))
        aware = [
            value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            for value in values
            if value is not None
        ]
        return max(aware).astimezone(timezone.utc) if aware else datetime(1970, 1, 1, tzinfo=timezone.utc)

    @staticmethod
    def _graph_version_id_from_execution(
        execution: Execution,
        plan: TestPlan | None,
    ) -> UUID | None:
        candidates = [
            execution.options.get("graphVersionId"),
            (plan.input_payload if plan else {}).get("graphVersionId"),
            (plan.metadata_json if plan else {}).get("graphVersionId"),
        ]
        for candidate in candidates:
            if candidate:
                try:
                    return UUID(str(candidate))
                except ValueError as exc:
                    raise GraphCoverageError("GRAPH_COVERAGE_GRAPH_VERSION_REF_INVALID") from exc
        return None

    def _relation_scope(self, requirement_id: UUID, plan: TestPlan | None) -> str:
        payload = TraceabilityService(self.db)._normalize_requirement_scope(
            requirement_id,
            requirement_scope=plan.requirement_scope if plan and plan.requirement_scope else None,
        )
        return str(payload["scopeId"])

    def _coverage_proof_authority(
        self,
        requirement: RequirementVersion,
        plan: TestPlan | None,
        context: ServiceContext,
    ) -> CoverageProofBundleRecord:
        traceability = TraceabilityService(self.db)
        scope_payload = traceability._normalize_requirement_scope(
            requirement.id,
            requirement_scope=plan.requirement_scope if plan and plan.requirement_scope else None,
        )
        active_items = traceability._active_requirement_items(
            requirement.id,
            requirement_scope=scope_payload,
        )
        if not active_items:
            raise GraphCoverageError("GRAPH_COVERAGE_REQUIREMENT_ITEMS_EMPTY", status_code=409)
        # The established Coverage Proof Bundle remains the proof authority.
        # This immutable CEG result is a dimension snapshot linked to one
        # authoritative bundle; it never creates another proof model.
        primary_item_id = str(active_items[0]["id"])
        record = self.db.scalar(
            select(CoverageProofBundleRecord)
            .join(
                TraceabilitySnapshotRecord,
                CoverageProofBundleRecord.traceability_snapshot_id == TraceabilitySnapshotRecord.id,
            )
            .where(
                CoverageProofBundleRecord.requirement_version_id == requirement.id,
                CoverageProofBundleRecord.requirement_item_id == primary_item_id,
                TraceabilitySnapshotRecord.scope_id == str(scope_payload["scopeId"]),
            )
            .order_by(CoverageProofBundleRecord.created_at.desc(), CoverageProofBundleRecord.id.desc())
            .limit(1)
        )
        if record is not None:
            return record
        traceability.coverage_proof(
            requirement_version_id=requirement.id,
            requirement_item_id=primary_item_id,
            requirement_scope=scope_payload,
            context=context,
        )
        record = self.db.scalar(
            select(CoverageProofBundleRecord)
            .join(
                TraceabilitySnapshotRecord,
                CoverageProofBundleRecord.traceability_snapshot_id == TraceabilitySnapshotRecord.id,
            )
            .where(
                CoverageProofBundleRecord.requirement_version_id == requirement.id,
                CoverageProofBundleRecord.requirement_item_id == primary_item_id,
                TraceabilitySnapshotRecord.scope_id == str(scope_payload["scopeId"]),
            )
            .order_by(CoverageProofBundleRecord.created_at.desc(), CoverageProofBundleRecord.id.desc())
            .limit(1)
        )
        if record is None:
            raise GraphCoverageError("GRAPH_COVERAGE_PROOF_AUTHORITY_UNAVAILABLE", status_code=409)
        return record

    @staticmethod
    def _coverage_proof_ref(record: CoverageProofBundleRecord) -> TraceabilityRef:
        return TraceabilityRef(
            type="coverage_proof_bundle",
            id=str(record.id),
            ref=f"coverage-proof://bundles/{record.id}",
            status=record.proof_status.value,
            contentHash=canonical_hash(record.proof_bundle),
        )

    def _execution_context(
        self,
        scope: Any,
        requirement: RequirementVersion,
        execution_id: UUID | None,
    ) -> tuple[Execution | None, TestPlan | None]:
        if execution_id is None:
            return None, None
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise GraphCoverageError("GRAPH_COVERAGE_EXECUTION_NOT_FOUND", status_code=404)
        plan = self.db.get(TestPlan, execution.plan_id)
        if plan is None or plan.project_id != scope.project.id:
            raise GraphCoverageError("GRAPH_COVERAGE_EXECUTION_SCOPE_MISMATCH", status_code=404)
        if plan.requirement_version_id != requirement.id:
            raise GraphCoverageError("GRAPH_COVERAGE_REQUIREMENT_SCOPE_MISMATCH", status_code=409)
        return execution, plan

    def _topology(
        self,
        version: CanonicalExecutionGraphVersion,
    ) -> tuple[list[Any], list[Any], list[Any], list[Any]]:
        nodes = list(self.db.scalars(select(CanonicalExecutionGraphNode).where(CanonicalExecutionGraphNode.version_id == version.id)))
        edges = list(self.db.scalars(select(CanonicalExecutionGraphEdge).where(CanonicalExecutionGraphEdge.version_id == version.id)))
        paths = list(self.db.scalars(select(CanonicalExecutionGraphPath).where(CanonicalExecutionGraphPath.version_id == version.id)))
        steps = list(self.db.scalars(select(CanonicalExecutionGraphPathStep).where(CanonicalExecutionGraphPathStep.version_id == version.id)))
        return nodes, edges, paths, steps

    def replay_snapshot_for_execution(self, execution_id: UUID) -> dict[str, Any] | None:
        record = self._latest_execution_snapshot_record(execution_id)
        if record is None:
            return None
        return {
            "snapshotId": str(record.id),
            "snapshotRef": record.snapshot_ref,
            "snapshotHash": record.snapshot_hash,
            "inputFingerprint": record.input_fingerprint,
            "algorithmVersion": record.algorithm_version,
            "graphVersionId": str(record.graph_version_id),
            "coverageProofRef": record.coverage_proof_ref,
            "requirementVersionId": str(record.requirement_version_id),
            "status": record.status,
            "metrics": record.metric_snapshot,
            "gaps": record.gap_snapshot,
            "rawFindingRefs": record.raw_finding_refs,
            "normalizedFindingRefs": record.normalized_finding_refs,
            "traceabilityProjection": record.traceability_snapshot,
        }

    def _latest_execution_snapshot_record(
        self,
        execution_id: UUID,
    ) -> GraphCoverageSnapshot | None:
        rows = list(
            self.db.scalars(
                select(GraphCoverageSnapshot).where(
                    GraphCoverageSnapshot.execution_id == execution_id
                )
            )
        )
        if not rows:
            return None

        def persistence_key(record: GraphCoverageSnapshot) -> tuple[datetime, str]:
            inspected = record.computed_at
            if inspected is None:
                inspected = datetime(1970, 1, 1, tzinfo=timezone.utc)
            return self._aware(inspected), str(record.id)

        # computedAt is an input fact and can legitimately precede an earlier
        # snapshot's timestamp (for example, late relation backfill). Pick the
        # newest persisted immutable record, not the greatest domain time.
        return max(rows, key=persistence_key)

    @staticmethod
    def _snapshot_projection(record: GraphCoverageSnapshot, *, deduplicated: bool) -> dict[str, Any]:
        result = dict(record.result_snapshot)
        result["snapshotId"] = str(record.id)
        result["deduplicated"] = deduplicated
        return result

    def _graph(self, scope: Any, graph_id: UUID) -> CanonicalExecutionGraph:
        graph = self.db.scalar(
            select(CanonicalExecutionGraph).where(
                CanonicalExecutionGraph.id == graph_id,
                CanonicalExecutionGraph.tenant_id == scope.tenant_id,
                CanonicalExecutionGraph.workspace_id == scope.workspace_id,
                CanonicalExecutionGraph.project_id == scope.project.id,
            )
        )
        if graph is None:
            raise GraphCoverageError("GRAPH_COVERAGE_GRAPH_NOT_FOUND", status_code=404)
        return graph

    def _version(
        self,
        scope: Any,
        graph: CanonicalExecutionGraph,
        version_id: UUID,
    ) -> CanonicalExecutionGraphVersion:
        version = self.db.scalar(
            select(CanonicalExecutionGraphVersion).where(
                CanonicalExecutionGraphVersion.id == version_id,
                CanonicalExecutionGraphVersion.graph_id == graph.id,
                CanonicalExecutionGraphVersion.tenant_id == scope.tenant_id,
                CanonicalExecutionGraphVersion.workspace_id == scope.workspace_id,
                CanonicalExecutionGraphVersion.project_id == scope.project.id,
            )
        )
        if version is None:
            raise GraphCoverageError("GRAPH_COVERAGE_GRAPH_VERSION_NOT_FOUND", status_code=404)
        return version

    def _scope(self, project_id: UUID, context: ServiceContext) -> Any:
        try:
            return ExecutionGraphService(self.db)._require_project_scope(project_id, context)
        except ExecutionGraphError as exc:
            raise GraphCoverageError(exc.code, status_code=exc.status_code, field=exc.field) from exc

    @staticmethod
    def _require_capability(context: ServiceContext, capability: str) -> None:
        if capability not in set(context.user.capabilities):
            raise GraphCoverageError("GRAPH_COVERAGE_CAPABILITY_REQUIRED", status_code=403, field=capability)

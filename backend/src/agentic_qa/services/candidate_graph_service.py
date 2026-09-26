# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import GraphSource, GraphStatus, ModelRole
from agentic_qa.domain.models import (
    CandidateGraphBuildRun,
    CandidateGraphSourceMapping,
    CanonicalExecutionGraph,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
    CanonicalExecutionGraphVersion,
    EvidenceIndexEntry,
    Execution,
    ExecutionArtifact,
    ExecutionTask,
    GuardrailEvent,
    ReplayExportRecord,
    SkillConnectorCall,
    SkillInvocation,
    SkillToolCall,
    TestPlan,
    Trace,
    TraceSpan,
    VerificationResult,
    VisualGroundingAttempt,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime import RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.candidate_graph import (
    CandidateBuildRequest,
    CandidateBuildResult,
    CandidateModelSuggestion,
    CandidateSourceRef,
    CandidateSuggestionItem,
)
from agentic_qa.schemas.model_outputs import CandidateSuggestionModelOutput
from agentic_qa.services.candidate_graph_transformer import (
    CandidateTransformOutput,
    ObservedTraceCandidateTransformer,
    graph_ref,
    source_ref,
    unique_refs,
)
from agentic_qa.services.candidate_graph_query_service import (
    CandidateGraphError,
    CandidateGraphQueryService,
)
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
)
from agentic_qa.services.execution_graph_hash import (
    build_graph_topology_material,
    build_graph_version_content_hash,
)
from agentic_qa.services.execution_graph_repository import ExecutionGraphRepository
from agentic_qa.tools.model_gateway import ModelGatewayTool


class CandidateGraphService(CandidateGraphQueryService):
    """P12 controlled Trace-to-Candidate conversion within existing services.

    This boundary writes candidate-only graph data and evidence statistics. It
    never promotes, activates, executes, writes Gate/Memory, invokes a Skill,
    or moves Visual Grounding out of execution-service.
    """

    def __init__(self, db: Session) -> None:
        super().__init__(db)
        self.graph_repository = ExecutionGraphRepository(db)
        self.transformer = ObservedTraceCandidateTransformer()
        self.guardrail_engine = RuntimeGuardrailEngine(db)

    def build_candidate(
        self,
        project_id: UUID,
        payload: CandidateBuildRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.candidate.create")
        if not {"admin", "system"}.intersection(context.user.roles):
            raise CandidateGraphError("CANDIDATE_BUILD_INTERNAL_ONLY", status_code=403)
        return self._build_candidate(project_id, payload, context)

    def build_community_observation(
        self,
        project_id: UUID,
        payload: CandidateBuildRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        """Build a bounded, non-authoritative Community observation.

        This entry is callable only by the existing Community analysis lifecycle;
        no public candidate command route is registered in the OSS composition.
        """

        if context.user.edition != "community":
            raise CandidateGraphError("CANDIDATE_COMMUNITY_ONLY", status_code=403)
        self._require_capability(context, "graph.candidate.observe")
        if payload.config.includeModelSuggestions:
            raise CandidateGraphError(
                "CANDIDATE_COMMUNITY_MODEL_DISABLED",
                status_code=422,
                field="config.includeModelSuggestions",
            )
        return self._build_candidate(project_id, payload, context)

    def _build_candidate(
        self,
        project_id: UUID,
        payload: CandidateBuildRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._scope(project_id, context)
        graph = self.graph_repository.find_graph(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            payload.graphId,
            for_update=True,
        )
        if graph is None:
            raise CandidateGraphError("CANDIDATE_GRAPH_NOT_FOUND", status_code=404)
        if graph.status == GraphStatus.ARCHIVED:
            raise CandidateGraphError("CANDIDATE_GRAPH_ARCHIVED", status_code=409)
        execution, plan = self._execution_scope(project_id, payload.executionId)
        self._require_graph_environment(graph, execution, plan)

        config = payload.config.model_dump(mode="json")
        config_hash = canonical_hash(config)
        request_hash = canonical_hash(payload.model_dump(mode="json"))
        lock_scope = (
            f"{scope.tenant_id}:{scope.workspace_id}:{graph.id}:"
            f"{execution.id}:{payload.transformerVersion}:{config_hash}"
        )
        acquire_transaction_advisory_lock(self.db, "candidate-graph-build", lock_scope)
        retry = self._find_idempotent_build(graph, execution.id, payload.transformerVersion, config_hash)
        if retry is not None:
            if retry.request_hash != request_hash:
                raise CandidateGraphError("CANDIDATE_BUILD_IDEMPOTENCY_CONFLICT", status_code=409)
            return self._build_projection(retry)

        observed = self._load_observed(scope, execution)
        guardrail_refs = [self._record_guardrail(
            context,
            execution.id,
            "candidate.trace-input-boundary.v1",
            GuardrailDecision.ALLOW,
            "Authoritative execution references accepted without expanding values or artifacts.",
            {
                "executionId": str(execution.id),
                "traceCount": len(observed["traces"]),
                "actionAttemptCount": len(observed["attempts"]),
                "copiesSensitivePayload": False,
                "createsCanonical": False,
            },
        )]
        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="candidate.graph.build",
                span_name="candidate.trace_normalize",
                service_name="orchestrator-service",
                attributes={
                    "graphId": str(graph.id),
                    "executionId": str(execution.id),
                    "transformerVersion": payload.transformerVersion,
                    "copiesSensitivePayload": False,
                    "createsCanonical": False,
                },
                parent_span_id=context.parent_span_id,
            ):
                self._require_observed_budgets(observed)
                transformed = self.transformer.transform(
                    execution=execution,
                    traces=observed["traces"],
                    spans=observed["spans"],
                    tasks=observed["tasks"],
                    attempts=observed["attempts"],
                    verifications=observed["verifications"],
                    artifacts=observed["artifacts"],
                    transformer_version=payload.transformerVersion,
                    max_actions=payload.config.maxActions,
                    confidence_floor=payload.config.confidenceFloor,
                )
        except (CandidateGraphError, ValueError) as exc:
            if isinstance(exc, CandidateGraphError):
                error = exc
            else:
                code = str(exc)
                if code not in {
                    "CANDIDATE_AUTHORITATIVE_ACTIONS_NOT_FOUND",
                    "CANDIDATE_ACTION_LIMIT_EXCEEDED",
                    "CANDIDATE_ACTION_ATTEMPT_LIMIT_EXCEEDED",
                }:
                    code = "CANDIDATE_TRANSFORM_FAILED"
                error = CandidateGraphError(code, status_code=422)
            write_audit_log(
                self.db,
                context.user.id,
                "candidate.graph.build_rejected",
                "execution",
                str(execution.id),
                context.request_id,
                context.trace_id,
                execution_id=execution.id,
                details={
                    "projectId": str(project_id),
                    "graphId": str(graph.id),
                    "executionId": str(execution.id),
                    "transformerVersion": payload.transformerVersion,
                    "errorCode": error.code,
                    "candidateWritten": False,
                    "createsCanonical": False,
                    "promotionPerformed": False,
                },
            )
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()
            if error is exc:
                raise error
            raise error from exc

        model_suggestion, model_invocation_id, model_guardrail_ref = self._model_suggestions(
            context,
            execution,
            transformed,
            payload.config.includeModelSuggestions,
        )
        if model_guardrail_ref:
            guardrail_refs.append(model_guardrail_ref)

        now = datetime.now(timezone.utc)
        build_id = uuid4()
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=execution.id,
            root_span_name="candidate.graph.build",
            span_name="candidate.trace_to_path",
            service_name="orchestrator-service",
            attributes={
                "buildId": str(build_id),
                "graphId": str(graph.id),
                "executionId": str(execution.id),
                "transformerVersion": payload.transformerVersion,
                "createsCanonical": False,
                "performsPromotion": False,
                "executesActions": False,
                "visualGroundingOwner": "execution-service",
            },
            parent_span_id=context.parent_span_id,
        ):
            existing = self._find_candidate_path_build(graph, transformed.semantic_path_hash)
            if existing is not None:
                version = self._require_reusable_candidate(existing.candidate_version_id, graph)
                nodes, edges, path, steps = self._topology(version)
            else:
                version, nodes, edges, path, steps = self._create_candidate_topology(
                    graph,
                    transformed,
                    payload.transformerVersion,
                    context,
                )

            trace_snapshot = self._observed_snapshot(execution, observed)
            build = CandidateGraphBuildRun(
                id=build_id,
                build_ref=f"candidate-build://builds/{build_id}",
                tenant_id=graph.tenant_id,
                workspace_id=graph.workspace_id,
                project_id=graph.project_id,
                graph_id=graph.id,
                scope_id=graph.scope_id,
                candidate_version_id=version.id,
                execution_id=execution.id,
                source_identity_hash=self._source_identity_hash(execution, observed["traces"]),
                semantic_path_hash=transformed.semantic_path_hash,
                transformer_version=payload.transformerVersion,
                config_hash=config_hash,
                request_hash=request_hash,
                status="completed",
                outcome=transformed.outcome,
                source_revision_hash=self._source_revision_hash(execution, plan),
                source_environment=execution.environment,
                source_observed_at=transformed.observed_at,
                action_count=transformed.action_count,
                verified_action_count=transformed.verified_action_count,
                retry_count=transformed.retry_count,
                coordinate_click_count=transformed.coordinate_click_count,
                fallback_types=transformed.fallback_types,
                observed_trace_snapshot=self._json_safe(trace_snapshot),
                evidence_summary={},
                ambiguities=transformed.global_ambiguities,
                model_suggestion=model_suggestion,
                model_invocation_id=model_invocation_id,
                guardrail_event_refs=unique_refs(guardrail_refs),
                audit_refs=[],
                trace_id=UUID(context.trace_id),
                canonical=False,
                active=False,
                promotion_performed=False,
                error_code=None,
                started_at=now,
                finished_at=datetime.now(timezone.utc),
                created_by=context.user.id,
            )
            self.db.add(build)
            self.db.flush()
            self._write_source_mappings(
                build,
                transformed,
                nodes,
                edges,
                path,
                steps,
                payload.transformerVersion,
            )
            self.db.flush()
            aggregate_summary = self._evidence_summary(build)
            build.evidence_summary = aggregate_summary
            for aggregate_row in self.db.scalars(
                select(CandidateGraphBuildRun).where(
                    CandidateGraphBuildRun.tenant_id == build.tenant_id,
                    CandidateGraphBuildRun.workspace_id == build.workspace_id,
                    CandidateGraphBuildRun.graph_id == build.graph_id,
                    CandidateGraphBuildRun.semantic_path_hash == build.semantic_path_hash,
                    CandidateGraphBuildRun.status == "completed",
                )
            ):
                aggregate_row.evidence_summary = aggregate_summary
            audit = write_audit_log(
                self.db,
                context.user.id,
                "candidate.graph.build",
                "candidate_graph_build",
                str(build.id),
                context.request_id,
                context.trace_id,
                execution_id=execution.id,
                details={
                    "projectId": str(project_id),
                    "graphId": str(graph.id),
                    "candidateVersionId": str(version.id),
                    "executionId": str(execution.id),
                    "transformerVersion": payload.transformerVersion,
                    "semanticPathHash": transformed.semantic_path_hash,
                    "outcome": transformed.outcome,
                    "canonical": False,
                    "active": False,
                    "promotionPerformed": False,
                    "writesGate": False,
                    "writesMemory": False,
                },
            )
            self.db.flush()
            audit_ref = source_ref("audit", audit.id)
            build.audit_refs = [audit_ref]
            projected_audit_ref = graph_ref(audit_ref)
            version.audit_refs = (
                [*version.audit_refs, projected_audit_ref][-128:]
                if projected_audit_ref is not None
                else version.audit_refs
            )
            projection = self._build_projection(build)
            CandidateBuildResult.model_validate(projection)
        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            recovered = self._find_idempotent_build(
                graph, execution.id, payload.transformerVersion, config_hash
            )
            if recovered is not None and recovered.request_hash == request_hash:
                return self._build_projection(recovered)
            raise CandidateGraphError("CANDIDATE_BUILD_CONFLICT", status_code=409) from exc
        return projection

    @staticmethod
    def _require_observed_budgets(observed: dict[str, Any]) -> None:
        event_count = 1 + sum(
            len(observed[key])
            for key in ("traces", "spans", "tasks", "attempts", "verifications", "artifacts", "evidence")
        )
        if (
            len(observed["traces"]) > 128
            or event_count > 20_000
            or len(observed["tool_calls"]) > 2_000
            or len(observed["connector_calls"]) > 2_000
            or len(observed["replays"]) > 256
        ):
            raise CandidateGraphError("CANDIDATE_SOURCE_LIMIT_EXCEEDED", status_code=422)

    def _execution_scope(self, project_id: UUID, execution_id: UUID) -> tuple[Execution, TestPlan]:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise CandidateGraphError("CANDIDATE_EXECUTION_NOT_FOUND", status_code=404)
        plan = self.db.get(TestPlan, execution.plan_id)
        if plan is None or plan.project_id != project_id:
            raise CandidateGraphError("CANDIDATE_EXECUTION_NOT_FOUND", status_code=404)
        return execution, plan

    @staticmethod
    def _require_graph_environment(
        graph: CanonicalExecutionGraph, execution: Execution, plan: TestPlan
    ) -> None:
        if graph.environment_id is not None and plan.environment_id != graph.environment_id:
            raise CandidateGraphError("CANDIDATE_ENVIRONMENT_SCOPE_MISMATCH", status_code=409)

    def _load_observed(self, scope: Any, execution: Execution) -> dict[str, Any]:
        traces = list(self.db.scalars(select(Trace).where(Trace.execution_id == execution.id).order_by(Trace.created_at, Trace.id)))
        trace_ids = [item.id for item in traces]
        spans = list(self.db.scalars(select(TraceSpan).where(TraceSpan.trace_id.in_(trace_ids)).order_by(TraceSpan.start_time, TraceSpan.id))) if trace_ids else []
        build_trace_ids = {
            item.trace_id
            for item in spans
            if item.span_name.startswith("candidate.")
        }
        if build_trace_ids:
            traces = [item for item in traces if item.id not in build_trace_ids]
            spans = [item for item in spans if item.trace_id not in build_trace_ids]
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution.id).order_by(ExecutionTask.started_at, ExecutionTask.created_at, ExecutionTask.id)))
        attempts = list(self.db.scalars(select(VisualGroundingAttempt).where(VisualGroundingAttempt.execution_id == execution.id).order_by(VisualGroundingAttempt.created_at, VisualGroundingAttempt.id)))
        verifications = list(self.db.scalars(select(VerificationResult).where(VerificationResult.execution_id == execution.id).order_by(VerificationResult.created_at, VerificationResult.id)))
        artifacts = list(self.db.scalars(select(ExecutionArtifact).where(ExecutionArtifact.execution_id == execution.id).order_by(ExecutionArtifact.created_at, ExecutionArtifact.id)))
        invocation_ids = list(self.db.scalars(select(SkillInvocation.id).where(SkillInvocation.execution_id == execution.id)))
        tool_calls = list(self.db.scalars(select(SkillToolCall).where(SkillToolCall.skill_invocation_id.in_(invocation_ids)))) if invocation_ids else []
        connector_calls = list(self.db.scalars(select(SkillConnectorCall).where(SkillConnectorCall.skill_invocation_id.in_(invocation_ids)))) if invocation_ids else []
        replays = list(self.db.scalars(select(ReplayExportRecord).where(ReplayExportRecord.execution_id == execution.id).order_by(ReplayExportRecord.created_at, ReplayExportRecord.id)))
        source_ids = [str(execution.id), *[str(item.id) for item in traces]]
        evidence = list(self.db.scalars(select(EvidenceIndexEntry).where(
            EvidenceIndexEntry.tenant_id == scope.tenant_id,
            EvidenceIndexEntry.workspace_id == scope.workspace_id,
            EvidenceIndexEntry.project_id == scope.project.id,
            EvidenceIndexEntry.source_id.in_(source_ids),
        )))
        return {
            "traces": traces,
            "spans": spans,
            "tasks": tasks,
            "attempts": attempts,
            "verifications": verifications,
            "artifacts": artifacts,
            "tool_calls": tool_calls,
            "connector_calls": connector_calls,
            "replays": replays,
            "evidence": evidence,
        }

    def _find_idempotent_build(self, graph: CanonicalExecutionGraph, execution_id: UUID, transformer: str, config_hash: str) -> CandidateGraphBuildRun | None:
        return self.db.scalar(select(CandidateGraphBuildRun).where(
            CandidateGraphBuildRun.tenant_id == graph.tenant_id,
            CandidateGraphBuildRun.workspace_id == graph.workspace_id,
            CandidateGraphBuildRun.graph_id == graph.id,
            CandidateGraphBuildRun.execution_id == execution_id,
            CandidateGraphBuildRun.transformer_version == transformer,
            CandidateGraphBuildRun.config_hash == config_hash,
        ))

    def _find_candidate_path_build(self, graph: CanonicalExecutionGraph, semantic_hash: str) -> CandidateGraphBuildRun | None:
        return self.db.scalar(select(CandidateGraphBuildRun).where(
            CandidateGraphBuildRun.tenant_id == graph.tenant_id,
            CandidateGraphBuildRun.workspace_id == graph.workspace_id,
            CandidateGraphBuildRun.graph_id == graph.id,
            CandidateGraphBuildRun.semantic_path_hash == semantic_hash,
            CandidateGraphBuildRun.status == "completed",
        ).order_by(CandidateGraphBuildRun.created_at.desc(), CandidateGraphBuildRun.id.asc()))

    def _require_reusable_candidate(self, version_id: UUID, graph: CanonicalExecutionGraph) -> CanonicalExecutionGraphVersion:
        version = self.graph_repository.find_version(
            graph.tenant_id, graph.workspace_id, graph.project_id, graph.id, version_id, for_update=True
        )
        if version is None or version.source != GraphSource.CANDIDATE or version.status != GraphStatus.CANDIDATE or version.is_frozen:
            raise CandidateGraphError("CANDIDATE_VERSION_NOT_MUTABLE", status_code=409)
        return version

    def _create_candidate_topology(
        self,
        graph: CanonicalExecutionGraph,
        transformed: CandidateTransformOutput,
        transformer_version: str,
        context: ServiceContext,
    ) -> tuple[CanonicalExecutionGraphVersion, list[CanonicalExecutionGraphNode], list[CanonicalExecutionGraphEdge], CanonicalExecutionGraphPath, list[CanonicalExecutionGraphPathStep]]:
        versions = self.graph_repository.list_versions(graph.tenant_id, graph.workspace_id, graph.project_id, graph.id)
        parent = versions[-1] if versions else None
        version_id = uuid4()
        source_refs = unique_refs(
            [
                projected
                for ref in transformed.actions[0].source_event_refs
                if (projected := graph_ref(ref)) is not None
            ],
            128,
        )
        metadata = {
            "candidateTransformerVersion": transformer_version,
            "semanticPathHash": transformed.semantic_path_hash,
            "promotionState": "not_performed",
        }
        applicability = {
            "status": "fresh",
            "source": "authoritative_candidate_build",
            "environmentScoped": graph.environment_id is not None,
        }
        version = CanonicalExecutionGraphVersion(
            id=version_id,
            graph_id=graph.id,
            tenant_id=graph.tenant_id,
            workspace_id=graph.workspace_id,
            project_id=graph.project_id,
            environment_id=graph.environment_id,
            scope_type=graph.scope_type,
            scope_id=graph.scope_id,
            version_number=(parent.version_number + 1) if parent else 1,
            version_ref=f"ceg-version://versions/{version_id}",
            parent_version_id=parent.id if parent else None,
            status=GraphStatus.CANDIDATE,
            source=GraphSource.CANDIDATE,
            schema_version="ceg.v1",
            content_hash=canonical_hash({"candidateVersionId": str(version_id)}),
            source_refs=source_refs,
            applicability=applicability,
            is_frozen=False,
            frozen_at=None,
            frozen_by=None,
            retention_policy="candidate-default",
            retention_until=None,
            retention_status="active",
            legal_hold=False,
            idempotency_key=f"candidate-path:{graph.id}:{transformed.semantic_path_hash}"[:255],
            request_hash=canonical_hash({"graphId": str(graph.id), "semanticPathHash": transformed.semantic_path_hash}),
            audit_refs=[],
            trace_id=UUID(context.trace_id),
            lock_version=1,
            created_by=context.user.id,
            updated_by=context.user.id,
            metadata_json=metadata,
        )
        self.db.add(version)
        self.db.flush()
        nodes: list[CanonicalExecutionGraphNode] = []
        for index, action in enumerate(transformed.actions, start=1):
            node_id = uuid4()
            attributes = ({"assertionType": action.action_type} if action.node_type == "assertion" else {"actionType": action.action_type, "intentKey": action.intent_key})
            node = CanonicalExecutionGraphNode(
                id=node_id,
                node_ref=f"ceg-node://versions/{version.id}/nodes/{node_id}",
                version_id=version.id,
                graph_id=graph.id,
                tenant_id=graph.tenant_id,
                workspace_id=graph.workspace_id,
                project_id=graph.project_id,
                scope_id=graph.scope_id,
                client_key=f"candidate-node-{index:04d}",
                semantic_key=action.semantic_key,
                node_type=action.node_type,
                display_metadata={"label": f"{action.action_type}:{action.intent_key}", "tags": ["candidate", "observed-trace"]},
                attributes_json=attributes,
                external_refs=unique_refs(
                    [
                        projected
                        for ref in action.source_event_refs + action.evidence_refs
                        if (projected := graph_ref(ref)) is not None
                    ],
                    32,
                ),
                risk_level=action.risk_level,
                source="candidate",
                confidence=Decimal(str(action.confidence)),
                request_hash=canonical_hash({"semanticKey": action.semantic_key, "order": index}),
                audit_refs=[],
                trace_id=UUID(context.trace_id),
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            nodes.append(node)
            self.db.add(node)
        self.db.flush()
        edges: list[CanonicalExecutionGraphEdge] = []
        for index in range(1, len(nodes)):
            edge_id = uuid4()
            confidence = min(float(nodes[index - 1].confidence), float(nodes[index].confidence))
            edge = CanonicalExecutionGraphEdge(
                id=edge_id,
                edge_ref=f"ceg-edge://versions/{version.id}/edges/{edge_id}",
                version_id=version.id,
                graph_id=graph.id,
                tenant_id=graph.tenant_id,
                workspace_id=graph.workspace_id,
                project_id=graph.project_id,
                scope_id=graph.scope_id,
                client_key=f"candidate-edge-{index:04d}",
                edge_type="precedes",
                source_node_id=nodes[index - 1].id,
                target_node_id=nodes[index].id,
                condition_json={},
                risk_level="high" if "high" in {nodes[index - 1].risk_level, nodes[index].risk_level} else "low",
                review_status="pending_review" if "high" in {nodes[index - 1].risk_level, nodes[index].risk_level} else "not_required",
                source="candidate",
                confidence=Decimal(str(confidence)),
                semantic_hash=canonical_hash({"edgeType": "precedes", "source": nodes[index - 1].semantic_key, "target": nodes[index].semantic_key}),
                request_hash=canonical_hash({"order": index, "source": nodes[index - 1].semantic_key, "target": nodes[index].semantic_key}),
                audit_refs=[],
                trace_id=UUID(context.trace_id),
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            edges.append(edge)
            self.db.add(edge)
        self.db.flush()
        path_id = uuid4()
        path_confidence = sum(item.confidence for item in transformed.actions) / len(transformed.actions)
        all_evidence = unique_refs(
            [
                projected
                for action in transformed.actions
                for ref in action.evidence_refs
                if (projected := graph_ref(ref)) is not None
            ],
            32,
        )
        action_risks = {item.risk_level for item in transformed.actions}
        risk_level = "high" if "high" in action_risks else "medium" if "medium" in action_risks else "low"
        path = CanonicalExecutionGraphPath(
            id=path_id,
            path_ref=f"ceg-path://versions/{version.id}/paths/{path_id}",
            version_id=version.id,
            graph_id=graph.id,
            tenant_id=graph.tenant_id,
            workspace_id=graph.workspace_id,
            project_id=graph.project_id,
            scope_id=graph.scope_id,
            client_key="observed-candidate-path",
            path_key=f"candidate.{transformed.semantic_path_hash[7:31]}",
            name="Observed Trace Candidate Path",
            description="Read-only candidate interpretation; P12 performs no promotion.",
            entry_node_id=nodes[0].id,
            exit_node_id=nodes[-1].id,
            preconditions=[],
            postconditions=[],
            risk_level=risk_level,
            applicability=applicability,
            evidence_refs=all_evidence,
            source="candidate",
            confidence=Decimal(str(path_confidence)),
            request_hash=canonical_hash({"semanticPathHash": transformed.semantic_path_hash}),
            audit_refs=[],
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
            updated_by=context.user.id,
        )
        self.db.add(path)
        self.db.flush()
        steps: list[CanonicalExecutionGraphPathStep] = []
        for index, (action, node) in enumerate(zip(transformed.actions, nodes), start=1):
            step_id = uuid4()
            step = CanonicalExecutionGraphPathStep(
                id=step_id,
                step_ref=f"ceg-step://versions/{version.id}/paths/{path.id}/steps/{step_id}",
                path_id=path.id,
                version_id=version.id,
                graph_id=graph.id,
                tenant_id=graph.tenant_id,
                workspace_id=graph.workspace_id,
                project_id=graph.project_id,
                scope_id=graph.scope_id,
                client_key=f"candidate-step-{index:04d}",
                step_order=index,
                node_id=node.id,
                via_edge_id=edges[index - 2].id if index > 1 else None,
                conditions=[],
                evidence_refs=unique_refs(
                    [
                        projected
                        for ref in action.evidence_refs
                        if (projected := graph_ref(ref)) is not None
                    ],
                    32,
                ),
                audit_refs=[],
                trace_id=UUID(context.trace_id),
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            steps.append(step)
            self.db.add(step)
        self.db.flush()
        topology = build_graph_topology_material(nodes=nodes, edges=edges, paths=[path], steps=steps)
        version.content_hash = build_graph_version_content_hash(
            graph=graph,
            parent_version_id=version.parent_version_id,
            source="candidate",
            source_refs=version.source_refs,
            schema_version=version.schema_version,
            applicability=version.applicability,
            metadata=version.metadata_json,
            topology=topology,
        )
        self.db.flush()
        return version, nodes, edges, path, steps

    def _write_source_mappings(self, build: CandidateGraphBuildRun, transformed: CandidateTransformOutput, nodes: list[CanonicalExecutionGraphNode], edges: list[CanonicalExecutionGraphEdge], path: CanonicalExecutionGraphPath, steps: list[CanonicalExecutionGraphPathStep], transformer_version: str) -> None:
        common = dict(candidate_version_id=build.candidate_version_id, graph_id=build.graph_id, tenant_id=build.tenant_id, workspace_id=build.workspace_id, project_id=build.project_id, scope_id=build.scope_id, transformer_version=transformer_version)
        all_source = unique_refs([ref for action in transformed.actions for ref in action.source_event_refs], 2000)
        all_evidence = unique_refs([ref for action in transformed.actions for ref in action.evidence_refs], 2000)
        for action, node, step in zip(transformed.actions, nodes, steps):
            entity_ambiguities = []
            for item in action.ambiguities:
                copied = dict(item)
                copied["entityRef"] = node.node_ref
                entity_ambiguities.append(copied)
            self.db.add(CandidateGraphSourceMapping(
                build_id=build.id, entity_type="node", entity_id=node.id, entity_ref=node.node_ref,
                source_event_refs=action.source_event_refs, evidence_refs=action.evidence_refs,
                observation_summary={"actionType": action.action_type, "intentKey": action.intent_key},
                confidence=Decimal(str(action.confidence)), ambiguities=entity_ambiguities, **common,
            ))
            step_ambiguities = [{**item, "entityRef": step.step_ref} for item in action.ambiguities]
            self.db.add(CandidateGraphSourceMapping(
                build_id=build.id, entity_type="path_step", entity_id=step.id, entity_ref=step.step_ref,
                source_event_refs=action.source_event_refs, evidence_refs=action.evidence_refs,
                observation_summary={"outcome": action.outcome, "retryCount": action.retry_count, "fallbackTypes": action.fallback_types, "verificationStatus": action.verification_status},
                confidence=Decimal(str(action.confidence)), ambiguities=step_ambiguities, **common,
            ))
        for index, edge in enumerate(edges):
            left, right = transformed.actions[index], transformed.actions[index + 1]
            self.db.add(CandidateGraphSourceMapping(
                build_id=build.id, entity_type="edge", entity_id=edge.id, entity_ref=edge.edge_ref,
                source_event_refs=unique_refs(left.source_event_refs + right.source_event_refs),
                evidence_refs=unique_refs(left.evidence_refs + right.evidence_refs), observation_summary={},
                confidence=Decimal(str(min(left.confidence, right.confidence))), ambiguities=[], **common,
            ))
        path_ambiguities = [{**item, "entityRef": path.path_ref} for item in transformed.global_ambiguities]
        self.db.add(CandidateGraphSourceMapping(
            build_id=build.id, entity_type="path", entity_id=path.id, entity_ref=path.path_ref,
            source_event_refs=all_source, evidence_refs=all_evidence, observation_summary={},
            confidence=path.confidence, ambiguities=path_ambiguities, **common,
        ))

    def _evidence_summary(self, current: CandidateGraphBuildRun) -> dict[str, Any]:
        rows = list(self.db.scalars(select(CandidateGraphBuildRun).where(
            CandidateGraphBuildRun.tenant_id == current.tenant_id,
            CandidateGraphBuildRun.workspace_id == current.workspace_id,
            CandidateGraphBuildRun.graph_id == current.graph_id,
            CandidateGraphBuildRun.semantic_path_hash == current.semantic_path_hash,
            CandidateGraphBuildRun.status == "completed",
        ).order_by(CandidateGraphBuildRun.source_observed_at, CandidateGraphBuildRun.id)))
        by_source: dict[str, list[CandidateGraphBuildRun]] = {}
        for row in rows:
            by_source.setdefault(row.source_identity_hash, []).append(row)
        selected: list[CandidateGraphBuildRun] = []
        conflict_refs: list[dict[str, Any]] = []
        flaky: set[str] = set()
        for group in by_source.values():
            outcomes = {item.outcome for item in group if item.outcome in {"success", "failure"}}
            if len(outcomes) > 1:
                flaky.add("outcome_conflict")
                conflict_refs.extend(source_ref("candidate_build", item.id) for item in group)
            selected.append(group[-1])
        success = sum(item.outcome == "success" for item in selected)
        failure = sum(item.outcome == "failure" for item in selected)
        action_count = sum(item.action_count for item in selected)
        verified = sum(item.verified_action_count for item in selected)
        fallback_types = sorted({value for item in selected for value in item.fallback_types})
        if any(item.retry_count for item in selected):
            flaky.add("retry_observed")
        if len({tuple(item.fallback_types) for item in selected}) > 1:
            flaky.add("fallback_variation")
        if verified < action_count:
            flaky.add("missing_verification")
        if any(item.coordinate_click_count for item in selected):
            flaky.add("coordinate_fallback")
        if success and failure:
            flaky.add("cross_run_outcome_conflict")
            conflict_refs.extend(source_ref("candidate_build", item.id) for item in selected)
        return {
            "independentRunCount": len(selected),
            "successCount": success,
            "failureCount": failure,
            "distinctRevisionCount": len({item.source_revision_hash for item in selected if item.source_revision_hash}),
            "distinctEnvironmentCount": len({item.source_environment for item in selected}),
            "verificationCoverage": round(verified / action_count, 6) if action_count else 0.0,
            "retryCount": sum(item.retry_count for item in selected),
            "fallbackTypes": fallback_types,
            "coordinateClickCount": sum(item.coordinate_click_count for item in selected),
            "conflictRefs": unique_refs(conflict_refs, 2000),
            "flakySignals": sorted(flaky),
            "lastObservedAt": max(
                self._aware(item.source_observed_at) for item in selected
            ).isoformat(),
        }

    def _observed_snapshot(self, execution: Execution, observed: dict[str, Any]) -> dict[str, Any]:
        event_refs = [source_ref("execution", execution.id)]
        event_refs.extend(source_ref("trace", item.id) for item in observed["traces"])
        event_refs.extend(source_ref("trace_span", item.id) for item in observed["spans"])
        event_refs.extend(source_ref("execution_task", item.id) for item in observed["tasks"])
        event_refs.extend(source_ref("visual_attempt", item.id) for item in observed["attempts"])
        event_refs.extend(source_ref("verification", item.id) for item in observed["verifications"])
        artifact_refs = []
        now = datetime.now(timezone.utc)
        for item in observed["artifacts"]:
            expired = item.expires_at is not None and self._aware(item.expires_at) <= now
            unavailable = expired or item.redaction_status in {"purged", "unavailable"}
            artifact_refs.append(source_ref("artifact", item.id, available=not unavailable, reason="EVIDENCE_UNAVAILABLE" if unavailable else None))
        for item in observed["evidence"]:
            available = item.retention_state not in {"purged", "purge_eligible"} and not item.stale
            event_refs.append(source_ref("evidence", item.entry_id, available=available, reason=item.unavailable_reason_code or "EVIDENCE_UNAVAILABLE" if not available else None))
        return {
            "executionId": execution.id,
            "traceRefs": [source_ref("trace", item.id) for item in observed["traces"][:128]],
            "sourceEventRefs": unique_refs(event_refs + artifact_refs, 20_000),
            "toolCallRefs": [source_ref("tool_call", item.id) for item in observed["tool_calls"][:2_000]],
            "connectorCallRefs": [source_ref("connector_call", item.id) for item in observed["connector_calls"][:2_000]],
            "replayRefs": [source_ref("replay", item.id) for item in observed["replays"][:256]],
            "authoritative": True, "observed": True, "immutable": True,
        }

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {str(key): CandidateGraphService._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [CandidateGraphService._json_safe(item) for item in value]
        return value

    def _model_suggestions(self, context: ServiceContext, execution: Execution, transformed: CandidateTransformOutput, requested: bool) -> tuple[dict[str, Any], UUID | None, dict[str, Any] | None]:
        if not requested:
            return CandidateModelSuggestion(status="not_requested", suggestions=[], applied=False).model_dump(mode="json"), None, None
        response = ModelGatewayTool(self.db).invoke_json(
            trace_id=UUID(context.trace_id), execution_id=execution.id, role=ModelRole.PRIMARY,
            prompt="Return only structured candidate review suggestions. Do not promote, activate, choose a provider, execute actions, or emit free-text-only results.",
            payload={
                "schemaVersion": "candidate-model-suggestion.v1",
                "actions": [{"semanticKey": item.semantic_key, "actionType": item.action_type, "confidence": item.confidence, "ambiguityCodes": [value["code"] for value in item.ambiguities]} for item in transformed.actions],
                "allowedSuggestionTypes": ["ambiguity", "confidence_review", "semantic_label"],
                "applied": False,
            },
            validator=CandidateSuggestionModelOutput,
            request_id=context.request_id,
        )
        invocation_id = UUID(str(response["modelInvocationId"]))
        if response.get("status") != "completed" or not response.get("success", False):
            suggestion = CandidateModelSuggestion(
                status="unavailable",
                suggestions=[],
                modelInvocationRef=CandidateSourceRef.model_validate(
                    source_ref("model_invocation", invocation_id)
                ),
                applied=False,
            )
            return suggestion.model_dump(mode="json"), invocation_id, self._record_guardrail(context, execution.id, "candidate.model-output.v1", GuardrailDecision.WARN, "Model unavailable; deterministic Candidate retained.", {"modelInvocationId": str(invocation_id), "applied": False})
        output = response.get("output")
        raw = output.get("suggestions") if isinstance(output, dict) else None
        try:
            if not isinstance(raw, list):
                raise ValueError("suggestions must be a list")
            suggestions = [CandidateSuggestionItem.model_validate(item) for item in raw]
            suggestion = CandidateModelSuggestion(
                status="suggested",
                suggestions=suggestions,
                modelInvocationRef=CandidateSourceRef.model_validate(
                    source_ref("model_invocation", invocation_id)
                ),
                applied=False,
            )
            decision = GuardrailDecision.ALLOW
            reason = "Structured model suggestions validated and retained as unapplied suggestions."
        except (ValueError, TypeError):
            suggestion = CandidateModelSuggestion(
                status="rejected",
                suggestions=[],
                modelInvocationRef=CandidateSourceRef.model_validate(
                    source_ref("model_invocation", invocation_id)
                ),
                applied=False,
            )
            decision = GuardrailDecision.WARN
            reason = "Invalid model suggestion structure rejected; deterministic Candidate retained."
        ref = self._record_guardrail(context, execution.id, "candidate.model-output.v1", decision, reason, {"modelInvocationId": str(invocation_id), "applied": False})
        return suggestion.model_dump(mode="json"), invocation_id, ref

    def _record_guardrail(self, context: ServiceContext, execution_id: UUID, rule_id: str, decision: GuardrailDecision, reason: str, metadata: dict[str, Any]) -> dict[str, Any]:
        self.guardrail_engine.record_result(
            GuardrailContext(trace_id=context.trace_id, request_id=context.request_id, actor_id=context.user.id, actor_roles=list(context.user.roles), resource_type="candidate_graph_build", resource_id=str(execution_id), execution_id=execution_id, payload={"referencesOnly": True, "createsCanonical": False}),
            GuardrailResult(rule_id=rule_id, decision=decision, reason=reason, evidence=[f"execution://executions/{execution_id}"], metadata=metadata),
        )
        self.db.flush()
        event = self.db.scalar(select(GuardrailEvent).where(GuardrailEvent.rule_id == rule_id, GuardrailEvent.trace_id == UUID(context.trace_id), GuardrailEvent.request_id == context.request_id).order_by(GuardrailEvent.created_at.desc(), GuardrailEvent.id.desc()))
        if event is None:
            raise CandidateGraphError("CANDIDATE_GUARDRAIL_AUDIT_MISSING", status_code=500)
        return source_ref("guardrail", event.id)

    @staticmethod
    def _source_identity_hash(execution: Execution, traces: list[Trace]) -> str:
        roots: list[str] = []
        for key in ("originalExecutionId", "sourceExecutionId", "replayOfExecutionId"):
            value = execution.options.get(key) if isinstance(execution.options, dict) else None
            if value:
                roots.append(str(value))
        for trace in traces:
            metadata = trace.trace_metadata if isinstance(trace.trace_metadata, dict) else {}
            copied_trace_root = metadata.get("originalTraceId") or metadata.get("sourceTraceId")
            if copied_trace_root:
                roots.append(str(copied_trace_root))
        return canonical_hash(sorted(set(roots)) or [str(execution.id)])

    @staticmethod
    def _source_revision_hash(execution: Execution, plan: TestPlan) -> str | None:
        mappings = [execution.options, execution.summary, plan.metadata_json]
        for key in ("sourceRevision", "revision", "commitSha", "commit", "buildRevision"):
            for mapping in mappings:
                value = mapping.get(key) if isinstance(mapping, dict) else None
                if isinstance(value, (str, int)) and str(value).strip():
                    return canonical_hash({"revision": str(value).strip()})
        return None

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


__all__ = ["CandidateGraphError", "CandidateGraphService"]

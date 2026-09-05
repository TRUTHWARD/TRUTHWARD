# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    AgentRun,
    Approval,
    AuditLog,
    DomainEventRecord,
    Execution,
    ExecutionArtifact,
    ExecutionMetric,
    ExecutionTask,
    Finding,
    GateDecision,
    GateInputSnapshot,
    GatePolicyBinding,
    GatePolicyBindingHistory,
    GuardrailEvent,
    ModelInvocation,
    OrchestrationCheckpoint,
    OrchestrationRun,
    Project,
    RawFindingRecord,
    ReplayExportRecord,
    ReplayRepositoryEntry,
    Skill,
    SkillConnectorCall,
    SkillInvocation,
    SkillInvocationEvent,
    SkillToolCall,
    SkillVersion,
    TestPlan,
    Trace,
    TraceSpan,
    TriageResult,
    VerificationResult,
    VisualGroundingAttempt,
)
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.schemas.decision_timeline import (
    TIMELINE_STAGE_INDEX,
    TIMELINE_STAGES,
    TimelineLifecycleStage,
    TimelineQuery,
    TimelineUnavailableReason,
    timeline_event_sort_key,
    timeline_event_sort_tuple,
)
from agentic_qa.services.common import ServiceContext, canonical_hash
from agentic_qa.services.execution_explanation_service import (
    PROFESSIONAL_VIEW_CAPABILITY,
    RAW_VIEW_CAPABILITY,
    build_explain_view_projection,
)
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


STAGES = TIMELINE_STAGES
STAGE_INDEX = TIMELINE_STAGE_INDEX
CEG_EVENT_KINDS = {
    "observed",
    "candidate",
    "validation",
    "promotion",
    "suspension",
    "rollback",
}
AUTO_PROMOTION_TYPES = {
    "automatic",
    "policy_auto",
    "policy_automatic",
    "system_auto",
    "system_automatic",
}
AGENT_STAGE: dict[str, TimelineLifecycleStage] = {
    "planneragent": "PREPARE",
    "generatoragent": "PREPARE",
    "runneragent": "EXECUTE",
    "triageagent": "ANALYZE",
    "healeragent": "ANALYZE",
    "perfagent": "ANALYZE",
    "securityagent": "ANALYZE",
    "judgeagent": "GATE",
}


class DecisionTimelineError(ValueError):
    def __init__(self, code: str, *, status_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(slots=True)
class _EventCandidate:
    payload: dict[str, Any]
    occurred_at: datetime
    persisted_at: datetime
    source_sequence: int

    @property
    def sort_tuple(self) -> tuple[int, datetime, int, str]:
        return timeline_event_sort_tuple(
            self.payload["lifecycleStage"],
            self.occurred_at,
            self.source_sequence,
            self.payload["eventId"],
        )


class DecisionTimelineProjectionService:
    """Build one read-only execution timeline from persisted authoritative sources."""

    SCHEMA_VERSION = "phase8.decision-timeline.v1"
    CURSOR_VERSION = "phase8.decision-timeline-cursor.v1"

    def __init__(self, db: Session) -> None:
        self.db = db

    def project(
        self,
        query: TimelineQuery,
        context: ServiceContext,
    ) -> dict[str, object]:
        generated_at = datetime.now(timezone.utc)
        cursor_state = self._decode_cursor(query.cursor) if query.cursor else None
        snapshot_at = self._resolve_snapshot(query, cursor_state, generated_at)
        query_hash = self._query_hash(query)
        if cursor_state and cursor_state.get("queryHash") != query_hash:
            raise DecisionTimelineError(
                "DECISION_TIMELINE_CURSOR_FILTER_MISMATCH",
                status_code=422,
            )

        execution, plan, project = self._require_scoped_execution(
            query.executionId,
            context,
        )
        tenant_id, workspace_id, scope_reasons = self._scope(project)
        capabilities = set(context.user.capabilities)
        if "replay.read" not in capabilities:
            raise DecisionTimelineError(
                "DECISION_TIMELINE_READ_CAPABILITY_REQUIRED",
                status_code=403,
            )
        capability_projection = {
            "baseExecution": "replay.read" in capabilities,
            "audit": "audit.logs.read" in capabilities,
            "skillInvocations": "skill_invocations.read" in capabilities,
            "replayExports": "replay.export.read" in capabilities,
            "replayRepository": "replay.repository.read" in capabilities,
            "gatePolicy": "gate_policy.read" in capabilities,
            "correctionGovernance": "correction.read" in capabilities,
            "knowledgeGovernance": "knowledge.read" in capabilities,
            "coverage": "coverage.read" in capabilities,
            "explanationPlain": "replay.read" in capabilities,
            "explanationProfessional": PROFESSIONAL_VIEW_CAPABILITY
            in capabilities,
            "explanationRaw": RAW_VIEW_CAPABILITY in capabilities,
        }

        unavailable: list[TimelineUnavailableReason] = list(scope_reasons)
        events: list[_EventCandidate] = []
        execution_ref = self._ref("execution", execution.id, "execution")

        traces = list(
            self.db.scalars(
                select(Trace)
                .where(Trace.execution_id == execution.id)
                .order_by(Trace.created_at.asc(), Trace.id.asc())
            )
        )
        trace_ids = {trace.id for trace in traces}

        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution.id)
                .order_by(ExecutionTask.created_at.asc(), ExecutionTask.id.asc())
            )
        )
        task_lookup = {task.id: task for task in tasks}
        findings = list(
            self.db.scalars(
                select(Finding)
                .where(Finding.execution_id == execution.id)
                .order_by(Finding.created_at.asc(), Finding.id.asc())
            )
        )
        finding_ids = {finding.id for finding in findings}

        skill_rows = list(
            self.db.execute(
                select(SkillInvocation, SkillVersion, Skill)
                .join(SkillVersion, SkillVersion.id == SkillInvocation.skill_version_id)
                .join(Skill, Skill.id == SkillVersion.skill_ref_id)
                .where(SkillInvocation.execution_id == execution.id)
                .order_by(SkillInvocation.created_at.asc(), SkillInvocation.id.asc())
            )
        )
        skill_invocations = [row[0] for row in skill_rows]
        skill_lookup = {row[0].id: row for row in skill_rows}
        skill_stage = {
            invocation.id: self._extension_point_stage(invocation.extension_point_id)
            for invocation in skill_invocations
        }
        invocation_ids = list(skill_lookup)

        tool_calls = self._load_for_invocations(SkillToolCall, invocation_ids)
        connector_calls = self._load_for_invocations(SkillConnectorCall, invocation_ids)
        tool_stage = {
            call.id: skill_stage.get(call.skill_invocation_id)
            for call in tool_calls
        }

        gate = self.db.scalar(
            select(GateDecision).where(GateDecision.execution_id == execution.id)
        )
        gate_snapshot = (
            self.db.scalar(
                select(GateInputSnapshot).where(
                    GateInputSnapshot.gate_decision_id == gate.id
                )
            )
            if gate is not None
            else None
        )
        binding, binding_history = self._load_gate_binding_history(
            gate,
            project,
            tenant_id,
            workspace_id,
            capability_projection["gatePolicy"],
            unavailable,
        )

        replay_exports: list[ReplayExportRecord] = []
        replay_entries: list[ReplayRepositoryEntry] = []
        if capability_projection["replayExports"]:
            replay_exports = list(
                self.db.scalars(
                    select(ReplayExportRecord)
                    .where(ReplayExportRecord.execution_id == execution.id)
                    .order_by(
                        ReplayExportRecord.created_at.asc(),
                        ReplayExportRecord.id.asc(),
                    )
                )
            )
        else:
            unavailable.append(
                self._reason(
                    "PERMISSION_RESTRICTED",
                    "replay_export",
                    "timeline.unavailable.permissionRestricted",
                    lifecycle_stage="GATE",
                )
            )
        if capability_projection["replayRepository"]:
            replay_entries = list(
                self.db.scalars(
                    select(ReplayRepositoryEntry)
                    .where(ReplayRepositoryEntry.execution_id == execution.id)
                    .order_by(
                        ReplayRepositoryEntry.frozen_at.asc(),
                        ReplayRepositoryEntry.id.asc(),
                    )
                )
            )
        else:
            unavailable.append(
                self._reason(
                    "PERMISSION_RESTRICTED",
                    "replay_repository",
                    "timeline.unavailable.permissionRestricted",
                    lifecycle_stage="GATE",
                )
            )

        domain_events = self._load_domain_events(execution.id, trace_ids)
        domain_events = self._filter_scoped_domain_events(
            domain_events,
            execution.id,
            tenant_id,
            workspace_id,
            unavailable,
        )

        approval_ids = self._collect_approval_ids(
            execution,
            plan,
            skill_invocations,
            binding_history,
            replay_entries,
        )
        approvals = self._load_approvals(execution, plan, approval_ids)
        approval_lookup = {approval.id: approval for approval in approvals}

        policy_trace_ids = {
            history.trace_id
            for history in binding_history
            if history.trace_id is not None
        }
        policy_traces = (
            {
                trace.id: trace
                for trace in self.db.scalars(
                    select(Trace).where(Trace.id.in_(policy_trace_ids))
                )
            }
            if policy_trace_ids
            else {}
        )
        scoped_policy_trace_ids = {
            history.trace_id
            for history in binding_history
            if history.trace_id is not None and history.trace_id in policy_traces
        }
        authorized_trace_ids = trace_ids | scoped_policy_trace_ids

        self._append_execution_events(events, execution, execution_ref)
        self._append_checkpoint_events(
            events,
            execution,
            execution_ref,
            authorized_trace_ids,
            unavailable,
        )
        self._append_task_events(events, execution, tasks, execution_ref)
        self._append_observation_events(
            events,
            execution,
            task_lookup,
            snapshot_at,
            authorized_trace_ids,
            finding_ids,
            unavailable,
        )
        self._append_analysis_events(events, execution, task_lookup, trace_ids, unavailable)
        self._append_finding_events(events, execution, execution_ref, findings)
        self._append_trace_span_events(events, execution, trace_ids, unavailable)

        if capability_projection["skillInvocations"]:
            self._append_skill_events(
                events,
                execution,
                skill_rows,
                skill_stage,
                trace_ids,
                unavailable,
            )
            self._append_tool_connector_events(
                events,
                execution,
                tool_calls,
                connector_calls,
                skill_stage,
                skill_lookup,
                trace_ids,
                unavailable,
            )
        else:
            unavailable.append(
                self._reason(
                    "PERMISSION_RESTRICTED",
                    "skill_invocation",
                    "timeline.unavailable.permissionRestricted",
                )
            )

        self._append_guardrail_events(
            events,
            execution,
            skill_stage,
            tool_stage,
            task_lookup,
            trace_ids,
            unavailable,
        )
        self._append_gate_events(
            events,
            execution,
            gate,
            gate_snapshot,
            binding,
            binding_history,
            approval_lookup,
            authorized_trace_ids,
            unavailable,
        )
        self._append_approval_events(
            events,
            execution,
            approvals,
            skill_stage,
            binding_history,
            authorized_trace_ids,
        )
        self._append_replay_events(
            events,
            execution,
            replay_exports,
            replay_entries,
            approval_lookup,
            snapshot_at,
        )
        authoritative_reference_ids = {
            str(reference.get("referenceId"))
            for candidate in events
            for reference in candidate.payload.get("refs", [])
            if isinstance(reference, dict)
            and reference.get("referenceId") is not None
        } | {
            str(candidate.payload["replayId"])
            for candidate in events
            if candidate.payload.get("replayId") is not None
        }
        self._append_domain_events(
            events,
            execution,
            domain_events,
            approval_lookup,
            authorized_trace_ids,
            unavailable,
            capability_projection,
            authoritative_reference_ids,
        )
        self._append_audit_events(
            events,
            execution,
            authorized_trace_ids,
            skill_stage,
            binding_history,
            capability_projection["audit"],
            unavailable,
        )

        return self._project_page(
            query=query,
            execution=execution,
            project=project,
            events=events,
            unavailable=unavailable,
            capability_projection=capability_projection,
            generated_at=generated_at,
            snapshot_at=snapshot_at,
            cursor_state=cursor_state,
            query_hash=query_hash,
        )

    def _require_scoped_execution(
        self,
        execution_id: UUID,
        context: ServiceContext,
    ) -> tuple[Execution, TestPlan, Project | None]:
        row = self.db.execute(
            select(Execution, TestPlan, Project)
            .join(TestPlan, TestPlan.id == Execution.plan_id)
            .outerjoin(Project, Project.id == TestPlan.project_id)
            .where(Execution.id == execution_id)
        ).one_or_none()
        if row is None:
            raise DecisionTimelineError(
                "DECISION_TIMELINE_EXECUTION_NOT_FOUND",
                status_code=404,
            )
        execution, plan, project = row
        if project is None:
            if not {"admin", "system"}.intersection(context.user.roles):
                raise DecisionTimelineError(
                    "DECISION_TIMELINE_EXECUTION_NOT_FOUND",
                    status_code=404,
                )
            return execution, plan, None
        try:
            ScopeAuthorizationService(self.db).resolve_project(project.id, context)
        except ScopeAuthorizationError as exc:
            raise DecisionTimelineError(
                "DECISION_TIMELINE_EXECUTION_NOT_FOUND",
                status_code=exc.status_code,
            ) from exc
        return execution, plan, project

    def _scope(
        self,
        project: Project | None,
    ) -> tuple[str | None, str | None, list[TimelineUnavailableReason]]:
        if project is None:
            return (
                None,
                None,
                [
                    self._reason(
                        "LEGACY_SCOPE_UNAVAILABLE",
                        "project",
                        "timeline.unavailable.legacyScope",
                    )
                ],
            )
        try:
            tenant_id, workspace_id = ScopeAuthorizationService.project_authority(project)
        except ScopeAuthorizationError as exc:
            raise DecisionTimelineError(
                "DECISION_TIMELINE_SCOPE_INVALID",
                status_code=409,
            ) from exc
        return tenant_id, workspace_id, []

    def _load_for_invocations(
        self,
        model: type[SkillToolCall] | type[SkillConnectorCall],
        invocation_ids: list[UUID],
    ) -> list[Any]:
        if not invocation_ids:
            return []
        return list(
            self.db.scalars(
                select(model)
                .where(model.skill_invocation_id.in_(invocation_ids))
                .order_by(model.created_at.asc(), model.id.asc())
            )
        )

    def _load_gate_binding_history(
        self,
        gate: GateDecision | None,
        project: Project | None,
        tenant_id: str | None,
        workspace_id: str | None,
        allowed: bool,
        unavailable: list[TimelineUnavailableReason],
    ) -> tuple[GatePolicyBinding | None, list[GatePolicyBindingHistory]]:
        if gate is None or not gate.policy_binding_ref:
            return None, []
        if not allowed:
            unavailable.append(
                self._reason(
                    "PERMISSION_RESTRICTED",
                    "gate_policy_binding",
                    "timeline.unavailable.permissionRestricted",
                    lifecycle_stage="GATE",
                )
            )
            return None, []
        binding = self.db.scalar(
            select(GatePolicyBinding).where(
                GatePolicyBinding.binding_ref == gate.policy_binding_ref
            )
        )
        if binding is None:
            unavailable.append(
                self._reason(
                    "REFERENCE_NOT_FOUND",
                    "gate_policy_binding",
                    "timeline.unavailable.referenceNotFound",
                    lifecycle_stage="GATE",
                    reference_type="gate_policy_binding",
                )
            )
            return None, []
        if (
            project is None
            or binding.tenant_id != tenant_id
            or binding.workspace_id != workspace_id
        ):
            unavailable.append(
                self._reason(
                    "CROSS_SCOPE_REFERENCE_BLOCKED",
                    "gate_policy_binding",
                    "timeline.unavailable.crossScopeBlocked",
                    lifecycle_stage="GATE",
                )
            )
            return None, []
        history = list(
            self.db.scalars(
                select(GatePolicyBindingHistory)
                .where(
                    GatePolicyBindingHistory.project_id == project.id,
                    GatePolicyBindingHistory.tenant_id == tenant_id,
                    GatePolicyBindingHistory.workspace_id == workspace_id,
                    or_(
                        GatePolicyBindingHistory.binding_id == binding.id,
                        GatePolicyBindingHistory.previous_binding_id == binding.id,
                    ),
                )
                .order_by(
                    GatePolicyBindingHistory.created_at.asc(),
                    GatePolicyBindingHistory.id.asc(),
                )
            )
        )
        return binding, history

    def _load_domain_events(
        self,
        execution_id: UUID,
        trace_ids: set[UUID],
    ) -> list[DomainEventRecord]:
        clauses = [
            DomainEventRecord.correlation_refs["executionId"].as_string()
            == str(execution_id)
        ]
        if trace_ids:
            clauses.append(DomainEventRecord.trace_id.in_(trace_ids))
        return list(
            self.db.scalars(
                select(DomainEventRecord)
                .where(or_(*clauses))
                .order_by(
                    DomainEventRecord.occurred_at.asc(),
                    DomainEventRecord.event_id.asc(),
                )
            )
        )

    def _filter_scoped_domain_events(
        self,
        domain_events: list[DomainEventRecord],
        execution_id: UUID,
        tenant_id: str | None,
        workspace_id: str | None,
        unavailable: list[TimelineUnavailableReason],
    ) -> list[DomainEventRecord]:
        scoped: list[DomainEventRecord] = []
        for event in domain_events:
            event_execution = event.correlation_refs.get("executionId")
            event_tenant = event.correlation_refs.get("tenantId")
            event_workspace = event.correlation_refs.get("workspaceId")
            if (
                (
                    event_execution is not None
                    and str(event_execution) != str(execution_id)
                )
                or (event_tenant is not None and str(event_tenant) != tenant_id)
                or (
                    event_workspace is not None
                    and str(event_workspace) != workspace_id
                )
            ):
                unavailable.append(
                    self._reason(
                        "CROSS_SCOPE_REFERENCE_BLOCKED",
                        "domain_event",
                        "timeline.unavailable.crossScopeBlocked",
                    )
                )
                continue
            scoped.append(event)
        return scoped

    def _collect_approval_ids(
        self,
        execution: Execution,
        plan: TestPlan,
        skill_invocations: list[SkillInvocation],
        binding_history: list[GatePolicyBindingHistory],
        replay_entries: list[ReplayRepositoryEntry],
    ) -> set[UUID]:
        ids: set[UUID] = {
            history.approval_id
            for history in binding_history
            if history.approval_id is not None
        }
        for refs in (
            *(invocation.approval_refs for invocation in skill_invocations),
            *(entry.approval_refs for entry in replay_entries),
        ):
            ids.update(self._reference_uuids(refs, "approval"))
        approval_conditions = [
            (Approval.resource_type == "execution")
            & (Approval.resource_id == str(execution.id)),
            (Approval.resource_type == "test_plan")
            & (Approval.resource_id == str(plan.id)),
        ]
        if execution.execution_plan_id is not None:
            approval_conditions.append(
                (Approval.resource_type == "execution_plan")
                & (Approval.resource_id == str(execution.execution_plan_id))
            )
        direct = list(
            self.db.scalars(
                select(Approval.id).where(
                    or_(*approval_conditions)
                )
            )
        )
        ids.update(direct)
        return ids

    def _load_approvals(
        self,
        execution: Execution,
        plan: TestPlan,
        approval_ids: set[UUID],
    ) -> list[Approval]:
        clauses: list[Any] = [
            (Approval.resource_type == "execution")
            & (Approval.resource_id == str(execution.id)),
            (Approval.resource_type == "test_plan")
            & (Approval.resource_id == str(plan.id)),
        ]
        if execution.execution_plan_id is not None:
            clauses.append(
                (Approval.resource_type == "execution_plan")
                & (Approval.resource_id == str(execution.execution_plan_id))
            )
        if approval_ids:
            clauses.append(Approval.id.in_(approval_ids))
        return list(
            self.db.scalars(
                select(Approval)
                .where(or_(*clauses))
                .order_by(Approval.created_at.asc(), Approval.id.asc())
            )
        )

    def _append_execution_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        execution_ref: dict[str, Any],
    ) -> None:
        self._add_event(
            events,
            execution,
            event_id=f"execution:{execution.id}:created",
            event_type="execution.created",
            stage="PREPARE",
            occurred_at=execution.created_at,
            status="queued",
            actor_type="service",
            actor_ref=self._ref("service", "execution-service", "actor"),
            summary_key="timeline.execution.created",
            professional_summary="Execution record created by execution-service.",
            refs=[execution_ref],
        )
        if execution.started_at is not None:
            self._add_event(
                events,
                execution,
                event_id=f"execution:{execution.id}:started",
                event_type="execution.started",
                stage="EXECUTE",
                occurred_at=execution.started_at,
                status="running",
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.execution.started",
                professional_summary="Execution entered its managed runtime.",
                refs=[execution_ref],
            )
        if execution.ended_at is not None:
            status = self._value(execution.status)
            self._add_event(
                events,
                execution,
                event_id=f"execution:{execution.id}:ended",
                event_type="execution.ended",
                stage=self._stage_value(execution.stage) or "GATE",
                occurred_at=execution.ended_at,
                status=status,
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.execution.ended",
                professional_summary=f"Execution reached terminal status {status}.",
                refs=[execution_ref],
            )

    def _append_checkpoint_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        execution_ref: dict[str, Any],
        authorized_trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        checkpoints = list(
            self.db.scalars(
                select(OrchestrationCheckpoint)
                .join(
                    OrchestrationRun,
                    OrchestrationRun.id == OrchestrationCheckpoint.run_id,
                )
                .where(
                    or_(
                        OrchestrationCheckpoint.execution_id == execution.id,
                        OrchestrationRun.linked_execution_id == execution.id,
                    )
                )
                .order_by(
                    OrchestrationCheckpoint.sequence_no.asc(),
                    OrchestrationCheckpoint.created_at.asc(),
                    OrchestrationCheckpoint.id.asc(),
                )
            )
        )
        for checkpoint in checkpoints:
            stage = self._stage_value(checkpoint.execution_stage)
            if stage is None:
                continue
            occurred_at = (
                checkpoint.ended_at
                or checkpoint.started_at
                or checkpoint.created_at
            )
            refs = [
                execution_ref,
                self._ref(
                    "orchestration_checkpoint",
                    checkpoint.id,
                    "source",
                ),
                self._ref("orchestration_run", checkpoint.run_id, "parent"),
            ]
            trace_id = self._scoped_trace_id(
                checkpoint.trace_id,
                authorized_trace_ids,
                unavailable,
                "orchestration_checkpoint_trace",
                lifecycle_stage=stage,
            )
            self._add_event(
                events,
                execution,
                event_id=f"orchestration_checkpoint:{checkpoint.id}",
                event_type="orchestration.checkpoint",
                stage=stage,
                occurred_at=occurred_at,
                persisted_at=checkpoint.created_at,
                status=self._value(checkpoint.status),
                actor_type="service",
                actor_ref=self._ref("service", "orchestrator-service", "actor"),
                summary_key="timeline.orchestration.checkpoint",
                professional_summary=(
                    f"Orchestration checkpoint {checkpoint.step_name} recorded "
                    f"for {stage}."
                ),
                refs=refs,
                trace_id=trace_id,
                source_sequence=checkpoint.sequence_no,
            )

    def _append_task_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        tasks: list[ExecutionTask],
        execution_ref: dict[str, Any],
    ) -> None:
        for task in tasks:
            stage = self._stage_value(task.stage) or "EXECUTE"
            task_ref = self._ref("execution_task", task.id, "source")
            refs = [execution_ref, task_ref]
            self._add_event(
                events,
                execution,
                event_id=f"execution_task:{task.id}:created",
                event_type="execution.task.created",
                stage=stage,
                occurred_at=task.created_at,
                status="queued",
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.execution.taskCreated",
                professional_summary=(
                    f"Execution task {task.task_type} was persisted for runner "
                    f"{task.runner}."
                ),
                refs=refs,
            )
            if task.started_at is not None:
                self._add_event(
                    events,
                    execution,
                    event_id=f"execution_task:{task.id}:started",
                    event_type="execution.task.started",
                    stage=stage,
                    occurred_at=task.started_at,
                    status="running",
                    actor_type="service",
                    actor_ref=self._ref("runner", task.runner, "actor"),
                    summary_key="timeline.execution.taskStarted",
                    professional_summary=f"Execution task {task.task_type} started.",
                    refs=refs,
                )
            if task.ended_at is not None:
                task_status = self._value(task.status)
                self._add_event(
                    events,
                    execution,
                    event_id=f"execution_task:{task.id}:ended",
                    event_type="execution.task.ended",
                    stage=stage,
                    occurred_at=task.ended_at,
                    status=task_status,
                    actor_type="service",
                    actor_ref=self._ref("runner", task.runner, "actor"),
                    summary_key="timeline.execution.taskEnded",
                    professional_summary=(
                        f"Execution task {task.task_type} reached status "
                        f"{task_status}."
                    ),
                    refs=refs,
                )

    def _append_observation_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        task_lookup: dict[UUID, ExecutionTask],
        snapshot_at: datetime,
        authorized_trace_ids: set[UUID],
        finding_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        artifacts = list(
            self.db.scalars(
                select(ExecutionArtifact)
                .where(ExecutionArtifact.execution_id == execution.id)
                .order_by(
                    ExecutionArtifact.created_at.asc(),
                    ExecutionArtifact.id.asc(),
                )
            )
        )
        metrics = list(
            self.db.scalars(
                select(ExecutionMetric)
                .where(ExecutionMetric.execution_id == execution.id)
                .order_by(
                    ExecutionMetric.created_at.asc(),
                    ExecutionMetric.id.asc(),
                )
            )
        )
        raw_findings = list(
            self.db.scalars(
                select(RawFindingRecord)
                .where(RawFindingRecord.execution_id == execution.id)
                .order_by(
                    RawFindingRecord.created_at.asc(),
                    RawFindingRecord.id.asc(),
                )
            )
        )
        visual_attempts = list(
            self.db.scalars(
                select(VisualGroundingAttempt)
                .where(VisualGroundingAttempt.execution_id == execution.id)
                .order_by(
                    VisualGroundingAttempt.created_at.asc(),
                    VisualGroundingAttempt.id.asc(),
                )
            )
        )
        verification_results = list(
            self.db.scalars(
                select(VerificationResult)
                .where(VerificationResult.execution_id == execution.id)
                .order_by(
                    VerificationResult.created_at.asc(),
                    VerificationResult.id.asc(),
                )
            )
        )
        for artifact in artifacts:
            expired = (
                artifact.expires_at is not None
                and self._aware(artifact.expires_at) <= snapshot_at
            )
            artifact_ref = self._ref(
                "execution_artifact",
                artifact.id,
                "evidence",
                available=not expired,
                unavailable_reason=(
                    "REFERENCE_RETAINED_OR_PURGED" if expired else None
                ),
            )
            refs = [self._ref("execution", execution.id, "execution"), artifact_ref]
            if artifact.task_id is not None and artifact.task_id in task_lookup:
                refs.append(self._ref("execution_task", artifact.task_id, "parent"))
            artifact_unavailable = (
                self._reason(
                    "REFERENCE_RETAINED_OR_PURGED",
                    "execution_artifact",
                    "timeline.unavailable.referenceRetainedOrPurged",
                    lifecycle_stage="OBSERVE",
                    reference_type="execution_artifact",
                    reference_id=str(artifact.id),
                )
                if expired
                else None
            )
            if artifact_unavailable is not None:
                unavailable.append(artifact_unavailable)
            self._add_event(
                events,
                execution,
                event_id=f"execution_artifact:{artifact.id}",
                event_type="evidence.artifact.recorded",
                stage="OBSERVE",
                occurred_at=artifact.created_at,
                status=("retained_or_purged" if expired else artifact.redaction_status),
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.evidence.artifactRecorded",
                professional_summary=(
                    f"Evidence artifact {self._value(artifact.artifact_type)} "
                    "was recorded after backend redaction handling."
                ),
                refs=refs,
                visibility="redacted",
                unavailable_reason=artifact_unavailable,
            )
        for metric in metrics:
            self._add_event(
                events,
                execution,
                event_id=f"execution_metric:{metric.id}",
                event_type="evidence.metric.recorded",
                stage="OBSERVE",
                occurred_at=metric.created_at,
                status="recorded",
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.evidence.metricRecorded",
                professional_summary=(
                    f"Execution metric {metric.metric_name} was persisted with "
                    "its authoritative unit and threshold fields."
                ),
                refs=[
                    self._ref("execution", execution.id, "execution"),
                    self._ref("execution_metric", metric.id, "source"),
                ],
            )
        for finding in raw_findings:
            refs = [
                self._ref("execution", execution.id, "execution"),
                self._ref("raw_finding", finding.id, "source"),
            ]
            if finding.normalized_finding_id is not None:
                normalized_available = finding.normalized_finding_id in finding_ids
                refs.append(
                    self._ref(
                        "finding",
                        finding.normalized_finding_id,
                        "normalized_as",
                        available=normalized_available,
                        unavailable_reason=(
                            None
                            if normalized_available
                            else "CROSS_SCOPE_REFERENCE_BLOCKED"
                        ),
                    )
                )
                if not normalized_available:
                    unavailable.append(
                        self._reason(
                            "CROSS_SCOPE_REFERENCE_BLOCKED",
                            "raw_finding_normalized_ref",
                            "timeline.unavailable.crossScopeBlocked",
                            lifecycle_stage="OBSERVE",
                            reference_type="finding",
                            reference_id=str(finding.normalized_finding_id),
                        )
                    )
            self._add_event(
                events,
                execution,
                event_id=f"raw_finding:{finding.id}",
                event_type="finding.raw.observed",
                stage="OBSERVE",
                occurred_at=finding.created_at,
                status=(
                    "normalized"
                    if finding.normalized_finding_id is not None
                    else "observed"
                ),
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.finding.rawObserved",
                professional_summary=(
                    f"Raw finding candidate recorded with category "
                    f"{finding.category} and severity {finding.severity}."
                ),
                refs=refs,
            )
        for attempt in visual_attempts:
            refs = [
                self._ref("visual_grounding_attempt", attempt.id, "source"),
                self._ref("execution", execution.id, "execution"),
            ]
            trace_id = self._scoped_trace_id(
                attempt.trace_id,
                authorized_trace_ids,
                unavailable,
                "visual_grounding_trace",
                lifecycle_stage="OBSERVE",
            )
            self._add_event(
                events,
                execution,
                event_id=f"visual_grounding_attempt:{attempt.id}",
                event_type="execution.visual_grounding.recorded",
                stage="OBSERVE",
                occurred_at=attempt.created_at,
                status=attempt.status,
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.execution.visualGrounding",
                professional_summary=(
                    f"Execution-service recorded visual grounding attempt "
                    f"{attempt.action_id} with action type {attempt.action_type}."
                ),
                refs=refs,
                trace_id=trace_id,
                visibility="redacted",
            )
        for result in verification_results:
            refs = [
                self._ref("verification_result", result.id, "source"),
                self._ref("execution", execution.id, "execution"),
            ]
            if result.visual_attempt_id is not None:
                refs.append(
                    self._ref(
                        "visual_grounding_attempt",
                        result.visual_attempt_id,
                        "verifies",
                    )
                )
            if result.normalized_finding_id is not None:
                normalized_available = result.normalized_finding_id in finding_ids
                refs.append(
                    self._ref(
                        "finding",
                        result.normalized_finding_id,
                        "normalized_as",
                        available=normalized_available,
                        unavailable_reason=(
                            None
                            if normalized_available
                            else "CROSS_SCOPE_REFERENCE_BLOCKED"
                        ),
                    )
                )
                if not normalized_available:
                    unavailable.append(
                        self._reason(
                            "CROSS_SCOPE_REFERENCE_BLOCKED",
                            "verification_normalized_ref",
                            "timeline.unavailable.crossScopeBlocked",
                            lifecycle_stage="OBSERVE",
                            reference_type="finding",
                            reference_id=str(result.normalized_finding_id),
                        )
                    )
            trace_id = self._scoped_trace_id(
                result.trace_id,
                authorized_trace_ids,
                unavailable,
                "verification_trace",
                lifecycle_stage="OBSERVE",
            )
            self._add_event(
                events,
                execution,
                event_id=f"verification_result:{result.id}",
                event_type="execution.verification.recorded",
                stage="OBSERVE",
                occurred_at=result.created_at,
                status=result.status,
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.execution.verification",
                professional_summary=(
                    f"Verification result {result.verification_type} was recorded "
                    f"with status {result.status}."
                ),
                refs=refs,
                trace_id=trace_id,
                visibility="redacted",
            )

    def _append_analysis_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        task_lookup: dict[UUID, ExecutionTask],
        trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        triage_results = list(
            self.db.scalars(
                select(TriageResult)
                .where(TriageResult.execution_id == execution.id)
                .order_by(TriageResult.created_at.asc(), TriageResult.id.asc())
            )
        )
        for result in triage_results:
            self._add_event(
                events,
                execution,
                event_id=f"triage_result:{result.id}",
                event_type="analysis.triage.recorded",
                stage="ANALYZE",
                occurred_at=result.created_at,
                status=self._value(result.category),
                actor_type="agent",
                actor_ref=self._ref("agent", "TriageAgent", "actor"),
                summary_key="timeline.analysis.triageRecorded",
                professional_summary=(
                    f"Triage classification {self._value(result.category)} was "
                    "persisted with evidence-backed confidence."
                ),
                refs=[
                    self._ref("triage_result", result.id, "source"),
                    self._ref("execution", execution.id, "execution"),
                ],
            )

        agent_runs = list(
            self.db.scalars(
                select(AgentRun)
                .where(AgentRun.execution_id == execution.id)
                .order_by(AgentRun.created_at.asc(), AgentRun.id.asc())
            )
        )
        agent_stage: dict[UUID, TimelineLifecycleStage] = {}
        for run in agent_runs:
            stage = None
            if run.task_id is not None and run.task_id in task_lookup:
                stage = self._stage_value(task_lookup[run.task_id].stage)
            stage = stage or AGENT_STAGE.get(run.agent_name.lower())
            if stage is None:
                unavailable.append(
                    self._reason(
                        "LEGACY_STAGE_LINK_MISSING",
                        "agent_run",
                        "timeline.unavailable.legacyStageLink",
                        reference_type="agent_run",
                        reference_id=str(run.id),
                    )
                )
                continue
            agent_stage[run.id] = stage
            trace_id = self._execution_trace_id(
                run.trace_id,
                trace_ids,
                "agent_run",
                run.id,
                unavailable,
            )
            occurred_at = run.ended_at or run.started_at or run.created_at
            refs = [
                self._ref("agent_run", run.id, "source"),
                self._ref("execution", execution.id, "execution"),
            ]
            self._add_event(
                events,
                execution,
                event_id=f"agent_run:{run.id}",
                event_type="agent.run.recorded",
                stage=stage,
                occurred_at=occurred_at,
                persisted_at=run.created_at,
                status=self._value(run.status),
                actor_type="agent",
                actor_ref=self._ref("agent", run.agent_name, "actor"),
                summary_key="timeline.agent.runRecorded",
                professional_summary=(
                    f"Agent run {run.agent_name} reached status "
                    f"{self._value(run.status)}."
                ),
                refs=refs,
                trace_id=trace_id,
                agent_run_id=run.id,
            )

        model_invocations = list(
            self.db.scalars(
                select(ModelInvocation)
                .where(ModelInvocation.execution_id == execution.id)
                .order_by(
                    ModelInvocation.created_at.asc(),
                    ModelInvocation.id.asc(),
                )
            )
        )
        for invocation in model_invocations:
            stage = (
                agent_stage.get(invocation.agent_run_id)
                if invocation.agent_run_id is not None
                else None
            )
            if stage is None:
                unavailable.append(
                    self._reason(
                        "LEGACY_STAGE_LINK_MISSING",
                        "model_invocation",
                        "timeline.unavailable.legacyStageLink",
                        reference_type="model_invocation",
                        reference_id=str(invocation.id),
                    )
                )
                continue
            trace_id = self._execution_trace_id(
                invocation.trace_id,
                trace_ids,
                "model_invocation",
                invocation.id,
                unavailable,
            )
            self._add_event(
                events,
                execution,
                event_id=f"model_invocation:{invocation.id}",
                event_type="model.invocation.recorded",
                stage=stage,
                occurred_at=invocation.created_at,
                status="succeeded" if invocation.success else "failed",
                actor_type="service",
                actor_ref=self._ref("service", "model-gateway", "actor"),
                summary_key="timeline.model.invocationRecorded",
                professional_summary=(
                    "Model-gateway persisted a successful model invocation."
                    if invocation.success
                    else "Model-gateway persisted a failed model invocation."
                ),
                refs=[
                    self._ref("model_invocation", invocation.id, "source"),
                    self._ref("agent_run", invocation.agent_run_id, "parent"),
                ],
                trace_id=trace_id,
                agent_run_id=invocation.agent_run_id,
                model_invocation_id=invocation.id,
                visibility="redacted",
            )

    def _append_finding_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        execution_ref: dict[str, Any],
        findings: list[Finding],
    ) -> None:
        for finding in findings:
            self._add_event(
                events,
                execution,
                event_id=f"finding:{finding.id}:normalized",
                event_type="finding.normalized",
                stage="NORMALIZE",
                occurred_at=finding.created_at,
                status=self._value(finding.status),
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.finding.normalized",
                professional_summary=(
                    f"Canonical finding persisted for domain "
                    f"{self._value(finding.domain)}, category "
                    f"{self._value(finding.category)}, and severity "
                    f"{self._value(finding.severity)}."
                ),
                refs=[execution_ref, self._ref("finding", finding.id, "source")],
            )

    def _append_trace_span_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        if not trace_ids:
            unavailable.append(
                self._reason(
                    "SOURCE_NOT_RECORDED_OR_RETAINED",
                    "trace",
                    "timeline.unavailable.sourceNotRecordedOrRetained",
                    retryable=self._value(execution.status)
                    not in {"completed", "failed", "cancelled"},
                )
            )
            return
        spans = list(
            self.db.scalars(
                select(TraceSpan)
                .where(TraceSpan.trace_id.in_(trace_ids))
                .order_by(
                    TraceSpan.start_time.asc(),
                    TraceSpan.created_at.asc(),
                    TraceSpan.id.asc(),
                )
            )
        )
        missing_stage = False
        for span in spans:
            attributes = span.attributes if isinstance(span.attributes, dict) else {}
            stage = self._stage_value(
                attributes.get("lifecycleStage")
                or attributes.get("executionStage")
                or attributes.get("stage")
                or span.span_type
            )
            if stage is None:
                missing_stage = True
                continue
            occurred_at = span.start_time or span.created_at
            self._add_event(
                events,
                execution,
                event_id=f"trace_span:{span.id}",
                event_type="trace.span.recorded",
                stage=stage,
                occurred_at=occurred_at,
                persisted_at=span.created_at,
                status=span.status or "recorded",
                actor_type="service",
                actor_ref=self._ref(
                    "service",
                    span.service_name or "unknown-service",
                    "actor",
                ),
                summary_key="timeline.trace.spanRecorded",
                professional_summary=f"Trace span {span.span_name} was recorded.",
                refs=[
                    self._ref("trace", span.trace_id, "trace"),
                    self._ref("trace_span", span.id, "source"),
                ],
                trace_id=span.trace_id,
            )
        if missing_stage:
            unavailable.append(
                self._reason(
                    "LEGACY_STAGE_LINK_MISSING",
                    "trace_span",
                    "timeline.unavailable.legacyStageLink",
                )
            )

    def _append_skill_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        skill_rows: list[Any],
        skill_stage: dict[UUID, TimelineLifecycleStage | None],
        trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        invocation_ids = [row[0].id for row in skill_rows]
        invocation_events = (
            list(
                self.db.scalars(
                    select(SkillInvocationEvent)
                    .where(
                        SkillInvocationEvent.skill_invocation_id.in_(
                            invocation_ids
                        )
                    )
                    .order_by(
                        SkillInvocationEvent.created_at.asc(),
                        SkillInvocationEvent.id.asc(),
                    )
                )
            )
            if invocation_ids
            else []
        )
        event_rows: dict[UUID, list[SkillInvocationEvent]] = {}
        for event in invocation_events:
            event_rows.setdefault(event.skill_invocation_id, []).append(event)

        for invocation, version, skill in skill_rows:
            stage = skill_stage.get(invocation.id)
            if stage is None:
                unavailable.append(
                    self._reason(
                        "LEGACY_STAGE_LINK_MISSING",
                        "skill_invocation",
                        "timeline.unavailable.legacyStageLink",
                        reference_type="skill_invocation",
                        reference_id=str(invocation.id),
                    )
                )
                continue
            trace_id = self._execution_trace_id(
                invocation.trace_id,
                trace_ids,
                "skill_invocation",
                invocation.id,
                unavailable,
            )
            refs = [
                self._ref("skill_invocation", invocation.id, "source"),
                self._ref("skill", skill.id, "capability"),
                self._ref("skill_version", version.id, "version"),
                self._ref("execution", execution.id, "execution"),
            ]
            self._add_event(
                events,
                execution,
                event_id=f"skill_invocation:{invocation.id}:recorded",
                event_type="skill.invocation.recorded",
                stage=stage,
                occurred_at=invocation.created_at,
                status=invocation.status,
                actor_type="skill",
                actor_ref=self._ref("skill", skill.skill_id, "actor"),
                summary_key="timeline.skill.invocationRecorded",
                professional_summary=(
                    f"Service-managed Skill invocation {skill.skill_id} was "
                    f"recorded at extension point "
                    f"{invocation.extension_point_id or 'legacy-unlinked'}."
                ),
                refs=refs,
                trace_id=trace_id,
                skill_invocation_id=invocation.id,
                visibility="redacted",
            )
            for invocation_event in event_rows.get(invocation.id, []):
                payload = (
                    invocation_event.payload
                    if isinstance(invocation_event.payload, dict)
                    else {}
                )
                status = str(payload.get("status") or invocation_event.event_type)
                event_trace_id = self._execution_trace_id(
                    invocation_event.trace_id,
                    trace_ids,
                    "skill_invocation_event",
                    invocation_event.id,
                    unavailable,
                )
                self._add_event(
                    events,
                    execution,
                    event_id=f"skill_invocation_event:{invocation_event.id}",
                    event_type=f"skill.{invocation_event.event_type}",
                    stage=stage,
                    occurred_at=invocation_event.created_at,
                    status=status,
                    actor_type="skill",
                    actor_ref=self._ref("skill", skill.skill_id, "actor"),
                    summary_key="timeline.skill.invocationEvent",
                    professional_summary=(
                        f"Skill invocation event "
                        f"{invocation_event.event_type} was persisted."
                    ),
                    refs=[
                        self._ref(
                            "skill_invocation_event",
                            invocation_event.id,
                            "source",
                        ),
                        self._ref(
                            "skill_invocation",
                            invocation.id,
                            "parent",
                        ),
                    ],
                    trace_id=event_trace_id or trace_id,
                    skill_invocation_id=invocation.id,
                    visibility="redacted",
                )

    def _append_tool_connector_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        tool_calls: list[SkillToolCall],
        connector_calls: list[SkillConnectorCall],
        skill_stage: dict[UUID, TimelineLifecycleStage | None],
        skill_lookup: dict[UUID, Any],
        trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        for call in tool_calls:
            stage = skill_stage.get(call.skill_invocation_id)
            row = skill_lookup.get(call.skill_invocation_id)
            if stage is None or row is None:
                unavailable.append(
                    self._reason(
                        "LEGACY_STAGE_LINK_MISSING",
                        "tool_call",
                        "timeline.unavailable.legacyStageLink",
                        reference_type="tool_call",
                        reference_id=str(call.id),
                    )
                )
                continue
            invocation = row[0]
            trace_id = self._execution_trace_id(
                invocation.trace_id,
                trace_ids,
                "tool_call",
                call.id,
                unavailable,
            )
            self._add_event(
                events,
                execution,
                event_id=f"skill_tool_call:{call.id}",
                event_type="tool.call.recorded",
                stage=stage,
                occurred_at=call.created_at,
                status="recorded",
                actor_type="tool",
                actor_ref=self._ref("tool", call.tool_name, "actor"),
                summary_key="timeline.tool.callRecorded",
                professional_summary=(
                    f"Managed runtime recorded a call to tool {call.tool_name}."
                ),
                refs=[
                    self._ref("tool_call", call.id, "source"),
                    self._ref(
                        "skill_invocation",
                        call.skill_invocation_id,
                        "parent",
                    ),
                ],
                trace_id=trace_id,
                skill_invocation_id=call.skill_invocation_id,
                tool_call_id=call.id,
                visibility="redacted",
            )
        for connector_call in connector_calls:
            stage = skill_stage.get(connector_call.skill_invocation_id)
            row = skill_lookup.get(connector_call.skill_invocation_id)
            if stage is None or row is None:
                unavailable.append(
                    self._reason(
                        "LEGACY_STAGE_LINK_MISSING",
                        "connector_call",
                        "timeline.unavailable.legacyStageLink",
                        reference_type="connector_call",
                        reference_id=str(connector_call.id),
                    )
                )
                continue
            invocation = row[0]
            trace_id = self._execution_trace_id(
                invocation.trace_id,
                trace_ids,
                "connector_call",
                connector_call.id,
                unavailable,
            )
            self._add_event(
                events,
                execution,
                event_id=f"skill_connector_call:{connector_call.id}",
                event_type="connector.call.recorded",
                stage=stage,
                occurred_at=connector_call.created_at,
                status="recorded",
                actor_type="connector",
                actor_ref=self._ref(
                    "connector",
                    connector_call.connector_name,
                    "actor",
                ),
                summary_key="timeline.connector.callRecorded",
                professional_summary=(
                    "Managed runtime recorded a connector adapter call to "
                    f"{connector_call.connector_name}."
                ),
                refs=[
                    self._ref("connector_call", connector_call.id, "source"),
                    self._ref(
                        "skill_invocation",
                        connector_call.skill_invocation_id,
                        "parent",
                    ),
                ],
                trace_id=trace_id,
                skill_invocation_id=connector_call.skill_invocation_id,
                connector_call_id=connector_call.id,
                visibility="redacted",
            )

    def _append_guardrail_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        skill_stage: dict[UUID, TimelineLifecycleStage | None],
        tool_stage: dict[UUID, TimelineLifecycleStage | None],
        task_lookup: dict[UUID, ExecutionTask],
        trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        rows = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.execution_id == execution.id)
                .order_by(
                    GuardrailEvent.created_at.asc(),
                    GuardrailEvent.id.asc(),
                )
            )
        )
        agent_ids = {
            row.agent_run_id for row in rows if row.agent_run_id is not None
        }
        agent_lookup = (
            {
                agent.id: agent
                for agent in self.db.scalars(
                    select(AgentRun).where(AgentRun.id.in_(agent_ids))
                )
            }
            if agent_ids
            else {}
        )
        for row in rows:
            payload = row.payload if isinstance(row.payload, dict) else {}
            stage = self._stage_value(
                payload.get("lifecycleStage")
                or payload.get("executionStage")
                or payload.get("stage")
            )
            if stage is None and row.skill_invocation_id is not None:
                stage = skill_stage.get(row.skill_invocation_id)
            if stage is None and row.tool_call_id is not None:
                stage = tool_stage.get(row.tool_call_id)
            if stage is None and row.agent_run_id is not None:
                agent = agent_lookup.get(row.agent_run_id)
                if agent and agent.task_id in task_lookup:
                    stage = self._stage_value(task_lookup[agent.task_id].stage)
                if agent and stage is None:
                    stage = AGENT_STAGE.get(agent.agent_name.lower())
            if stage is None:
                unavailable.append(
                    self._reason(
                        "LEGACY_STAGE_LINK_MISSING",
                        "guardrail_event",
                        "timeline.unavailable.legacyStageLink",
                        reference_type="guardrail_event",
                        reference_id=str(row.id),
                    )
                )
                continue
            trace_id = self._execution_trace_id(
                row.trace_id,
                trace_ids,
                "guardrail_event",
                row.id,
                unavailable,
            )
            self._add_event(
                events,
                execution,
                event_id=f"guardrail_event:{row.id}",
                event_type="guardrail.decision.recorded",
                stage=stage,
                occurred_at=row.created_at,
                status=self._value(row.decision),
                actor_type="service",
                actor_ref=self._ref("service", "guardrail-runtime", "actor"),
                summary_key="timeline.guardrail.decisionRecorded",
                professional_summary=(
                    f"Guardrail rule {row.rule_id} recorded decision "
                    f"{self._value(row.decision)}."
                ),
                refs=[
                    self._ref("guardrail_event", row.id, "source"),
                    self._ref("execution", execution.id, "execution"),
                ],
                trace_id=trace_id,
                skill_invocation_id=row.skill_invocation_id,
                tool_call_id=row.tool_call_id,
                agent_run_id=row.agent_run_id,
                visibility="redacted",
                professional_fields={
                    "ruleIds": [row.rule_id],
                    "policyId": row.policy_id,
                    "policyVersionId": row.policy_version_id,
                    "reasonCodes": [
                        f"GUARDRAIL_{self._value(row.decision).upper()}"
                    ],
                },
            )

    def _append_gate_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        gate: GateDecision | None,
        gate_snapshot: GateInputSnapshot | None,
        binding: GatePolicyBinding | None,
        binding_history: list[GatePolicyBindingHistory],
        approval_lookup: dict[UUID, Approval],
        authorized_trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        if gate is None:
            return
        gate_ref = self._ref("gate_decision", gate.id, "source")
        if gate_snapshot is not None:
            trace_id = self._scoped_trace_id(
                self._first_uuid(gate_snapshot.trace_refs),
                authorized_trace_ids,
                unavailable,
                "gate_input_snapshot_trace",
                lifecycle_stage="GATE",
            )
            self._add_event(
                events,
                execution,
                event_id=f"gate_input_snapshot:{gate_snapshot.id}",
                event_type="gate.input_snapshot.frozen",
                stage="GATE",
                occurred_at=gate_snapshot.created_at,
                status="frozen",
                actor_type="service",
                actor_ref=self._ref("service", "execution-service", "actor"),
                summary_key="timeline.gate.inputSnapshotFrozen",
                professional_summary=(
                    "Gate input and policy resolution snapshots were frozen "
                    "before authoritative evaluation."
                ),
                refs=[
                    self._ref("gate_input_snapshot", gate_snapshot.id, "source"),
                    gate_ref,
                ],
                trace_id=trace_id,
                gate_decision_id=gate.id,
                visibility="redacted",
                professional_fields={
                    "policyVersionId": gate_snapshot.policy_snapshot_ref,
                    "policyVersionHash": gate_snapshot.policy_snapshot_hash,
                    "reasonCodes": ["GATE_INPUT_SNAPSHOT_FROZEN"],
                },
            )
        gate_refs = [gate_ref, self._ref("execution", execution.id, "execution")]
        if binding is not None:
            gate_refs.append(
                self._ref("gate_policy_binding", binding.id, "policy_binding")
            )
        self._add_event(
            events,
            execution,
            event_id=f"gate_decision:{gate.id}",
            event_type="gate.decision.recorded",
            stage="GATE",
            occurred_at=gate.created_at,
            status=self._value(gate.overall),
            actor_type="service",
            actor_ref=self._ref("service", "execution-service", "actor"),
            summary_key="timeline.gate.decisionRecorded",
            professional_summary=(
                f"Authoritative Gate decision {self._value(gate.overall)} was "
                f"persisted by evaluator {gate.evaluator_version}."
            ),
            refs=gate_refs,
            gate_decision_id=gate.id,
            visibility="redacted",
            professional_fields={
                "ruleIds": list(gate.matched_rules or []),
                "reasonCodes": list(gate.reason_codes or []),
                "policyVersionId": gate.policy_version_id,
                "policyVersionHash": gate.policy_version_hash,
            },
        )
        for history in binding_history:
            approval_refs = []
            if (
                history.approval_id is not None
                and history.approval_id in approval_lookup
            ):
                approval_refs.append(
                    self._ref("approval", history.approval_id, "authorizes")
                )
            trace_id = self._scoped_trace_id(
                history.trace_id,
                authorized_trace_ids,
                unavailable,
                "gate_policy_history_trace",
                lifecycle_stage="GATE",
            )
            linked_approval_id = (
                history.approval_id
                if history.approval_id is not None
                and history.approval_id in approval_lookup
                else None
            )
            self._add_event(
                events,
                execution,
                event_id=f"gate_policy_binding_history:{history.id}",
                event_type=f"gate.policy.{history.action}",
                stage="GATE",
                occurred_at=history.created_at,
                status=history.status,
                actor_type="service",
                actor_ref=self._ref(
                    "service",
                    "gate-policy-deployment",
                    "actor",
                ),
                summary_key=f"timeline.gatePolicy.{history.action}",
                professional_summary=(
                    f"Gate Policy {history.action} recorded mode "
                    f"{self._value(history.mode)} with status {history.status}."
                ),
                refs=[
                    self._ref(
                        "gate_policy_binding_history",
                        history.id,
                        "source",
                    ),
                    self._ref(
                        "gate_policy_binding",
                        history.binding_id,
                        "binding",
                    ),
                    self._ref(
                        "gate_policy_version",
                        history.policy_version_id,
                        "policy_version",
                    ),
                    *approval_refs,
                ],
                trace_id=trace_id,
                gate_decision_id=gate.id,
                approval_id=linked_approval_id,
                approval_refs=approval_refs,
                visibility="redacted",
                professional_fields={
                    "policyVersionId": history.policy_version_id,
                    "approvalState": (
                        self._value(approval_lookup[linked_approval_id].status)
                        if linked_approval_id is not None
                        else None
                    ),
                    "reasonCodes": [
                        f"GATE_POLICY_{history.action.upper()}_{history.status.upper()}"
                    ],
                },
            )

    def _append_approval_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        approvals: list[Approval],
        skill_stage: dict[UUID, TimelineLifecycleStage | None],
        binding_history: list[GatePolicyBindingHistory],
        trace_ids: set[UUID],
    ) -> None:
        history_by_approval = {
            history.approval_id: history
            for history in binding_history
            if history.approval_id is not None
        }
        for approval in approvals:
            stage: TimelineLifecycleStage = "PREPARE"
            history = history_by_approval.get(approval.id)
            if history is not None:
                stage = "GATE"
            elif approval.resource_type == "skill_invocation":
                resource_id = self._uuid_or_none(approval.resource_id)
                if resource_id is not None:
                    stage = skill_stage.get(resource_id) or "PREPARE"
            elif approval.resource_type in {
                "gate_policy_activation",
                "gate_policy_rollback",
                "gate_policy_binding",
                "gate_policy_version",
                "replay_repository",
            }:
                stage = "GATE"
            payload = approval.payload if isinstance(approval.payload, dict) else {}
            explicit_stage = self._stage_value(
                payload.get("lifecycleStage")
                or payload.get("executionStage")
                or payload.get("stage")
            )
            stage = explicit_stage or stage
            trace_id = history.trace_id if history is not None else None
            if trace_id is None:
                payload_trace = self._uuid_or_none(payload.get("traceId"))
                trace_id = payload_trace if payload_trace in trace_ids else None
            approval_ref = self._ref("approval", approval.id, "source")
            requester_ref = (
                self._ref("user", approval.requested_by, "actor")
                if approval.requested_by is not None
                else self._ref("system", "approval-flow", "actor")
            )
            self._add_event(
                events,
                execution,
                event_id=f"approval:{approval.id}:requested",
                event_type="approval.requested",
                stage=stage,
                occurred_at=approval.created_at,
                status="pending",
                actor_type=(
                    "human" if approval.requested_by is not None else "system"
                ),
                actor_ref=requester_ref,
                summary_key="timeline.approval.requested",
                professional_summary=(
                    f"Approval Flow recorded request type "
                    f"{self._value(approval.type)} for resource "
                    f"{approval.resource_type}."
                ),
                refs=[approval_ref],
                trace_id=trace_id,
                approval_id=approval.id,
                approval_refs=[approval_ref],
                visibility="redacted",
                professional_fields={
                    "approvalState": "pending",
                    "reasonCodes": ["APPROVAL_REQUESTED"],
                },
            )
            if approval.decided_at is not None:
                decision_actor = (
                    self._ref("user", approval.decided_by, "actor")
                    if approval.decided_by is not None
                    else self._ref("system", "approval-flow", "actor")
                )
                self._add_event(
                    events,
                    execution,
                    event_id=f"approval:{approval.id}:decided",
                    event_type="approval.decided",
                    stage=stage,
                    occurred_at=approval.decided_at,
                    status=self._value(approval.status),
                    actor_type=(
                        "human" if approval.decided_by is not None else "system"
                    ),
                    actor_ref=decision_actor,
                    summary_key="timeline.approval.decided",
                    professional_summary=(
                        f"Approval Flow persisted decision "
                        f"{self._value(approval.status)}."
                    ),
                    refs=[approval_ref],
                    trace_id=trace_id,
                    approval_id=approval.id,
                    approval_refs=[approval_ref],
                    visibility="redacted",
                    professional_fields={
                        "approvalState": self._value(approval.status),
                        "reasonCodes": ["APPROVAL_DECIDED"],
                    },
                )

    def _append_replay_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        replay_exports: list[ReplayExportRecord],
        replay_entries: list[ReplayRepositoryEntry],
        approval_lookup: dict[UUID, Approval],
        snapshot_at: datetime,
    ) -> None:
        for export in replay_exports:
            self._add_event(
                events,
                execution,
                event_id=f"replay_export:{export.id}",
                event_type="replay.export.recorded",
                stage="GATE",
                occurred_at=export.created_at,
                status=export.redaction_status,
                actor_type="service",
                actor_ref=self._ref("service", "observability", "actor"),
                summary_key="timeline.replay.exportRecorded",
                professional_summary=(
                    f"Replay export {export.export_id} was persisted with "
                    f"redaction status {export.redaction_status}."
                ),
                refs=[
                    self._ref("replay_export", export.id, "source"),
                    self._ref("execution", execution.id, "execution"),
                ],
                replay_id=export.export_id,
                visibility="redacted",
            )
        for entry in replay_entries:
            purged = entry.retention_status == "purged" or (
                entry.retention_until is not None
                and self._aware(entry.retention_until) <= snapshot_at
                and not entry.legal_hold
            )
            approval_refs = []
            for approval_id in self._reference_uuids(
                entry.approval_refs,
                "approval",
            ):
                if approval_id in approval_lookup:
                    approval_refs.append(
                        self._ref("approval", approval_id, "authorizes")
                    )
            replay_ref = self._ref(
                "replay_repository_entry",
                entry.id,
                "source",
                available=not purged,
                unavailable_reason=(
                    "REFERENCE_RETAINED_OR_PURGED" if purged else None
                ),
            )
            self._add_event(
                events,
                execution,
                event_id=f"replay_repository_entry:{entry.id}",
                event_type="replay.repository.frozen",
                stage="GATE",
                occurred_at=entry.frozen_at,
                persisted_at=entry.created_at,
                status=entry.retention_status,
                actor_type="service",
                actor_ref=self._ref(
                    "service",
                    "replay-repository-governance",
                    "actor",
                ),
                summary_key="timeline.replay.repositoryFrozen",
                professional_summary=(
                    f"Replay repository entry {entry.replay_id} was frozen with "
                    f"retention status {entry.retention_status}."
                ),
                refs=[replay_ref, *approval_refs],
                approval_id=(
                    self._reference_uuids(entry.approval_refs, "approval")[0]
                    if approval_refs
                    else None
                ),
                replay_id=entry.replay_id,
                approval_refs=approval_refs,
                visibility="redacted",
                unavailable_reason=(
                    self._reason(
                        "REFERENCE_RETAINED_OR_PURGED",
                        "replay_repository",
                        "timeline.unavailable.referenceRetainedOrPurged",
                        lifecycle_stage="GATE",
                        reference_type="replay_repository_entry",
                        reference_id=str(entry.id),
                    )
                    if purged
                    else None
                ),
            )

    def _append_domain_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        domain_events: list[DomainEventRecord],
        approval_lookup: dict[UUID, Approval],
        authorized_trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
        capability_projection: dict[str, bool],
        authoritative_reference_ids: set[str],
    ) -> None:
        for event in domain_events:
            payload = event.payload if isinstance(event.payload, dict) else {}
            stage = self._stage_value(
                payload.get("lifecycleStage")
                or payload.get("executionStage")
                or payload.get("stage")
                or event.correlation_refs.get("lifecycleStage")
            )
            is_ceg = event.event_type.startswith("ceg.")
            if stage is None:
                unavailable.append(
                    self._reason(
                        "LEGACY_STAGE_LINK_MISSING",
                        "domain_event",
                        "timeline.unavailable.legacyStageLink",
                        reference_type="domain_event",
                        reference_id=event.event_id,
                    )
                )
                continue
            restricted_source = None
            allowed = True
            if is_ceg:
                restricted_source = "ceg_domain_event"
                allowed = capability_projection["coverage"]
            elif event.event_type.startswith("correction."):
                restricted_source = "correction_domain_event"
                allowed = capability_projection["correctionGovernance"]
            elif event.event_type.startswith(("knowledge.", "ccg.")):
                restricted_source = "knowledge_domain_event"
                allowed = capability_projection["knowledgeGovernance"]
            if not allowed:
                unavailable.append(
                    self._reason(
                        "PERMISSION_RESTRICTED",
                        restricted_source or "domain_event",
                        "timeline.unavailable.permissionRestricted",
                        lifecycle_stage=stage,
                    )
                )
                continue
            trace_id = event.trace_id if event.trace_id in authorized_trace_ids else None
            if event.trace_id is not None and trace_id is None:
                unavailable.append(
                    self._reason(
                        "CROSS_SCOPE_REFERENCE_BLOCKED",
                        "domain_event_trace",
                        "timeline.unavailable.crossScopeBlocked",
                    )
                )
            actor_type, actor_ref = self._domain_actor(event.actor_ref)
            ceg_kind = self._ceg_kind(event, payload) if is_ceg else None
            promotion_type = (
                str(payload.get("promotionType"))
                if payload.get("promotionType") is not None
                else None
            )
            graph_learning_mode = (
                str(payload.get("graphLearningMode"))
                if payload.get("graphLearningMode") is not None
                else None
            )
            policy_refs = self._verified_refs(
                payload.get("policyDecisionRefs", []),
                "policy_decision",
                authoritative_reference_ids,
                unavailable,
                stage,
            )
            evidence_refs = self._verified_refs(
                event.evidence_refs,
                "evidence",
                authoritative_reference_ids,
                unavailable,
                stage,
            )
            replay_refs = self._verified_refs(
                event.replay_refs,
                "replay",
                authoritative_reference_ids,
                unavailable,
                stage,
            )
            requested_approval_ids = self._reference_uuids(
                payload.get("approvalRefs", []),
                "approval",
            )
            auto_promotion = (
                (promotion_type or "").lower() in AUTO_PROMOTION_TYPES
                or str(payload.get("approvalState") or "").lower()
                == "not_required"
            )
            approval_refs = []
            if not auto_promotion:
                approval_refs = [
                    self._ref("approval", approval_id, "authorizes")
                    for approval_id in requested_approval_ids
                    if approval_id in approval_lookup
                ]
            refs = [
                self._ref("domain_event", event.event_id, "source"),
                self._ref("execution", execution.id, "execution"),
                *evidence_refs,
                *replay_refs,
                *policy_refs,
                *approval_refs,
            ]
            status = str(payload.get("status") or "recorded")
            self._add_event(
                events,
                execution,
                event_id=f"domain_event:{event.event_id}",
                event_type=event.event_type,
                stage=stage,
                occurred_at=event.occurred_at,
                persisted_at=event.created_at,
                status=status,
                actor_type=actor_type,
                actor_ref=actor_ref,
                summary_key=str(
                    payload.get("plainSummaryKey")
                    or f"timeline.domain.{event.event_type}"
                ),
                professional_summary=(
                    f"Authoritative domain event {event.event_type} was "
                    "projected from its persisted record."
                ),
                refs=refs,
                trace_id=trace_id,
                approval_id=(
                    requested_approval_ids[0]
                    if approval_refs and requested_approval_ids
                    else None
                ),
                replay_id=next(
                    (
                        str(reference["referenceId"])
                        for reference in replay_refs
                        if reference["available"]
                    ),
                    None,
                ),
                visibility="redacted",
                ceg_event_kind=ceg_kind,
                graph_learning_mode=graph_learning_mode,
                promotion_type=promotion_type,
                policy_decision_refs=policy_refs,
                approval_refs=approval_refs,
                professional_fields={
                    "approvalState": payload.get("approvalState"),
                    "reasonCodes": [
                        str(payload.get("reasonCode"))
                    ]
                    if payload.get("reasonCode")
                    else [],
                },
            )

    def _append_audit_events(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        authorized_trace_ids: set[UUID],
        skill_stage: dict[UUID, TimelineLifecycleStage | None],
        binding_history: list[GatePolicyBindingHistory],
        allowed: bool,
        unavailable: list[TimelineUnavailableReason],
    ) -> None:
        if not allowed:
            unavailable.append(
                self._reason(
                    "PERMISSION_RESTRICTED",
                    "audit_log",
                    "timeline.unavailable.permissionRestricted",
                )
            )
            return
        if not authorized_trace_ids:
            return
        history_ids = {str(history.id) for history in binding_history}
        binding_ids = {str(history.binding_id) for history in binding_history}
        approvals = {
            str(history.approval_id)
            for history in binding_history
            if history.approval_id is not None
        }
        rows = list(
            self.db.scalars(
                select(AuditLog)
                .where(AuditLog.trace_id.in_(authorized_trace_ids))
                .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            )
        )
        for row in rows:
            stage = self._audit_stage(row, skill_stage)
            scoped_to_execution = row.trace_id in {
                trace_id
                for trace_id in authorized_trace_ids
                if trace_id not in {
                    history.trace_id
                    for history in binding_history
                    if history.trace_id is not None
                }
            }
            if not scoped_to_execution and row.resource_id not in (
                history_ids | binding_ids | approvals
            ):
                continue
            if stage is None:
                unavailable.append(
                    self._reason(
                        "LEGACY_STAGE_LINK_MISSING",
                        "audit_log",
                        "timeline.unavailable.legacyStageLink",
                        reference_type="audit_log",
                        reference_id=str(row.id),
                    )
                )
                continue
            actor_ref = (
                self._ref("user", row.actor_id, "actor")
                if row.actor_id is not None
                else self._ref("system", "audit-runtime", "actor")
            )
            self._add_event(
                events,
                execution,
                event_id=f"audit_log:{row.id}",
                event_type="audit.recorded",
                stage=stage,
                occurred_at=row.created_at,
                status=row.retention_status,
                actor_type="human" if row.actor_id is not None else "system",
                actor_ref=actor_ref,
                summary_key="timeline.audit.recorded",
                professional_summary=(
                    f"Audit action {row.action} was recorded for resource type "
                    f"{row.resource_type}."
                ),
                refs=[
                    self._ref("audit_log", row.id, "source"),
                    self._ref(
                        row.resource_type,
                        row.resource_id,
                        "audited_resource",
                    ),
                ],
                trace_id=row.trace_id,
                visibility="redacted",
            )

    def _project_page(
        self,
        *,
        query: TimelineQuery,
        execution: Execution,
        project: Project | None,
        events: list[_EventCandidate],
        unavailable: list[TimelineUnavailableReason],
        capability_projection: dict[str, bool],
        generated_at: datetime,
        snapshot_at: datetime,
        cursor_state: dict[str, Any] | None,
        query_hash: str,
    ) -> dict[str, object]:
        snapshot_events = [
            event
            for event in events
            if self._aware(event.persisted_at) <= snapshot_at
        ]
        snapshot_events.sort(key=lambda event: event.sort_tuple)
        all_stage_counts = {stage: 0 for stage in STAGES}
        materialized: list[dict[str, Any]] = []
        for sequence, event_candidate in enumerate(snapshot_events, start=1):
            event_candidate.payload["sequence"] = sequence
            event_candidate.payload["sourceSequence"] = (
                event_candidate.source_sequence
                if event_candidate.source_sequence != 0
                else None
            )
            event_candidate.payload["sortKey"] = self._sort_key(event_candidate)
            all_stage_counts[event_candidate.payload["lifecycleStage"]] += 1
            materialized.append(event_candidate.payload)

        filtered = [
            event_payload
            for event_payload in materialized
            if self._matches_query(event_payload, query)
        ]
        filtered_stage_counts = {stage: 0 for stage in STAGES}
        for event_payload in filtered:
            filtered_stage_counts[event_payload["lifecycleStage"]] += 1
        total_events = len(filtered)

        last_sort_key = (
            str(cursor_state.get("lastSortKey"))
            if cursor_state and cursor_state.get("lastSortKey")
            else None
        )
        if last_sort_key is not None:
            if not any(
                event_payload["sortKey"] == last_sort_key
                for event_payload in filtered
            ):
                raise DecisionTimelineError(
                    "DECISION_TIMELINE_CURSOR_EVENT_UNAVAILABLE",
                    status_code=409,
                )
            filtered = [
                event_payload
                for event_payload in filtered
                if event_payload["sortKey"] > last_sort_key
            ]

        page_events = filtered[: query.pageSize]
        # Explain-view projection is substantially more expensive than the
        # lightweight filtering metadata above. Materialize it only for the
        # requested page so page_size remains an effective performance bound.
        for page_event in page_events:
            professional_fields = page_event.pop("_professionalFields", {})
            page_event["explainView"] = build_explain_view_projection(
                page_event,
                professional_allowed=capability_projection[
                    "explanationProfessional"
                ],
                raw_allowed=capability_projection["explanationRaw"],
                projected_at=generated_at,
                professional_fields=professional_fields,
            )
            if not capability_projection["explanationProfessional"]:
                page_event["professionalSummary"] = None
        has_more = len(filtered) > query.pageSize
        next_cursor = None
        if has_more and page_events:
            next_cursor = self._encode_cursor(
                {
                    "version": self.CURSOR_VERSION,
                    "queryHash": query_hash,
                    "snapshotAt": snapshot_at.isoformat(),
                    "lastSortKey": page_events[-1]["sortKey"],
                }
            )

        deduped_unavailable = self._dedupe_reasons(unavailable)
        page_by_stage: dict[str, list[dict[str, Any]]] = {
            stage: [] for stage in STAGES
        }
        for page_event in page_events:
            page_by_stage[page_event["lifecycleStage"]].append(page_event)

        stage_groups = []
        for index, stage in enumerate(STAGES, start=1):
            status = self._stage_status(execution, stage)
            unavailable_reason = self._stage_unavailable_reason(
                execution=execution,
                stage=stage,
                status=status,
                unfiltered_count=all_stage_counts[stage],
                filtered_count=filtered_stage_counts[stage],
                has_filters=self._has_event_filters(query),
            )
            stage_groups.append(
                {
                    "lifecycleStage": stage,
                    "sequence": index,
                    "status": status,
                    "eventCount": filtered_stage_counts[stage],
                    "pageEventCount": len(page_by_stage[stage]),
                    "events": page_by_stage[stage],
                    "unavailableReason": (
                        unavailable_reason.model_dump(mode="json")
                        if unavailable_reason is not None
                        else None
                    ),
                }
            )

        projection = {
            "schemaVersion": self.SCHEMA_VERSION,
            "generatedAt": generated_at.isoformat(),
            "executionId": str(execution.id),
            "projectId": str(project.id) if project is not None else None,
            "authoritative": True,
            "readOnly": True,
            "writesDecision": False,
            "sortOrder": [
                "lifecycleStage.sequence ASC",
                "occurredAt ASC",
                "sourceSequence ASC NULLS FIRST",
                "eventId ASC",
            ],
            "appliedFilters": self._filter_projection(query),
            "capabilityProjection": capability_projection,
            "stageGroups": stage_groups,
            "unavailableReasons": [
                reason.model_dump(mode="json") for reason in deduped_unavailable
            ],
            "pagination": {
                "pageSize": query.pageSize,
                "totalEvents": total_events,
                "returnedEvents": len(page_events),
                "hasMore": has_more,
                "nextCursor": next_cursor,
                "snapshotAt": snapshot_at.isoformat(),
            },
        }
        redacted = redact_sensitive_data(projection)
        return validate_contract("decision-timeline", redacted)

    def _add_event(
        self,
        events: list[_EventCandidate],
        execution: Execution,
        *,
        event_id: str,
        event_type: str,
        stage: TimelineLifecycleStage,
        occurred_at: datetime,
        status: str,
        actor_type: str,
        actor_ref: dict[str, Any] | None,
        summary_key: str,
        professional_summary: str,
        refs: list[dict[str, Any]],
        persisted_at: datetime | None = None,
        trace_id: UUID | None = None,
        skill_invocation_id: UUID | None = None,
        tool_call_id: UUID | None = None,
        connector_call_id: UUID | None = None,
        agent_run_id: UUID | None = None,
        model_invocation_id: UUID | None = None,
        gate_decision_id: UUID | None = None,
        approval_id: UUID | None = None,
        replay_id: str | None = None,
        visibility: str = "full",
        unavailable_reason: TimelineUnavailableReason | None = None,
        ceg_event_kind: str | None = None,
        graph_learning_mode: str | None = None,
        promotion_type: str | None = None,
        policy_decision_refs: list[dict[str, Any]] | None = None,
        approval_refs: list[dict[str, Any]] | None = None,
        professional_fields: dict[str, Any] | None = None,
        source_sequence: int | None = None,
    ) -> None:
        occurred = self._aware(occurred_at)
        persisted = self._aware(persisted_at or occurred_at)
        payload = {
            "eventId": event_id,
            "eventType": event_type,
            "lifecycleStage": stage,
            "sequence": 1,
            "sourceSequence": source_sequence,
            "sortKey": "pending",
            "occurredAt": occurred.isoformat(),
            "status": str(status),
            "actorType": actor_type,
            "actorRef": actor_ref,
            "plainSummaryKey": summary_key,
            "professionalSummary": professional_summary,
            "refs": refs,
            "traceId": str(trace_id) if trace_id is not None else None,
            "executionId": str(execution.id),
            "skillInvocationId": (
                str(skill_invocation_id)
                if skill_invocation_id is not None
                else None
            ),
            "toolCallId": str(tool_call_id) if tool_call_id is not None else None,
            "connectorCallId": (
                str(connector_call_id)
                if connector_call_id is not None
                else None
            ),
            "agentRunId": str(agent_run_id) if agent_run_id is not None else None,
            "modelInvocationId": (
                str(model_invocation_id)
                if model_invocation_id is not None
                else None
            ),
            "gateDecisionId": (
                str(gate_decision_id) if gate_decision_id is not None else None
            ),
            "approvalId": str(approval_id) if approval_id is not None else None,
            "replayId": replay_id,
            "visibility": visibility,
            "unavailableReason": (
                unavailable_reason.model_dump(mode="json")
                if unavailable_reason is not None
                else None
            ),
            "cegEventKind": ceg_event_kind,
            "graphLearningMode": graph_learning_mode,
            "promotionType": promotion_type,
            "policyDecisionRefs": policy_decision_refs or [],
            "approvalRefs": approval_refs or [],
            "_professionalFields": professional_fields or {},
        }
        events.append(
            _EventCandidate(
                payload=payload,
                occurred_at=occurred,
                persisted_at=persisted,
                source_sequence=source_sequence or 0,
            )
        )

    def _matches_query(
        self,
        event: dict[str, Any],
        query: TimelineQuery,
    ) -> bool:
        if query.traceId is not None and event.get("traceId") != str(query.traceId):
            return False
        if query.lifecycleStages and event["lifecycleStage"] not in set(
            query.lifecycleStages
        ):
            return False
        if query.eventTypes and event["eventType"] not in set(query.eventTypes):
            return False
        if query.statuses and event["status"] not in set(query.statuses):
            return False
        if query.actorTypes and event["actorType"] not in set(query.actorTypes):
            return False
        occurred_at = self._aware(datetime.fromisoformat(event["occurredAt"]))
        if query.occurredAfter is not None and occurred_at < self._aware(
            query.occurredAfter
        ):
            return False
        if query.occurredBefore is not None and occurred_at > self._aware(
            query.occurredBefore
        ):
            return False
        return True

    def _stage_status(
        self,
        execution: Execution,
        stage: TimelineLifecycleStage,
    ) -> str:
        current_stage = self._stage_value(execution.stage) or "PREPARE"
        current_index = STAGE_INDEX[current_stage]
        stage_index = STAGE_INDEX[stage]
        execution_status = self._value(execution.status)
        if stage_index < current_index:
            return "completed"
        if stage_index > current_index:
            return "pending"
        if execution_status == "completed":
            return "completed"
        if execution_status == "failed":
            return "failed"
        if execution_status == "cancelled":
            return "cancelled"
        if execution_status in {"running", "analyzing"}:
            return "running"
        return "pending"

    def _stage_unavailable_reason(
        self,
        *,
        execution: Execution,
        stage: TimelineLifecycleStage,
        status: str,
        unfiltered_count: int,
        filtered_count: int,
        has_filters: bool,
    ) -> TimelineUnavailableReason | None:
        if status == "pending" and STAGE_INDEX[stage] > STAGE_INDEX[
            self._stage_value(execution.stage) or "PREPARE"
        ]:
            return self._reason(
                "EXECUTION_NOT_REACHED",
                "lifecycle_stage",
                "timeline.unavailable.executionNotReached",
                lifecycle_stage=stage,
                retryable=True,
            )
        if status in {"pending", "running"} and unfiltered_count == 0:
            return self._reason(
                "EXECUTION_IN_PROGRESS",
                "lifecycle_stage",
                "timeline.unavailable.executionInProgress",
                lifecycle_stage=stage,
                retryable=True,
            )
        if unfiltered_count == 0 and not has_filters:
            return self._reason(
                "SOURCE_NOT_RECORDED_OR_RETAINED",
                "lifecycle_stage",
                "timeline.unavailable.sourceNotRecordedOrRetained",
                lifecycle_stage=stage,
            )
        if has_filters and filtered_count == 0:
            return None
        return None

    def _filter_projection(self, query: TimelineQuery) -> dict[str, object]:
        return {
            "traceId": str(query.traceId) if query.traceId else None,
            "lifecycleStages": list(query.lifecycleStages),
            "eventTypes": list(query.eventTypes),
            "statuses": list(query.statuses),
            "actorTypes": list(query.actorTypes),
            "occurredAfter": (
                self._aware(query.occurredAfter).isoformat()
                if query.occurredAfter
                else None
            ),
            "occurredBefore": (
                self._aware(query.occurredBefore).isoformat()
                if query.occurredBefore
                else None
            ),
        }

    @staticmethod
    def _has_event_filters(query: TimelineQuery) -> bool:
        return bool(
            query.traceId
            or query.lifecycleStages
            or query.eventTypes
            or query.statuses
            or query.actorTypes
            or query.occurredAfter
            or query.occurredBefore
        )

    def _audit_stage(
        self,
        audit: AuditLog,
        skill_stage: dict[UUID, TimelineLifecycleStage | None],
    ) -> TimelineLifecycleStage | None:
        details = audit.details if isinstance(audit.details, dict) else {}
        explicit = self._stage_value(
            details.get("lifecycleStage")
            or details.get("executionStage")
            or details.get("stage")
        )
        if explicit is not None:
            return explicit
        if audit.resource_type == "skill_invocation":
            invocation_id = self._uuid_or_none(audit.resource_id)
            if invocation_id is not None:
                return skill_stage.get(invocation_id)
        marker = f"{audit.action}:{audit.resource_type}".lower()
        if "gate" in marker or "replay" in marker:
            return "GATE"
        if "finding" in marker or "normalize" in marker:
            return "NORMALIZE"
        if "triage" in marker or "analysis" in marker:
            return "ANALYZE"
        if "artifact" in marker or "metric" in marker or "evidence" in marker:
            return "OBSERVE"
        if "execution_task" in marker or "execution" in marker:
            return "EXECUTE"
        if "plan" in marker or "requirement" in marker:
            return "PREPARE"
        return None

    @staticmethod
    def _extension_point_stage(value: str | None) -> TimelineLifecycleStage | None:
        prefix = str(value or "").split(".", 1)[0].upper()
        return prefix if prefix in STAGE_INDEX else None  # type: ignore[return-value]

    @staticmethod
    def _stage_value(value: object) -> TimelineLifecycleStage | None:
        resolved = getattr(value, "value", value)
        normalized = str(resolved or "").upper()
        return normalized if normalized in STAGE_INDEX else None  # type: ignore[return-value]

    @staticmethod
    def _value(value: object) -> str:
        return str(getattr(value, "value", value))

    @staticmethod
    def _aware(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _execution_trace_id(
        self,
        trace_id: UUID | None,
        trace_ids: set[UUID],
        source_type: str,
        source_id: UUID,
        unavailable: list[TimelineUnavailableReason],
    ) -> UUID | None:
        if trace_id is None:
            return None
        if trace_id in trace_ids:
            return trace_id
        unavailable.append(
            self._reason(
                "CROSS_SCOPE_REFERENCE_BLOCKED",
                source_type,
                "timeline.unavailable.crossScopeBlocked",
                reference_type=source_type,
                reference_id=str(source_id),
            )
        )
        return None

    def _scoped_trace_id(
        self,
        trace_id: UUID | None,
        authorized_trace_ids: set[UUID],
        unavailable: list[TimelineUnavailableReason],
        source_type: str,
        *,
        lifecycle_stage: TimelineLifecycleStage,
    ) -> UUID | None:
        if trace_id is None:
            return None
        if trace_id in authorized_trace_ids:
            return trace_id
        unavailable.append(
            self._reason(
                "CROSS_SCOPE_REFERENCE_BLOCKED",
                source_type,
                "timeline.unavailable.crossScopeBlocked",
                lifecycle_stage=lifecycle_stage,
                reference_type="trace",
                reference_id=str(trace_id),
            )
        )
        return None

    @classmethod
    def _ref(
        cls,
        reference_type: str,
        reference_id: object,
        relationship: str,
        *,
        available: bool = True,
        visibility: str = "full",
        unavailable_reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "referenceType": reference_type,
            "referenceId": str(reference_id),
            "relationship": relationship,
            "available": available,
            "visibility": visibility,
            "unavailableReasonCode": unavailable_reason,
            "href": (
                cls._reference_href(reference_type, reference_id)
                if available
                else None
            ),
        }

    @staticmethod
    def _reference_href(reference_type: str, reference_id: object) -> str | None:
        route_parameters = {
            "execution": ("/executions", "executionId"),
            "execution_artifact": ("/executions", "artifactId"),
            "execution_metric": ("/executions", "metricId"),
            "verification_result": ("/executions", "verificationId"),
            "visual_grounding_attempt": ("/executions", "visualGroundingId"),
            "trace": ("/observability", "traceId"),
            "trace_span": ("/observability", "traceSpanId"),
            "finding": ("/findings", "findingId"),
            "raw_finding": ("/findings", "rawFindingId"),
            "gate_decision": ("/gate-decisions", "gateDecisionId"),
            "approval": ("/correction-governance", "approvalId"),
            "replay_export": ("/replay-center", "replayId"),
            "replay_repository_entry": ("/replay-repository", "replayId"),
            "skill_invocation": ("/skill-invocations", "skillInvocationId"),
            "audit_log": ("/audit-logs", "auditLogId"),
        }
        route = route_parameters.get(reference_type)
        if route is None:
            return None
        path, parameter = route
        return f"{path}?{parameter}={quote(str(reference_id), safe='')}"

    @staticmethod
    def _reason(
        code: str,
        source_type: str,
        detail_key: str,
        *,
        lifecycle_stage: TimelineLifecycleStage | None = None,
        reference_type: str | None = None,
        reference_id: str | None = None,
        retryable: bool = False,
    ) -> TimelineUnavailableReason:
        return TimelineUnavailableReason.model_validate(
            {
                "code": code,
                "sourceType": source_type,
                "detailKey": detail_key,
                "lifecycleStage": lifecycle_stage,
                "referenceType": reference_type,
                "referenceId": reference_id,
                "retryable": retryable,
            }
        )

    @staticmethod
    def _dedupe_reasons(
        reasons: list[TimelineUnavailableReason],
    ) -> list[TimelineUnavailableReason]:
        seen: set[tuple[object, ...]] = set()
        deduped = []
        for reason in reasons:
            key = (
                reason.code,
                reason.sourceType,
                reason.lifecycleStage,
                reason.referenceType,
                reason.referenceId,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(reason)
        return deduped

    @staticmethod
    def _reference_uuids(refs: object, expected_type: str) -> list[UUID]:
        if not isinstance(refs, list):
            return []
        resolved: list[UUID] = []
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            ref_type = str(
                ref.get("type")
                or ref.get("referenceType")
                or ref.get("resourceType")
                or ""
            ).lower()
            if ref_type not in {expected_type, f"{expected_type}_ref"}:
                continue
            value = ref.get("id") or ref.get("referenceId") or ref.get("resourceId")
            try:
                resolved.append(UUID(str(value)))
            except (TypeError, ValueError):
                continue
        return resolved

    def _verified_refs(
        self,
        refs: object,
        default_type: str,
        authoritative_reference_ids: set[str],
        unavailable: list[TimelineUnavailableReason],
        lifecycle_stage: TimelineLifecycleStage,
    ) -> list[dict[str, Any]]:
        if not isinstance(refs, list):
            return []
        safe: list[dict[str, Any]] = []
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            reference_id = (
                ref.get("id")
                or ref.get("referenceId")
                or ref.get("resourceId")
            )
            if reference_id is None:
                continue
            reference_type = str(
                ref.get("type")
                or ref.get("referenceType")
                or ref.get("resourceType")
                or default_type
            )
            reference_id = str(reference_id)
            available = reference_id in authoritative_reference_ids
            if not available:
                unavailable.append(
                    self._reason(
                        "REFERENCE_NOT_FOUND",
                        "domain_event_reference",
                        "timeline.unavailable.referenceNotFound",
                        lifecycle_stage=lifecycle_stage,
                        reference_type=reference_type,
                        reference_id=reference_id,
                    )
                )
            safe.append(
                self._ref(
                    reference_type,
                    reference_id,
                    str(ref.get("relationship") or default_type),
                    available=available,
                    visibility="redacted",
                    unavailable_reason=(
                        None if available else "REFERENCE_NOT_FOUND"
                    ),
                )
            )
        return safe

    def _domain_actor(
        self,
        actor: object,
    ) -> tuple[str, dict[str, Any]]:
        if not isinstance(actor, dict):
            return "system", self._ref("system", "domain-event-runtime", "actor")
        actor_type = str(
            actor.get("type") or actor.get("actorType") or "system"
        ).lower()
        actor_id = actor.get("id") or actor.get("actorId") or "domain-event-runtime"
        if actor_type not in {
            "human",
            "system",
            "service",
            "agent",
            "skill",
            "tool",
            "connector",
        }:
            actor_type = "system"
        return actor_type, self._ref(actor_type, actor_id, "actor", visibility="redacted")

    @staticmethod
    def _ceg_kind(
        event: DomainEventRecord,
        payload: dict[str, Any],
    ) -> str | None:
        candidate = str(
            payload.get("cegEventKind")
            or event.event_type.removeprefix("ceg.").split(".", 1)[0]
        ).lower()
        return candidate if candidate in CEG_EVENT_KINDS else None

    @staticmethod
    def _first_uuid(values: object) -> UUID | None:
        if not isinstance(values, list):
            return None
        for value in values:
            try:
                return UUID(str(value))
            except (TypeError, ValueError):
                continue
        return None

    @staticmethod
    def _uuid_or_none(value: object) -> UUID | None:
        try:
            return UUID(str(value))
        except (TypeError, ValueError):
            return None

    def _sort_key(self, event: _EventCandidate) -> str:
        return timeline_event_sort_key(
            event.payload["lifecycleStage"],
            event.occurred_at,
            event.source_sequence,
            event.payload["eventId"],
        )

    def _query_hash(self, query: TimelineQuery) -> str:
        return canonical_hash(
            {
                "executionId": str(query.executionId),
                "traceId": str(query.traceId) if query.traceId else None,
                "lifecycleStages": sorted(query.lifecycleStages),
                "eventTypes": sorted(query.eventTypes),
                "statuses": sorted(query.statuses),
                "actorTypes": sorted(query.actorTypes),
                "occurredAfter": (
                    self._aware(query.occurredAfter).isoformat()
                    if query.occurredAfter
                    else None
                ),
                "occurredBefore": (
                    self._aware(query.occurredBefore).isoformat()
                    if query.occurredBefore
                    else None
                ),
            }
        )

    def _resolve_snapshot(
        self,
        query: TimelineQuery,
        cursor_state: dict[str, Any] | None,
        generated_at: datetime,
    ) -> datetime:
        cursor_snapshot = None
        if cursor_state is not None:
            try:
                cursor_snapshot = self._aware(
                    datetime.fromisoformat(str(cursor_state["snapshotAt"]))
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise DecisionTimelineError(
                    "DECISION_TIMELINE_CURSOR_INVALID",
                    status_code=422,
                ) from exc
        explicit_snapshot = (
            self._aware(query.snapshotAt) if query.snapshotAt is not None else None
        )
        if (
            cursor_snapshot is not None
            and explicit_snapshot is not None
            and cursor_snapshot != explicit_snapshot
        ):
            raise DecisionTimelineError(
                "DECISION_TIMELINE_CURSOR_SNAPSHOT_MISMATCH",
                status_code=422,
            )
        snapshot = cursor_snapshot or explicit_snapshot or generated_at
        if snapshot > generated_at:
            raise DecisionTimelineError(
                "DECISION_TIMELINE_SNAPSHOT_IN_FUTURE",
                status_code=422,
            )
        return snapshot

    def _encode_cursor(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        # The non-secret prefix prevents the generic redactor from treating a
        # base64-encoded JSON cursor (which starts with ``eyJ``) as a JWT.
        encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return f"dt1.{encoded}"

    def _decode_cursor(self, cursor: str) -> dict[str, Any]:
        try:
            prefix, encoded = cursor.split(".", 1)
            if prefix != "dt1":
                raise ValueError("unsupported cursor prefix")
            padding = "=" * (-len(encoded) % 4)
            payload = json.loads(
                base64.urlsafe_b64decode((encoded + padding).encode("ascii"))
            )
        except Exception as exc:
            raise DecisionTimelineError(
                "DECISION_TIMELINE_CURSOR_INVALID",
                status_code=422,
            ) from exc
        if (
            not isinstance(payload, dict)
            or payload.get("version") != self.CURSOR_VERSION
            or not isinstance(payload.get("queryHash"), str)
            or not isinstance(payload.get("lastSortKey"), str)
        ):
            raise DecisionTimelineError(
                "DECISION_TIMELINE_CURSOR_INVALID",
                status_code=422,
            )
        return payload


__all__ = [
    "DecisionTimelineError",
    "DecisionTimelineProjectionService",
]

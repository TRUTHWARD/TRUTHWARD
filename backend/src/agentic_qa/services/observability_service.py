# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import ApprovalStatus, ApprovalType, GateResult, TaskStatus
from agentic_qa.domain.models import (
    AgentRun,
    Approval,
    AuditLog,
    ClarificationItem,
    CorrectionProposal,
    CorrectionRecord,
    DomainEventRecord,
    Execution,
    ExecutionArtifact,
    ExecutionLog,
    ExecutionMetric,
    ExecutionPlan,
    ExecutionTask,
    ExternalIssueLink,
    Finding,
    GateDecision,
    GuardrailEvent,
    Memory,
    Model,
    ModelInvocation,
    OrchestrationCheckpoint,
    OrchestrationRun,
    RawFindingRecord,
    ReplayExportRecord,
    RequirementVersion,
    Skill,
    SkillInvocation,
    SkillVersion,
    TestPlan,
    TestAsset,
    TestAssetReview,
    Trace,
    TraceSpan,
    TriageResult,
    VerificationResult,
    VisualGroundingAttempt,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.artifact_storage import (
    ArtifactStorageAdapter,
    artifact_storage_adapter,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.infra.safe_projection import ConnectorBindingSafeProjectionBuilder
from agentic_qa.runtime.qa_harness.context_builder import validate_context_envelope
from agentic_qa.schemas.contracts import ContractValidationError, validate_contract
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result
from agentic_qa.services.correction_governance_service import CorrectionGovernanceService
from agentic_qa.services.traceability_service import TraceabilityService


class AuditRetentionConflictError(ValueError):
    """Raised when an audit retention action violates retention state."""


class ReplayExportIntegrityError(ValueError):
    """Raised when an imported or persisted Replay Export fails hash validation."""


class ObservabilityService:
    REPLAY_EXPORT_INLINE_MAX_BYTES = 64 * 1024 * 1024
    REPLAY_EXPORT_PROJECTION_KEYS = (
        "schemaVersion",
        "exportedAt",
        "requestId",
        "executionId",
        "traceRefs",
        "storageRef",
        "exportArtifactRef",
        "exportHash",
        "exportPayloadHash",
        "redactionStatus",
        "auditRefs",
        "traceabilitySnapshotRef",
        "traceabilitySnapshotHash",
        "requirementScope",
        "coverageSummarySnapshot",
        "coverageMatrixSnapshotRef",
        "graphCoverageSnapshot",
    )

    def __init__(
        self,
        db: Session,
        *,
        artifact_storage: ArtifactStorageAdapter | None = None,
    ) -> None:
        self.db = db
        self._artifact_storage = artifact_storage
        self.connector_snapshot_builder = ConnectorBindingSafeProjectionBuilder()

    def list_traces(self, page: int, page_size: int, execution_id: str | None = None) -> dict[str, object]:
        statement = select(Trace).order_by(Trace.created_at.desc())
        if execution_id:
            statement = statement.where(Trace.execution_id == UUID(str(execution_id)))
        traces, total = paginate_query(self.db, statement, page, page_size)
        trace_counts = self._build_trace_counts([trace.id for trace in traces])
        items = [self.serialize_trace_summary(trace, trace_counts) for trace in traces]
        return paginate_result(items, total, page, page_size)

    def get_trace(self, trace_id: UUID) -> dict[str, object]:
        trace = self._require_trace(trace_id)
        # A trace detail view is assembled from every table that can contribute
        # evidence to one decision path.
        spans = list(
            self.db.scalars(
                select(TraceSpan)
                .where(TraceSpan.trace_id == trace.id)
                .order_by(TraceSpan.start_time.asc(), TraceSpan.created_at.asc())
            )
        )
        invocations = list(
            self.db.scalars(
                select(ModelInvocation)
                .where(ModelInvocation.trace_id == trace.id)
                .order_by(ModelInvocation.created_at.asc())
            )
        )
        agent_runs = list(
            self.db.scalars(
                select(AgentRun)
                .where(AgentRun.trace_id == trace.id)
                .order_by(AgentRun.created_at.asc())
            )
        )
        audit_logs = list(
            self.db.scalars(
                select(AuditLog)
                .where(AuditLog.trace_id == trace.id)
                .order_by(AuditLog.created_at.asc())
            )
        )
        guardrail_events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.trace_id == trace.id)
                .order_by(GuardrailEvent.created_at.asc())
            )
        )
        skill_invocations = list(
            self.db.scalars(
                select(SkillInvocation)
                .where(SkillInvocation.trace_id == trace.id)
                .order_by(SkillInvocation.created_at.asc())
            )
        )
        model_lookup = self._load_models([invocation.model_id for invocation in invocations])
        return {
            **self.serialize_trace_summary(
                trace,
                {
                    trace.id: {
                        "spanCount": len(spans),
                        "modelInvocationCount": len(invocations),
                        "agentRunCount": len(agent_runs),
                        "skillInvocationCount": len(skill_invocations),
                        "auditLogCount": len(audit_logs),
                        "guardrailEventCount": len(guardrail_events),
                    }
                },
            ),
            "spans": [self.serialize_span(span) for span in spans],
            "modelInvocations": [self.serialize_model_invocation(invocation, model_lookup) for invocation in invocations],
            "agentRuns": [self.serialize_agent_run(agent_run) for agent_run in agent_runs],
            "skillInvocations": [self.serialize_skill_invocation(invocation) for invocation in skill_invocations],
            "auditLogs": [self.serialize_audit_log(audit_log) for audit_log in audit_logs],
            "guardrailEvents": [self.serialize_guardrail_event(event) for event in guardrail_events],
            "decisionPath": self._build_decision_path(spans, invocations, agent_runs, skill_invocations, guardrail_events),
        }

    def replay_execution(
        self,
        execution_id: UUID,
        *,
        exclude_audit_actions: set[str] | None = None,
        compact: bool = False,
    ) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        if compact:
            return self._compact_replay_execution(
                execution,
                exclude_audit_actions=exclude_audit_actions,
            )
        plan = self.db.get(TestPlan, execution.plan_id)
        requirement_scope = dict(plan.requirement_scope) if plan and plan.requirement_scope else None
        requirement_version = self.db.get(RequirementVersion, plan.requirement_version_id) if plan and plan.requirement_version_id else None
        clarifications: list[ClarificationItem] = []
        test_assets: list[TestAsset] = []
        asset_reviews: list[TestAssetReview] = []
        corrections: list[CorrectionRecord] = []
        correction_governance_proposals: list[CorrectionProposal] = []
        domain_events: list[DomainEventRecord] = []
        execution_plan = self.db.get(ExecutionPlan, execution.execution_plan_id) if execution.execution_plan_id else None
        if requirement_version is not None:
            clarifications = list(
                self.db.scalars(
                    select(ClarificationItem)
                    .where(ClarificationItem.requirement_version_id == requirement_version.id)
                    .order_by(ClarificationItem.created_at.asc())
                )
            )
            test_assets = list(
                self.db.scalars(
                    select(TestAsset)
                    .where(TestAsset.requirement_version_id == requirement_version.id, TestAsset.test_plan_id == execution.plan_id)
                    .order_by(TestAsset.created_at.asc())
                )
            )
            asset_reviews = list(
                self.db.scalars(
                    select(TestAssetReview)
                    .where(TestAssetReview.requirement_version_id == requirement_version.id, TestAssetReview.test_plan_id == execution.plan_id)
                    .order_by(TestAssetReview.created_at.asc())
                )
            )
            corrections = list(
                self.db.scalars(
                    select(CorrectionRecord)
                    .where(CorrectionRecord.requirement_version_id == requirement_version.id)
                    .order_by(CorrectionRecord.created_at.asc())
                )
            )
            correction_governance_proposals.extend(
                list(
                    self.db.scalars(
                        select(CorrectionProposal)
                        .where(CorrectionProposal.requirement_version_id == requirement_version.id)
                        .order_by(CorrectionProposal.created_at.asc())
                    )
                )
            )
        execution_scoped_correction_governance = list(
            self.db.scalars(
                select(CorrectionProposal)
                .where(CorrectionProposal.execution_id == execution.id)
                .order_by(CorrectionProposal.created_at.asc())
            )
        )
        seen_correction_governance_ids = {proposal.id for proposal in correction_governance_proposals}
        for proposal in execution_scoped_correction_governance:
            if proposal.id not in seen_correction_governance_ids:
                correction_governance_proposals.append(proposal)
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
        all_domain_events = list(self.db.scalars(select(DomainEventRecord).order_by(DomainEventRecord.occurred_at.asc())))
        for event in all_domain_events:
            if str(event.correlation_refs.get("executionId")) == str(execution.id):
                domain_events.append(event)
            elif requirement_version and str(event.correlation_refs.get("requirementVersionId")) == str(requirement_version.id):
                domain_events.append(event)
        # Replay is execution-centric: return both execution-owned records and
        # the trace-scoped events needed to rebuild the timeline in one call.
        traces = list(
            self.db.scalars(
                select(Trace)
                .where(Trace.execution_id == execution.id)
                .order_by(Trace.created_at.asc())
            )
        )
        trace_ids = [trace.id for trace in traces]

        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution.id)
                .order_by(ExecutionTask.created_at.asc())
            )
        )
        artifacts = list(
            self.db.scalars(
                select(ExecutionArtifact)
                .where(ExecutionArtifact.execution_id == execution.id)
                .order_by(ExecutionArtifact.created_at.asc())
            )
        )
        metrics = list(
            self.db.scalars(
                select(ExecutionMetric)
                .where(ExecutionMetric.execution_id == execution.id)
                .order_by(ExecutionMetric.created_at.asc())
            )
        )
        visual_grounding_attempts = list(
            self.db.scalars(
                select(VisualGroundingAttempt)
                .where(VisualGroundingAttempt.execution_id == execution.id)
                .order_by(VisualGroundingAttempt.created_at.asc())
            )
        )
        verification_results = list(
            self.db.scalars(
                select(VerificationResult)
                .where(VerificationResult.execution_id == execution.id)
                .order_by(VerificationResult.created_at.asc())
            )
        )
        findings = list(
            self.db.scalars(
                select(Finding)
                .where(Finding.execution_id == execution.id)
                .order_by(
                    Finding.created_at.asc(),
                    Finding.id.asc(),
                )
            )
        )
        external_issue_links_by_finding = self._latest_external_issue_links_for_execution(
            execution.id
        )
        approvals = list(
            self.db.scalars(
                select(Approval)
                .where(
                    self._approval_resource_filter(
                        execution.id,
                        execution_plan.id if execution_plan is not None else None,
                    )
                )
                .order_by(Approval.created_at.asc())
            )
        )
        gate = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id))
        model_invocations = list(
            self.db.scalars(
                select(ModelInvocation)
                .where(ModelInvocation.execution_id == execution.id)
                .order_by(ModelInvocation.created_at.asc())
            )
        )
        agent_runs = list(
            self.db.scalars(
                select(AgentRun)
                .where(AgentRun.execution_id == execution.id)
                .order_by(AgentRun.created_at.asc())
            )
        )
        skill_invocations = list(
            self.db.scalars(
                select(SkillInvocation)
                .where(SkillInvocation.execution_id == execution.id)
                .order_by(SkillInvocation.created_at.asc())
            )
        )
        audit_logs: list[AuditLog] = []
        if trace_ids:
            audit_statement = select(AuditLog).where(AuditLog.trace_id.in_(trace_ids))
            if exclude_audit_actions:
                audit_statement = audit_statement.where(
                    ~AuditLog.action.in_(exclude_audit_actions)
                )
            audit_logs = list(
                self.db.scalars(audit_statement.order_by(AuditLog.created_at.asc()))
            )
        guardrail_events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.execution_id == execution.id)
                .order_by(GuardrailEvent.created_at.asc())
            )
        )
        spans: list[TraceSpan] = []
        if trace_ids:
            spans = list(
                self.db.scalars(
                    select(TraceSpan)
                    .where(TraceSpan.trace_id.in_(trace_ids))
                    .order_by(TraceSpan.start_time.asc(), TraceSpan.created_at.asc())
                )
            )
        trace_counts = self._build_trace_counts(
            trace_ids,
            exclude_audit_actions=exclude_audit_actions,
        )
        orchestrator_run = self.db.scalar(
            select(OrchestrationRun)
            .where(OrchestrationRun.linked_execution_id == execution.id)
            .order_by(OrchestrationRun.created_at.desc())
        )
        orchestrator_checkpoints: list[OrchestrationCheckpoint] = []
        if orchestrator_run is not None:
            orchestrator_checkpoints = list(
                self.db.scalars(
                    select(OrchestrationCheckpoint)
                    .where(OrchestrationCheckpoint.run_id == orchestrator_run.id)
                    .order_by(OrchestrationCheckpoint.sequence_no.asc(), OrchestrationCheckpoint.created_at.asc())
                )
            )
        return {
            "executionId": str(execution.id),
            "status": execution.status.value,
            "stage": execution.stage.value,
            "environment": execution.environment,
            "requirementScope": requirement_scope,
            "requirementVersion": self.serialize_requirement_version(requirement_version) if requirement_version else None,
            "clarifications": [self.serialize_clarification(item) for item in clarifications],
            "testAssets": [self.serialize_test_asset(item) for item in test_assets],
            "assetReviews": [self.serialize_asset_review(item) for item in asset_reviews],
            "executionPlan": self.serialize_execution_plan(execution_plan) if execution_plan else None,
            "startedAt": execution.started_at.isoformat() if execution.started_at else None,
            "endedAt": execution.ended_at.isoformat() if execution.ended_at else None,
            "traceCount": len(traces),
            "traces": [self.serialize_trace_summary(trace, trace_counts) for trace in traces],
            "tasks": [self.serialize_task(task) for task in tasks],
            "artifacts": [self.serialize_artifact(artifact) for artifact in artifacts],
            "metrics": [self.serialize_metric(metric) for metric in metrics],
            "visualGroundingAttempts": [self.serialize_visual_grounding_attempt(attempt) for attempt in visual_grounding_attempts],
            "verificationResults": [self.serialize_verification_result(result) for result in verification_results],
            "findings": [
                self._serialize_finding(
                    finding,
                    external_issue_links_by_finding.get(finding.id),
                )
                for finding in findings
            ],
            "rawFindings": [self.serialize_raw_finding(finding) for finding in raw_findings],
            "correctionRecords": [self.serialize_correction(item) for item in corrections],
            "corrections": [self.serialize_correction(item) for item in corrections],
            "correctionGovernance": [
                CorrectionGovernanceService(self.db).serialize_proposal_detail(item) for item in correction_governance_proposals
            ],
            "domainEvents": [self.serialize_domain_event(item) for item in domain_events],
            "approvals": [self.serialize_approval(item) for item in approvals],
            "gate": self.serialize_gate(gate) if gate else None,
            "skillInvocations": [self.serialize_skill_invocation(invocation) for invocation in skill_invocations],
            "guardrailEvents": [self.serialize_guardrail_event(event) for event in guardrail_events],
            "orchestrator": self.serialize_orchestration(orchestrator_run, orchestrator_checkpoints) if orchestrator_run else None,
            "timeline": self._build_timeline(
                spans,
                model_invocations,
                agent_runs,
                skill_invocations,
                audit_logs,
                guardrail_events,
                orchestrator_checkpoints,
                visual_grounding_attempts,
                verification_results,
            ),
        }

    def _compact_replay_execution(
        self,
        execution: Execution,
        *,
        exclude_audit_actions: set[str] | None = None,
    ) -> dict[str, object]:
        """Build the read-only Replay Center projection without frozen payloads.

        The complete replay remains the authority for export and reconstruction.
        This projection intentionally contains only the fields consumed by the
        Replay Center so opening the page does not deserialize multi-megabyte
        snapshots or run export integrity work.
        """
        plan = self.db.get(TestPlan, execution.plan_id)
        requirement_version_id = plan.requirement_version_id if plan else None
        traces = list(
            self.db.scalars(
                select(Trace)
                .where(Trace.execution_id == execution.id)
                .order_by(Trace.created_at.asc())
            )
        )
        trace_ids = [trace.id for trace in traces]
        findings = list(
            self.db.scalars(
                select(Finding)
                .where(Finding.execution_id == execution.id)
                .order_by(Finding.created_at.asc(), Finding.id.asc())
            )
        )
        external_issue_links_by_finding = self._latest_external_issue_links_for_execution(
            execution.id
        )
        gate = self.db.scalar(
            select(GateDecision).where(GateDecision.execution_id == execution.id)
        )

        correction_filter = CorrectionProposal.execution_id == execution.id
        if requirement_version_id is not None:
            correction_filter = or_(
                correction_filter,
                CorrectionProposal.requirement_version_id == requirement_version_id,
            )
        correction_ids = list(
            self.db.scalars(
                select(CorrectionProposal.id)
                .where(correction_filter)
                .order_by(CorrectionProposal.created_at.asc())
            )
        )
        model_invocations = list(
            self.db.scalars(
                select(ModelInvocation)
                .where(ModelInvocation.execution_id == execution.id)
                .order_by(ModelInvocation.created_at.asc())
            )
        )
        agent_runs = list(
            self.db.scalars(
                select(AgentRun)
                .where(AgentRun.execution_id == execution.id)
                .order_by(AgentRun.created_at.asc())
            )
        )
        skill_invocations = list(
            self.db.scalars(
                select(SkillInvocation)
                .where(SkillInvocation.execution_id == execution.id)
                .order_by(SkillInvocation.created_at.asc())
            )
        )
        skill_metadata = self._load_skill_metadata(skill_invocations)
        guardrail_events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.execution_id == execution.id)
                .order_by(GuardrailEvent.created_at.asc())
            )
        )
        visual_grounding_attempts = list(
            self.db.scalars(
                select(VisualGroundingAttempt)
                .where(VisualGroundingAttempt.execution_id == execution.id)
                .order_by(VisualGroundingAttempt.created_at.asc())
            )
        )
        verification_results = list(
            self.db.scalars(
                select(VerificationResult)
                .where(VerificationResult.execution_id == execution.id)
                .order_by(VerificationResult.created_at.asc())
            )
        )

        spans: list[TraceSpan] = []
        audit_logs: list[AuditLog] = []
        if trace_ids:
            spans = list(
                self.db.scalars(
                    select(TraceSpan)
                    .where(TraceSpan.trace_id.in_(trace_ids))
                    .order_by(TraceSpan.start_time.asc(), TraceSpan.created_at.asc())
                )
            )
            audit_statement = select(AuditLog).where(AuditLog.trace_id.in_(trace_ids))
            if exclude_audit_actions:
                audit_statement = audit_statement.where(
                    ~AuditLog.action.in_(exclude_audit_actions)
                )
            audit_logs = list(
                self.db.scalars(audit_statement.order_by(AuditLog.created_at.asc()))
            )

        orchestrator_run = self.db.scalar(
            select(OrchestrationRun)
            .where(OrchestrationRun.linked_execution_id == execution.id)
            .order_by(OrchestrationRun.created_at.desc())
        )
        orchestrator_checkpoints: list[OrchestrationCheckpoint] = []
        if orchestrator_run is not None:
            orchestrator_checkpoints = list(
                self.db.scalars(
                    select(OrchestrationCheckpoint)
                    .where(OrchestrationCheckpoint.run_id == orchestrator_run.id)
                    .order_by(
                        OrchestrationCheckpoint.sequence_no.asc(),
                        OrchestrationCheckpoint.created_at.asc(),
                    )
                )
            )

        projection = {
            "executionId": str(execution.id),
            "status": execution.status.value,
            "stage": execution.stage.value,
            "environment": execution.environment,
            "traceCount": len(traces),
            "timeline": self._build_timeline(
                spans,
                model_invocations,
                agent_runs,
                skill_invocations,
                audit_logs,
                guardrail_events,
                orchestrator_checkpoints,
                visual_grounding_attempts,
                verification_results,
                compact=True,
                skill_metadata=skill_metadata,
            ),
            "findings": [
                self._serialize_finding(
                    finding,
                    external_issue_links_by_finding.get(finding.id),
                )
                for finding in findings
            ],
            "rawFindings": [],
            "metrics": [],
            "correctionRecords": [],
            "correctionGovernance": [
                {"correctionProposalId": str(correction_id)}
                for correction_id in correction_ids
            ],
            "skillInvocations": [
                {"id": str(invocation.id)} for invocation in skill_invocations
            ],
            "visualGroundingAttempts": [],
            "verificationResults": [],
            "guardrailEvents": [
                {"id": str(event.id)} for event in guardrail_events
            ],
            "gate": self.serialize_gate(gate) if gate else None,
            "orchestrator": (
                {
                    "checkpointCount": len(orchestrator_checkpoints),
                    "status": orchestrator_run.status.value,
                }
                if orchestrator_run is not None
                else None
            ),
        }
        return redact_sensitive_data(projection)

    def export_execution_replay(
        self,
        execution_id: UUID,
        request_id: str | None = None,
        actor_id: UUID | None = None,
        *,
        persist: bool = True,
    ) -> dict[str, object]:
        replay = redact_sensitive_data(
            self.replay_execution(
                execution_id,
                exclude_audit_actions={"replay_export.persist"},
            )
        )
        traceability_snapshot = self._traceability_snapshot_for_execution(execution_id)
        from agentic_qa.services.graph_coverage_service import GraphCoverageService

        graph_coverage_snapshot = GraphCoverageService(self.db).replay_snapshot_for_execution(
            execution_id
        )
        trace_refs = [str(item["id"]) for item in replay["traces"]]
        trace_ids = [UUID(trace_id) for trace_id in trace_refs]
        # Preserve the established source replay payload hash contract. The
        # frozen coverage snapshot participates in the full exportHash and
        # repository section hash, while exportPayloadHash remains replay-only
        # for backward compatibility.
        export_payload_hash = self._hash_payload({"replay": replay})
        existing = self._replay_export_by_payload_hash(execution_id, export_payload_hash) if persist else None
        if existing is not None:
            return self.serialize_replay_export_record(existing)
        audit_logs: list[AuditLog] = []
        if trace_ids:
            audit_logs = list(
                self.db.scalars(
                    select(AuditLog)
                    .where(AuditLog.trace_id.in_(trace_ids))
                    .order_by(AuditLog.created_at.asc())
                )
            )
        redacted_audit_logs = redact_sensitive_data([self.serialize_audit_log(audit_log) for audit_log in audit_logs])
        redacted_payload = {
            "replay": replay,
            "auditLogs": redacted_audit_logs,
            "traceabilitySnapshot": traceability_snapshot,
            "graphCoverageSnapshot": graph_coverage_snapshot,
        }
        export_id = f"replay_export_{export_payload_hash.removeprefix('sha256:')[:24]}"
        audit_refs: list[dict[str, object]] = []
        if persist:
            audit_trace_id = trace_ids[0] if trace_ids else uuid4()
            audit = write_audit_log(
                self.db,
                str(actor_id) if actor_id else None,
                "replay_export.persist",
                "replay_export",
                export_id,
                request_id,
                audit_trace_id,
                {"executionId": str(execution_id), "exportPayloadHash": export_payload_hash},
                execution_id=execution_id,
            )
            self.db.flush()
            audit_refs.append({"type": "audit_log", "id": str(audit.id), "action": audit.action})
        payload = {
            "schemaVersion": "phase8.replay-export.v1",
            "exportedAt": datetime.now(timezone.utc).isoformat(),
            "requestId": request_id or "",
            "executionId": str(execution_id),
            "traceRefs": trace_refs,
            "storageRef": None,
            "exportArtifactRef": None,
            "exportPayloadHash": export_payload_hash,
            "redactionStatus": self._redaction_status(redacted_payload),
            "auditRefs": audit_refs,
            "traceabilitySnapshotRef": traceability_snapshot["traceabilitySnapshotRef"] if traceability_snapshot else None,
            "traceabilitySnapshotHash": traceability_snapshot["traceabilitySnapshotHash"] if traceability_snapshot else None,
            "requirementScope": traceability_snapshot["requirementScope"] if traceability_snapshot else None,
            "coverageSummarySnapshot": traceability_snapshot["coverageSummarySnapshot"] if traceability_snapshot else None,
            "coverageMatrixSnapshotRef": traceability_snapshot["coverageMatrixSnapshotRef"] if traceability_snapshot else None,
            "graphCoverageSnapshot": graph_coverage_snapshot,
            "replay": replay,
            "auditLogs": redacted_audit_logs,
        }
        export = {
            **payload,
            "exportHash": self._hash_payload(payload),
        }
        validated = self.verify_replay_export_payload(export)
        if persist:
            return self._persist_replay_export(validated, actor_id=actor_id)
        return validated

    def list_replay_exports(
        self,
        *,
        page: int,
        page_size: int,
        execution_id: UUID | None = None,
    ) -> dict[str, object]:
        statement = select(ReplayExportRecord).order_by(ReplayExportRecord.created_at.desc())
        if execution_id is not None:
            statement = statement.where(ReplayExportRecord.execution_id == execution_id)
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result([self.serialize_replay_export_record(row, include_payload=False) for row in rows], total, page, page_size)

    def get_replay_export(self, export_id: str) -> dict[str, object]:
        record = self.db.scalar(select(ReplayExportRecord).where(ReplayExportRecord.export_id == export_id))
        if record is None:
            raise ValueError("replay export not found")
        return self.serialize_replay_export_record(record)

    def serialize_replay_export_record(self, record: ReplayExportRecord, *, include_payload: bool = True) -> dict[str, object]:
        stored_payload = dict(record.payload or {})
        if stored_payload.get("storageMode") == "external":
            payload = self._serialize_external_replay_export(
                record,
                stored_payload,
                include_payload=include_payload,
            )
        else:
            payload = self.verify_replay_export_payload(stored_payload)
            self._verify_replay_export_record_metadata(record, payload)
            if not include_payload:
                payload = self._replay_export_projection(payload)
        return {
            **payload,
            "exportId": record.export_id,
            "persistedAt": record.created_at.isoformat(),
            "createdBy": str(record.created_by) if record.created_by else None,
        }

    def _serialize_external_replay_export(
        self,
        record: ReplayExportRecord,
        manifest: dict[str, object],
        *,
        include_payload: bool,
    ) -> dict[str, object]:
        (
            projection,
            storage_ref,
            expected_byte_size,
            expected_content_hash,
        ) = self._verify_replay_export_storage_manifest(record, manifest)
        if not include_payload:
            return projection
        try:
            encoded_payload = self._artifact_storage_adapter().read_artifact(storage_ref)
        except (FileNotFoundError, OSError, ValueError) as exc:
            raise ReplayExportIntegrityError("replay export storage payload is unavailable") from exc
        if len(encoded_payload) != expected_byte_size:
            raise ReplayExportIntegrityError("replay export storage byte size mismatch")
        content_hash = "sha256:" + hashlib.sha256(encoded_payload).hexdigest()
        if content_hash != expected_content_hash:
            raise ReplayExportIntegrityError("replay export storage hash mismatch")
        try:
            decoded = json.loads(encoded_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReplayExportIntegrityError("replay export storage payload is invalid") from exc
        if not isinstance(decoded, dict):
            raise ReplayExportIntegrityError("replay export storage payload must be an object")
        payload = self.verify_replay_export_payload(decoded)
        self._verify_replay_export_record_metadata(record, payload)
        if self._replay_export_projection(payload) != projection:
            raise ReplayExportIntegrityError("replay export storage projection mismatch")
        return payload

    def _verify_replay_export_storage_manifest(
        self,
        record: ReplayExportRecord,
        manifest: dict[str, object],
    ) -> tuple[dict[str, object], str, int, str]:
        byte_size = manifest.get("byteSize")
        content_hash = manifest.get("contentHash")
        storage_ref = manifest.get("storageRef")
        projection_value = manifest.get("projection")
        if (
            manifest.get("schemaVersion") != "phase8.replay-export-storage-manifest.v1"
            or manifest.get("storageMode") != "external"
            or manifest.get("contentSchemaVersion") != record.schema_version
            or not isinstance(storage_ref, str)
            or storage_ref != record.storage_ref
            or not isinstance(content_hash, str)
            or not isinstance(byte_size, int)
            or byte_size < 1
            or not isinstance(projection_value, dict)
        ):
            raise ReplayExportIntegrityError("persisted replay export storage manifest is invalid")
        projection = dict(projection_value)
        projection_hash = self._hash_payload(projection)
        if projection_hash != manifest.get("projectionHash"):
            raise ReplayExportIntegrityError("replay export storage projection hash mismatch")
        self._verify_replay_export_record_metadata(record, projection)
        return projection, storage_ref, byte_size, content_hash

    @staticmethod
    def _verify_replay_export_record_metadata(
        record: ReplayExportRecord,
        payload: dict[str, object],
    ) -> None:
        trace_refs = payload.get("traceRefs")
        audit_refs = payload.get("auditRefs")
        if not isinstance(trace_refs, list) or not isinstance(audit_refs, list):
            raise ReplayExportIntegrityError("persisted replay export refs are invalid")
        if (
            record.schema_version != payload["schemaVersion"]
            or record.export_hash != payload["exportHash"]
            or record.export_payload_hash != payload["exportPayloadHash"]
            or str(record.execution_id) != payload["executionId"]
            or record.redaction_status != payload["redactionStatus"]
            or list(record.trace_refs or []) != trace_refs
            or list(record.audit_refs or []) != audit_refs
        ):
            raise ReplayExportIntegrityError("persisted replay export metadata does not match its frozen payload")

    @classmethod
    def _replay_export_projection(cls, payload: dict[str, object]) -> dict[str, object]:
        return {key: payload.get(key) for key in cls.REPLAY_EXPORT_PROJECTION_KEYS}

    def _persist_replay_export(self, export: dict[str, object], *, actor_id: UUID | None) -> dict[str, object]:
        execution_id = UUID(str(export["executionId"]))
        existing = self._replay_export_by_payload_hash(execution_id, str(export["exportPayloadHash"]))
        if existing is not None:
            return self.serialize_replay_export_record(existing)
        export_id = f"replay_export_{str(export['exportPayloadHash']).removeprefix('sha256:')[:24]}"
        record_id = uuid4()
        encoded_export = json.dumps(
            export,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        stored_payload = dict(export)
        external_storage_ref: str | None = None
        if len(encoded_export) > self.REPLAY_EXPORT_INLINE_MAX_BYTES:
            storage_adapter = self._artifact_storage_adapter()
            storage = storage_adapter.write_artifact(
                namespace="replay-exports",
                artifact_id=str(record_id),
                filename="payload.json",
                payload=encoded_export,
            )
            content_hash = "sha256:" + hashlib.sha256(encoded_export).hexdigest()
            if storage["contentHash"] != content_hash:
                storage_adapter.delete_artifact(str(storage["storageRef"]))
                raise ReplayExportIntegrityError("replay export storage hash mismatch")
            storage_byte_size = storage.get("byteSize")
            if not isinstance(storage_byte_size, int):
                storage_adapter.delete_artifact(str(storage["storageRef"]))
                raise ReplayExportIntegrityError("replay export storage byte size is invalid")
            external_storage_ref = str(storage["storageRef"])
            projection = self._replay_export_projection(export)
            stored_payload = {
                "schemaVersion": "phase8.replay-export-storage-manifest.v1",
                "storageMode": "external",
                "storageRef": external_storage_ref,
                "contentHash": content_hash,
                "byteSize": storage_byte_size,
                "storageAdapter": str(storage["adapter"]),
                "contentSchemaVersion": str(export["schemaVersion"]),
                "projectionHash": self._hash_payload(projection),
                "projection": projection,
            }
        record = ReplayExportRecord(
            id=record_id,
            export_id=export_id,
            execution_id=execution_id,
            schema_version=str(export["schemaVersion"]),
            export_hash=str(export["exportHash"]),
            export_payload_hash=str(export["exportPayloadHash"]),
            storage_ref=external_storage_ref or export.get("storageRef"),
            export_artifact_ref=export.get("exportArtifactRef"),
            redaction_status=str(export["redactionStatus"]),
            trace_refs=[str(item) for item in export.get("traceRefs", [])],
            audit_refs=list(export.get("auditRefs", [])),
            payload=stored_payload,
            request_id=str(export.get("requestId") or "") or None,
            created_by=actor_id,
        )
        committed = False
        try:
            self.db.add(record)
            self.db.flush()
            self.db.commit()
            committed = True
            self.db.refresh(record)
        except Exception:
            if external_storage_ref is not None and not committed:
                self._artifact_storage_adapter().delete_artifact(external_storage_ref)
            raise
        return self.serialize_replay_export_record(record)

    def _artifact_storage_adapter(self) -> ArtifactStorageAdapter:
        if self._artifact_storage is None:
            self._artifact_storage = artifact_storage_adapter()
        return self._artifact_storage

    @classmethod
    def verify_replay_export_payload(cls, payload: dict[str, object]) -> dict[str, object]:
        try:
            validated = validate_contract("replay-export", dict(payload))
        except (ContractValidationError, TypeError, ValueError) as exc:
            raise ReplayExportIntegrityError("replay export contract validation failed") from exc
        expected_payload_hash = cls._hash_payload({"replay": validated["replay"]})
        if validated["exportPayloadHash"] != expected_payload_hash:
            raise ReplayExportIntegrityError("replay export payload hash mismatch")
        hash_input = {
            key: value
            for key, value in validated.items()
            if key != "exportHash"
        }
        expected_export_hash = cls._hash_payload(hash_input)
        if validated["exportHash"] != expected_export_hash:
            raise ReplayExportIntegrityError("replay export hash mismatch")
        replay = validated.get("replay")
        invocations = replay.get("skillInvocations") if isinstance(replay, dict) else None
        for item in invocations if isinstance(invocations, list) else []:
            if not isinstance(item, dict):
                continue
            input_snapshot = item.get("inputSnapshot")
            envelope = (
                input_snapshot.get("authorizedContextEnvelope")
                if isinstance(input_snapshot, dict)
                else None
            )
            if envelope is None:
                continue  # Historical Replay before the authorized-context contract.
            try:
                verified_envelope = validate_context_envelope(envelope)
            except (TypeError, ValueError) as exc:
                raise ReplayExportIntegrityError(
                    "Skill Context Envelope integrity check failed"
                ) from exc
            expected_context_hash = verified_envelope["envelopeHash"]
            resolution = item.get("resolutionSnapshot")
            policy = item.get("policySnapshot")
            resolution_summary = (
                resolution.get("authorizedContext") if isinstance(resolution, dict) else None
            )
            policy_summary = policy.get("authorizedContext") if isinstance(policy, dict) else None
            if policy_summary is None and isinstance(policy, dict):
                policy_resolution = policy.get("resolution")
                policy_summary = (
                    policy_resolution.get("authorizedContext")
                    if isinstance(policy_resolution, dict)
                    else None
                )
            if (
                not isinstance(resolution_summary, dict)
                or resolution_summary.get("envelopeHash") != expected_context_hash
                or not isinstance(policy_summary, dict)
                or policy_summary.get("envelopeHash") != expected_context_hash
            ):
                raise ReplayExportIntegrityError(
                    "Skill Context Envelope integrity summary mismatch"
                )
        return validated

    def _replay_export_by_payload_hash(self, execution_id: UUID, export_payload_hash: str) -> ReplayExportRecord | None:
        return self.db.scalar(
            select(ReplayExportRecord)
            .where(ReplayExportRecord.execution_id == execution_id)
            .where(ReplayExportRecord.export_payload_hash == export_payload_hash)
        )

    def _traceability_snapshot_for_execution(self, execution_id: UUID) -> dict[str, object] | None:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            return None
        plan = self.db.get(TestPlan, execution.plan_id)
        if plan is None or plan.requirement_version_id is None:
            return None
        try:
            return TraceabilityService(self.db).freeze_traceability_snapshot(
                plan.requirement_version_id,
                requirement_scope=plan.requirement_scope,
            )
        except ValueError:
            return None

    def minimum_observability_metrics(self, execution_id: UUID | None = None) -> dict[str, object]:
        statement = select(Execution)
        if execution_id is not None:
            statement = statement.where(Execution.id == execution_id)
        executions = list(self.db.scalars(statement.order_by(Execution.created_at.asc())))
        return {
            "metrics": [
                self._coverage_rate_metric(executions),
                self._execution_success_rate_metric(executions),
                self._replay_success_rate_metric(executions),
            ],
            "statusValues": ["available", "pending", "not_applicable"],
        }

    def observability_metrics(self, execution_id: UUID | None = None) -> dict[str, object]:
        executions = self._scoped_executions(execution_id)
        metrics = [
            self._coverage_rate_metric(executions),
            self._execution_success_rate_metric(executions),
            self._replay_success_rate_metric(executions),
            self._task_success_rate_metric(executions),
            self._agent_success_rate_metric(execution_id),
            self._skill_success_rate_metric(execution_id),
            self._model_success_rate_metric(execution_id),
            self._model_latency_metric(execution_id),
            self._model_cost_metric(execution_id),
            self._cost_per_execution_metric(executions, execution_id),
            self._evidence_link_rate_metric(execution_id),
            self._gate_pass_rate_metric(execution_id),
            self._review_pending_metric(execution_id),
            self._review_approved_metric(execution_id),
            self._review_rejected_metric(execution_id),
            self._memory_hit_rate_metric(),
            self._judge_disagreement_rate_metric(execution_id),
            self._empty_response_rate_metric(execution_id),
            self._agent_loop_rate_metric(execution_id),
            self._hallucination_rate_metric(execution_id),
        ]
        return {
            "scope": {"executionId": str(execution_id) if execution_id else None},
            "metrics": metrics,
            "statusValues": ["available", "pending", "not_applicable"],
        }

    def list_structured_logs(
        self,
        *,
        page: int,
        page_size: int,
        execution_id: UUID | None = None,
        trace_id: UUID | None = None,
        level: str | None = None,
        component: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> dict[str, object]:
        items = self._collect_structured_log_items(
            execution_id=execution_id,
            trace_id=trace_id,
            level=level,
            component=component,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        paged_items = redact_sensitive_data(items[(page - 1) * page_size : page * page_size])
        source_counts = Counter(str(item.get("source") or "unknown") for item in items)
        level_counts = Counter(str(item.get("level") or "unknown") for item in items)
        component_counts = Counter(str(item.get("component") or "unknown") for item in items)
        service_counts = Counter(str(item.get("service") or "unknown") for item in items)
        resource_counts = Counter(str(item.get("resourceType") or "unscoped") for item in items)
        trace_refs = sorted({str(item["traceId"]) for item in items if item.get("traceId")})
        execution_refs = sorted({str(item["executionId"]) for item in items if item.get("executionId")})
        payload = {
            "schemaVersion": "phase8.structured-log-projection.v1",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "scope": {
                "executionId": str(execution_id) if execution_id else None,
                "traceId": str(trace_id) if trace_id else None,
                "resourceType": resource_type,
                "resourceId": resource_id,
            },
            "filters": {
                "level": level,
                "component": component,
                "resourceType": resource_type,
                "resourceId": resource_id,
                "page": page,
                "pageSize": page_size,
            },
            "supportedFilters": ["executionId", "traceId", "level", "component", "resourceType", "resourceId", "page", "pageSize"],
            "summary": {
                "total": len(items),
                "executionLogCount": source_counts.get("execution_log", 0),
                "auditLogCount": source_counts.get("audit_log", 0),
                "traceRefCount": len(trace_refs),
                "executionRefCount": len(execution_refs),
                "resourceScopedCount": sum(count for key, count in resource_counts.items() if key != "unscoped"),
                "errorCount": level_counts.get("error", 0),
                "warnCount": level_counts.get("warn", 0) + level_counts.get("warning", 0),
            },
            "sourceCounts": dict(sorted(source_counts.items())),
            "levelCounts": dict(sorted(level_counts.items())),
            "componentCounts": dict(sorted(component_counts.items())),
            "serviceCounts": dict(sorted(service_counts.items())),
            "resourceTypeCounts": dict(sorted(resource_counts.items())),
            "traceRefs": trace_refs,
            "executionRefs": execution_refs,
            "retentionProjection": {
                "policy": "default-audit-log-retention",
                "retentionDays": 365,
                "readOnly": True,
                "destructiveActionsExposed": False,
                "manageCapability": "audit.retention.manage",
            },
            "items": paged_items,
            "total": len(items),
            "page": page,
            "pageSize": page_size,
            "evidenceOnly": True,
            "writesDecision": False,
            "capability": {
                "required": "audit.logs.read",
                "frontendBoundary": "ux_only",
                "authorizationBoundary": "backend_service_api",
            },
        }
        return validate_contract("structured-log-projection", payload)

    def audit_log_projection(
        self,
        *,
        page: int,
        page_size: int,
        execution_id: UUID | None = None,
        trace_id: UUID | None = None,
        level: str | None = None,
        component: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> dict[str, object]:
        items = self._collect_structured_log_items(
            execution_id=execution_id,
            trace_id=trace_id,
            level=level,
            component=component,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        paged_items = redact_sensitive_data(items[(page - 1) * page_size : page * page_size])
        source_counts = Counter(str(item.get("source") or "unknown") for item in items)
        level_counts = Counter(str(item.get("level") or "unknown") for item in items)
        resource_counts = Counter(str(item.get("resourceType") or "unscoped") for item in items)
        trace_refs = sorted({str(item["traceId"]) for item in items if item.get("traceId")})
        execution_refs = sorted({str(item["executionId"]) for item in items if item.get("executionId")})
        payload = {
            "schemaVersion": "phase8.audit-log-projection.v1",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "scope": {
                "executionId": str(execution_id) if execution_id else None,
                "traceId": str(trace_id) if trace_id else None,
                "resourceType": resource_type,
                "resourceId": resource_id,
            },
            "filters": {
                "level": level,
                "component": component,
                "resourceType": resource_type,
                "resourceId": resource_id,
                "page": page,
                "pageSize": page_size,
            },
            "supportedFilters": ["executionId", "traceId", "level", "component", "resourceType", "resourceId", "page", "pageSize"],
            "summary": {
                "total": len(items),
                "executionLogCount": source_counts.get("execution_log", 0),
                "auditLogCount": source_counts.get("audit_log", 0),
                "traceRefCount": len(trace_refs),
                "executionRefCount": len(execution_refs),
                "resourceScopedCount": sum(count for key, count in resource_counts.items() if key != "unscoped"),
            },
            "sourceCounts": dict(sorted(source_counts.items())),
            "levelCounts": dict(sorted(level_counts.items())),
            "resourceTypeCounts": dict(sorted(resource_counts.items())),
            "retentionProjection": {
                "policy": "default-audit-log-retention",
                "retentionDays": 365,
                "readOnly": True,
                "destructiveActionsExposed": False,
                "manageCapability": "audit.retention.manage",
            },
            "items": paged_items,
            "total": len(items),
            "page": page,
            "pageSize": page_size,
            "evidenceOnly": True,
            "writesDecision": False,
            "capability": {
                "required": "audit.logs.read",
                "frontendBoundary": "ux_only",
                "authorizationBoundary": "backend_service_api",
            },
        }
        return validate_contract("audit-log-projection", payload)

    def audit_retention_policy(self) -> dict[str, object]:
        rows = list(self.db.scalars(select(AuditLog)))
        status_counts = Counter(row.retention_status for row in rows)
        approvals = list(
            self.db.scalars(
                select(Approval)
                .where(Approval.resource_type == "audit_retention_action")
                .order_by(Approval.created_at.desc())
            )
        )
        audit_refs = list(
            self.db.scalars(
                select(AuditLog)
                .where(AuditLog.resource_type == "audit_retention_action")
                .order_by(AuditLog.created_at.desc())
            )
        )
        return {
            "schemaVersion": "phase8.audit-retention-policy.v1",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "retentionPolicy": "default-audit-log-retention",
            "defaultRetentionDays": 365,
            "supportedActions": ["archive", "purge", "set_legal_hold", "clear_legal_hold"],
            "statusCounts": dict(sorted(status_counts.items())),
            "capability": {
                "read": "audit.logs.read",
                "manage": "audit.retention.manage",
                "authorizationBoundary": "backend_service_api",
                "frontendBoundary": "ux_only",
            },
            "approval": {
                "approvalMode": "always",
                "requiredForActions": ["archive", "purge", "set_legal_hold", "clear_legal_hold"],
                "approvalExecutionSurface": "existing_approval_flow",
                "approvalActionType": "audit_retention.apply",
            },
            "guardrail": {
                "required": True,
                "ruleId": "audit_retention.mutation_preflight",
            },
            "audit": {
                "required": True,
                "recentAuditRefs": [{"type": "audit_log", "id": str(row.id), "action": row.action} for row in audit_refs[:5]],
            },
            "approvalRefs": [
                {"type": "approval", "id": str(row.id), "status": row.status.value, "action": row.payload.get("retentionAction")}
                for row in approvals[:5]
            ],
            "readOnlyProjectionRemainsReadOnly": True,
        }

    def request_audit_retention_action(self, payload, context: ServiceContext) -> dict[str, object]:
        audit_log = self._require_audit_log(payload.auditLogId)
        if payload.action == "purge" and audit_log.legal_hold:
            raise AuditRetentionConflictError("legal hold blocks audit log purge")
        preview = self._audit_retention_preview(audit_log, payload.action, payload.retentionUntil)
        decision = self._audit_retention_policy_decision(payload.action)
        current_state = self._audit_retention_state(audit_log.created_at, audit_log)
        if payload.dryRun:
            return {
                "approvalRequired": False,
                "dryRun": True,
                "approvalMode": decision["approvalMode"],
                "auditLogId": str(audit_log.id),
                "action": payload.action,
                "currentRetentionState": current_state,
                "projectedRetentionState": preview,
                "policyOutcome": decision,
            }
        guardrail_refs = self._record_audit_retention_guardrail(
            context,
            audit_log=audit_log,
            action=payload.action,
            projected_state=preview,
            policy_outcome=decision,
        )
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="audit_retention_action",
            resource_id=payload.idempotencyKey or f"{audit_log.id}:{payload.action}",
            summary=f"Approval required before applying audit retention action '{payload.action}' to audit log {audit_log.id}.",
            payload={
                "action": "audit_retention.apply",
                "auditLogId": str(audit_log.id),
                "retentionAction": payload.action,
                "retentionUntil": payload.retentionUntil.isoformat() if payload.retentionUntil else None,
                "reason": payload.reason,
                "approvalMode": decision["approvalMode"],
                "policyOutcome": decision,
                "guardrailEventRefs": guardrail_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        audit_refs = self._approval_request_audit_refs(approval.id)
        return {
            "approvalRequired": True,
            "approvalMode": decision["approvalMode"],
            "approvalId": str(approval.id),
            "approvalRefs": [{"type": "approval", "id": str(approval.id), "state": approval.status.value, "action": payload.action}],
            "status": approval.status.value,
            "auditLogId": str(audit_log.id),
            "action": payload.action,
            "projectedRetentionState": preview,
            "guardrailEventRefs": guardrail_refs,
            "auditRefs": audit_refs,
        }

    def execute_approved_audit_retention_action(
        self,
        *,
        audit_log_id: UUID,
        action: str,
        retention_until: str | None,
        approval_id: UUID | None,
        context: ServiceContext,
    ) -> dict[str, object]:
        audit_log = self._require_audit_log(audit_log_id)
        if action == "purge" and audit_log.legal_hold:
            raise ValueError("legal hold blocks audit log purge")
        now = datetime.now(timezone.utc)
        if action == "archive":
            audit_log.archived_at = now
            audit_log.retention_status = "archived"
        elif action == "purge":
            previous_details_hash = self._hash_payload({"details": audit_log.details})
            audit_log.details = {
                "purged": True,
                "previousDetailsHash": previous_details_hash,
                "retentionAction": action,
                "approvalId": str(approval_id) if approval_id else None,
                "purgedAt": now.isoformat(),
            }
            audit_log.retention_status = "purged"
            audit_log.purge_eligible_at = now
        elif action == "set_legal_hold":
            audit_log.legal_hold = True
            audit_log.retention_status = "legal_hold"
        elif action == "clear_legal_hold":
            audit_log.legal_hold = False
            audit_log.retention_status = "active"
        else:
            raise ValueError("unsupported audit retention action")
        if retention_until:
            audit_log.retention_until = datetime.fromisoformat(retention_until)
        action_audit = write_audit_log(
            self.db,
            str(context.user.id),
            "audit_retention.apply",
            "audit_retention_action",
            str(audit_log.id),
            context.request_id,
            context.trace_id,
            {
                "action": action,
                "approvalId": str(approval_id) if approval_id else None,
                "retentionState": self._audit_retention_state(audit_log.created_at, audit_log),
            },
        )
        self.db.flush()
        return {
            "auditLogId": str(audit_log.id),
            "action": action,
            "retentionState": self._audit_retention_state(audit_log.created_at, audit_log),
            "approvalRefs": [{"type": "approval", "id": str(approval_id), "state": "approved", "action": action}] if approval_id else [],
            "guardrailEventRefs": self._audit_retention_approval_guardrail_refs(approval_id) if approval_id else [],
            "auditRefs": [{"type": "audit_log", "id": str(action_audit.id), "action": action_audit.action}],
        }

    def _collect_structured_log_items(
        self,
        *,
        execution_id: UUID | None = None,
        trace_id: UUID | None = None,
        level: str | None = None,
        component: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        normalized_level = level.lower() if level else None
        normalized_component = component.lower() if component else None
        trace_ids = self._trace_ids_for_scope(execution_id=execution_id, trace_id=trace_id)

        if resource_type is None and resource_id is None:
            execution_log_statement = select(ExecutionLog).order_by(ExecutionLog.created_at.desc())
            if execution_id is not None:
                execution_log_statement = execution_log_statement.where(ExecutionLog.execution_id == execution_id)
            execution_logs = list(self.db.scalars(execution_log_statement))
            for log in execution_logs:
                item = self.serialize_execution_log(log)
                if trace_id is not None and item.get("traceId") != str(trace_id):
                    continue
                if self._matches_log_filter(item, normalized_level, normalized_component):
                    items.append(item)

        audit_statement = select(AuditLog).order_by(AuditLog.created_at.desc())
        if trace_ids:
            audit_statement = audit_statement.where(AuditLog.trace_id.in_(trace_ids))
        elif trace_id is not None or execution_id is not None:
            audit_statement = audit_statement.where(AuditLog.id.is_(None))
        if resource_type:
            audit_statement = audit_statement.where(AuditLog.resource_type == resource_type)
        if resource_id:
            audit_statement = audit_statement.where(AuditLog.resource_id == resource_id)
        audit_logs = list(self.db.scalars(audit_statement))
        for log in audit_logs:
            item = self.serialize_structured_audit_log(log)
            if self._matches_log_filter(item, normalized_level, normalized_component):
                items.append(item)

        return sorted(items, key=lambda item: str(item.get("timestamp") or ""), reverse=True)

    def compare_replays(
        self,
        *,
        baseline_execution_id: UUID,
        candidate_execution_id: UUID,
        request_id: str | None = None,
    ) -> dict[str, object]:
        baseline_export = self.export_execution_replay(baseline_execution_id, request_id=request_id, persist=False)
        candidate_export = self.export_execution_replay(candidate_execution_id, request_id=request_id, persist=False)
        baseline_metrics = self.observability_metrics(baseline_execution_id)["metrics"]
        candidate_metrics = self.observability_metrics(candidate_execution_id)["metrics"]
        baseline_replay = baseline_export["replay"]
        candidate_replay = candidate_export["replay"]
        return {
            "schemaVersion": "phase8.replay-comparison.v1",
            "comparedAt": datetime.now(timezone.utc).isoformat(),
            "baselineReplay": {
                "executionId": str(baseline_execution_id),
                "exportHash": baseline_export["exportHash"],
                "exportPayloadHash": baseline_export["exportPayloadHash"],
                "traceRefs": baseline_export["traceRefs"],
            },
            "candidateReplay": {
                "executionId": str(candidate_execution_id),
                "exportHash": candidate_export["exportHash"],
                "exportPayloadHash": candidate_export["exportPayloadHash"],
                "traceRefs": candidate_export["traceRefs"],
            },
            "metricDiff": self._metric_diff(baseline_metrics, candidate_metrics),
            "findingDiff": self._finding_diff(baseline_replay, candidate_replay),
            "gateDiff": self._gate_diff(baseline_replay, candidate_replay),
            "judgeDiff": self._judge_diff(baseline_execution_id, candidate_execution_id),
            "costDiff": self._named_metric_diff(baseline_metrics, candidate_metrics, "Model Cost Total"),
            "latencyDiff": self._named_metric_diff(baseline_metrics, candidate_metrics, "Model Latency P95"),
            "evidenceOnly": True,
            "writesDecision": False,
        }

    def quality_dashboard(self, execution_id: UUID | None = None) -> dict[str, object]:
        metrics_payload = self.observability_metrics(execution_id)
        logs = self.list_structured_logs(page=1, page_size=10, execution_id=execution_id)
        findings = self._findings_for_scope(execution_id)
        quality_signals = self._quality_signals(metrics_payload["metrics"])
        return {
            "scope": {"executionId": str(execution_id) if execution_id else None},
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "metrics": metrics_payload["metrics"],
            "executionQuality": self._execution_quality_summary(execution_id),
            "skillQuality": self._skill_quality_summary(execution_id),
            "modelQuality": self._model_quality_summary(execution_id),
            "costSummary": self._cost_summary(execution_id),
            "failureReasons": self._failure_reasons(findings, logs["items"]),
            "qualitySignals": quality_signals,
            "evidenceOnly": True,
            "writesDecision": False,
        }

    def serialize_trace_summary(self, trace: Trace, trace_counts: dict[UUID, dict[str, int]] | None = None) -> dict[str, object]:
        counts = (trace_counts or {}).get(trace.id, self._empty_trace_counts())
        return {
            "id": str(trace.id),
            "executionId": str(trace.execution_id) if trace.execution_id else None,
            "rootSpanName": trace.root_span_name,
            "metadata": trace.trace_metadata,
            "createdAt": trace.created_at.isoformat(),
            "spanCount": counts["spanCount"],
            "modelInvocationCount": counts["modelInvocationCount"],
            "agentRunCount": counts["agentRunCount"],
            "skillInvocationCount": counts["skillInvocationCount"],
            "auditLogCount": counts["auditLogCount"],
            "guardrailEventCount": counts["guardrailEventCount"],
        }

    def _coverage_rate_metric(self, executions: list[Execution]) -> dict[str, object]:
        if not executions:
            return self._metric("Coverage Rate", "pending", None, {"reason": "no executions reviewed"})
        coverage_values: list[float] = []
        for execution in executions:
            plan = self.db.get(TestPlan, execution.plan_id)
            if plan is None:
                continue
            requirements = [str(item) for item in plan.input_payload.get("requirements", []) if str(item).strip()]
            generated_plan = plan.generated_plan or {}
            generated_text = json.dumps(generated_plan, ensure_ascii=False).lower()
            if not requirements:
                continue
            covered = len([requirement for requirement in requirements if requirement.lower() in generated_text])
            coverage_values.append(covered / len(requirements))
        if not coverage_values:
            return self._metric("Coverage Rate", "not_applicable", None, {"reason": "no requirement coverage inputs"})
        return self._metric("Coverage Rate", "available", sum(coverage_values) / len(coverage_values), {"sampleSize": len(coverage_values)})

    def _execution_success_rate_metric(self, executions: list[Execution]) -> dict[str, object]:
        if not executions:
            return self._metric("Execution Success Rate", "pending", None, {"reason": "no executions reviewed"})
        terminal = [execution for execution in executions if execution.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}]
        if not terminal:
            return self._metric("Execution Success Rate", "pending", None, {"reason": "no terminal executions"})
        completed = len([execution for execution in terminal if execution.status == TaskStatus.COMPLETED])
        return self._metric("Execution Success Rate", "available", completed / len(terminal), {"sampleSize": len(terminal)})

    def _replay_success_rate_metric(self, executions: list[Execution]) -> dict[str, object]:
        if not executions:
            return self._metric("Replay Success Rate", "pending", None, {"reason": "no executions reviewed"})
        terminal = [
            execution
            for execution in executions
            if execution.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}
        ]
        if not terminal:
            return self._metric("Replay Success Rate", "pending", None, {"reason": "no terminal executions"})
        replayable = 0
        for execution in terminal:
            trace_count = self.db.scalar(select(func.count()).select_from(Trace).where(Trace.execution_id == execution.id)) or 0
            if trace_count > 0:
                replayable += 1
        return self._metric("Replay Success Rate", "available", replayable / len(terminal), {"sampleSize": len(terminal)})

    def _task_success_rate_metric(self, executions: list[Execution]) -> dict[str, object]:
        execution_ids = [execution.id for execution in executions]
        if not execution_ids:
            return self._metric("Task Success Rate", "pending", None, {"reason": "no executions reviewed"})
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id.in_(execution_ids))))
        terminal = [task for task in tasks if task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}]
        if not terminal:
            return self._metric("Task Success Rate", "pending", None, {"reason": "no terminal tasks"})
        completed = len([task for task in terminal if task.status == TaskStatus.COMPLETED])
        return self._metric("Task Success Rate", "available", completed / len(terminal), {"sampleSize": len(terminal)})

    def _agent_success_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        runs = self._agent_runs_for_scope(execution_id)
        if not runs:
            return self._metric("Agent Success Rate", "pending", None, {"reason": "no agent runs"})
        terminal = [run for run in runs if run.status.value in {"completed", "failed", "cancelled"}]
        if not terminal:
            return self._metric("Agent Success Rate", "pending", None, {"reason": "no terminal agent runs"})
        completed = len([run for run in terminal if run.status.value == "completed"])
        return self._metric("Agent Success Rate", "available", completed / len(terminal), {"sampleSize": len(terminal)})

    def _skill_success_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        invocations = self._skill_invocations_for_scope(execution_id)
        if not invocations:
            return self._metric("Skill Success Rate", "not_applicable", None, {"reason": "no skill invocations"})
        completed = len([item for item in invocations if item.status == "completed"])
        failed = len([item for item in invocations if item.status == "failed"])
        terminal = completed + failed
        if terminal == 0:
            return self._metric("Skill Success Rate", "pending", None, {"reason": "no terminal skill invocations"})
        return self._metric("Skill Success Rate", "available", completed / terminal, {"sampleSize": terminal, "failed": failed})

    def _model_success_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        invocations = self._model_invocations_for_scope(execution_id)
        if not invocations:
            return self._metric("Model Success Rate", "pending", None, {"reason": "no model invocations"})
        successful = len([item for item in invocations if item.success])
        return self._metric("Model Success Rate", "available", successful / len(invocations), {"sampleSize": len(invocations)})

    def _model_latency_metric(self, execution_id: UUID | None) -> dict[str, object]:
        latencies = [item.latency_ms for item in self._model_invocations_for_scope(execution_id) if item.latency_ms is not None]
        if not latencies:
            return self._metric("Model Latency P95", "pending", None, {"reason": "no model latency samples"})
        return self._metric(
            "Model Latency P95",
            "available",
            float(self._percentile(latencies, 95)),
            {
                "unit": "ms",
                "p50": float(self._percentile(latencies, 50)),
                "p95": float(self._percentile(latencies, 95)),
                "p99": float(self._percentile(latencies, 99)),
                "sampleSize": len(latencies),
            },
        )

    def _model_cost_metric(self, execution_id: UUID | None) -> dict[str, object]:
        invocations = self._model_invocations_for_scope(execution_id)
        costs = [float(item.cost_amount) for item in invocations if item.cost_amount is not None]
        if not invocations:
            return self._metric("Model Cost Total", "pending", None, {"reason": "no model invocations"})
        if not costs:
            return self._metric("Model Cost Total", "pending", None, {"reason": "no cost samples", "sampleSize": len(invocations)})
        currency = next((item.currency for item in invocations if item.cost_amount is not None), "USD")
        return self._metric("Model Cost Total", "available", sum(costs), {"currency": currency, "sampleSize": len(costs)})

    def _cost_per_execution_metric(self, executions: list[Execution], execution_id: UUID | None) -> dict[str, object]:
        cost_metric = self._model_cost_metric(execution_id)
        if cost_metric["status"] != "available" or cost_metric["value"] is None:
            return self._metric("Cost Per Execution", cost_metric["status"], None, cost_metric["metadata"])
        denominator = 1 if execution_id is not None else max(len(executions), 1)
        metadata = dict(cost_metric["metadata"])
        metadata["executionCount"] = denominator
        return self._metric("Cost Per Execution", "available", float(cost_metric["value"]) / denominator, metadata)

    def _evidence_link_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        findings = self._findings_for_scope(execution_id)
        if not findings:
            return self._metric("Evidence Link Rate", "not_applicable", None, {"reason": "no findings"})
        linked = len([finding for finding in findings if finding.evidence or finding.evidence_ref])
        return self._metric("Evidence Link Rate", "available", linked / len(findings), {"sampleSize": len(findings)})

    def _gate_pass_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        gates = self._gates_for_scope(execution_id)
        if not gates:
            return self._metric("Gate Pass Rate", "pending", None, {"reason": "no gate decisions"})
        passed = len([gate for gate in gates if gate.overall == GateResult.PASS])
        return self._metric("Gate Pass Rate", "available", passed / len(gates), {"sampleSize": len(gates)})

    def _review_pending_metric(self, execution_id: UUID | None) -> dict[str, object]:
        approvals = self._approvals_for_scope(execution_id)
        return self._count_metric("Review Pending Count", approvals, ApprovalStatus.PENDING)

    def _review_approved_metric(self, execution_id: UUID | None) -> dict[str, object]:
        approvals = self._approvals_for_scope(execution_id)
        return self._count_metric("Review Approved Count", approvals, ApprovalStatus.APPROVED)

    def _review_rejected_metric(self, execution_id: UUID | None) -> dict[str, object]:
        approvals = self._approvals_for_scope(execution_id)
        return self._count_metric("Review Rejected Count", approvals, ApprovalStatus.REJECTED)

    def _memory_hit_rate_metric(self) -> dict[str, object]:
        audit_logs = list(
            self.db.scalars(
                select(AuditLog).where(AuditLog.action.in_(["memory.hit", "memory.miss", "memory.search"]))
            )
        )
        hits = len([item for item in audit_logs if item.action == "memory.hit" or item.details.get("hit") is True])
        misses = len([item for item in audit_logs if item.action == "memory.miss" or item.details.get("hit") is False])
        total = hits + misses
        if total == 0:
            memory_count = self.db.scalar(select(func.count()).select_from(Memory)) or 0
            return self._metric("Memory Hit Rate", "pending", None, {"reason": "no memory hit/miss audit samples", "memoryCount": memory_count})
        return self._metric("Memory Hit Rate", "available", hits / total, {"hits": hits, "misses": misses})

    def _judge_disagreement_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        statement = select(TriageResult)
        if execution_id is not None:
            statement = statement.where(TriageResult.execution_id == execution_id)
        triage_results = list(self.db.scalars(statement))
        if not triage_results:
            return self._metric("Judge Disagreement Rate", "pending", None, {"reason": "no triage results"})
        challenged = len([item for item in triage_results if item.challenged])
        return self._metric("Judge Disagreement Rate", "available", challenged / len(triage_results), {"sampleSize": len(triage_results)})

    def _empty_response_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        runs = self._agent_runs_for_scope(execution_id)
        if not runs:
            return self._metric("Empty Response Rate", "pending", None, {"reason": "no agent runs"})
        empty = len([run for run in runs if not run.output_payload])
        return self._metric("Empty Response Rate", "available", empty / len(runs), {"sampleSize": len(runs)})

    def _agent_loop_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        logs = self._execution_logs_for_scope(execution_id)
        loop_logs = [log for log in logs if "loop" in log.message.lower() or log.context.get("agentLoop") is True]
        if not loop_logs:
            return self._metric("Agent Loop Rate", "pending", None, {"reason": "no loop detection samples"})
        task_count = self.db.scalar(select(func.count()).select_from(ExecutionTask)) or 0
        if execution_id is not None:
            task_count = self.db.scalar(select(func.count()).select_from(ExecutionTask).where(ExecutionTask.execution_id == execution_id)) or 0
        denominator = max(task_count, len(loop_logs), 1)
        return self._metric("Agent Loop Rate", "available", len(loop_logs) / denominator, {"loopLogCount": len(loop_logs)})

    def _hallucination_rate_metric(self, execution_id: UUID | None) -> dict[str, object]:
        guardrails = self._guardrail_events_for_scope(execution_id)
        relevant = [
            item
            for item in guardrails
            if "hallucination" in item.rule_id.lower()
            or "hallucination" in item.message.lower()
            or item.metadata_json.get("signal") == "hallucination"
        ]
        if not relevant:
            return self._metric("Hallucination Rate", "pending", None, {"reason": "no hallucination detection samples"})
        blocked_or_warned = len([item for item in relevant if item.decision.value in {"warn", "block"}])
        return self._metric("Hallucination Rate", "available", blocked_or_warned / len(relevant), {"sampleSize": len(relevant)})

    def _metric(self, name: str, status: str, value: float | None, metadata: dict[str, object]) -> dict[str, object]:
        return {
            "name": name,
            "status": status,
            "value": value,
            "metadata": metadata,
        }

    def _count_metric(self, name: str, approvals: list[Approval], status: ApprovalStatus) -> dict[str, object]:
        count = len([item for item in approvals if item.status == status])
        return self._metric(name, "available", float(count), {"sampleSize": len(approvals)})

    def _scoped_executions(self, execution_id: UUID | None) -> list[Execution]:
        statement = select(Execution)
        if execution_id is not None:
            statement = statement.where(Execution.id == execution_id)
        return list(self.db.scalars(statement.order_by(Execution.created_at.asc())))

    def _agent_runs_for_scope(self, execution_id: UUID | None) -> list[AgentRun]:
        statement = select(AgentRun)
        if execution_id is not None:
            statement = statement.where(AgentRun.execution_id == execution_id)
        return list(self.db.scalars(statement))

    def _skill_invocations_for_scope(self, execution_id: UUID | None) -> list[SkillInvocation]:
        statement = select(SkillInvocation)
        if execution_id is not None:
            statement = statement.where(SkillInvocation.execution_id == execution_id)
        return list(self.db.scalars(statement))

    def _model_invocations_for_scope(self, execution_id: UUID | None) -> list[ModelInvocation]:
        statement = select(ModelInvocation)
        if execution_id is not None:
            statement = statement.where(ModelInvocation.execution_id == execution_id)
        return list(self.db.scalars(statement))

    def _findings_for_scope(self, execution_id: UUID | None) -> list[Finding]:
        statement = select(Finding)
        if execution_id is not None:
            statement = statement.where(Finding.execution_id == execution_id)
        return list(self.db.scalars(statement))

    def _gates_for_scope(self, execution_id: UUID | None) -> list[GateDecision]:
        statement = select(GateDecision)
        if execution_id is not None:
            statement = statement.where(GateDecision.execution_id == execution_id)
        return list(self.db.scalars(statement))

    def _approvals_for_scope(self, execution_id: UUID | None) -> list[Approval]:
        if execution_id is None:
            return list(self.db.scalars(select(Approval)))
        execution = self.db.get(Execution, execution_id)
        execution_plan_id = execution.execution_plan_id if execution else None
        return list(
            self.db.scalars(
                select(Approval).where(
                    self._approval_resource_filter(execution_id, execution_plan_id)
                )
            )
        )

    @staticmethod
    def _approval_resource_filter(
        execution_id: UUID,
        execution_plan_id: UUID | None,
    ):
        direct_resource_ids = [str(execution_id).replace("-", "")]
        if execution_plan_id is not None:
            direct_resource_ids.append(str(execution_plan_id).replace("-", ""))
        finding_resource_ids = select(
            func.replace(cast(Finding.id, String), "-", "")
        ).where(Finding.execution_id == execution_id)
        normalized_resource_id = func.replace(Approval.resource_id, "-", "")
        return or_(
            normalized_resource_id.in_(direct_resource_ids),
            normalized_resource_id.in_(finding_resource_ids),
        )

    def _execution_logs_for_scope(self, execution_id: UUID | None) -> list[ExecutionLog]:
        statement = select(ExecutionLog)
        if execution_id is not None:
            statement = statement.where(ExecutionLog.execution_id == execution_id)
        return list(self.db.scalars(statement))

    def _guardrail_events_for_scope(self, execution_id: UUID | None) -> list[GuardrailEvent]:
        statement = select(GuardrailEvent)
        if execution_id is not None:
            statement = statement.where(GuardrailEvent.execution_id == execution_id)
        return list(self.db.scalars(statement))

    def _trace_ids_for_scope(self, execution_id: UUID | None, trace_id: UUID | None) -> list[UUID]:
        if trace_id is not None:
            return [trace_id]
        if execution_id is None:
            return []
        return list(self.db.scalars(select(Trace.id).where(Trace.execution_id == execution_id)))

    def _matches_log_filter(
        self,
        item: dict[str, object],
        normalized_level: str | None,
        normalized_component: str | None,
    ) -> bool:
        if normalized_level and str(item.get("level", "")).lower() != normalized_level:
            return False
        if normalized_component and normalized_component not in str(item.get("component", "")).lower():
            return False
        return True

    def _percentile(self, values: list[int], percentile: int) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        index = min(len(ordered) - 1, max(0, round((percentile / 100) * (len(ordered) - 1))))
        return float(ordered[index])

    def _metric_diff(self, baseline_metrics: list[dict[str, object]], candidate_metrics: list[dict[str, object]]) -> list[dict[str, object]]:
        names = sorted({str(metric["name"]) for metric in baseline_metrics} | {str(metric["name"]) for metric in candidate_metrics})
        return [self._named_metric_diff(baseline_metrics, candidate_metrics, name) for name in names]

    def _named_metric_diff(
        self,
        baseline_metrics: list[dict[str, object]],
        candidate_metrics: list[dict[str, object]],
        name: str,
    ) -> dict[str, object]:
        baseline = self._metric_by_name(baseline_metrics, name)
        candidate = self._metric_by_name(candidate_metrics, name)
        baseline_value = baseline.get("value") if baseline else None
        candidate_value = candidate.get("value") if candidate else None
        delta = None
        if isinstance(baseline_value, int | float) and isinstance(candidate_value, int | float):
            delta = float(candidate_value) - float(baseline_value)
        return {
            "name": name,
            "baseline": baseline_value,
            "candidate": candidate_value,
            "delta": delta,
            "baselineStatus": baseline.get("status") if baseline else "missing",
            "candidateStatus": candidate.get("status") if candidate else "missing",
        }

    def _metric_by_name(self, metrics: list[dict[str, object]], name: str) -> dict[str, object] | None:
        for metric in metrics:
            if metric.get("name") == name:
                return metric
        return None

    def _finding_diff(self, baseline_replay: dict[str, object], candidate_replay: dict[str, object]) -> dict[str, object]:
        baseline_findings = {self._finding_key(item): item for item in baseline_replay.get("findings", [])}
        candidate_findings = {self._finding_key(item): item for item in candidate_replay.get("findings", [])}
        added_keys = sorted(set(candidate_findings) - set(baseline_findings))
        removed_keys = sorted(set(baseline_findings) - set(candidate_findings))
        return {
            "baselineCount": len(baseline_findings),
            "candidateCount": len(candidate_findings),
            "addedCount": len(added_keys),
            "removedCount": len(removed_keys),
            "added": [self._finding_diff_item(candidate_findings[key]) for key in added_keys[:20]],
            "removed": [self._finding_diff_item(baseline_findings[key]) for key in removed_keys[:20]],
            "baselineSeverityCounts": self._severity_counts(list(baseline_findings.values())),
            "candidateSeverityCounts": self._severity_counts(list(candidate_findings.values())),
        }

    def _finding_key(self, finding: object) -> str:
        if isinstance(finding, dict):
            return str(finding.get("dedupeKey") or finding.get("rawRef") or finding.get("id"))
        return str(finding)

    def _finding_diff_item(self, finding: object) -> dict[str, object]:
        if not isinstance(finding, dict):
            return {"id": str(finding)}
        return {
            "id": finding.get("id"),
            "dedupeKey": finding.get("dedupeKey"),
            "severity": finding.get("severity"),
            "category": finding.get("category"),
            "title": finding.get("title"),
        }

    def _severity_counts(self, findings: list[object]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in findings:
            if isinstance(finding, dict):
                severity = str(finding.get("severity") or "unknown")
            else:
                severity = "unknown"
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _gate_diff(self, baseline_replay: dict[str, object], candidate_replay: dict[str, object]) -> dict[str, object]:
        baseline_gate = baseline_replay.get("gate") or {}
        candidate_gate = candidate_replay.get("gate") or {}
        fields = ["functional", "performance", "security", "overall"]
        changed_fields = [
            field
            for field in fields
            if isinstance(baseline_gate, dict)
            and isinstance(candidate_gate, dict)
            and baseline_gate.get(field) != candidate_gate.get(field)
        ]
        return {
            "baseline": baseline_gate,
            "candidate": candidate_gate,
            "changed": bool(changed_fields),
            "changedFields": changed_fields,
        }

    def _judge_diff(self, baseline_execution_id: UUID, candidate_execution_id: UUID) -> dict[str, object]:
        baseline = self._triage_summary(baseline_execution_id)
        candidate = self._triage_summary(candidate_execution_id)
        return {
            "baseline": baseline,
            "candidate": candidate,
            "challengedDelta": candidate["challengedCount"] - baseline["challengedCount"],
        }

    def _triage_summary(self, execution_id: UUID) -> dict[str, int]:
        rows = list(self.db.scalars(select(TriageResult).where(TriageResult.execution_id == execution_id)))
        return {
            "total": len(rows),
            "challengedCount": len([row for row in rows if row.challenged]),
            "judgeDecisionCount": len([row for row in rows if row.final_decision_by]),
        }

    def _quality_signals(self, metrics: list[dict[str, object]]) -> list[dict[str, object]]:
        signals: list[dict[str, object]] = []
        thresholds = {
            "Execution Success Rate": 0.9,
            "Task Success Rate": 0.9,
            "Agent Success Rate": 0.9,
            "Skill Success Rate": 0.9,
            "Model Success Rate": 0.95,
            "Evidence Link Rate": 1.0,
            "Gate Pass Rate": 0.8,
        }
        for metric in metrics:
            name = str(metric.get("name"))
            value = metric.get("value")
            if name in thresholds and isinstance(value, int | float) and float(value) < thresholds[name]:
                signals.append(
                    {
                        "signal": name,
                        "severity": "warn",
                        "value": value,
                        "threshold": thresholds[name],
                        "evidence": metric.get("metadata", {}),
                    }
                )
            elif metric.get("status") == "pending":
                signals.append(
                    {
                        "signal": name,
                        "severity": "info",
                        "value": None,
                        "threshold": None,
                        "evidence": metric.get("metadata", {}),
                    }
                )
        return signals

    def _execution_quality_summary(self, execution_id: UUID | None) -> dict[str, object]:
        executions = self._scoped_executions(execution_id)
        findings = self._findings_for_scope(execution_id)
        gates = self._gates_for_scope(execution_id)
        return {
            "executionCount": len(executions),
            "statusCounts": self._enum_counts([execution.status.value for execution in executions]),
            "stageCounts": self._enum_counts([execution.stage.value for execution in executions]),
            "findingCount": len(findings),
            "findingSeverityCounts": self._enum_counts([finding.severity.value for finding in findings]),
            "gateCounts": self._enum_counts([gate.overall.value for gate in gates]),
        }

    def _skill_quality_summary(self, execution_id: UUID | None) -> list[dict[str, object]]:
        rows: dict[str, dict[str, object]] = {}
        for invocation in self._skill_invocations_for_scope(execution_id):
            version = self.db.get(SkillVersion, invocation.skill_version_id)
            skill = self.db.get(Skill, version.skill_ref_id) if version else None
            skill_id = skill.skill_id if skill else str(invocation.skill_version_id)
            row = rows.setdefault(
                skill_id,
                {
                    "skillId": skill_id,
                    "invocations": 0,
                    "completed": 0,
                    "failed": 0,
                    "evidenceLinked": 0,
                    "failureReasons": [],
                },
            )
            row["invocations"] = int(row["invocations"]) + 1
            if invocation.status == "completed":
                row["completed"] = int(row["completed"]) + 1
            if invocation.status == "failed":
                row["failed"] = int(row["failed"]) + 1
            if invocation.artifact_refs or invocation.output_snapshot.get("evidence"):
                row["evidenceLinked"] = int(row["evidenceLinked"]) + 1
            if invocation.error_message:
                row["failureReasons"].append(invocation.error_message)
        for row in rows.values():
            invocations = max(int(row["invocations"]), 1)
            row["successRate"] = int(row["completed"]) / invocations
            row["evidenceRate"] = int(row["evidenceLinked"]) / invocations
            row["failureReasons"] = row["failureReasons"][:10]
        return list(rows.values())

    def _model_quality_summary(self, execution_id: UUID | None) -> list[dict[str, object]]:
        invocations = self._model_invocations_for_scope(execution_id)
        model_lookup = self._load_models([item.model_id for item in invocations])
        rows: dict[str, dict[str, object]] = {}
        for invocation in invocations:
            model = model_lookup.get(invocation.model_id) if invocation.model_id else None
            model_key = model.name if model else str(invocation.model_id or "unknown")
            row = rows.setdefault(
                model_key,
                {
                    "model": model_key,
                    "provider": model.provider.value if model else None,
                    "invocations": 0,
                    "success": 0,
                    "failures": 0,
                    "totalTokens": 0,
                    "totalCost": 0.0,
                    "latencySamples": [],
                },
            )
            row["invocations"] = int(row["invocations"]) + 1
            row["success"] = int(row["success"]) + (1 if invocation.success else 0)
            row["failures"] = int(row["failures"]) + (0 if invocation.success else 1)
            row["totalTokens"] = int(row["totalTokens"]) + int(invocation.total_tokens or 0)
            row["totalCost"] = float(row["totalCost"]) + float(invocation.cost_amount or 0)
            if invocation.latency_ms is not None:
                row["latencySamples"].append(invocation.latency_ms)
        for row in rows.values():
            invocations_count = max(int(row["invocations"]), 1)
            latencies = list(row.pop("latencySamples"))
            row["successRate"] = int(row["success"]) / invocations_count
            row["latencyP95Ms"] = self._percentile(latencies, 95) if latencies else None
        return list(rows.values())

    def _cost_summary(self, execution_id: UUID | None) -> dict[str, object]:
        invocations = self._model_invocations_for_scope(execution_id)
        costs = [float(invocation.cost_amount) for invocation in invocations if invocation.cost_amount is not None]
        token_total = sum(int(invocation.total_tokens or 0) for invocation in invocations)
        return {
            "totalCost": sum(costs),
            "currency": next((invocation.currency for invocation in invocations if invocation.cost_amount is not None), "USD"),
            "totalTokens": token_total,
            "modelInvocationCount": len(invocations),
            "status": "available" if costs else "pending",
        }

    def _failure_reasons(self, findings: list[Finding], logs: list[dict[str, object]]) -> list[dict[str, object]]:
        reasons: list[dict[str, object]] = []
        for finding in findings[:20]:
            reasons.append(
                {
                    "source": "finding",
                    "severity": finding.severity.value,
                    "message": finding.title,
                    "evidenceRef": str(finding.evidence_ref) if finding.evidence_ref else finding.raw_ref,
                }
            )
        for log in logs:
            if str(log.get("level")).lower() in {"error", "warn", "warning"}:
                reasons.append(
                    {
                        "source": log.get("source"),
                        "severity": log.get("level"),
                        "message": log.get("message"),
                        "evidenceRef": log.get("id"),
                    }
                )
        return reasons[:20]

    def _enum_counts(self, values: list[str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for value in values:
            counts[value] = counts.get(value, 0) + 1
        return counts

    def serialize_span(self, span: TraceSpan) -> dict[str, object]:
        return {
            "id": str(span.id),
            "traceId": str(span.trace_id),
            "parentSpanId": str(span.parent_span_id) if span.parent_span_id else None,
            "spanName": span.span_name,
            "spanType": span.span_type,
            "serviceName": span.service_name,
            "status": span.status,
            "startTime": span.start_time.isoformat() if span.start_time else None,
            "endTime": span.end_time.isoformat() if span.end_time else None,
            "durationMs": span.duration_ms,
            "attributes": span.attributes,
        }

    def serialize_model_invocation(
        self,
        invocation: ModelInvocation,
        model_lookup: dict[UUID, Model] | None = None,
    ) -> dict[str, object]:
        model = None
        if invocation.model_id:
            model = (model_lookup or {}).get(invocation.model_id)
            if model is None:
                model = self.db.get(Model, invocation.model_id)
        return {
            "id": str(invocation.id),
            "traceId": str(invocation.trace_id) if invocation.trace_id else None,
            "executionId": str(invocation.execution_id) if invocation.execution_id else None,
            "modelId": str(invocation.model_id) if invocation.model_id else None,
            "modelName": model.model_name if model else None,
            "provider": model.provider.value if model else None,
            "requestSummary": invocation.request_summary,
            "requestPayload": invocation.request_payload,
            "responsePayload": invocation.response_payload,
            "promptTokens": invocation.prompt_tokens,
            "completionTokens": invocation.completion_tokens,
            "totalTokens": invocation.total_tokens,
            "latencyMs": invocation.latency_ms,
            "costAmount": float(invocation.cost_amount) if invocation.cost_amount is not None else None,
            "currency": invocation.currency,
            "success": invocation.success,
            "errorMessage": invocation.error_message,
            "createdAt": invocation.created_at.isoformat(),
        }

    def serialize_agent_run(self, agent_run: AgentRun) -> dict[str, object]:
        return {
            "id": str(agent_run.id),
            "traceId": str(agent_run.trace_id) if agent_run.trace_id else None,
            "executionId": str(agent_run.execution_id) if agent_run.execution_id else None,
            "taskId": str(agent_run.task_id) if agent_run.task_id else None,
            "agentName": agent_run.agent_name,
            "status": agent_run.status.value,
            "input": agent_run.input_payload,
            "output": agent_run.output_payload,
            "modelId": str(agent_run.model_id) if agent_run.model_id else None,
            "latencyMs": agent_run.latency_ms,
            "startedAt": agent_run.started_at.isoformat() if agent_run.started_at else None,
            "endedAt": agent_run.ended_at.isoformat() if agent_run.ended_at else None,
            "createdAt": agent_run.created_at.isoformat(),
        }

    def serialize_audit_log(self, audit_log: AuditLog) -> dict[str, object]:
        return {
            "id": str(audit_log.id),
            "traceId": str(audit_log.trace_id) if audit_log.trace_id else None,
            "actorId": str(audit_log.actor_id) if audit_log.actor_id else None,
            "action": audit_log.action,
            "resourceType": audit_log.resource_type,
            "resourceId": audit_log.resource_id,
            "requestId": audit_log.request_id,
            "details": audit_log.details,
            "createdAt": audit_log.created_at.isoformat(),
        }

    def serialize_execution_log(self, log: ExecutionLog) -> dict[str, object]:
        return {
            "id": str(log.id),
            "source": "execution_log",
            "timestamp": log.created_at.isoformat(),
            "level": log.level.lower(),
            "component": str(log.context.get("component") or log.context.get("service") or "execution-service"),
            "service": str(log.context.get("service") or log.context.get("component") or "execution-service"),
            "traceId": str(log.context.get("traceId")) if log.context.get("traceId") else None,
            "spanId": str(log.context.get("spanId")) if log.context.get("spanId") else None,
            "executionId": str(log.execution_id),
            "taskId": str(log.task_id) if log.task_id else None,
            "requestId": str(log.context.get("requestId")) if log.context.get("requestId") else None,
            "message": log.message,
            "metadata": log.context,
            "retentionState": self._audit_retention_state(log.created_at),
        }

    def serialize_structured_audit_log(self, audit_log: AuditLog) -> dict[str, object]:
        return {
            "id": str(audit_log.id),
            "source": "audit_log",
            "timestamp": audit_log.created_at.isoformat(),
            "level": "info",
            "component": audit_log.resource_type,
            "service": str(audit_log.details.get("service") or audit_log.resource_type),
            "traceId": str(audit_log.trace_id) if audit_log.trace_id else None,
            "spanId": str(audit_log.details.get("spanId")) if audit_log.details.get("spanId") else None,
            "executionId": str(audit_log.details.get("executionId")) if audit_log.details.get("executionId") else None,
            "taskId": str(audit_log.details.get("taskId")) if audit_log.details.get("taskId") else None,
            "requestId": audit_log.request_id,
            "resourceType": audit_log.resource_type,
            "resourceId": audit_log.resource_id,
            "message": audit_log.action,
            "metadata": {
                "actorId": str(audit_log.actor_id) if audit_log.actor_id else None,
                "resourceType": audit_log.resource_type,
                "resourceId": audit_log.resource_id,
                "details": audit_log.details,
            },
            "retentionState": self._audit_retention_state(audit_log.created_at, audit_log),
        }

    def serialize_guardrail_event(self, event: GuardrailEvent) -> dict[str, object]:
        return {
            "id": str(event.id),
            "traceId": str(event.trace_id) if event.trace_id else None,
            "executionId": str(event.execution_id) if event.execution_id else None,
            "agentRunId": str(event.agent_run_id) if event.agent_run_id else None,
            "skillInvocationId": str(event.skill_invocation_id) if event.skill_invocation_id else None,
            "connectorBindingId": str(event.connector_binding_id) if event.connector_binding_id else None,
            "toolCallId": str(event.tool_call_id) if event.tool_call_id else None,
            "ruleId": event.rule_id,
            "decision": event.decision.value,
            "message": event.message,
            "reason": event.message,
            "evidence": event.evidence,
            "resourceType": event.payload.get("resourceType"),
            "resourceId": event.payload.get("resourceId"),
            "metadata": event.metadata_json,
            "requestId": event.request_id,
            "createdAt": event.created_at.isoformat(),
        }

    def serialize_skill_invocation(self, invocation: SkillInvocation) -> dict[str, object]:
        version = self.db.get(SkillVersion, invocation.skill_version_id)
        skill = self.db.get(Skill, version.skill_ref_id) if version else None
        return {
            "id": str(invocation.id),
            "traceId": str(invocation.trace_id) if invocation.trace_id else None,
            "executionId": str(invocation.execution_id) if invocation.execution_id else None,
            "agentRunId": str(invocation.agent_run_id) if invocation.agent_run_id else None,
            "skillId": skill.skill_id if skill else None,
            "skillVersionId": str(invocation.skill_version_id),
            "version": version.version if version else None,
            "manifestHash": version.manifest_hash if version else None,
            "extensionPointId": invocation.extension_point_id,
            "bindingId": str(invocation.binding_id) if invocation.binding_id else None,
            "sourceWorkflow": invocation.source_workflow,
            "status": invocation.status,
            "inputSnapshot": redact_sensitive_data(invocation.input_snapshot),
            "outputSnapshot": redact_sensitive_data(invocation.output_snapshot),
            "policySnapshot": redact_sensitive_data(invocation.policy_snapshot),
            "resolutionSnapshot": redact_sensitive_data(invocation.resolution_snapshot),
            "connectorBindingSnapshot": self.connector_snapshot_builder.build(
                invocation.connector_binding_snapshot
            ),
            "approvalRefs": redact_sensitive_data(invocation.approval_refs),
            "artifactRefs": redact_sensitive_data(invocation.artifact_refs),
            "toolCallRefs": redact_sensitive_data(invocation.tool_call_refs),
            "connectorCallRefs": redact_sensitive_data(invocation.connector_call_refs),
            "errorMessage": redact_sensitive_data(invocation.error_message),
            "createdAt": invocation.created_at.isoformat(),
            "updatedAt": invocation.updated_at.isoformat(),
        }

    def serialize_task(self, task: ExecutionTask) -> dict[str, object]:
        return {
            "id": str(task.id),
            "domain": task.domain.value,
            "taskType": task.task_type,
            "runner": task.runner,
            "status": task.status.value,
            "stage": task.stage.value if task.stage else None,
            "resultPayload": task.result_payload,
            "errorMessage": task.error_message,
            "startedAt": task.started_at.isoformat() if task.started_at else None,
            "endedAt": task.ended_at.isoformat() if task.ended_at else None,
        }

    def serialize_artifact(self, artifact: ExecutionArtifact) -> dict[str, object]:
        return {
            "id": str(artifact.id),
            "taskId": str(artifact.task_id) if artifact.task_id else None,
            "artifactType": artifact.artifact_type.value,
            "uri": artifact.uri,
            "summary": artifact.summary,
            "redactionStatus": artifact.redaction_status,
            "redactedUri": artifact.redacted_uri,
            "expiresAt": artifact.expires_at.isoformat() if artifact.expires_at else None,
            "metadata": artifact.metadata_json,
            "createdAt": artifact.created_at.isoformat(),
        }

    def serialize_metric(self, metric: ExecutionMetric) -> dict[str, object]:
        return {
            "id": str(metric.id),
            "executionId": str(metric.execution_id),
            "taskId": str(metric.task_id) if metric.task_id else None,
            "metricName": metric.metric_name,
            "metricValue": float(metric.metric_value),
            "metricUnit": metric.metric_unit,
            "thresholdValue": float(metric.threshold_value) if metric.threshold_value is not None else None,
            "baselineValue": float(metric.baseline_value) if metric.baseline_value is not None else None,
            "metadata": metric.metadata_json,
            "createdAt": metric.created_at.isoformat(),
        }

    def serialize_finding(self, finding: Finding) -> dict[str, object]:
        return self._serialize_finding(
            finding,
            self._external_issue_link_for_finding(finding.id),
        )

    def _serialize_finding(
        self,
        finding: Finding,
        external_issue_link: ExternalIssueLink | None,
    ) -> dict[str, object]:
        self._validate_finding_contract(finding)
        return {
            "id": str(finding.id),
            "taskId": str(finding.task_id) if finding.task_id else None,
            "domain": finding.domain.value,
            "source": finding.source.value,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "category": finding.category.value,
            "title": finding.title,
            "summary": finding.summary,
            "description": finding.description,
            "evidenceRef": str(finding.evidence_ref) if finding.evidence_ref else None,
            "confidence": float(finding.confidence) if finding.confidence is not None else None,
            "dedupeKey": finding.dedupe_key,
            "rawRef": finding.raw_ref,
            "location": finding.location,
            "evidence": finding.evidence,
            "comment": finding.comment,
            "metadata": finding.metadata_json,
            "externalIssueLink": self._serialize_external_issue_link(
                external_issue_link
            ),
            "createdAt": finding.created_at.isoformat(),
        }

    def _external_issue_link_for_finding(
        self,
        finding_id: UUID,
    ) -> ExternalIssueLink | None:
        return self.db.scalar(
            select(ExternalIssueLink)
            .where(ExternalIssueLink.finding_id == finding_id)
            .order_by(
                ExternalIssueLink.updated_at.desc(),
                ExternalIssueLink.created_at.desc(),
            )
        )

    def _latest_external_issue_links_for_execution(
        self,
        execution_id: UUID,
    ) -> dict[UUID, ExternalIssueLink]:
        rows = list(
            self.db.scalars(
                select(ExternalIssueLink)
                .join(Finding, Finding.id == ExternalIssueLink.finding_id)
                .where(Finding.execution_id == execution_id)
                .order_by(
                    ExternalIssueLink.updated_at.desc(),
                    ExternalIssueLink.created_at.desc(),
                )
            )
        )
        latest: dict[UUID, ExternalIssueLink] = {}
        for row in rows:
            latest.setdefault(row.finding_id, row)
        return latest

    def _serialize_external_issue_link_for_finding(
        self,
        finding_id: UUID,
    ) -> dict[str, object] | None:
        return self._serialize_external_issue_link(
            self._external_issue_link_for_finding(finding_id)
        )

    def _serialize_external_issue_link(
        self,
        link: ExternalIssueLink | None,
    ) -> dict[str, object] | None:
        if link is None:
            return None
        return {
            "id": str(link.id),
            "connectorName": link.connector_name,
            "externalIssueId": link.external_issue_id,
            "externalIssueKey": link.external_issue_key,
            "externalIssueUrl": link.external_issue_url,
            "externalStatus": link.external_status,
            "syncStatus": link.sync_status,
            "lastSyncedAt": link.last_synced_at.isoformat() if link.last_synced_at else None,
            "lastStatusSyncedAt": link.last_status_synced_at.isoformat() if link.last_status_synced_at else None,
            "evidenceRefs": link.evidence_refs,
            "replayRefs": link.replay_refs,
            "traceRefs": link.trace_refs,
            "auditRefs": link.audit_refs,
        }

    def serialize_requirement_version(self, row: RequirementVersion) -> dict[str, object]:
        return validate_contract(
            "requirement-version",
            {
                "schemaVersion": "phase8.requirement-version.v1",
                "requirementVersionId": str(row.id),
                "sourceRef": row.source_ref,
                "version": row.version_no,
                "contentHash": row.content_hash,
                "document": row.document,
                "requirements": row.requirements,
                "acceptanceCriteria": row.acceptance_criteria,
                "metadata": row.metadata_json,
                "createdAt": row.created_at.isoformat(),
            },
        )

    def serialize_clarification(self, row: ClarificationItem) -> dict[str, object]:
        return validate_contract(
            "clarification",
            {
                "schemaVersion": "phase8.clarification.v1",
                "clarificationId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "question": row.question,
                "priority": row.priority,
                "status": row.status,
                "answer": row.answer,
                "evidenceRefs": row.evidence_refs,
                "metadata": {**row.metadata_json, "questionKey": row.question_key},
            },
        )

    def serialize_test_asset(self, row: TestAsset) -> dict[str, object]:
        return validate_contract(
            "test-asset",
            {
                "schemaVersion": "phase8.test-asset.v1",
                "assetId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "assetType": row.asset_type,
                "domain": row.domain,
                "title": row.title,
                "objective": row.objective,
                "requirementRefs": row.requirement_refs,
                "status": row.status,
                "evidenceRefs": row.evidence_refs,
                "metadata": row.metadata_json,
            },
        )

    def serialize_asset_review(self, row: TestAssetReview) -> dict[str, object]:
        return validate_contract(
            "asset-review",
            {
                "schemaVersion": "phase8.asset-review.v1",
                "reviewId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "planId": str(row.test_plan_id),
                "status": row.status,
                "confidence": float(row.confidence),
                "issues": row.issues,
                "coverageMap": row.coverage_map,
                "evidenceRefs": row.evidence_refs,
                "metadata": row.metadata_json,
            },
        )

    def serialize_execution_plan(self, row: ExecutionPlan) -> dict[str, object]:
        return validate_contract(
            "execution-plan",
            {
                "schemaVersion": "phase8.execution-plan.v1",
                "executionPlanId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "testPlanId": str(row.test_plan_id),
                "status": row.status,
                "riskLevel": row.risk_level.value,
                "approvalRequired": row.approval_required,
                "tasks": row.tasks,
                "assetRefs": row.asset_refs,
                "retryStrategy": row.retry_strategy,
                "replayRefs": row.replay_refs,
                "requirementScope": row.requirement_scope,
                "metadata": row.metadata_json,
            },
        )

    def serialize_raw_finding(self, row: RawFindingRecord) -> dict[str, object]:
        return {
            "id": str(row.id),
            "executionId": str(row.execution_id),
            "taskId": str(row.task_id) if row.task_id else None,
            "source": row.source,
            "category": row.category,
            "severity": row.severity,
            "title": row.title,
            "summary": row.summary,
            "confidence": float(row.confidence),
            "dedupeKey": row.dedupe_key,
            "rawRef": row.raw_ref,
            "location": row.location,
            "evidence": row.evidence,
            "normalizedFindingId": str(row.normalized_finding_id) if row.normalized_finding_id else None,
            "metadata": row.metadata_json,
            "createdAt": row.created_at.isoformat(),
        }

    def serialize_correction(self, row: CorrectionRecord) -> dict[str, object]:
        return validate_contract(
            "correction-record",
            {
                "schemaVersion": "phase8.correction-record.v1",
                "correctionId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "executionId": str(row.execution_id) if row.execution_id else None,
                "targetType": row.target_type,
                "targetId": row.target_id,
                "before": row.before_payload,
                "after": row.after_payload,
                "reason": row.reason,
                "actorRef": row.actor_ref,
                "evidenceRefs": row.evidence_refs,
                "affectedAssetRefs": row.affected_asset_refs,
                "createdAt": row.created_at.isoformat(),
                "metadata": row.metadata_json,
            },
        )

    def serialize_domain_event(self, row: DomainEventRecord) -> dict[str, object]:
        return validate_contract(
            "domain-event",
            {
                "eventId": row.event_id,
                "eventType": row.event_type,
                "schemaVersion": row.schema_version,
                "traceId": str(row.trace_id) if row.trace_id else "",
                "correlationRefs": row.correlation_refs,
                "occurredAt": row.occurred_at.isoformat(),
                "actorRef": row.actor_ref,
                "sourceRef": row.source_ref,
                "payload": row.payload,
                "evidenceRefs": row.evidence_refs,
                "replayRefs": row.replay_refs,
            },
        )

    def serialize_approval(self, row: Approval) -> dict[str, object]:
        return {
            "id": str(row.id),
            "type": row.type.value,
            "resourceType": row.resource_type,
            "resourceId": row.resource_id,
            "summary": row.summary,
            "payload": row.payload,
            "status": row.status.value,
            "requestedBy": str(row.requested_by) if row.requested_by else None,
            "decidedBy": str(row.decided_by) if row.decided_by else None,
            "decisionComment": row.decision_comment,
            "decidedAt": row.decided_at.isoformat() if row.decided_at else None,
            "createdAt": row.created_at.isoformat(),
            "updatedAt": row.updated_at.isoformat(),
        }

    def _validate_finding_contract(self, finding: Finding) -> None:
        validate_contract(
            "finding",
            {
                "id": str(finding.id),
                "source": finding.source.value,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "title": finding.title,
                "summary": finding.summary,
                "evidence": finding.evidence,
                "location": finding.location,
                "confidence": float(finding.confidence) if finding.confidence is not None else None,
                "dedupeKey": finding.dedupe_key,
                "rawRef": finding.raw_ref,
            },
        )

    def serialize_gate(self, gate: GateDecision) -> dict[str, object]:
        return {
            "gateDecisionId": str(gate.id),
            "executionId": str(gate.execution_id),
            "functional": gate.functional.value,
            "performance": gate.performance.value,
            "security": gate.security.value,
            "overall": gate.overall.value,
            "reasons": gate.reasons,
            "reasonCodes": list(gate.reason_codes or []),
            "matchedRules": list(gate.matched_rules or []),
            "completeness": dict(gate.completeness or {}),
            "confidence": float(gate.confidence),
            "policyVersionId": gate.policy_version_id,
            "policyVersionHash": gate.policy_version_hash,
            "policyBindingRef": gate.policy_binding_ref,
            "inputFingerprint": gate.input_fingerprint,
            "decisionSnapshot": dict(gate.decision_snapshot or {}),
            "decisionSnapshotHash": gate.decision_snapshot_hash,
            "evaluatorVersion": gate.evaluator_version,
            "decidedBy": gate.decided_by,
            "createdAt": gate.created_at.isoformat(),
        }

    def serialize_orchestration(
        self,
        run: OrchestrationRun,
        checkpoints: list[OrchestrationCheckpoint],
    ) -> dict[str, object]:
        return {
            "id": str(run.id),
            "source": run.source,
            "triggerType": run.trigger_type,
            "status": run.status.value,
            "currentStep": run.current_step,
            "traceId": str(run.trace_id) if run.trace_id else None,
            "planId": str(run.linked_plan_id) if run.linked_plan_id else None,
            "executionId": str(run.linked_execution_id) if run.linked_execution_id else None,
            "requirementVersionId": str(run.linked_requirement_version_id) if run.linked_requirement_version_id else None,
            "requirementScope": self._requirement_scope_for_orchestration(run),
            "checkpointCount": len(checkpoints),
            "result": run.result_payload,
            "errorMessage": run.error_message,
            "startedAt": run.started_at.isoformat() if run.started_at else None,
            "endedAt": run.ended_at.isoformat() if run.ended_at else None,
            "checkpoints": [self.serialize_orchestration_checkpoint(item) for item in checkpoints],
        }

    def _requirement_scope_for_orchestration(self, run: OrchestrationRun) -> dict[str, object] | None:
        if run.requirement_scope:
            return dict(run.requirement_scope)
        if run.linked_plan_id is not None:
            plan = self.db.get(TestPlan, run.linked_plan_id)
            if plan is not None and plan.requirement_scope:
                return dict(plan.requirement_scope)
        for key in ("selectedRequirementContext", "requirementLibrarySelection"):
            raw = (run.envelope_snapshot or {}).get(key)
            if isinstance(raw, dict) and isinstance(raw.get("requirementScope"), dict):
                return dict(raw["requirementScope"])
        return None

    def serialize_orchestration_checkpoint(self, checkpoint: OrchestrationCheckpoint) -> dict[str, object]:
        return {
            "id": str(checkpoint.id),
            "runId": str(checkpoint.run_id),
            "sequenceNo": checkpoint.sequence_no,
            "stepName": checkpoint.step_name,
            "executionStage": checkpoint.execution_stage,
            "status": checkpoint.status.value,
            "traceId": str(checkpoint.trace_id) if checkpoint.trace_id else None,
            "executionId": str(checkpoint.execution_id) if checkpoint.execution_id else None,
            "envelope": checkpoint.envelope_snapshot,
            "result": checkpoint.result_payload,
            "errorMessage": checkpoint.error_message,
            "startedAt": checkpoint.started_at.isoformat() if checkpoint.started_at else None,
            "endedAt": checkpoint.ended_at.isoformat() if checkpoint.ended_at else None,
            "createdAt": checkpoint.created_at.isoformat(),
        }

    def serialize_visual_grounding_attempt(self, attempt: VisualGroundingAttempt) -> dict[str, object]:
        return {
            "id": str(attempt.id),
            "executionId": str(attempt.execution_id),
            "taskId": str(attempt.task_id) if attempt.task_id else None,
            "actionId": attempt.action_id,
            "actionType": attempt.action_type,
            "candidateLocators": attempt.candidate_locators,
            "chosenLocator": attempt.chosen_locator,
            "confidence": float(attempt.confidence) if attempt.confidence is not None else None,
            "threshold": float(attempt.threshold) if attempt.threshold is not None else None,
            "coordinateClickAllowed": attempt.coordinate_click_allowed,
            "riskLevel": attempt.risk_level.value,
            "guardrailDecision": attempt.guardrail_decision.value if attempt.guardrail_decision else None,
            "verificationStatus": attempt.verification_status,
            "verificationResult": attempt.verification_result,
            "artifactRefs": attempt.artifact_refs,
            "redactionStatus": attempt.redaction_status,
            "status": attempt.status,
            "errorMessage": attempt.error_message,
            "createdAt": attempt.created_at.isoformat(),
        }

    def serialize_verification_result(self, result: VerificationResult) -> dict[str, object]:
        return {
            "id": str(result.id),
            "executionId": str(result.execution_id),
            "taskId": str(result.task_id) if result.task_id else None,
            "visualAttemptId": str(result.visual_attempt_id) if result.visual_attempt_id else None,
            "verificationType": result.verification_type,
            "status": result.status,
            "confidence": float(result.confidence) if result.confidence is not None else None,
            "evidence": result.evidence,
            "artifactRefs": result.artifact_refs,
            "resultPayload": result.result_payload,
            "normalizedFindingId": str(result.normalized_finding_id) if result.normalized_finding_id else None,
            "createdAt": result.created_at.isoformat(),
        }

    def _build_decision_path(
        self,
        spans: list[TraceSpan],
        invocations: list[ModelInvocation],
        agent_runs: list[AgentRun],
        skill_invocations: list[SkillInvocation],
        guardrail_events: list[GuardrailEvent],
    ) -> list[dict[str, object]]:
        # Flatten heterogeneous records into one ordered list so the API stays
        # easy for the UI and future audit exports to consume.
        decision_path: list[dict[str, object]] = []
        for span in spans:
            decision_path.append(
                {
                    "step": span.span_name,
                    "serviceName": span.service_name,
                    "status": span.status,
                    "timestamp": self._serialize_time(span.start_time or span.created_at),
                    "attributes": span.attributes,
                }
            )
        for invocation in invocations:
            decision_path.append(
                {
                    "step": "model.invoke",
                    "serviceName": "model-gateway",
                    "status": "ok" if invocation.success else "error",
                    "timestamp": invocation.created_at.isoformat(),
                    "attributes": {
                        "role": invocation.response_payload.get("role"),
                        "latencyMs": invocation.latency_ms,
                        "totalTokens": invocation.total_tokens,
                    },
                }
            )
        for agent_run in agent_runs:
            decision_path.append(
                {
                    "step": f"agent.{agent_run.agent_name}",
                    "serviceName": "agent-service",
                    "status": agent_run.status.value,
                    "timestamp": agent_run.created_at.isoformat(),
                    "attributes": {"taskId": str(agent_run.task_id) if agent_run.task_id else None},
                }
            )
        for invocation in skill_invocations:
            version = self.db.get(SkillVersion, invocation.skill_version_id)
            skill = self.db.get(Skill, version.skill_ref_id) if version else None
            decision_path.append(
                {
                    "step": f"skill.{skill.skill_id if skill else invocation.skill_version_id}",
                    "serviceName": "agent-service",
                    "status": invocation.status,
                    "timestamp": invocation.created_at.isoformat(),
                    "attributes": {
                        "skillInvocationId": str(invocation.id),
                        "skillVersionId": str(invocation.skill_version_id),
                        "manifestHash": version.manifest_hash if version else None,
                    },
                }
            )
        for event in guardrail_events:
            decision_path.append(
                {
                    "step": f"guardrail.{event.rule_id}",
                    "serviceName": "guardrails",
                    "status": event.decision.value,
                    "timestamp": event.created_at.isoformat(),
                    "attributes": {
                        "reason": event.message,
                        "executionId": str(event.execution_id) if event.execution_id else None,
                        "skillInvocationId": str(event.skill_invocation_id) if event.skill_invocation_id else None,
                    },
                }
            )
        return sorted(decision_path, key=lambda item: item["timestamp"] or "")

    def _build_timeline(
        self,
        spans: list[TraceSpan],
        invocations: list[ModelInvocation],
        agent_runs: list[AgentRun],
        skill_invocations: list[SkillInvocation],
        audit_logs: list[AuditLog],
        guardrail_events: list[GuardrailEvent],
        orchestrator_checkpoints: list[OrchestrationCheckpoint],
        visual_grounding_attempts: list[VisualGroundingAttempt],
        verification_results: list[VerificationResult],
        *,
        compact: bool = False,
        skill_metadata: dict[
            UUID,
            tuple[SkillVersion | None, Skill | None],
        ] | None = None,
    ) -> list[dict[str, object]]:
        # Replay consumers only care about chronological events, so normalize
        # spans, model calls, agent runs, and audit logs onto one timeline.
        events: list[tuple[datetime, dict[str, object]]] = []
        for span in spans:
            event_time = span.start_time or span.created_at
            events.append(
                (
                    event_time,
                    {
                        "kind": "span",
                        "timestamp": self._serialize_time(event_time),
                        "traceId": str(span.trace_id),
                        "label": span.span_name,
                        "serviceName": span.service_name,
                        "status": span.status,
                        "details": {} if compact else span.attributes,
                    },
                )
            )
        for model_invocation in invocations:
            events.append(
                (
                    model_invocation.created_at,
                    {
                        "kind": "model_invocation",
                        "timestamp": model_invocation.created_at.isoformat(),
                        "traceId": str(model_invocation.trace_id) if model_invocation.trace_id else None,
                        "label": model_invocation.request_summary or "model invocation",
                        "status": "ok" if model_invocation.success else "error",
                        "details": {
                            "role": model_invocation.response_payload.get("role"),
                            "latencyMs": model_invocation.latency_ms,
                            "totalTokens": model_invocation.total_tokens,
                        },
                    },
                )
            )
        for agent_run in agent_runs:
            events.append(
                (
                    agent_run.created_at,
                    {
                        "kind": "agent_run",
                        "timestamp": agent_run.created_at.isoformat(),
                        "traceId": str(agent_run.trace_id) if agent_run.trace_id else None,
                        "label": agent_run.agent_name,
                        "status": agent_run.status.value,
                        "details": {"taskId": str(agent_run.task_id) if agent_run.task_id else None},
                    },
                )
            )
        for skill_invocation in skill_invocations:
            if skill_metadata is None:
                version = self.db.get(SkillVersion, skill_invocation.skill_version_id)
                skill = self.db.get(Skill, version.skill_ref_id) if version else None
            else:
                version, skill = skill_metadata.get(
                    skill_invocation.skill_version_id,
                    (None, None),
                )
            events.append(
                (
                    skill_invocation.created_at,
                    {
                        "kind": "skill_invocation",
                        "timestamp": skill_invocation.created_at.isoformat(),
                        "traceId": str(skill_invocation.trace_id) if skill_invocation.trace_id else None,
                        "label": skill.skill_id if skill else str(skill_invocation.skill_version_id),
                        "status": skill_invocation.status,
                        "details": (
                            {}
                            if compact
                            else {
                                "skillInvocationId": str(skill_invocation.id),
                                "skillVersionId": str(skill_invocation.skill_version_id),
                                "manifestHash": version.manifest_hash if version else None,
                                "inputSnapshot": redact_sensitive_data(skill_invocation.input_snapshot),
                                "outputSnapshot": redact_sensitive_data(skill_invocation.output_snapshot),
                                "policySnapshot": redact_sensitive_data(skill_invocation.policy_snapshot),
                                "connectorBindingSnapshot": self.connector_snapshot_builder.build(
                                    skill_invocation.connector_binding_snapshot
                                ),
                            }
                        ),
                    },
                )
            )
        for guardrail_event in guardrail_events:
            events.append(
                (
                    guardrail_event.created_at,
                    {
                        "kind": "guardrail",
                        "timestamp": guardrail_event.created_at.isoformat(),
                        "traceId": str(guardrail_event.trace_id) if guardrail_event.trace_id else None,
                        "label": guardrail_event.rule_id,
                        "status": guardrail_event.decision.value,
                        "details": {
                            "reason": guardrail_event.message,
                            "executionId": str(guardrail_event.execution_id) if guardrail_event.execution_id else None,
                            "skillInvocationId": str(guardrail_event.skill_invocation_id) if guardrail_event.skill_invocation_id else None,
                        },
                    },
                )
            )
        for audit_log in audit_logs:
            events.append(
                (
                    audit_log.created_at,
                    {
                        "kind": "audit_log",
                        "timestamp": audit_log.created_at.isoformat(),
                        "traceId": str(audit_log.trace_id) if audit_log.trace_id else None,
                        "label": audit_log.action,
                        "status": "recorded",
                        "details": {
                            "resourceType": audit_log.resource_type,
                            "resourceId": audit_log.resource_id,
                            "requestId": audit_log.request_id,
                        },
                    },
                )
            )
        for checkpoint in orchestrator_checkpoints:
            checkpoint_time = checkpoint.ended_at or checkpoint.created_at
            events.append(
                (
                    checkpoint_time,
                    {
                        "kind": "orchestration_checkpoint",
                        "timestamp": checkpoint_time.isoformat(),
                        "traceId": str(checkpoint.trace_id) if checkpoint.trace_id else None,
                        "label": checkpoint.step_name,
                        "status": checkpoint.status.value,
                        "details": {
                            "executionStage": checkpoint.execution_stage,
                            "sequenceNo": checkpoint.sequence_no,
                            "executionId": str(checkpoint.execution_id) if checkpoint.execution_id else None,
                        },
                    },
                )
            )
        for attempt in visual_grounding_attempts:
            events.append(
                (
                    attempt.created_at,
                    {
                        "kind": "visual_grounding",
                        "timestamp": attempt.created_at.isoformat(),
                        "traceId": str(attempt.trace_id) if attempt.trace_id else None,
                        "label": attempt.action_id,
                        "status": attempt.status,
                        "details": {
                            "actionType": attempt.action_type,
                            "confidence": float(attempt.confidence) if attempt.confidence is not None else None,
                            "chosenLocator": None if compact else attempt.chosen_locator,
                            "guardrailDecision": attempt.guardrail_decision.value if attempt.guardrail_decision else None,
                        },
                    },
                )
            )
        for result in verification_results:
            events.append(
                (
                    result.created_at,
                    {
                        "kind": "verification",
                        "timestamp": result.created_at.isoformat(),
                        "traceId": str(result.trace_id) if result.trace_id else None,
                        "label": result.verification_type,
                        "status": result.status,
                        "details": {
                            "confidence": float(result.confidence) if result.confidence is not None else None,
                            "normalizedFindingId": str(result.normalized_finding_id) if result.normalized_finding_id else None,
                        },
                    },
                )
            )
        ordered = sorted(events, key=lambda item: item[0])
        timeline = [event for _, event in ordered]
        if compact:
            for timeline_event in timeline:
                timeline_event.pop("details", None)
        return timeline

    def _build_trace_counts(
        self,
        trace_ids: list[UUID],
        *,
        exclude_audit_actions: set[str] | None = None,
    ) -> dict[UUID, dict[str, int]]:
        if not trace_ids:
            return {}

        counts = {trace_id: self._empty_trace_counts() for trace_id in trace_ids}
        aggregates = [
            ("spanCount", TraceSpan),
            ("modelInvocationCount", ModelInvocation),
            ("agentRunCount", AgentRun),
            ("skillInvocationCount", SkillInvocation),
            ("auditLogCount", AuditLog),
            ("guardrailEventCount", GuardrailEvent),
        ]
        for key, model in aggregates:
            statement = (
                select(model.trace_id, func.count())
                .where(model.trace_id.in_(trace_ids))
                .group_by(model.trace_id)
            )
            if model is AuditLog and exclude_audit_actions:
                statement = statement.where(
                    ~AuditLog.action.in_(exclude_audit_actions)
                )
            rows = self.db.execute(statement)
            for trace_id, count in rows:
                counts[trace_id][key] = count
        return counts

    def _load_models(self, model_ids: list[UUID | None]) -> dict[UUID, Model]:
        normalized_ids = [model_id for model_id in model_ids if model_id is not None]
        if not normalized_ids:
            return {}
        models = self.db.scalars(select(Model).where(Model.id.in_(normalized_ids)))
        return {model.id: model for model in models}

    def _load_skill_metadata(
        self,
        invocations: list[SkillInvocation],
    ) -> dict[UUID, tuple[SkillVersion | None, Skill | None]]:
        version_ids = {invocation.skill_version_id for invocation in invocations}
        if not version_ids:
            return {}
        versions = list(
            self.db.scalars(select(SkillVersion).where(SkillVersion.id.in_(version_ids)))
        )
        skill_ids = {version.skill_ref_id for version in versions}
        skills = (
            list(self.db.scalars(select(Skill).where(Skill.id.in_(skill_ids))))
            if skill_ids
            else []
        )
        skill_lookup = {skill.id: skill for skill in skills}
        return {
            version.id: (version, skill_lookup.get(version.skill_ref_id))
            for version in versions
        }

    def _empty_trace_counts(self) -> dict[str, int]:
        return {
            "spanCount": 0,
            "modelInvocationCount": 0,
            "agentRunCount": 0,
            "skillInvocationCount": 0,
            "auditLogCount": 0,
            "guardrailEventCount": 0,
        }

    @staticmethod
    def _hash_payload(payload: dict[str, object]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def _audit_retention_state(self, created_at: datetime, audit_log: AuditLog | None = None) -> dict[str, object]:
        retention_days = 365
        expires_at = created_at.replace(tzinfo=timezone.utc) if created_at.tzinfo is None else created_at
        expires_at = (expires_at + timedelta(days=retention_days)).replace(microsecond=0)
        if audit_log is not None and audit_log.retention_until is not None:
            expires_at = audit_log.retention_until
        return {
            "policy": audit_log.retention_policy if audit_log is not None else "default-audit-log-retention",
            "retentionDays": retention_days,
            "expiresAt": expires_at.isoformat(),
            "legalHold": bool(audit_log.legal_hold) if audit_log is not None else False,
            "retentionStatus": audit_log.retention_status if audit_log is not None else "active",
            "archivedAt": audit_log.archived_at.isoformat() if audit_log is not None and audit_log.archived_at else None,
            "purgeEligibleAt": audit_log.purge_eligible_at.isoformat() if audit_log is not None and audit_log.purge_eligible_at else None,
            "destructiveActionsRequireApproval": True,
        }

    def _audit_retention_preview(self, audit_log: AuditLog, action: str, retention_until: datetime | None) -> dict[str, object]:
        preview = self._audit_retention_state(audit_log.created_at, audit_log)
        if retention_until is not None:
            preview["expiresAt"] = retention_until.isoformat()
        if action == "archive":
            preview["retentionStatus"] = "archived"
            preview["archivedAt"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        elif action == "purge":
            preview["retentionStatus"] = "purged"
            preview["purgeEligibleAt"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            preview["blockedByLegalHold"] = bool(audit_log.legal_hold)
        elif action == "set_legal_hold":
            preview["retentionStatus"] = "legal_hold"
            preview["legalHold"] = True
        elif action == "clear_legal_hold":
            preview["retentionStatus"] = "active"
            preview["legalHold"] = False
        else:
            raise ValueError("unsupported audit retention action")
        return preview

    def _audit_retention_policy_decision(self, action: str) -> dict[str, object]:
        risk_level = "high" if action in {"purge", "set_legal_hold", "clear_legal_hold"} else "medium"
        return {
            "approvalMode": "always",
            "approvalRequired": True,
            "policyOutcome": "approval-required",
            "reason": "audit_retention_system_hard_rule",
            "action": f"audit_retention.{action}",
            "riskLevel": risk_level,
            "systemHardRule": True,
        }

    def _record_audit_retention_guardrail(
        self,
        context: ServiceContext,
        *,
        audit_log: AuditLog,
        action: str,
        projected_state: dict[str, object],
        policy_outcome: dict[str, object],
    ) -> list[dict[str, object]]:
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type="audit_retention_action",
            resource_id=str(audit_log.id),
            payload={
                "action": f"audit_retention.{action}",
                "auditLogId": str(audit_log.id),
                "projectedRetentionState": projected_state,
                "policyOutcome": policy_outcome,
            },
        )
        RuntimeGuardrailEngine(self.db).record_result(
            guardrail_context,
            GuardrailResult(
                rule_id="audit_retention.mutation_preflight",
                decision=GuardrailDecision.ALLOW,
                reason="Audit retention mutation passed governance preflight",
                evidence=[f"audit_retention.{action}", str(audit_log.id)],
                metadata={"approvalMode": policy_outcome.get("approvalMode", "always")},
            ),
        )
        self.db.flush()
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.request_id == context.request_id)
                .where(GuardrailEvent.rule_id == "audit_retention.mutation_preflight")
                .order_by(GuardrailEvent.created_at.desc())
            )
        )
        return [{"type": "guardrail_event", "id": str(event.id), "ruleId": event.rule_id, "decision": event.decision.value} for event in events[:1]]

    def _audit_retention_approval_guardrail_refs(self, approval_id: UUID | None) -> list[dict[str, object]]:
        if approval_id is None:
            return []
        approval = self.db.get(Approval, approval_id)
        if approval is None:
            return []
        return list(approval.payload.get("guardrailEventRefs") or [])

    def _approval_request_audit_refs(self, approval_id: UUID) -> list[dict[str, object]]:
        rows = list(
            self.db.scalars(
                select(AuditLog)
                .where(AuditLog.resource_type == "approval")
                .where(AuditLog.resource_id == str(approval_id))
                .where(AuditLog.action == "approval.request")
                .order_by(AuditLog.created_at.desc())
            )
        )
        return [{"type": "audit_log", "id": str(row.id), "action": row.action} for row in rows[:1]]

    def _redaction_status(self, payload: dict[str, object]) -> str:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return "redacted" if "[REDACTED]" in serialized or "***" in serialized else "not_required"

    def _require_trace(self, trace_id: UUID) -> Trace:
        trace = self.db.get(Trace, trace_id)
        if trace is None:
            raise ValueError("trace not found")
        return trace

    def _require_audit_log(self, audit_log_id: UUID) -> AuditLog:
        audit_log = self.db.get(AuditLog, audit_log_id)
        if audit_log is None:
            raise ValueError("audit log not found")
        return audit_log

    def _require_execution(self, execution_id: UUID) -> Execution:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise ValueError("execution not found")
        return execution

    def _serialize_time(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.isoformat()

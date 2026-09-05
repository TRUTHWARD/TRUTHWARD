# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, TypeVar
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from pydantic import BaseModel

from agentic_qa.domain.enums import ApprovalStatus, ExecutionStage, PlanStatus, RiskLevel, SourceType, TaskStatus, TestDomain
from agentic_qa.domain.models import (
    AdmissionRunRecord,
    Approval,
    AuditLog,
    CIEnforcementPolicyRecord,
    CIWritebackAttemptRecord,
    ChangeSetRecord,
    CodeChangeSetRecord,
    Execution,
    ExecutionTask,
    GateDecision,
    GuardrailEvent,
    Project,
    ProjectEnvironment,
    RequirementMatchSnapshotRecord,
    ScmPrContextRecord,
    ScmPrContextVersionRecord,
    SelectiveReplayPlanRecord,
    TestPlan,
    TraceSpan,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.runtime import ActionGuard, RuntimeGuardrailEngine, SandboxExecutionGuard
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.redaction import redact_sensitive_data, redact_sensitive_text
from agentic_qa.infra.trace import ensure_trace, traced_operation
from agentic_qa.schemas.admission import (
    AdmissionArtifactRef,
    AdmissionEnforceGateProjection,
    AdmissionResultProjection,
    AdmissionRetryRequest,
    AdmissionReviewProjection,
    AdmissionReviewRequest,
    AdmissionRunProjection,
    AdmissionRunRequest,
    AdmissionShadowGateProjection,
    AdmissionStageProjection,
    AdmissionTimelineProjection,
    AdmissionToolResult,
    SmokePlan,
    SmokeResult,
    SmokeRun,
    SmokeTestSpec,
    StaticScanResult,
)
from agentic_qa.services.common import (
    IdempotencyConflictError,
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
    paginate_result,
)
from agentic_qa.services.execution_service import ExecutionService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService
from agentic_qa.tools.sandbox_runners import PYTHON_SMOKE_IMAGE, SEMGREP_IMAGE


ContractModel = TypeVar("ContractModel", bound=BaseModel)


def _validated_contract(model_type: type[ContractModel], **values: Any) -> ContractModel:
    return model_type.model_validate(values)


class AdmissionError(ValueError):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


ADMISSION_WORKFLOW_VERSION = "p23.ci-enforce.v1"
DEFAULT_CI_CHECK_NAME = "Agentic QA / PR Admission"
ADMISSION_LIFECYCLE: tuple[str, ...] = (
    "PREPARE",
    "EXECUTE",
    "OBSERVE",
    "ANALYZE",
    "NORMALIZE",
    "GATE",
)


class AdmissionService:
    """Service-owned P21-P23 PR Admission orchestration and authoritative Enforce boundary."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.guardrails = RuntimeGuardrailEngine(db)

    def create_run(
        self,
        project_id: UUID,
        payload: AdmissionRunRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, context, capability="admission.execute")
        if payload.mode in {"shadow", "enforce"} and "admission.mode.manage" not in set(context.user.capabilities):
            raise AdmissionError(
                "ADMISSION_MODE_CAPABILITY_REQUIRED",
                status_code=403,
                field="admission.mode.manage",
            )
        version = self.db.scalar(
            select(ScmPrContextVersionRecord)
            .join(ScmPrContextRecord, ScmPrContextRecord.id == ScmPrContextVersionRecord.context_id)
            .where(
                ScmPrContextVersionRecord.id == payload.prContextVersionId,
                ScmPrContextRecord.project_id == project_id,
                ScmPrContextRecord.tenant_id == scope[0],
                ScmPrContextRecord.workspace_id == scope[1],
            )
        )
        if version is None:
            raise AdmissionError("ADMISSION_PR_CONTEXT_VERSION_NOT_FOUND", status_code=404)
        pr_context = self.db.get(ScmPrContextRecord, version.context_id)
        if pr_context is None:
            raise AdmissionError("ADMISSION_PR_CONTEXT_NOT_FOUND", status_code=404)
        if payload.mode == "enforce":
            policy = self.db.scalar(
                select(CIEnforcementPolicyRecord).where(
                    CIEnforcementPolicyRecord.tenant_id == scope[0],
                    CIEnforcementPolicyRecord.workspace_id == scope[1],
                    CIEnforcementPolicyRecord.project_id == project_id,
                    CIEnforcementPolicyRecord.repository_ref == pr_context.repository_ref,
                    CIEnforcementPolicyRecord.check_name == DEFAULT_CI_CHECK_NAME,
                    CIEnforcementPolicyRecord.mode == "enforce",
                    CIEnforcementPolicyRecord.status == "active",
                    CIEnforcementPolicyRecord.branch_protection_configured.is_(True),
                )
            )
            approval = self.db.get(Approval, policy.activation_approval_id) if policy and policy.activation_approval_id else None
            if policy is None or approval is None or approval.status != ApprovalStatus.APPROVED:
                raise AdmissionError("ADMISSION_ENFORCE_NOT_APPROVED", status_code=409)
        plan = self.db.scalar(
            select(SelectiveReplayPlanRecord).where(
                SelectiveReplayPlanRecord.id == payload.selectiveReplayPlanId,
                SelectiveReplayPlanRecord.tenant_id == scope[0],
                SelectiveReplayPlanRecord.workspace_id == scope[1],
                SelectiveReplayPlanRecord.project_id == project_id,
            )
        )
        if plan is None:
            raise AdmissionError("ADMISSION_REPLAY_PLAN_NOT_FOUND", status_code=404)
        if self._aware(plan.expires_at) <= datetime.now(timezone.utc):
            raise AdmissionError("ADMISSION_REPLAY_PLAN_EXPIRED")
        if plan.plan_snapshot.get("validity", {}).get("requiresRegeneration"):
            raise AdmissionError("ADMISSION_REPLAY_PLAN_STALE")
        if payload.sourceArtifactRef.headSha != version.head_sha.lower():
            raise AdmissionError("ADMISSION_SOURCE_HEAD_MISMATCH", field="sourceArtifactRef.headSha")
        expected_head = plan.replay_snapshot.get("expectedHeadRevision")
        if expected_head and str(expected_head).lower() != version.head_sha.lower():
            raise AdmissionError("ADMISSION_REPLAY_PLAN_HEAD_MISMATCH")
        self._validate_frozen_handoff((scope[0], scope[1]), project_id, version, plan)
        if payload.environmentId is not None:
            environment = self.db.scalar(
                select(ProjectEnvironment).where(
                    ProjectEnvironment.id == payload.environmentId,
                    ProjectEnvironment.project_id == project_id,
                    ProjectEnvironment.status == "active",
                )
            )
            if environment is None:
                raise AdmissionError("ADMISSION_ENVIRONMENT_NOT_FOUND", status_code=404)
        self._validate_source_artifact_ref(
            payload.sourceArtifactRef.storageRef,
            project_id=project_id,
            head_sha=version.head_sha.lower(),
        )

        snapshot = self.db.scalar(
            select(RequirementMatchSnapshotRecord).where(
                RequirementMatchSnapshotRecord.pr_context_version_id == version.id
            )
        )
        if snapshot is None:
            raise AdmissionError("ADMISSION_REQUIREMENT_MATCH_SNAPSHOT_NOT_FOUND")
        smoke_plan = self._build_smoke_plan(plan, version.head_sha.lower())
        input_material = {
            "projectId": str(project_id),
            "repositoryRef": pr_context.repository_ref,
            "pullRequestNumber": pr_context.pull_request_number,
            "prContextVersionId": str(version.id),
            "prContextHash": version.context_hash,
            "requirementMatchSnapshotId": str(snapshot.id) if snapshot else None,
            "requirementMatchHash": snapshot.snapshot_hash if snapshot else None,
            "selectiveReplayPlanId": str(plan.id),
            "selectiveReplayPlanHash": plan.plan_hash,
            "environmentId": str(payload.environmentId) if payload.environmentId else None,
            "mode": payload.mode,
            "workflowVersion": ADMISSION_WORKFLOW_VERSION,
            "sourceArtifactRef": payload.sourceArtifactRef.model_dump(mode="json"),
            "sandboxProfile": payload.sandboxProfile.model_dump(mode="json"),
            "scanTools": sorted(payload.scanTools),
            "smokePlan": smoke_plan.model_dump(mode="json"),
        }
        non_authoritative = payload.mode != "enforce"
        input_fingerprint = canonical_hash(
            {
                "tenantId": scope[0],
                "workspaceId": scope[1],
                "projectId": str(project_id),
                "repositoryRef": pr_context.repository_ref,
                "pullRequestNumber": pr_context.pull_request_number,
                "headSha": version.head_sha.lower(),
                "mode": payload.mode,
                "workflowVersion": ADMISSION_WORKFLOW_VERSION,
            }
        )
        request_hash = canonical_hash(input_material)
        acquire_transaction_advisory_lock(
            self.db,
            "p22-admission-run",
            f"{scope[0]}:{scope[1]}:{project_id}:{input_fingerprint}",
        )
        same_key = self.db.scalar(
            select(AdmissionRunRecord).where(
                AdmissionRunRecord.tenant_id == scope[0],
                AdmissionRunRecord.workspace_id == scope[1],
                AdmissionRunRecord.project_id == project_id,
                AdmissionRunRecord.idempotency_key == payload.idempotencyKey,
            )
        )
        if same_key is not None:
            if same_key.request_hash != request_hash:
                raise IdempotencyConflictError("ADMISSION_IDEMPOTENCY_CONFLICT")
            return self._projection(same_key, deduplicated=True)
        existing = self.db.scalar(
            select(AdmissionRunRecord).where(
                AdmissionRunRecord.tenant_id == scope[0],
                AdmissionRunRecord.workspace_id == scope[1],
                AdmissionRunRecord.project_id == project_id,
                AdmissionRunRecord.repository_ref == pr_context.repository_ref,
                AdmissionRunRecord.pull_request_number == pr_context.pull_request_number,
                AdmissionRunRecord.source_head_sha == version.head_sha.lower(),
                AdmissionRunRecord.admission_mode == payload.mode,
                AdmissionRunRecord.workflow_version == ADMISSION_WORKFLOW_VERSION,
            )
        )
        if existing is not None:
            if existing.request_hash != request_hash:
                raise IdempotencyConflictError("ADMISSION_ORCHESTRATION_CONFLICT")
            return self._projection(existing, deduplicated=True)

        run_id = uuid4()
        trace_id = UUID(str(context.trace_id))
        ensure_trace(self.db, execution_id=None, root_span_name="admission.prepare", trace_id=trace_id)
        guardrail_refs = self._sandbox_preflight(run_id, payload, context)
        base_execution = self.db.get(Execution, plan.base_execution_id)
        base_test_plan = self.db.get(TestPlan, base_execution.plan_id) if base_execution else None
        if base_test_plan is None or base_test_plan.project_id != project_id:
            raise AdmissionError("ADMISSION_REPLAY_BASE_EXECUTION_INVALID")
        test_plan = TestPlan(
            id=uuid4(),
            name=f"PR admission {version.head_sha[:12]}",
            source_type=SourceType.PR,
            source_ref=f"pr-context-version://{version.id}",
            environment=f"p22-admission:{payload.environmentId or 'isolated'}",
            project_id=project_id,
            environment_id=payload.environmentId,
            risk_level=RiskLevel.MEDIUM,
            status=PlanStatus.READY,
            input_payload={
                "prContextVersionId": str(version.id),
                "selectiveReplayPlanId": str(plan.id),
                "mode": payload.mode,
                "workflowVersion": ADMISSION_WORKFLOW_VERSION,
            },
            generated_plan={
                "managedBy": "AdmissionService",
                "arbitraryCommandApi": False,
                "lifecycle": list(ADMISSION_LIFECYCLE),
            },
            requirement_scope={},
            metadata_json={
                "admissionRunId": str(run_id),
                "admissionMode": payload.mode,
                "nonAuthoritative": non_authoritative,
                "admissionDecisionCreated": payload.mode == "enforce",
            },
            created_by=context.user.id,
        )
        execution = Execution(
            id=uuid4(),
            plan_id=test_plan.id,
            status=TaskStatus.QUEUED,
            stage=ExecutionStage.PREPARE,
            environment="p22-admission-sandbox",
            triggered_by=context.user.id,
            trigger_source="pr_admission",
            options={
                "parallelism": 1,
                "admissionRunId": str(run_id),
                "prContextVersionId": str(version.id),
                "sourceHeadSha": version.head_sha.lower(),
                "admissionMode": payload.mode,
                "admissionWorkflowVersion": ADMISSION_WORKFLOW_VERSION,
                "nonAuthoritative": non_authoritative,
                "sandboxProfileHash": canonical_hash(payload.sandboxProfile.model_dump(mode="json")),
            },
            summary={"functional": "queued", "performance": "queued", "security": "queued"},
        )
        self.db.add(test_plan)
        self.db.flush()
        self.db.add(execution)
        self.db.flush()
        ensure_trace(
            self.db,
            execution_id=execution.id,
            root_span_name="admission.run",
            trace_id=trace_id,
        )
        common_config = {
            "sourceStorageRef": payload.sourceArtifactRef.storageRef,
            "sourceContentHash": payload.sourceArtifactRef.contentHash,
            "sourceHeadSha": payload.sourceArtifactRef.headSha,
            "projectId": str(project_id),
            "sandboxProfile": payload.sandboxProfile.model_dump(mode="json"),
            "actualExecution": True,
            "admissionRunId": str(run_id),
            "prContextVersionId": str(version.id),
            "requirementMatchSnapshotId": str(snapshot.id) if snapshot else None,
            "selectiveReplayPlanId": str(plan.id),
        }
        tasks: list[ExecutionTask] = []
        for priority, tool in enumerate(payload.scanTools, start=1):
            if tool != "semgrep":
                raise AdmissionError("ADMISSION_SCAN_TOOL_UNSUPPORTED")
            tasks.append(
                ExecutionTask(
                    id=uuid4(),
                    execution_id=execution.id,
                    domain=TestDomain.SECURITY,
                    task_type="admission.static_scan",
                    runner="sandbox-semgrep",
                    status=TaskStatus.QUEUED,
                    stage=ExecutionStage.PREPARE,
                    priority=priority,
                    config={**common_config, "timeoutSeconds": payload.sandboxProfile.timeoutSeconds},
                    result_payload={"enabled": True, "scanTool": tool},
                )
            )
        offset = len(tasks)
        for index, test in enumerate(smoke_plan.tests, start=1):
            tasks.append(
                ExecutionTask(
                    id=uuid4(),
                    execution_id=execution.id,
                    domain=TestDomain.FUNCTIONAL,
                    task_type="admission.selective_smoke",
                    runner="sandbox-python-unittest",
                    status=TaskStatus.QUEUED,
                    stage=ExecutionStage.PREPARE,
                    priority=offset + index,
                    config={
                        **common_config,
                        "timeoutSeconds": min(payload.sandboxProfile.timeoutSeconds, test.estimatedSeconds + 60),
                        "testModule": test.testModule,
                        "selectedTestRef": test.taskRef,
                        "selectionReasonCodes": test.selectedReasonCodes,
                    },
                    result_payload={"enabled": True, "recipe": test.recipe},
                )
            )
        self.db.add_all(tasks)
        plan_snapshot = {
            "schemaVersion": "phase8.admission-execution-plan.v2",
            "mode": payload.mode,
            "workflowVersion": ADMISSION_WORKFLOW_VERSION,
            "lifecycle": list(ADMISSION_LIFECYCLE),
            "staticScanRequest": {
                "schemaVersion": "phase8.static-scan-request.v1",
                "prContextVersionId": str(version.id),
                "sourceArtifactRef": payload.sourceArtifactRef.model_dump(mode="json"),
                "headSha": version.head_sha.lower(),
                "tools": payload.scanTools,
                "sandboxProfile": payload.sandboxProfile.model_dump(mode="json"),
                "idempotencyKey": payload.idempotencyKey,
            },
            "smokePlan": smoke_plan.model_dump(mode="json"),
            "toolRecipes": ["sandbox-semgrep", *("sandbox-python-unittest" for _ in smoke_plan.tests)],
            "arbitraryCommandApi": False,
        }
        replay_snapshot = {
            "schemaVersion": "phase8.admission-replay-snapshot.v2",
            "mode": payload.mode,
            "workflowVersion": ADMISSION_WORKFLOW_VERSION,
            "nonAuthoritative": non_authoritative,
            "inputFingerprint": input_fingerprint,
            "repositoryRef": pr_context.repository_ref,
            "pullRequestNumber": pr_context.pull_request_number,
            "baseSha": version.base_sha.lower(),
            "sourceHeadSha": version.head_sha.lower(),
            "sourceArtifactRef": payload.sourceArtifactRef.model_dump(mode="json"),
            "prContextVersion": {"id": str(version.id), "contentHash": version.context_hash},
            "requirementMatchSnapshot": (
                {"id": str(snapshot.id), "contentHash": snapshot.snapshot_hash} if snapshot else None
            ),
            "changeSetId": str(version.change_set_id) if version.change_set_id else None,
            "selectiveReplayPlan": {"id": str(plan.id), "planHash": plan.plan_hash},
            "sandboxProfile": payload.sandboxProfile.model_dump(mode="json"),
            "tools": [
                {"runner": "sandbox-semgrep", "image": SEMGREP_IMAGE, "version": "1.163.0"},
                *(
                    {"runner": "sandbox-python-unittest", "image": PYTHON_SMOKE_IMAGE, "version": "3.14"}
                    for _ in smoke_plan.tests
                ),
            ],
            "toolRecipes": plan_snapshot["toolRecipes"],
            "gateDecisionCreated": False,
            "admissionDecisionCreated": False,
            "ciWriteback": False,
            "mergeBlocking": False,
        }
        record = AdmissionRunRecord(
            id=run_id,
            tenant_id=scope[0],
            workspace_id=scope[1],
            project_id=project_id,
            pr_context_version_id=version.id,
            requirement_match_snapshot_id=snapshot.id if snapshot else None,
            selective_replay_plan_id=plan.id,
            environment_id=payload.environmentId,
            execution_id=execution.id,
            repository_ref=pr_context.repository_ref,
            pull_request_number=pr_context.pull_request_number,
            base_sha=version.base_sha.lower(),
            source_head_sha=version.head_sha.lower(),
            admission_mode=payload.mode,
            workflow_version=ADMISSION_WORKFLOW_VERSION,
            non_authoritative=non_authoritative,
            input_fingerprint=input_fingerprint,
            idempotency_key=payload.idempotencyKey,
            request_hash=request_hash,
            status="queued",
            sandbox_profile=payload.sandboxProfile.model_dump(mode="json"),
            plan_snapshot=plan_snapshot,
            stage_snapshot=self._initial_stage_snapshot(non_authoritative=non_authoritative),
            result_snapshot={},
            result_snapshot_hash=None,
            shadow_gate_snapshot=None,
            retry_snapshot={"attemptCount": 1, "state": "not_requested"},
            attempt_count=1,
            replay_snapshot=replay_snapshot,
            trace_id=trace_id,
            guardrail_event_refs=guardrail_refs,
            audit_refs=[],
            created_by=context.user.id,
        )
        self.db.add(record)
        self.db.flush()
        audit = write_audit_log(
            self.db,
            context.user.id,
            "admission.run.create",
            "admission_run",
            str(record.id),
            context.request_id,
            context.trace_id,
            execution_id=execution.id,
            details={
                "projectId": str(project_id),
                "prContextVersionId": str(version.id),
                "selectiveReplayPlanId": str(plan.id),
                "inputFingerprint": input_fingerprint,
                "sourceHeadSha": version.head_sha.lower(),
                "mode": payload.mode,
                "workflowVersion": ADMISSION_WORKFLOW_VERSION,
                "nonAuthoritative": non_authoritative,
                "sandboxed": True,
                "gateDecisionCreated": False,
                "admissionDecisionCreated": False,
            },
        )
        self.db.flush()
        record.audit_refs = [self._audit_ref(audit)]
        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            recovered = self.db.scalar(
                select(AdmissionRunRecord).where(
                    AdmissionRunRecord.tenant_id == scope[0],
                    AdmissionRunRecord.workspace_id == scope[1],
                    AdmissionRunRecord.project_id == project_id,
                    AdmissionRunRecord.input_fingerprint == input_fingerprint,
                )
            )
            if recovered is not None:
                return self._projection(recovered, deduplicated=True)
            raise AdmissionError("ADMISSION_CONCURRENT_CREATE_CONFLICT") from exc

        from agentic_qa.infra.queue import enqueue_task

        try:
            queued = enqueue_task(
                "admission.run",
                str(record.id),
                str(context.user.id),
                list(context.user.roles),
                context.request_id,
                context.trace_id,
            )
        except Exception as exc:
            self._mark_dispatch_unavailable(record.id, context, str(exc))
            raise AdmissionError("ADMISSION_QUEUE_UNAVAILABLE", status_code=503) from exc
        self.db.expire_all()
        refreshed = self.db.get(AdmissionRunRecord, record.id)
        projection = self._projection(refreshed or record, deduplicated=False)
        projection["queueTaskId"] = str(queued.id)
        return projection

    def run_job(self, run_id: UUID, context: ServiceContext) -> dict[str, Any]:
        record = self._require_run(run_id)
        if record.status in {"completed", "failed", "partial", "unavailable", "cancelled", "stale"}:
            return self._projection(record, deduplicated=True)
        context = ServiceContext(
            user=context.user,
            request_id=context.request_id,
            trace_id=str(record.trace_id),
        )
        version = self.db.get(ScmPrContextVersionRecord, record.pr_context_version_id)
        plan = self.db.get(SelectiveReplayPlanRecord, record.selective_replay_plan_id)
        if version is None or plan is None:
            raise AdmissionError("ADMISSION_FROZEN_INPUT_MISSING")
        pr_context = self.db.get(ScmPrContextRecord, version.context_id)
        current_head = pr_context.latest_head_sha.lower() if pr_context else None
        if (
            version.head_sha.lower() != record.source_head_sha
            or current_head != record.source_head_sha
            or self._aware(plan.expires_at) <= datetime.now(timezone.utc)
        ):
            reason_code = (
                "ADMISSION_REPLAY_PLAN_EXPIRED"
                if self._aware(plan.expires_at) <= datetime.now(timezone.utc)
                else "ADMISSION_HEAD_CHANGED"
            )
            self._finalize_without_execution(record, status="stale", reason_code=reason_code)
            self.db.commit()
            return self._projection(record, deduplicated=False)
        pr_block_reason = self._pr_execution_block_reason(pr_context, version)
        if pr_block_reason is not None:
            self._finalize_without_execution(record, status="unavailable", reason_code=pr_block_reason)
            self.db.commit()
            return self._projection(record, deduplicated=False)
        self._validate_frozen_handoff(
            (record.tenant_id, record.workspace_id),
            record.project_id,
            version,
            plan,
        )
        self._stage_preflight(record, "PREPARE", context)
        record.status = "running"
        record.stage_snapshot = self._running_stage_snapshot(
            "PREPARE", non_authoritative=record.non_authoritative
        )
        self.db.commit()
        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=record.execution_id,
                root_span_name="admission.run",
                span_name="admission.orchestrate",
                service_name="orchestrator-service",
                attributes={
                    "admissionRunId": str(record.id),
                    "prContextVersionId": str(record.pr_context_version_id),
                    "sourceHeadSha": record.source_head_sha,
                    "mode": record.admission_mode,
                    "workflowVersion": record.workflow_version,
                    "nonAuthoritative": record.non_authoritative,
                    "gateDecisionCreated": False,
                },
            ):
                runtime = dict(
                    ExecutionService(self.db).run_managed_admission_execution(record.execution_id, context)
                )
                raw_runtime_counts = runtime.get("counts")
                runtime_counts = dict(raw_runtime_counts) if isinstance(raw_runtime_counts, dict) else {}
                result_snapshot = self._build_result_snapshot(record, runtime)
                shadow_gate: dict[str, Any] | None = None
                enforce_gate: dict[str, Any] | None = None
                if record.admission_mode == "shadow":
                    self._stage_preflight(record, "GATE", context)
                    try:
                        with traced_operation(
                            self.db,
                            trace_id=context.trace_id,
                            execution_id=record.execution_id,
                            root_span_name="admission.run",
                            span_name="admission.gate.shadow",
                            service_name="orchestrator-service",
                            attributes={
                                "admissionRunId": str(record.id),
                                "nonAuthoritative": True,
                                "gateDecisionCreated": False,
                                "ciWriteback": False,
                            },
                        ):
                            shadow_gate = ExecutionService(self.db).evaluate_admission_shadow_gate(
                                record.execution_id,
                                context,
                            )
                    except Exception as gate_exc:
                        shadow_gate = AdmissionShadowGateProjection(
                            status="unavailable",
                            decision=None,
                            evaluatedAt=datetime.now(timezone.utc),
                            reasonCode="ADMISSION_SHADOW_GATE_UNAVAILABLE",
                        ).model_dump(mode="json")
                        result_snapshot["shadowGateError"] = str(
                            redact_sensitive_data(str(gate_exc))
                        )
                elif record.admission_mode == "enforce":
                    self._stage_preflight(record, "GATE", context)
                    try:
                        with traced_operation(
                            self.db,
                            trace_id=context.trace_id,
                            execution_id=record.execution_id,
                            root_span_name="admission.run",
                            span_name="admission.gate.enforce",
                            service_name="orchestrator-service",
                            attributes={
                                "admissionRunId": str(record.id),
                                "nonAuthoritative": False,
                                "gateAuthority": "execution-service",
                                "ciConclusionOwner": "domain-service",
                            },
                        ):
                            enforce_gate = ExecutionService(self.db).evaluate_admission_enforce_gate(
                                record.execution_id,
                                context,
                            )
                    except Exception as gate_exc:
                        enforce_gate = AdmissionEnforceGateProjection(
                            status="unavailable",
                            decision=None,
                            gateDecisionId=None,
                            gateDecisionRef=None,
                            evaluatedAt=datetime.now(timezone.utc),
                            reasonCode="ADMISSION_ENFORCE_GATE_UNAVAILABLE",
                            gateDecisionCreated=False,
                        ).model_dump(mode="json")
                        result_snapshot["enforceGateError"] = str(redact_sensitive_data(str(gate_exc)))
                gate_projection = enforce_gate if record.admission_mode == "enforce" else shadow_gate
                stages = self._completed_stage_snapshot(record, result_snapshot, gate_projection)
                result_snapshot["shadowGate"] = shadow_gate
                result_snapshot["enforceGate"] = enforce_gate
                result_snapshot["stages"] = stages
                admission_result = self._build_admission_result(
                    record, result_snapshot, shadow_gate, enforce_gate
                )
                result_snapshot["admissionResult"] = admission_result
                result_snapshot["schemaVersion"] = "phase8.admission-result-snapshot.v3"
                result_snapshot["nonAuthoritative"] = record.non_authoritative
                result_snapshot["ciWriteback"] = False
                result_snapshot["mergeBlocking"] = bool(admission_result["mergeBlocking"])
                record.status = self._admission_overall_status(result_snapshot, gate_projection)
                result_snapshot["overallStatus"] = record.status
                record.result_snapshot = result_snapshot
                record.result_snapshot_hash = canonical_hash(result_snapshot)
                record.shadow_gate_snapshot = shadow_gate
                record.stage_snapshot = stages
                record.guardrail_event_refs = self._all_guardrail_refs(record)
                record.replay_snapshot = {
                    **record.replay_snapshot,
                    "stageSnapshotHash": canonical_hash(stages),
                    "resultSnapshotHash": record.result_snapshot_hash,
                    "shadowGateSnapshotHash": canonical_hash(shadow_gate) if shadow_gate else None,
                    "enforceGateSnapshotHash": canonical_hash(enforce_gate) if enforce_gate else None,
                    "normalizedFindingRefs": admission_result["normalizedFindingRefs"],
                    "gateDecisionCreated": bool(admission_result["gateDecisionCreated"]),
                    "admissionDecisionCreated": record.admission_mode == "enforce",
                    "ciWriteback": False,
                    "mergeBlocking": bool(admission_result["mergeBlocking"]),
                }
                audit = write_audit_log(
                    self.db,
                    context.user.id,
                    "admission.run.complete",
                    "admission_run",
                    str(record.id),
                    context.request_id,
                    context.trace_id,
                    execution_id=record.execution_id,
                    details={
                        "status": record.status,
                        "executionId": str(record.execution_id),
                        "rawFindingCount": runtime_counts["rawFindingRefCount"],
                        "normalizedFindingCount": runtime_counts["normalizedFindingRefCount"],
                        "mode": record.admission_mode,
                        "nonAuthoritative": record.non_authoritative,
                        "shadowGateStatus": shadow_gate.get("status") if shadow_gate else "not_run",
                        "ciWriteback": False,
                        "mergeBlocking": bool(admission_result["mergeBlocking"]),
                        "gateDecisionCreated": bool(admission_result["gateDecisionCreated"]),
                        "admissionDecisionCreated": record.admission_mode == "enforce",
                    },
                )
                self.db.flush()
                record.audit_refs = [*record.audit_refs, self._audit_ref(audit)]
            self.db.commit()
            self._attempt_ci_writeback(record.id, context)
            record = self._require_run(record.id)
        except Exception as exc:
            self.db.rollback()
            record = self._require_run(run_id)
            record.status = "failed"
            reason_code = self._reason_code_for_exception(exc)
            record.stage_snapshot = self._failed_stage_snapshot(record, reason_code)
            record.result_snapshot = {
                "schemaVersion": "phase8.admission-result-snapshot.v3",
                "overallStatus": "failed",
                "reasonCode": reason_code,
                "error": str(redact_sensitive_data(str(exc))),
                "stages": record.stage_snapshot,
                "nonAuthoritative": record.non_authoritative,
                "ciWriteback": False,
                "mergeBlocking": False,
                "gateDecisionCreated": False,
                "admissionDecisionCreated": False,
            }
            record.result_snapshot_hash = canonical_hash(record.result_snapshot)
            self.db.commit()
            raise
        return self._projection(record, deduplicated=False)

    def list_runs(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        page: int,
        page_size: int,
        pr_context_version_id: UUID | None = None,
        environment_id: UUID | None = None,
        mode: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, context, capability="admission.read")
        statement = select(AdmissionRunRecord).where(
            AdmissionRunRecord.tenant_id == scope[0],
            AdmissionRunRecord.workspace_id == scope[1],
            AdmissionRunRecord.project_id == project_id,
        )
        if pr_context_version_id is not None:
            statement = statement.where(AdmissionRunRecord.pr_context_version_id == pr_context_version_id)
        if environment_id is not None:
            statement = statement.where(AdmissionRunRecord.environment_id == environment_id)
        if mode is not None:
            if mode not in {"observe", "shadow", "enforce"}:
                raise AdmissionError("ADMISSION_MODE_INVALID", field="mode")
            statement = statement.where(AdmissionRunRecord.admission_mode == mode)
        if status is not None:
            if status not in {"queued", "running", "completed", "failed", "partial", "unavailable", "cancelled", "stale"}:
                raise AdmissionError("ADMISSION_STATUS_INVALID", field="status")
            statement = statement.where(AdmissionRunRecord.status == status)
        total = self.db.scalar(select(func.count()).select_from(statement.subquery())) or 0
        rows = list(
            self.db.scalars(
                statement.order_by(AdmissionRunRecord.created_at.desc(), AdmissionRunRecord.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        return {
            "schemaVersion": "phase8.admission-run-list.v3",
            **paginate_result([self._projection(row, deduplicated=False) for row in rows], total, page, page_size),
            "readOnly": True,
            "observeShadowImplemented": True,
            "enforceImplemented": True,
            "authoritativeAdmissionDecisionImplemented": True,
            "ciWritebackImplemented": True,
        }

    def get_run(self, project_id: UUID, run_id: UUID, context: ServiceContext) -> dict[str, Any]:
        scope = self._require_scope(project_id, context, capability="admission.read")
        row = self.db.scalar(
            select(AdmissionRunRecord).where(
                AdmissionRunRecord.id == run_id,
                AdmissionRunRecord.tenant_id == scope[0],
                AdmissionRunRecord.workspace_id == scope[1],
                AdmissionRunRecord.project_id == project_id,
            )
        )
        if row is None:
            raise AdmissionError("ADMISSION_RUN_NOT_FOUND", status_code=404)
        return self._projection(row, deduplicated=False)

    def get_timeline(self, project_id: UUID, run_id: UUID, context: ServiceContext) -> dict[str, Any]:
        row = self._scoped_run(project_id, run_id, context, capability="admission.read")
        return self._timeline_projection(row)

    def get_review(self, project_id: UUID, run_id: UUID, context: ServiceContext) -> dict[str, Any]:
        row = self._scoped_run(project_id, run_id, context, capability="admission.read")
        return self._review_projection(row).model_dump(mode="json")

    def request_review(
        self,
        project_id: UUID,
        run_id: UUID,
        payload: AdmissionReviewRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        row = self._scoped_run(project_id, run_id, context, capability="admission.review")
        if row.status in {"queued", "running"}:
            raise AdmissionError("ADMISSION_REVIEW_RESULT_NOT_READY")
        self._action_preflight(
            row,
            context,
            action="admission.review",
            payload={"intent": payload.intent, "mode": row.admission_mode},
        )
        from agentic_qa.services.approval_service import ApprovalService

        approval_result = ApprovalService(self.db).request_admission_review(
            admission_run_id=row.id,
            result_snapshot_hash=row.result_snapshot_hash,
            intent=payload.intent,
            comment=redact_sensitive_text(payload.comment) if payload.comment else None,
            idempotency_key=payload.idempotencyKey,
            context=context,
        )
        audit = write_audit_log(
            self.db,
            context.user.id,
            "admission.review.request",
            "admission_run",
            str(row.id),
            context.request_id,
            context.trace_id,
            execution_id=row.execution_id,
            details={
                "intent": payload.intent,
                "approvalId": approval_result["approvalId"],
                "resultSnapshotHash": row.result_snapshot_hash,
                "mutatesCanonicalFinding": False,
                "mutatesGateDecision": False,
            },
        )
        self.db.flush()
        row.audit_refs = [*row.audit_refs, self._audit_ref(audit)]
        self.db.commit()
        return self._review_projection(row).model_dump(mode="json")

    def retry_run(
        self,
        project_id: UUID,
        run_id: UUID,
        payload: AdmissionRetryRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        row = self._scoped_run(project_id, run_id, context, capability="admission.retry")
        if row.status in {"queued", "running"}:
            raise AdmissionError("ADMISSION_RETRY_ALREADY_RUNNING")
        if row.admission_mode == "enforce" and self.db.scalar(
            select(GateDecision).where(GateDecision.execution_id == row.execution_id)
        ) is not None:
            raise AdmissionError("ADMISSION_ENFORCE_RETRY_REQUIRES_NEW_RUN")
        version = self.db.get(ScmPrContextVersionRecord, row.pr_context_version_id)
        pr_context = self.db.get(ScmPrContextRecord, version.context_id) if version else None
        if version is None or pr_context is None or pr_context.latest_head_sha.lower() != row.source_head_sha:
            raise AdmissionError("ADMISSION_RETRY_STALE_HEAD")
        self._action_preflight(
            row,
            context,
            action="admission.retry",
            payload={"scope": payload.scope, "mode": row.admission_mode},
        )
        root_context = ServiceContext(
            user=context.user,
            request_id=context.request_id,
            trace_id=str(row.trace_id),
        )
        result = ExecutionService(self.db).retry(row.execution_id, payload.scope, root_context)
        row.retry_snapshot = {
            "state": "approval_pending" if result.get("approvalRequired") else "queued",
            "scope": payload.scope,
            "approvalId": result.get("approvalId"),
            "jobId": result.get("jobId"),
            "requestedAt": datetime.now(timezone.utc).isoformat(),
            "attemptCount": row.attempt_count + 1,
        }
        self.db.commit()
        return {
            "schemaVersion": "phase8.admission-retry.v1",
            "admissionRunId": str(row.id),
            "rootTraceRef": f"trace://{row.trace_id}",
            "scope": payload.scope,
            "approvalRequired": bool(result.get("approvalRequired")),
            "approvalRef": (
                f"approval://{result['approvalId']}" if result.get("approvalId") else None
            ),
            "jobRef": f"job://{result['jobId']}" if result.get("jobId") else None,
            "nonAuthoritative": row.non_authoritative,
            "ciWriteback": False,
            "mergeBlocking": False,
        }

    def refresh_after_execution_retry(
        self,
        execution_id: UUID,
        runtime: dict[str, Any],
        context: ServiceContext,
    ) -> None:
        """Refresh the P22 snapshot after the existing execution retry lifecycle completes."""

        row = self.db.scalar(
            select(AdmissionRunRecord).where(AdmissionRunRecord.execution_id == execution_id)
        )
        if row is None:
            return
        root_context = ServiceContext(
            user=context.user,
            request_id=context.request_id,
            trace_id=str(row.trace_id),
        )
        result_snapshot = self._build_result_snapshot(row, runtime)
        shadow_gate: dict[str, Any] | None = None
        enforce_gate: dict[str, Any] | None = None
        if row.admission_mode == "shadow":
            try:
                shadow_gate = ExecutionService(self.db).evaluate_admission_shadow_gate(
                    row.execution_id,
                    root_context,
                )
            except Exception:
                shadow_gate = AdmissionShadowGateProjection(
                    status="unavailable",
                    decision=None,
                    evaluatedAt=datetime.now(timezone.utc),
                    reasonCode="ADMISSION_SHADOW_GATE_UNAVAILABLE",
                ).model_dump(mode="json")
        elif row.admission_mode == "enforce":
            try:
                enforce_gate = ExecutionService(self.db).evaluate_admission_enforce_gate(
                    row.execution_id,
                    root_context,
                )
            except Exception:
                enforce_gate = AdmissionEnforceGateProjection(
                    status="unavailable",
                    decision=None,
                    evaluatedAt=datetime.now(timezone.utc),
                    reasonCode="ADMISSION_ENFORCE_GATE_UNAVAILABLE",
                    gateDecisionCreated=False,
                ).model_dump(mode="json")
        gate_projection = enforce_gate if row.admission_mode == "enforce" else shadow_gate
        stages = self._completed_stage_snapshot(row, result_snapshot, gate_projection)
        result_snapshot.update(
            {
                "schemaVersion": "phase8.admission-result-snapshot.v3",
                "shadowGate": shadow_gate,
                "enforceGate": enforce_gate,
                "stages": stages,
                "nonAuthoritative": row.non_authoritative,
                "ciWriteback": False,
                "mergeBlocking": False,
            }
        )
        result_snapshot["admissionResult"] = self._build_admission_result(
            row,
            result_snapshot,
            shadow_gate,
            enforce_gate,
        )
        row.status = self._admission_overall_status(result_snapshot, gate_projection)
        result_snapshot["overallStatus"] = row.status
        row.result_snapshot = result_snapshot
        row.result_snapshot_hash = canonical_hash(result_snapshot)
        row.shadow_gate_snapshot = shadow_gate
        row.stage_snapshot = stages
        row.guardrail_event_refs = self._all_guardrail_refs(row)
        row.attempt_count += 1
        row.retry_snapshot = {
            **dict(row.retry_snapshot or {}),
            "state": "completed" if row.status == "completed" else row.status,
            "attemptCount": row.attempt_count,
            "completedAt": datetime.now(timezone.utc).isoformat(),
        }
        row.replay_snapshot = {
            **row.replay_snapshot,
            "stageSnapshotHash": canonical_hash(stages),
            "resultSnapshotHash": row.result_snapshot_hash,
            "retry": row.retry_snapshot,
            "gateDecisionCreated": bool(result_snapshot["admissionResult"]["gateDecisionCreated"]),
            "admissionDecisionCreated": row.admission_mode == "enforce",
        }

    @staticmethod
    def _initial_stage_snapshot(*, non_authoritative: bool = True) -> list[dict[str, Any]]:
        return [
            _validated_contract(
                AdmissionStageProjection,
                sequence=index,
                lifecycleStage=stage,
                status="pending",
                nonAuthoritative=non_authoritative,
            ).model_dump(mode="json")
            for index, stage in enumerate(ADMISSION_LIFECYCLE, start=1)
        ]

    def _running_stage_snapshot(
        self, current_stage: str, *, non_authoritative: bool = True
    ) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        return [
            _validated_contract(
                AdmissionStageProjection,
                sequence=index,
                lifecycleStage=stage,
                status="running" if stage == current_stage else "pending",
                startedAt=now if stage == current_stage else None,
                nonAuthoritative=non_authoritative,
            ).model_dump(mode="json")
            for index, stage in enumerate(ADMISSION_LIFECYCLE, start=1)
        ]

    def _finalize_without_execution(
        self,
        record: AdmissionRunRecord,
        *,
        status: str,
        reason_code: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        first_status = "stale" if status == "stale" else "unavailable"
        stages = [
            _validated_contract(
                AdmissionStageProjection,
                sequence=index,
                lifecycleStage=stage,
                status=first_status if index == 1 else "skipped",
                reasonCode=reason_code if index == 1 else "ADMISSION_DEPENDENCY_NOT_SATISFIED",
                startedAt=now if index == 1 else None,
                endedAt=now if index == 1 else None,
                traceRefs=self._trace_refs_for_stage(record, stage),
                nonAuthoritative=record.non_authoritative,
            ).model_dump(mode="json")
            for index, stage in enumerate(ADMISSION_LIFECYCLE, start=1)
        ]
        conclusion = "stale" if status == "stale" else "unavailable"
        result_hash = canonical_hash(
            {"runId": str(record.id), "mode": record.admission_mode, "conclusion": conclusion, "reasonCode": reason_code}
        )
        admission_result = _validated_contract(
            AdmissionResultProjection,
            mode=record.admission_mode,
            conclusion=conclusion,
            reasonCodes=[reason_code],
            normalizedFindingRefs=[],
            evidenceRefs=[],
            shadowGate=None,
            enforceGate=None,
            resultHash=result_hash,
            nonAuthoritative=record.non_authoritative,
        ).model_dump(mode="json")
        record.status = status
        record.stage_snapshot = stages
        record.result_snapshot = {
            "schemaVersion": "phase8.admission-result-snapshot.v2",
            "overallStatus": status,
            "reasonCode": reason_code,
            "stages": stages,
            "admissionResult": admission_result,
            "shadowGate": None,
            "nonAuthoritative": record.non_authoritative,
            "gateDecisionCreated": False,
            "admissionDecisionCreated": False,
            "ciWriteback": False,
            "mergeBlocking": False,
        }
        record.result_snapshot_hash = canonical_hash(record.result_snapshot)
        record.replay_snapshot = {
            **record.replay_snapshot,
            "stageSnapshotHash": canonical_hash(stages),
            "resultSnapshotHash": record.result_snapshot_hash,
            "terminalReasonCode": reason_code,
            "gateDecisionCreated": False,
            "admissionDecisionCreated": False,
        }

    @staticmethod
    def _pr_execution_block_reason(
        pr_context: ScmPrContextRecord | None,
        version: ScmPrContextVersionRecord,
    ) -> str | None:
        snapshot = dict(version.context_snapshot or {})
        if bool(snapshot.get("draft")):
            return "ADMISSION_DRAFT_PR_NOT_EXECUTED"
        state = str(snapshot.get("state") or (pr_context.state if pr_context else "unknown"))
        if state not in {"open", "reopened"}:
            return "ADMISSION_PR_NOT_OPEN"
        return None

    def _stage_preflight(
        self,
        record: AdmissionRunRecord,
        stage: str,
        context: ServiceContext,
    ) -> None:
        self._action_preflight(
            record,
            context,
            action=f"admission.stage.{stage.lower()}",
            payload={
                "stage": stage,
                "mode": record.admission_mode,
                "nonAuthoritative": record.non_authoritative,
            },
        )

    def _action_preflight(
        self,
        record: AdmissionRunRecord,
        context: ServiceContext,
        *,
        action: str,
        payload: dict[str, Any],
    ) -> None:
        self.guardrails.enforce(
            GuardrailContext(
                trace_id=str(record.trace_id),
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="admission_run",
                resource_id=str(record.id),
                execution_id=record.execution_id,
                payload=payload,
                metadata={"action": action},
            ),
            [ActionGuard()],
        )
        event = self.db.scalar(
            select(GuardrailEvent)
            .where(
                GuardrailEvent.trace_id == record.trace_id,
                GuardrailEvent.execution_id == record.execution_id,
                GuardrailEvent.rule_id == "action.high_risk_operations_controlled",
            )
            .order_by(GuardrailEvent.created_at.desc(), GuardrailEvent.id.desc())
        )
        if event is not None:
            ref = {"type": "guardrail_event", "ref": f"guardrail-event://{event.id}", "contentHash": None}
            if ref not in record.guardrail_event_refs:
                record.guardrail_event_refs = [*record.guardrail_event_refs, ref]

    def _completed_stage_snapshot(
        self,
        record: AdmissionRunRecord,
        result_snapshot: dict[str, Any],
        gate_projection: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        static_scan = dict(result_snapshot.get("staticScan") or {})
        smoke_result = dict(result_snapshot.get("smokeResult") or {})
        overall = str(result_snapshot.get("overallStatus") or "unavailable")
        execute_status = overall if overall in {"failed", "partial", "unavailable", "cancelled"} else "completed"
        execute_reason = None
        if execute_status != "completed":
            execute_reason = {
                "failed": "ADMISSION_TOOL_EXECUTION_FAILED",
                "partial": "ADMISSION_TOOL_EXECUTION_PARTIAL",
                "unavailable": "ADMISSION_TOOL_EXECUTION_UNAVAILABLE",
                "cancelled": "ADMISSION_TOOL_EXECUTION_CANCELLED",
            }[execute_status]
        normalize_completed = bool(static_scan.get("normalizeCompleted")) and bool(
            smoke_result.get("normalizeCompleted")
        )
        artifact_refs = [
            *list(static_scan.get("artifactRefs") or []),
            *list(smoke_result.get("artifactRefs") or []),
        ]
        raw_refs = [
            *list(static_scan.get("rawFindingRefs") or []),
            *list(smoke_result.get("rawFindingRefs") or []),
        ]
        finding_refs = [
            *list(static_scan.get("normalizedFindingRefs") or []),
            *list(smoke_result.get("normalizedFindingRefs") or []),
        ]
        match = self.db.get(RequirementMatchSnapshotRecord, record.requirement_match_snapshot_id)
        prepare_reason = None
        if match is None or match.review_required or match.status != "confirmed":
            prepare_reason = "ADMISSION_REQUIREMENT_MATCH_UNCONFIRMED"
        plan = self.db.get(SelectiveReplayPlanRecord, record.selective_replay_plan_id)
        if prepare_reason is None and plan is not None and plan.fallback_used:
            prepare_reason = "ADMISSION_IMPACT_FALLBACK_USED"
        stage_values: dict[str, tuple[str, str | None, list[dict[str, Any]], dict[str, Any]]] = {
            "PREPARE": (
                "completed",
                prepare_reason,
                [],
                {"requirementMatchStatus": match.status if match else "unavailable"},
            ),
            "EXECUTE": (
                execute_status,
                execute_reason,
                artifact_refs,
                {"staticScanStatus": static_scan.get("status"), "smokeStatus": smoke_result.get("status")},
            ),
            "OBSERVE": (
                "partial" if execute_status in {"partial", "unavailable"} else "completed",
                "ADMISSION_EVIDENCE_PARTIAL" if execute_status in {"partial", "unavailable"} else None,
                [*artifact_refs, *raw_refs],
                {"artifactCount": len(artifact_refs), "rawFindingCount": len(raw_refs)},
            ),
            "ANALYZE": (
                "completed" if static_scan.get("analyzeCompleted") and smoke_result.get("analyzeCompleted") else "unavailable",
                None if static_scan.get("analyzeCompleted") and smoke_result.get("analyzeCompleted") else "ADMISSION_ANALYZE_UNAVAILABLE",
                raw_refs,
                {},
            ),
            "NORMALIZE": (
                "completed" if normalize_completed else "failed",
                None if normalize_completed else "ADMISSION_NORMALIZE_NOT_COMPLETED",
                finding_refs,
                {"normalizedFindingCount": len(finding_refs)},
            ),
            "GATE": (
                "skipped" if record.admission_mode == "observe" else (
                    "completed" if gate_projection and gate_projection.get("status") == "completed" else "unavailable"
                ),
                "ADMISSION_OBSERVE_GATE_NOT_EVALUATED" if record.admission_mode == "observe" else (
                    (
                        "ADMISSION_ENFORCE_AUTHORITATIVE"
                        if record.admission_mode == "enforce"
                        else "ADMISSION_SHADOW_NON_AUTHORITATIVE"
                    )
                    if gate_projection and gate_projection.get("status") == "completed"
                    else (
                        "ADMISSION_ENFORCE_GATE_UNAVAILABLE"
                        if record.admission_mode == "enforce"
                        else "ADMISSION_SHADOW_GATE_UNAVAILABLE"
                    )
                ),
                [],
                {
                    "nonAuthoritative": record.non_authoritative,
                    "decision": gate_projection.get("decision") if gate_projection else None,
                },
            ),
        }
        stages: list[dict[str, Any]] = []
        for index, stage in enumerate(ADMISSION_LIFECYCLE, start=1):
            status, reason_code, evidence, summary = stage_values[stage]
            started_at, ended_at = self._stage_times(record, stage)
            stages.append(
                _validated_contract(
                    AdmissionStageProjection,
                    sequence=index,
                    lifecycleStage=stage,
                    status=status,
                    reasonCode=reason_code,
                    startedAt=started_at,
                    endedAt=ended_at,
                    traceRefs=self._trace_refs_for_stage(record, stage),
                    evidenceRefs=evidence,
                    summary=summary,
                    nonAuthoritative=record.non_authoritative,
                ).model_dump(mode="json")
            )
        return stages

    def _failed_stage_snapshot(self, record: AdmissionRunRecord, reason_code: str) -> list[dict[str, Any]]:
        execution = self.db.get(Execution, record.execution_id)
        reached = execution.stage.value if execution else "PREPARE"
        reached_index = ADMISSION_LIFECYCLE.index(reached) if reached in ADMISSION_LIFECYCLE else 0
        stages: list[dict[str, Any]] = []
        for index, stage in enumerate(ADMISSION_LIFECYCLE):
            if index < reached_index:
                status, reason = "completed", None
            elif index == reached_index:
                status, reason = "failed", reason_code
            else:
                status, reason = "skipped", "ADMISSION_DEPENDENCY_NOT_SATISFIED"
            started_at, ended_at = self._stage_times(record, stage)
            stages.append(
                _validated_contract(
                    AdmissionStageProjection,
                    sequence=index + 1,
                    lifecycleStage=stage,
                    status=status,
                    reasonCode=reason,
                    startedAt=started_at,
                    endedAt=ended_at,
                    traceRefs=self._trace_refs_for_stage(record, stage),
                    nonAuthoritative=record.non_authoritative,
                ).model_dump(mode="json")
            )
        return stages

    @staticmethod
    def _reason_code_for_exception(exc: Exception) -> str:
        value = str(exc).upper()
        if "NORMALIZE" in value:
            return "ADMISSION_NORMALIZE_FAILED"
        if "TIMEOUT" in value or "TIMED OUT" in value:
            return "ADMISSION_STAGE_TIMEOUT"
        if "CANCEL" in value:
            return "ADMISSION_STAGE_CANCELLED"
        return "ADMISSION_ORCHESTRATION_FAILED"

    def _build_admission_result(
        self,
        record: AdmissionRunRecord,
        result_snapshot: dict[str, Any],
        shadow_gate: dict[str, Any] | None,
        enforce_gate: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        static_scan = dict(result_snapshot.get("staticScan") or {})
        smoke_result = dict(result_snapshot.get("smokeResult") or {})
        normalized = [
            *list(static_scan.get("normalizedFindingRefs") or []),
            *list(smoke_result.get("normalizedFindingRefs") or []),
        ]
        evidence = [
            *list(static_scan.get("artifactRefs") or []),
            *list(smoke_result.get("artifactRefs") or []),
        ]
        reasons: list[str] = []
        match = self.db.get(RequirementMatchSnapshotRecord, record.requirement_match_snapshot_id)
        if match is None or match.review_required or match.status != "confirmed":
            reasons.append("ADMISSION_REQUIREMENT_MATCH_UNCONFIRMED")
        plan = self.db.get(SelectiveReplayPlanRecord, record.selective_replay_plan_id)
        if plan is not None and plan.fallback_used:
            reasons.append("ADMISSION_IMPACT_FALLBACK_USED")
        overall = str(result_snapshot.get("overallStatus") or "unavailable")
        if record.admission_mode == "enforce":
            if not enforce_gate or enforce_gate.get("status") != "completed":
                conclusion = "unavailable"
                reasons.append("ADMISSION_ENFORCE_GATE_UNAVAILABLE")
            else:
                decision = str(enforce_gate.get("decision") or "blocked")
                conclusion = {
                    "pass": "passed",
                    "warn": "warned",
                    "fail": "failed",
                    "blocked": "blocked",
                }[decision]
                reasons.extend(str(value) for value in enforce_gate.get("reasonCodes", []))
                reasons.append("ADMISSION_ENFORCE_AUTHORITATIVE")
        elif overall in {"partial", "failed"}:
            conclusion = "partial"
            reasons.append("ADMISSION_EXECUTION_PARTIAL" if overall == "partial" else "ADMISSION_EXECUTION_FAILED")
        elif overall == "unavailable":
            conclusion = "unavailable"
            reasons.append("ADMISSION_EXECUTION_UNAVAILABLE")
        elif overall == "cancelled":
            conclusion = "cancelled"
            reasons.append("ADMISSION_EXECUTION_CANCELLED")
        elif overall == "stale":
            conclusion = "stale"
            reasons.append("ADMISSION_HEAD_CHANGED")
        elif record.admission_mode == "observe":
            conclusion = "observed"
            reasons.append("ADMISSION_OBSERVE_NON_BLOCKING")
        elif not shadow_gate or shadow_gate.get("status") != "completed":
            conclusion = "unavailable"
            reasons.append("ADMISSION_SHADOW_GATE_UNAVAILABLE")
        else:
            decision = str(shadow_gate.get("decision") or "blocked")
            conclusion = {
                "pass": "would_pass",
                "warn": "would_warn",
                "fail": "would_fail",
                "blocked": "would_block",
            }[decision]
            reasons.extend(str(value) for value in shadow_gate.get("reasonCodes", []))
            reasons.append("ADMISSION_SHADOW_NON_AUTHORITATIVE")
        if "ADMISSION_REQUIREMENT_MATCH_UNCONFIRMED" in reasons and conclusion == "would_pass":
            conclusion = "would_block"
        reasons = sorted(set(reasons))
        result_hash = canonical_hash(
            {
                "runId": str(record.id),
                "mode": record.admission_mode,
                "conclusion": conclusion,
                "reasonCodes": reasons,
                "normalizedFindingRefs": normalized,
                "evidenceRefs": evidence,
                "shadowGateHash": canonical_hash(shadow_gate) if shadow_gate else None,
                "enforceGateHash": canonical_hash(enforce_gate) if enforce_gate else None,
            }
        )
        gate_created = bool(enforce_gate and enforce_gate.get("gateDecisionCreated"))
        merge_blocking = record.admission_mode == "enforce" and conclusion in {"failed", "blocked"}
        authoritative_decision = (
            {
                "conclusion": conclusion,
                "gateDecisionRef": enforce_gate.get("gateDecisionRef") if enforce_gate else None,
                "source": "service_owned_gate",
            }
            if record.admission_mode == "enforce" and enforce_gate and enforce_gate.get("status") == "completed"
            else None
        )
        return _validated_contract(
            AdmissionResultProjection,
            mode=record.admission_mode,
            conclusion=conclusion,
            reasonCodes=reasons,
            normalizedFindingRefs=normalized,
            evidenceRefs=evidence,
            shadowGate=shadow_gate,
            enforceGate=enforce_gate,
            resultHash=result_hash,
            nonAuthoritative=record.non_authoritative,
            authoritativeAdmissionDecision=authoritative_decision,
            gateDecisionCreated=gate_created,
            ciWriteback=False,
            mergeBlocking=merge_blocking,
        ).model_dump(mode="json")

    @staticmethod
    def _admission_overall_status(
        result_snapshot: dict[str, Any],
        gate_projection: dict[str, Any] | None,
    ) -> str:
        status = str(result_snapshot.get("overallStatus") or "unavailable")
        if gate_projection and gate_projection.get("status") == "unavailable" and status == "completed":
            return "partial"
        return status

    def _timeline_projection(self, row: AdmissionRunRecord) -> dict[str, Any]:
        stages = [AdmissionStageProjection.model_validate(item) for item in row.stage_snapshot]
        return _validated_contract(
            AdmissionTimelineProjection,
            admissionRunId=row.id,
            rootTraceRef=f"trace://{row.trace_id}",
            mode=row.admission_mode,
            workflowVersion=row.workflow_version,
            stages=stages,
            stageSnapshotHash=canonical_hash([item.model_dump(mode="json") for item in stages]),
            nonAuthoritative=row.non_authoritative,
        ).model_dump(mode="json")

    def _review_projection(self, row: AdmissionRunRecord) -> AdmissionReviewProjection:
        approval = self.db.scalar(
            select(Approval)
            .where(
                Approval.resource_type == "admission_run_review",
                Approval.resource_id == str(row.id),
            )
            .order_by(Approval.created_at.desc(), Approval.id.desc())
        )
        if approval is None:
            return _validated_contract(
                AdmissionReviewProjection,
                admissionRunId=row.id,
                state="not_requested",
                intent=None,
                approvalRef=None,
                requestedBy=None,
                decidedBy=None,
                requestedAt=None,
                decidedAt=None,
                commentPresent=False,
            )
        return _validated_contract(
            AdmissionReviewProjection,
            admissionRunId=row.id,
            state=approval.status.value,
            intent=str(approval.payload.get("intent") or "acknowledge_evidence"),
            approvalRef=AdmissionArtifactRef(
                type="approval",
                ref=f"approval://{approval.id}",
                redactionStatus="redacted",
            ),
            requestedBy=str(approval.requested_by) if approval.requested_by else None,
            decidedBy=str(approval.decided_by) if approval.decided_by else None,
            requestedAt=approval.created_at,
            decidedAt=approval.decided_at,
            commentPresent=bool(approval.payload.get("comment") or approval.decision_comment),
        )

    def _scoped_run(
        self,
        project_id: UUID,
        run_id: UUID,
        context: ServiceContext,
        *,
        capability: str,
    ) -> AdmissionRunRecord:
        scope = self._require_scope(project_id, context, capability=capability)
        row = self.db.scalar(
            select(AdmissionRunRecord).where(
                AdmissionRunRecord.id == run_id,
                AdmissionRunRecord.tenant_id == scope[0],
                AdmissionRunRecord.workspace_id == scope[1],
                AdmissionRunRecord.project_id == project_id,
            )
        )
        if row is None:
            raise AdmissionError("ADMISSION_RUN_NOT_FOUND", status_code=404)
        return row

    def _trace_refs_for_stage(self, row: AdmissionRunRecord, stage: str) -> list[str]:
        token = stage.lower()
        spans = list(
            self.db.scalars(
                select(TraceSpan)
                .where(
                    TraceSpan.trace_id == row.trace_id,
                    TraceSpan.span_name.like(f"%{token}%"),
                )
                .order_by(TraceSpan.start_time.asc(), TraceSpan.id.asc())
            )
        )
        return [f"trace-span://{span.id}" for span in spans]

    def _all_guardrail_refs(self, row: AdmissionRunRecord) -> list[dict[str, Any]]:
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.trace_id == row.trace_id)
                .order_by(GuardrailEvent.created_at.asc(), GuardrailEvent.id.asc())
            )
        )
        return [
            {
                "type": "guardrail_event",
                "ref": f"guardrail-event://{event.id}",
                "contentHash": None,
            }
            for event in events
        ]

    def _stage_times(
        self,
        row: AdmissionRunRecord,
        stage: str,
    ) -> tuple[datetime | None, datetime | None]:
        token = stage.lower()
        spans = list(
            self.db.scalars(
                select(TraceSpan).where(
                    TraceSpan.trace_id == row.trace_id,
                    TraceSpan.span_name.like(f"%{token}%"),
                )
            )
        )
        started = min((span.start_time for span in spans if span.start_time), default=None)
        ended = max((span.end_time for span in spans if span.end_time), default=None)
        return started, ended

    def _build_smoke_plan(self, plan: SelectiveReplayPlanRecord, head_sha: str) -> SmokePlan:
        tests: list[SmokeTestSpec] = []
        unsupported: list[dict[str, str]] = []
        for item in plan.plan_snapshot.get("selectedTests", []):
            if not isinstance(item, dict):
                continue
            test_ref = str(item.get("testRef") or "")
            reason_codes = [str(value) for value in item.get("selectionReasonCodes", [])]
            domain = str(item.get("domain") or "")
            task = self._task_from_ref(str(item.get("taskRef") or ""), plan.base_execution_id)
            recipe = self._sandbox_recipe_for_task(task)
            test_module = str(task.config.get("testModule") or "") if task is not None else ""
            if domain == TestDomain.FUNCTIONAL.value and recipe is not None and self._safe_test_module(test_module):
                tests.append(
                    _validated_contract(
                        SmokeTestSpec,
                        taskRef=str(item.get("taskRef") or ""),
                        recipe=recipe,
                        testModule=test_module,
                        selectedReasonCodes=reason_codes or ["SMOKE_BASELINE"],
                        estimatedSeconds=max(1, min(3600, int(item.get("estimatedSeconds") or 60))),
                    )
                )
            else:
                reason = "SMOKE_NON_FUNCTIONAL_UNSUPPORTED"
                if domain == TestDomain.FUNCTIONAL.value and task is None:
                    reason = "SMOKE_TASK_REF_INVALID"
                elif domain == TestDomain.FUNCTIONAL.value:
                    reason = "SMOKE_SELECTOR_INVALID" if recipe is not None else "SMOKE_RUNNER_NOT_SANDBOXED"
                unsupported.append({"testRef": test_ref, "reasonCode": reason})
        return _validated_contract(
            SmokePlan,
            schemaVersion="phase8.smoke-plan.v1",
            selectiveReplayPlanId=plan.id,
            selectiveReplayPlanHash=plan.plan_hash,
            headSha=head_sha,
            tests=tests,
            unsupportedTests=unsupported,
            conservativeSelectionPreserved=True,
        )

    def _task_from_ref(self, task_ref: str, base_execution_id: UUID) -> ExecutionTask | None:
        prefix = "execution-task://"
        if not task_ref.startswith(prefix):
            return None
        try:
            task_id = UUID(task_ref.removeprefix(prefix))
        except ValueError:
            return None
        return self.db.scalar(
            select(ExecutionTask).where(
                ExecutionTask.id == task_id,
                ExecutionTask.execution_id == base_execution_id,
            )
        )

    @staticmethod
    def _sandbox_recipe_for_task(task: ExecutionTask | None) -> str | None:
        if task is None:
            return None
        recipe = str(task.config.get("sandboxRecipe") or "")
        if recipe == "python-unittest" or task.runner == "sandbox-python-unittest":
            return "python-unittest"
        return None

    @staticmethod
    def _safe_test_module(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,254}", value))

    @staticmethod
    def _validate_source_artifact_ref(storage_ref: str, *, project_id: UUID, head_sha: str) -> None:
        prefix = "local://artifacts/"
        relative = storage_ref.removeprefix(prefix)
        parts = relative.split("/")
        namespace = f"pr-source-archives-{project_id}"
        if len(parts) < 3 or parts[0] != namespace or parts[1] != head_sha:
            raise AdmissionError("ADMISSION_SOURCE_ARTIFACT_SCOPE_INVALID", field="sourceArtifactRef.storageRef")

    def _validate_frozen_handoff(
        self,
        scope: tuple[str, str],
        project_id: UUID,
        version: ScmPrContextVersionRecord,
        plan: SelectiveReplayPlanRecord,
    ) -> None:
        snapshot = self.db.scalar(
            select(RequirementMatchSnapshotRecord).where(
                RequirementMatchSnapshotRecord.pr_context_version_id == version.id
            )
        )
        if snapshot is None:
            raise AdmissionError("ADMISSION_REQUIREMENT_MATCH_SNAPSHOT_NOT_FOUND")
        replay_match = snapshot.replay_snapshot
        if (
            str(replay_match.get("prContextVersionId") or "") != str(version.id)
            or str(replay_match.get("prContextHash") or "") != version.context_hash
            or str(replay_match.get("snapshotHash") or "") != snapshot.snapshot_hash
        ):
            raise AdmissionError("ADMISSION_REQUIREMENT_MATCH_SNAPSHOT_INVALID")
        if version.change_set_id is None:
            raise AdmissionError("ADMISSION_CHANGE_SET_REQUIRED")
        change_set = self.db.scalar(
            select(ChangeSetRecord).where(
                ChangeSetRecord.id == version.change_set_id,
                ChangeSetRecord.tenant_id == scope[0],
                ChangeSetRecord.workspace_id == scope[1],
                ChangeSetRecord.project_id == project_id,
                ChangeSetRecord.change_set_type == "code",
            )
        )
        code_change = self.db.get(CodeChangeSetRecord, version.change_set_id)
        if (
            change_set is None
            or code_change is None
            or code_change.base_sha.lower() != version.base_sha.lower()
            or code_change.head_sha.lower() != version.head_sha.lower()
        ):
            raise AdmissionError("ADMISSION_CHANGE_SET_INVALID")
        frozen_change_sets = plan.replay_snapshot.get("changeSets")
        if not isinstance(frozen_change_sets, list):
            raise AdmissionError("ADMISSION_REPLAY_PLAN_CHANGE_SET_MISSING")
        frozen = next(
            (
                item for item in frozen_change_sets
                if isinstance(item, dict) and str(item.get("id") or "") == str(change_set.id)
            ),
            None,
        )
        if frozen is None or str(frozen.get("fingerprint") or "") != change_set.fingerprint:
            raise AdmissionError("ADMISSION_REPLAY_PLAN_CHANGE_SET_MISMATCH")

    def _sandbox_preflight(
        self,
        run_id: UUID,
        payload: AdmissionRunRequest,
        context: ServiceContext,
    ) -> list[dict[str, Any]]:
        results = self.guardrails.enforce(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="admission_run",
                resource_id=str(run_id),
                payload={
                    "sandboxProfile": payload.sandboxProfile.model_dump(mode="json"),
                    "commandSurface": "platform_recipe_only",
                    "sourceArtifactRef": payload.sourceArtifactRef.model_dump(mode="json"),
                },
                metadata={"action": "admission.execute"},
            ),
            [SandboxExecutionGuard()],
        )
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(
                    GuardrailEvent.trace_id == UUID(str(context.trace_id)),
                    GuardrailEvent.rule_id == "execution.untrusted_code_sandbox",
                )
                .order_by(GuardrailEvent.created_at.desc())
                .limit(len(results))
            )
        )
        return [
            {"type": "guardrail_event", "ref": f"guardrail-event://{event.id}", "contentHash": None}
            for event in events
        ]

    def _build_result_snapshot(self, record: AdmissionRunRecord, runtime: dict[str, Any]) -> dict[str, Any]:
        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == record.execution_id)
                .order_by(ExecutionTask.priority.asc(), ExecutionTask.id.asc())
            )
        )
        artifacts = list(runtime["refs"]["artifactRefs"])
        raw_refs = list(runtime["refs"]["rawFindingRefs"])
        finding_refs = list(runtime["refs"]["findingRefs"])
        tool_results = [self._tool_result(task, artifacts, raw_refs) for task in tasks]
        scan_results = [item for item in tool_results if item.tool == "sandbox-semgrep"]
        smoke_results = [item for item in tool_results if item.tool == "sandbox-python-unittest"]
        scan_status = self._aggregate_status(scan_results)
        smoke_status = self._aggregate_status(smoke_results, empty="unavailable")
        unsupported_tests = list(record.plan_snapshot["smokePlan"].get("unsupportedTests", []))
        if unsupported_tests:
            smoke_status = "unavailable" if not smoke_results else "partial"
        normalize_completed = bool(runtime["readiness"]["normalizeCompleted"])
        static_scan = _validated_contract(
            StaticScanResult,
            schemaVersion="phase8.static-scan-result.v1",
            admissionRunId=record.id,
            executionId=record.execution_id,
            status=scan_status,
            headSha=record.source_head_sha,
            toolResults=scan_results,
            artifactRefs=self._artifact_contract_refs(artifacts, task_types={"admission.static_scan"}, tasks=tasks),
            rawFindingRefs=self._raw_contract_refs(raw_refs, task_types={"admission.static_scan"}, tasks=tasks),
            findingCandidates=[],
            normalizedFindingRefs=self._finding_contract_refs(finding_refs, task_types={"admission.static_scan"}, tasks=tasks),
            analyzeCompleted=True,
            normalizeCompleted=normalize_completed,
            gateDecisionCreated=False,
        )
        smoke_result = _validated_contract(
            SmokeResult,
            schemaVersion="phase8.smoke-result.v1",
            admissionRunId=record.id,
            executionId=record.execution_id,
            status=smoke_status,
            toolResults=smoke_results,
            artifactRefs=self._artifact_contract_refs(artifacts, task_types={"admission.selective_smoke"}, tasks=tasks),
            rawFindingRefs=self._raw_contract_refs(raw_refs, task_types={"admission.selective_smoke"}, tasks=tasks),
            findingCandidates=[],
            normalizedFindingRefs=self._finding_contract_refs(finding_refs, task_types={"admission.selective_smoke"}, tasks=tasks),
            unsupportedTests=unsupported_tests,
            flakyDetected=None,
            analyzeCompleted=True,
            normalizeCompleted=normalize_completed,
            gateDecisionCreated=False,
        )
        statuses = [scan_status, smoke_status]
        overall = "completed"
        if "unavailable" in statuses:
            overall = "unavailable" if all(status == "unavailable" for status in statuses) else "partial"
        elif "failed" in statuses:
            overall = "failed"
        elif "partial" in statuses:
            overall = "partial"
        return {
            "schemaVersion": "phase8.admission-result-snapshot.v1",
            "overallStatus": overall,
            "staticScan": static_scan.model_dump(mode="json"),
            "smokeResult": smoke_result.model_dump(mode="json"),
            "runtime": runtime,
            "gateDecisionCreated": False,
            "admissionDecisionCreated": False,
        }

    def _tool_result(
        self,
        task: ExecutionTask,
        artifacts: list[dict[str, Any]],
        raw_refs: list[dict[str, Any]],
    ) -> AdmissionToolResult:
        payload = dict(task.result_payload or {})
        raw_metadata = payload.get("runnerMetadata")
        metadata: dict[str, Any] = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
        tool_status = str(payload.get("toolStatus") or "infra_error")
        runner_status = str(payload.get("runnerStatus") or "failed")
        unavailable = str(metadata.get("availability") or "") == "unavailable"
        status = "unavailable" if unavailable else (
            "completed" if runner_status == "completed" else (
                "cancelled" if runner_status == "cancelled" else "failed"
            )
        )
        task_artifacts = [item for item in artifacts if item.get("taskId") == str(task.id)]
        task_raw = [item for item in raw_refs if item.get("taskId") == str(task.id)]
        return _validated_contract(
            AdmissionToolResult,
            tool=task.runner,
            toolVersion=str(metadata.get("binaryVersion")) if metadata.get("binaryVersion") else None,
            status=status,
            toolStatus=tool_status,
            actualExecution=bool(payload.get("actualExecution", False)),
            sandboxed=True,
            exitCode=int(payload.get("exitCode", -1) if "exitCode" in payload else (-1 if unavailable else 0)),
            durationMs=int(payload.get("durationMs") or 0),
            unavailableReason=task.error_message if unavailable else None,
            artifactRefs=self._artifact_contract_refs(task_artifacts),
            rawFindingRefs=self._raw_contract_refs(task_raw),
        )

    @staticmethod
    def _aggregate_status(results: list[AdmissionToolResult], *, empty: str = "unavailable") -> str:
        if not results:
            return empty
        statuses = {item.status for item in results}
        if statuses == {"completed"}:
            return "completed"
        if statuses == {"unavailable"}:
            return "unavailable"
        if "cancelled" in statuses:
            return "cancelled"
        if "failed" in statuses and len(statuses) == 1:
            return "failed"
        return "partial"

    @staticmethod
    def _artifact_contract_refs(
        rows: list[dict[str, Any]],
        *,
        task_types: set[str] | None = None,
        tasks: list[ExecutionTask] | None = None,
    ) -> list[AdmissionArtifactRef]:
        allowed = None
        if task_types is not None and tasks is not None:
            allowed = {str(task.id) for task in tasks if task.task_type in task_types}
        return [
            AdmissionArtifactRef(
                type=str(row.get("artifactType") or "artifact"),
                ref=str(row.get("uri") or f"artifact://{row['id']}"),
                redactionStatus="redacted",
            )
            for row in rows
            if allowed is None or str(row.get("taskId")) in allowed
        ]

    @staticmethod
    def _raw_contract_refs(
        rows: list[dict[str, Any]],
        *,
        task_types: set[str] | None = None,
        tasks: list[ExecutionTask] | None = None,
    ) -> list[AdmissionArtifactRef]:
        allowed = None
        if task_types is not None and tasks is not None:
            allowed = {str(task.id) for task in tasks if task.task_type in task_types}
        return [
            AdmissionArtifactRef(type="raw_finding", ref=f"raw-finding://{row['id']}", redactionStatus="redacted")
            for row in rows
            if allowed is None or str(row.get("taskId")) in allowed
        ]

    @staticmethod
    def _finding_contract_refs(
        rows: list[dict[str, Any]],
        *,
        task_types: set[str],
        tasks: list[ExecutionTask],
    ) -> list[AdmissionArtifactRef]:
        allowed = {str(task.id) for task in tasks if task.task_type in task_types}
        return [
            AdmissionArtifactRef(type="finding", ref=f"finding://{row['id']}", redactionStatus="redacted")
            for row in rows
            if str(row.get("taskId")) in allowed
        ]

    def _projection(self, row: AdmissionRunRecord, *, deduplicated: bool) -> dict[str, Any]:
        smoke_plan = SmokePlan.model_validate(row.plan_snapshot["smokePlan"])
        execution = self.db.get(Execution, row.execution_id)
        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == row.execution_id)
                .order_by(ExecutionTask.priority.asc(), ExecutionTask.id.asc())
            )
        )
        smoke_tasks = [task for task in tasks if task.task_type == "admission.selective_smoke"]
        started = min((task.started_at for task in smoke_tasks if task.started_at), default=None)
        ended = max((task.ended_at for task in smoke_tasks if task.ended_at), default=None)
        smoke_run = _validated_contract(
            SmokeRun,
            schemaVersion="phase8.smoke-run.v1",
            admissionRunId=row.id,
            executionId=row.execution_id,
            status=(
                "running" if row.status == "running" else (
                    row.status if row.status in {"completed", "failed", "partial", "unavailable", "cancelled"} else (
                        "unavailable" if row.status == "stale" else "queued"
                    )
                )
            ),
            taskRefs=[f"execution-task://{task.id}" for task in smoke_tasks],
            sandboxProfileHash=canonical_hash(row.sandbox_profile),
            startedAt=started,
            endedAt=ended,
        )
        result = dict(row.result_snapshot or {})
        effective_status = row.status
        if (
            row.status in {"queued", "running"}
            and execution is not None
            and execution.status in {TaskStatus.QUEUED, TaskStatus.RUNNING}
        ):
            effective_status = execution.status.value
        stage_snapshot = list(
            row.stage_snapshot
            or self._initial_stage_snapshot(non_authoritative=row.non_authoritative)
        )
        match = self.db.get(RequirementMatchSnapshotRecord, row.requirement_match_snapshot_id)
        plan = self.db.get(SelectiveReplayPlanRecord, row.selective_replay_plan_id)
        change_set_id = row.replay_snapshot.get("changeSetId")
        trace_spans = list(
            self.db.scalars(
                select(TraceSpan)
                .where(TraceSpan.trace_id == row.trace_id)
                .order_by(TraceSpan.start_time.asc(), TraceSpan.id.asc())
            )
        )
        ci_attempt = self.db.scalar(
            select(CIWritebackAttemptRecord)
            .where(CIWritebackAttemptRecord.admission_run_id == row.id)
            .order_by(CIWritebackAttemptRecord.created_at.desc(), CIWritebackAttemptRecord.id.desc())
        )
        ci_projection = None
        if ci_attempt is not None:
            from agentic_qa.services.ci_writeback_service import CIWritebackService

            ci_projection = CIWritebackService(self.db)._serialize_attempt(ci_attempt, idempotent=False)
        readiness = self._enforcement_readiness(row)
        projection = _validated_contract(
            AdmissionRunProjection,
            schemaVersion="phase8.admission-run.v3",
            admissionRunId=row.id,
            projectId=row.project_id,
            repositoryRef=row.repository_ref,
            pullRequestNumber=row.pull_request_number,
            prContextVersionId=row.pr_context_version_id,
            selectiveReplayPlanId=row.selective_replay_plan_id,
            executionId=row.execution_id,
            environmentId=row.environment_id,
            mode=row.admission_mode,
            workflowVersion=row.workflow_version,
            nonAuthoritative=row.non_authoritative,
            status=effective_status,
            baseSha=row.base_sha,
            sourceHeadSha=row.source_head_sha,
            inputFingerprint=row.input_fingerprint,
            sandboxProfile=row.sandbox_profile,
            staticScan=result.get("staticScan"),
            smokePlan=smoke_plan,
            smokeRun=smoke_run,
            smokeResult=result.get("smokeResult"),
            requirementMatchRef=(
                AdmissionArtifactRef(
                    type="requirement_match_snapshot",
                    ref=f"requirement-match-snapshot://{match.id}",
                    contentHash=match.snapshot_hash,
                    redactionStatus="redacted",
                )
                if match else None
            ),
            impactResultRef=(
                AdmissionArtifactRef(
                    type="impact_result",
                    ref=f"impact-result://{plan.impact_result_id}",
                    redactionStatus="redacted",
                )
                if plan else None
            ),
            changeSetRef=(
                AdmissionArtifactRef(
                    type="change_set",
                    ref=f"change-set://{change_set_id}",
                    redactionStatus="redacted",
                )
                if change_set_id else None
            ),
            selectiveReplayPlanRef=AdmissionArtifactRef(
                type="selective_replay_plan",
                ref=f"selective-replay-plan://{row.selective_replay_plan_id}",
                contentHash=plan.plan_hash if plan else None,
                redactionStatus="redacted",
            ),
            stages=stage_snapshot,
            stageSnapshotHash=canonical_hash(stage_snapshot),
            admissionResult=result.get("admissionResult"),
            review=self._review_projection(row),
            retry=dict(row.retry_snapshot or {}),
            replaySnapshot=row.replay_snapshot,
            guardrailEventRefs=row.guardrail_event_refs,
            auditRefs=row.audit_refs,
            traceRefs=[f"trace://{row.trace_id}", *(f"trace-span://{span.id}" for span in trace_spans)],
            createdAt=row.created_at,
            updatedAt=row.updated_at,
            rootTraceRef=f"trace://{row.trace_id}",
            readOnly=True,
            admissionDecision=(result.get("admissionResult") or {}).get("authoritativeAdmissionDecision"),
            gateDecisionCreated=bool((result.get("admissionResult") or {}).get("gateDecisionCreated")),
            ciWriteback=ci_projection,
            enforcementReadiness=readiness,
            frontendAuthoritative=False,
        ).model_dump(mode="json")
        return {
            **projection,
            "deduplicated": deduplicated,
            "executionStatus": execution.status.value if execution else "unavailable",
            "resultSnapshot": result,
        }

    def _attempt_ci_writeback(self, run_id: UUID, context: ServiceContext) -> None:
        row = self._require_run(run_id)
        policy = self.db.scalar(
            select(CIEnforcementPolicyRecord).where(
                CIEnforcementPolicyRecord.tenant_id == row.tenant_id,
                CIEnforcementPolicyRecord.workspace_id == row.workspace_id,
                CIEnforcementPolicyRecord.project_id == row.project_id,
                CIEnforcementPolicyRecord.repository_ref == row.repository_ref,
                CIEnforcementPolicyRecord.check_name == DEFAULT_CI_CHECK_NAME,
                CIEnforcementPolicyRecord.status == "active",
            )
        )
        mode_rank = {"observe": 1, "shadow": 2, "enforce": 3}
        if policy is None or mode_rank[row.admission_mode] > mode_rank[policy.mode]:
            return
        try:
            from agentic_qa.services.ci_writeback_service import CIWritebackService

            result = CIWritebackService(self.db).write_for_admission(
                row,
                DEFAULT_CI_CHECK_NAME,
                context,
            )
            row = self._require_run(run_id)
            row.replay_snapshot = {
                **row.replay_snapshot,
                "ciWritebackAttemptId": result["writebackAttemptId"],
                "ciWritebackStatus": result["writeStatus"],
                "ciConclusionStatus": result["status"],
                "ciHeadCheck": result["staleRevision"],
                "externalActionRef": result["externalAction"],
            }
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            row = self._require_run(run_id)
            audit = write_audit_log(
                self.db,
                context.user.id,
                "ci.writeback.unavailable",
                "admission_run",
                str(row.id),
                context.request_id,
                context.trace_id,
                execution_id=row.execution_id,
                details={
                    "reasonCode": "CI_WRITEBACK_UNAVAILABLE",
                    "error": str(redact_sensitive_data(str(exc))),
                    "admissionResultPreserved": True,
                    "closePullRequest": False,
                    "merge": False,
                    "deleteBranch": False,
                    "modifyCode": False,
                },
            )
            row.audit_refs = [*row.audit_refs, self._audit_ref(audit)]
            self.db.commit()

    def _enforcement_readiness(self, row: AdmissionRunRecord) -> dict[str, Any]:
        policy = self.db.scalar(
            select(CIEnforcementPolicyRecord).where(
                CIEnforcementPolicyRecord.tenant_id == row.tenant_id,
                CIEnforcementPolicyRecord.workspace_id == row.workspace_id,
                CIEnforcementPolicyRecord.project_id == row.project_id,
                CIEnforcementPolicyRecord.repository_ref == row.repository_ref,
                CIEnforcementPolicyRecord.check_name == DEFAULT_CI_CHECK_NAME,
            )
        )
        if policy is None:
            return {
                "ready": False,
                "mode": "observe",
                "status": "disabled",
                "branchProtectionConfigured": False,
                "branchProtectionExternallyManaged": True,
                "unavailableReason": "CI_WRITEBACK_POLICY_NOT_CONFIGURED",
                "requiredCapabilities": ["ci.write", "enforce.manage", "ci.retry"],
            }
        approval = self.db.get(Approval, policy.activation_approval_id) if policy.activation_approval_id else None
        ready = policy.status == "active" and (
            policy.mode != "enforce"
            or (
                policy.branch_protection_configured
                and approval is not None
                and approval.status == ApprovalStatus.APPROVED
            )
        )
        return {
            "ready": ready,
            "mode": policy.mode,
            "status": policy.status,
            "policyHash": policy.policy_hash,
            "branchProtectionConfigured": policy.branch_protection_configured,
            "branchProtectionExternallyManaged": True,
            "approvalRef": f"approval://{policy.activation_approval_id}" if policy.activation_approval_id else None,
            "unavailableReason": None if ready else "CI_ENFORCEMENT_NOT_READY",
            "requiredCapabilities": ["ci.write", "enforce.manage", "ci.retry"],
        }

    def _require_scope(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        capability: str,
    ) -> tuple[str, str, Project]:
        if capability not in set(context.user.capabilities):
            raise AdmissionError("ADMISSION_CAPABILITY_REQUIRED", status_code=403, field=capability)
        try:
            scope = ScopeAuthorizationService(self.db).resolve_project(project_id, context)
        except ScopeAuthorizationError as exc:
            raise AdmissionError(
                "ADMISSION_PROJECT_NOT_FOUND" if exc.status_code != 409 else "ADMISSION_SCOPE_INVALID",
                status_code=exc.status_code,
                field=exc.field,
            ) from exc
        return scope.tenant_id, scope.workspace_id, scope.project

    def _require_run(self, run_id: UUID) -> AdmissionRunRecord:
        row = self.db.get(AdmissionRunRecord, run_id)
        if row is None:
            raise AdmissionError("ADMISSION_RUN_NOT_FOUND", status_code=404)
        return row

    def _mark_dispatch_unavailable(self, run_id: UUID, context: ServiceContext, reason: str) -> None:
        self.db.rollback()
        row = self._require_run(run_id)
        self._finalize_without_execution(
            row,
            status="unavailable",
            reason_code="ADMISSION_QUEUE_UNAVAILABLE",
        )
        row.result_snapshot = {
            **row.result_snapshot,
            "error": str(redact_sensitive_data(reason)),
        }
        row.result_snapshot_hash = canonical_hash(row.result_snapshot)
        write_audit_log(
            self.db,
            context.user.id,
            "admission.run.queue_unavailable",
            "admission_run",
            str(run_id),
            context.request_id,
            context.trace_id,
            execution_id=row.execution_id,
            details={"reasonCode": "ADMISSION_QUEUE_UNAVAILABLE"},
        )
        self.db.commit()

    @staticmethod
    def _audit_ref(audit: AuditLog) -> dict[str, Any]:
        return {"type": "audit_log", "ref": f"audit-log://{audit.id}", "contentHash": None}

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


__all__ = ["AdmissionError", "AdmissionService"]

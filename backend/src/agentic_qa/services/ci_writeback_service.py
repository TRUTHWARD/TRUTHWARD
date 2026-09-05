# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.connectors.contracts import ConnectorOperationRequest, ConnectorOperationResult
from agentic_qa.connectors.github import GitHubReadOnlyConnector
from agentic_qa.connectors.gitlab import GitLabReadOnlyConnector
from agentic_qa.connectors.mock import MockScmConnector
from agentic_qa.domain.models import (
    AdmissionRunRecord,
    AuditLog,
    CIEnforcementPolicyRecord,
    CIWritebackAttemptRecord,
    GateDecision,
    GuardrailEvent,
    ScmPrContextRecord,
    ScmPrContextVersionRecord,
    Skill,
    SkillConnectorBinding,
    SkillInvocation,
    SkillVersion,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.runtime import CIWritebackGuard, RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.credentials import CredentialResolver
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.infra.safe_projection import ConnectorBindingSafeProjectionBuilder
from agentic_qa.infra.trace import ensure_trace, traced_operation
from agentic_qa.schemas.ci_writeback import (
    CIConclusion,
    CIEnforcementChangeRequest,
    CIEnforcementPolicyProjection,
    CIWritebackRequest,
    CIWritebackRetryRequest,
    CIWritebackResult,
    EnforcementDecision,
    ExternalActionRef,
    LegacySkillDecisionFieldNotice,
    StaleRevisionResult,
)
from agentic_qa.services.common import (
    IdempotencyConflictError,
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
)
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


class CIWritebackError(ValueError):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


MODE_RANK = {"observe": 1, "shadow": 2, "enforce": 3}


class CIWritebackService:
    """Service-owned Gate/Admission to provider-neutral CI mapping and governed writeback."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.credentials = CredentialResolver()
        self.guardrails = RuntimeGuardrailEngine(db)
        self.connector_snapshot_builder = ConnectorBindingSafeProjectionBuilder()

    def get_policy(
        self,
        project_id: UUID,
        repository_ref: str,
        check_name: str,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, context, capability="admission.read")
        row = self._policy(scope[0], scope[1], project_id, repository_ref, check_name)
        if row is None:
            return {
                "schemaVersion": "phase8.ci-enforcement-policy.v1",
                "projectId": str(project_id),
                "repositoryRef": repository_ref,
                "checkName": check_name,
                "mode": "observe",
                "status": "disabled",
                "policyHash": canonical_hash(
                    {"projectId": str(project_id), "repositoryRef": repository_ref, "checkName": check_name, "status": "disabled"}
                ),
                "branchProtectionConfigured": False,
                "branchProtectionExternallyManaged": True,
                "approvalRef": None,
                "ready": False,
                "unavailableReason": "CI_WRITEBACK_POLICY_NOT_CONFIGURED",
                "requiredCapabilities": ["ci.write", "enforce.manage", "ci.retry"],
            }
        return self._policy_projection(row)

    def request_policy_change(
        self,
        project_id: UUID,
        payload: CIEnforcementChangeRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, context, capability="enforce.manage")
        ensure_trace(self.db, execution_id=None, root_span_name="ci.enforcement.governance", trace_id=context.trace_id)
        self._require_repository_context(project_id, payload.repositoryRef, scope)
        acquire_transaction_advisory_lock(
            self.db,
            "ci-enforcement-policy",
            f"{scope[0]}:{scope[1]}:{project_id}:{payload.repositoryRef}:{payload.checkName}",
        )
        proposed = {
            "projectId": str(project_id),
            "tenantId": scope[0],
            "workspaceId": scope[1],
            "repositoryRef": payload.repositoryRef,
            "checkName": payload.checkName,
            "mode": payload.targetMode,
            "branchProtectionConfigured": payload.branchProtectionConfigured,
            "branchProtectionExternallyManaged": True,
        }
        policy_hash = canonical_hash(proposed)
        row = self._policy(scope[0], scope[1], project_id, payload.repositoryRef, payload.checkName)
        if row is not None and row.idempotency_key == payload.idempotencyKey:
            if row.policy_hash != policy_hash and row.pending_snapshot.get("policyHash") != policy_hash:
                raise IdempotencyConflictError("CI_ENFORCEMENT_POLICY_IDEMPOTENCY_CONFLICT")
            return self._policy_projection(row)
        if row is None:
            row = CIEnforcementPolicyRecord(
                id=uuid4(),
                tenant_id=scope[0],
                workspace_id=scope[1],
                project_id=project_id,
                repository_ref=payload.repositoryRef,
                check_name=payload.checkName,
                mode="observe",
                status="disabled",
                branch_protection_configured=False,
                policy_hash=canonical_hash({**proposed, "mode": "observe", "status": "disabled"}),
                activation_approval_id=None,
                pending_snapshot={},
                idempotency_key=payload.idempotencyKey,
                lock_version=1,
                guardrail_event_refs=[],
                audit_refs=[],
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(row)
            self.db.flush()
        self._guard(
            context,
            resource_type="ci_enforcement_policy",
            resource_id=str(row.id),
            action="ci.enforcement.change",
            mode=payload.targetMode,
            approval_ref="approval-pending" if payload.targetMode == "enforce" else None,
            head_current=True,
        )
        if payload.targetMode == "enforce":
            if not payload.branchProtectionConfigured:
                raise CIWritebackError(
                    "CI_BRANCH_PROTECTION_CONFIGURATION_REQUIRED",
                    field="branchProtectionConfigured",
                )
            row.status = "approval_pending"
            row.pending_snapshot = {**proposed, "policyHash": policy_hash, "reason": payload.reason}
            row.idempotency_key = payload.idempotencyKey
            row.updated_by = context.user.id
            from agentic_qa.services.approval_service import ApprovalService

            approval = ApprovalService(self.db).request_ci_enforcement_change(
                policy_id=row.id,
                project_id=project_id,
                repository_ref=row.repository_ref,
                check_name=row.check_name,
                target_mode=payload.targetMode,
                branch_protection_configured=True,
                policy_hash=policy_hash,
                idempotency_key=payload.idempotencyKey,
                reason=payload.reason,
                context=context,
                commit=False,
            )
            row.activation_approval_id = UUID(str(approval["approvalId"]))
        else:
            row.mode = payload.targetMode
            row.status = "active"
            row.branch_protection_configured = payload.branchProtectionConfigured
            row.policy_hash = policy_hash
            row.activation_approval_id = None
            row.pending_snapshot = {}
            row.idempotency_key = payload.idempotencyKey
            row.lock_version += 1
            row.updated_by = context.user.id
        audit = write_audit_log(
            self.db,
            context.user.id,
            "ci.enforcement.change.request",
            "ci_enforcement_policy",
            str(row.id),
            context.request_id,
            context.trace_id,
            details={
                "projectId": str(project_id),
                "repositoryRef": row.repository_ref,
                "checkName": row.check_name,
                "targetMode": payload.targetMode,
                "policyHash": policy_hash,
                "approvalRequired": payload.targetMode == "enforce",
                "branchProtectionExternallyManaged": True,
            },
        )
        self.db.flush()
        row.audit_refs = [*row.audit_refs, self._audit_ref(audit)]
        row.guardrail_event_refs = self._guardrail_refs(resource_id=str(row.id))
        self.db.commit()
        self.db.refresh(row)
        return self._policy_projection(row)

    def execute_approved_enforcement_change(
        self,
        *,
        approval_payload: dict[str, Any],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        row = self.db.get(CIEnforcementPolicyRecord, UUID(str(approval_payload["policyId"])))
        if row is None or row.status != "approval_pending":
            raise CIWritebackError("CI_ENFORCEMENT_POLICY_NOT_PENDING")
        ensure_trace(self.db, execution_id=None, root_span_name="ci.enforcement.governance", trace_id=context.trace_id)
        proposed = dict(row.pending_snapshot or {})
        if (
            approval_payload.get("policyHash") != proposed.get("policyHash")
            or approval_payload.get("targetMode") != "enforce"
            or str(approval_payload.get("projectId")) != str(row.project_id)
            or approval_payload.get("repositoryRef") != row.repository_ref
            or approval_payload.get("checkName") != row.check_name
        ):
            raise CIWritebackError("CI_ENFORCEMENT_APPROVAL_SNAPSHOT_MISMATCH")
        self._guard(
            context,
            resource_type="ci_enforcement_policy",
            resource_id=str(row.id),
            action="ci.enforcement.apply",
            mode="enforce",
            approval_ref=f"approval://{approval_id}",
            head_current=True,
        )
        row.mode = "enforce"
        row.status = "active"
        row.branch_protection_configured = bool(proposed.get("branchProtectionConfigured"))
        row.policy_hash = str(proposed["policyHash"])
        row.activation_approval_id = approval_id
        row.pending_snapshot = {}
        row.lock_version += 1
        row.updated_by = context.user.id
        audit = write_audit_log(
            self.db,
            context.user.id,
            "ci.enforcement.activate",
            "ci_enforcement_policy",
            str(row.id),
            context.request_id,
            context.trace_id,
            details={
                "mode": "enforce",
                "policyHash": row.policy_hash,
                "approvalId": str(approval_id),
                "branchProtectionConfiguredByAdmin": row.branch_protection_configured,
                "branchProtectionExternallyManaged": True,
            },
        )
        self.db.flush()
        row.audit_refs = [*row.audit_refs, self._audit_ref(audit)]
        row.guardrail_event_refs = self._guardrail_refs(resource_id=str(row.id))
        return self._policy_projection(row)

    def writeback(
        self,
        project_id: UUID,
        payload: CIWritebackRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, context, capability="ci.write")
        run = self.db.scalar(
            select(AdmissionRunRecord).where(
                AdmissionRunRecord.id == payload.admissionRunId,
                AdmissionRunRecord.project_id == project_id,
                AdmissionRunRecord.tenant_id == scope[0],
                AdmissionRunRecord.workspace_id == scope[1],
            )
        )
        if run is None:
            raise CIWritebackError("CI_ADMISSION_RUN_NOT_FOUND", status_code=404)
        return self.write_for_admission(run, payload.checkName, context)

    def get_writeback(
        self,
        project_id: UUID,
        admission_run_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, context, capability="admission.read")
        attempt = self.db.scalar(
            select(CIWritebackAttemptRecord)
            .join(AdmissionRunRecord, AdmissionRunRecord.id == CIWritebackAttemptRecord.admission_run_id)
            .where(
                CIWritebackAttemptRecord.admission_run_id == admission_run_id,
                CIWritebackAttemptRecord.project_id == project_id,
                CIWritebackAttemptRecord.tenant_id == scope[0],
                CIWritebackAttemptRecord.workspace_id == scope[1],
            )
            .order_by(CIWritebackAttemptRecord.created_at.desc(), CIWritebackAttemptRecord.id.desc())
        )
        if attempt is None:
            raise CIWritebackError("CI_WRITEBACK_ATTEMPT_NOT_FOUND", status_code=404)
        return self._serialize_attempt(attempt, idempotent=False)

    def request_retry(
        self,
        project_id: UUID,
        admission_run_id: UUID,
        payload: CIWritebackRetryRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, context, capability="ci.retry")
        attempt = self.db.scalar(
            select(CIWritebackAttemptRecord)
            .where(
                CIWritebackAttemptRecord.admission_run_id == admission_run_id,
                CIWritebackAttemptRecord.project_id == project_id,
                CIWritebackAttemptRecord.tenant_id == scope[0],
                CIWritebackAttemptRecord.workspace_id == scope[1],
            )
            .order_by(CIWritebackAttemptRecord.created_at.desc(), CIWritebackAttemptRecord.id.desc())
        )
        if attempt is None:
            raise CIWritebackError("CI_WRITEBACK_ATTEMPT_NOT_FOUND", status_code=404)
        if attempt.status not in {"write_failed", "unknown"}:
            raise CIWritebackError("CI_WRITEBACK_RETRY_NOT_ALLOWED_FOR_STATUS")
        from agentic_qa.services.approval_service import ApprovalService

        return ApprovalService(self.db).request_ci_writeback_retry(
            attempt_id=attempt.id,
            admission_run_id=attempt.admission_run_id,
            request_hash=attempt.request_hash,
            head_sha=attempt.head_sha,
            policy_hash=attempt.policy_hash,
            idempotency_key=payload.idempotencyKey,
            reason=payload.reason,
            context=context,
        )

    def execute_approved_retry(
        self,
        *,
        approval_payload: dict[str, Any],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        attempt = self.db.get(CIWritebackAttemptRecord, UUID(str(approval_payload["attemptId"])))
        if attempt is None or attempt.status not in {"write_failed", "unknown"}:
            raise CIWritebackError("CI_WRITEBACK_RETRY_STATE_CHANGED")
        if (
            str(attempt.admission_run_id) != str(approval_payload.get("admissionRunId"))
            or attempt.request_hash != approval_payload.get("requestHash")
            or attempt.head_sha != approval_payload.get("headSha")
            or attempt.policy_hash != approval_payload.get("policyHash")
        ):
            raise CIWritebackError("CI_WRITEBACK_RETRY_APPROVAL_SNAPSHOT_MISMATCH")
        run = self.db.get(AdmissionRunRecord, attempt.admission_run_id)
        policy = self.db.scalar(
            select(CIEnforcementPolicyRecord).where(
                CIEnforcementPolicyRecord.project_id == attempt.project_id,
                CIEnforcementPolicyRecord.repository_ref == attempt.repository_ref,
                CIEnforcementPolicyRecord.check_name == attempt.check_name,
                CIEnforcementPolicyRecord.policy_hash == attempt.policy_hash,
                CIEnforcementPolicyRecord.status == "active",
            )
        )
        binding = self.db.get(SkillConnectorBinding, attempt.connector_binding_id)
        if run is None or policy is None or binding is None or binding.status != "active":
            raise CIWritebackError("CI_WRITEBACK_RETRY_FROZEN_INPUT_UNAVAILABLE", status_code=503)
        self._require_binding_scope(binding, run)
        pr_version = self.db.get(ScmPrContextVersionRecord, run.pr_context_version_id)
        pr_context = self.db.get(ScmPrContextRecord, pr_version.context_id) if pr_version else None
        if pr_context is None:
            raise CIWritebackError("CI_WRITEBACK_RETRY_PR_CONTEXT_UNAVAILABLE", status_code=503)
        stale = self._check_current_head(run, pr_context, binding, context)
        attempt.attempt_count += 1
        attempt.stale_revision_snapshot = stale.model_dump(mode="json")
        attempt.approval_refs = [*attempt.approval_refs, {"type": "approval", "ref": f"approval://{approval_id}"}]
        if stale.connectorCallRef:
            attempt.connector_call_refs = [
                *attempt.connector_call_refs,
                {"type": "connector_call", "ref": stale.connectorCallRef, "operation": "fetch_current_head"},
            ]
        if stale.status != "current":
            attempt.status = "stale"
            attempt.last_error_code = stale.reasonCode
            audit = self._write_attempt_audit(attempt, context, "ci.writeback.retry.suppressed")
            attempt.audit_refs = [*attempt.audit_refs, self._audit_ref(audit)]
            return self._serialize_attempt(attempt, idempotent=False)
        self._guard(
            context,
            resource_type="ci_writeback_attempt",
            resource_id=str(attempt.id),
            action="ci.writeback.retry",
            mode=attempt.admission_mode,
            approval_ref=f"approval://{approval_id}",
            head_current=True,
            execution_id=run.execution_id,
        )
        attempt.status = "in_progress"
        attempt.last_error_code = None
        attempt.guardrail_event_refs = [
            *attempt.guardrail_event_refs,
            *self._guardrail_refs(resource_id=str(attempt.id)),
        ]
        start_audit = self._write_attempt_audit(attempt, context, "ci.writeback.retry.start")
        attempt.audit_refs = [*attempt.audit_refs, self._audit_ref(start_audit)]
        self.db.flush()
        result = self._invoke_write(
            binding,
            run,
            CIConclusion.model_validate(attempt.conclusion_snapshot),
            attempt.check_name,
            attempt.idempotency_key,
            context,
        )
        return self._record_connector_result(attempt, binding, result, context, commit=False)

    def write_for_admission(
        self,
        run: AdmissionRunRecord,
        check_name: str,
        context: ServiceContext,
    ) -> dict[str, Any]:
        if run.status in {"queued", "running"}:
            raise CIWritebackError("CI_ADMISSION_RESULT_NOT_READY")
        policy = self._policy(run.tenant_id, run.workspace_id, run.project_id, run.repository_ref, check_name)
        if policy is None or policy.status != "active":
            raise CIWritebackError("CI_WRITEBACK_POLICY_UNAVAILABLE", status_code=503)
        if MODE_RANK[run.admission_mode] > MODE_RANK[policy.mode]:
            raise CIWritebackError("CI_WRITEBACK_MODE_NOT_ENABLED")
        pr_version = self.db.get(ScmPrContextVersionRecord, run.pr_context_version_id)
        pr_context = self.db.get(ScmPrContextRecord, pr_version.context_id) if pr_version else None
        if pr_version is None or pr_context is None:
            raise CIWritebackError("CI_PR_CONTEXT_UNAVAILABLE", status_code=503)
        binding = self.db.get(SkillConnectorBinding, pr_context.connector_binding_id)
        if binding is None or binding.status != "active":
            raise CIWritebackError("CI_CONNECTOR_BINDING_UNAVAILABLE", status_code=503)
        self._require_binding_scope(binding, run)
        self._require_connector_capability(binding.connector_name, "write_check")
        conclusion, enforcement = self._map_ci_conclusion(run, policy)
        notice = self._legacy_field_notice(run.execution_id)
        fixed_identity = {
            "repositoryRef": run.repository_ref,
            "pullRequestNumber": run.pull_request_number,
            "headSha": run.source_head_sha,
            "checkName": check_name,
            "admissionRunId": str(run.id),
            "policyHash": policy.policy_hash,
        }
        idempotency_key = canonical_hash(fixed_identity)
        request_snapshot = {
            **fixed_identity,
            "provider": binding.connector_name,
            "conclusion": conclusion.model_dump(mode="json"),
            "enforcement": enforcement.model_dump(mode="json"),
            "connectorBindingId": str(binding.id),
            "credentialMaterialPersisted": False,
            "dangerousActions": {
                "closePullRequest": False,
                "merge": False,
                "deleteBranch": False,
                "modifyCode": False,
            },
        }
        request_hash = canonical_hash(request_snapshot)
        acquire_transaction_advisory_lock(self.db, "ci-writeback", idempotency_key)
        existing = self.db.scalar(
            select(CIWritebackAttemptRecord).where(CIWritebackAttemptRecord.idempotency_key == idempotency_key)
        )
        if existing is not None:
            if existing.request_hash != request_hash:
                raise IdempotencyConflictError("CI_WRITEBACK_IDEMPOTENCY_CONFLICT")
            return self._serialize_attempt(existing, idempotent=True)

        stale = self._check_current_head(run, pr_context, binding, context)
        attempt = CIWritebackAttemptRecord(
            id=uuid4(),
            tenant_id=run.tenant_id,
            workspace_id=run.workspace_id,
            project_id=run.project_id,
            admission_run_id=run.id,
            connector_binding_id=binding.id,
            provider=binding.connector_name,
            repository_ref=run.repository_ref,
            pull_request_number=run.pull_request_number,
            head_sha=run.source_head_sha,
            check_name=check_name,
            admission_mode=run.admission_mode,
            policy_hash=policy.policy_hash,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            status="stale" if stale.status != "current" else "in_progress",
            conclusion_snapshot=conclusion.model_dump(mode="json"),
            enforcement_snapshot=enforcement.model_dump(mode="json"),
            stale_revision_snapshot=stale.model_dump(mode="json"),
            request_snapshot=redact_sensitive_data(request_snapshot),
            response_snapshot={},
            external_action_ref=None,
            legacy_field_notice=notice.model_dump(mode="json") if notice else None,
            connector_call_refs=(
                [{"type": "connector_call", "ref": stale.connectorCallRef, "operation": "fetch_current_head"}]
                if stale.connectorCallRef else []
            ),
            guardrail_event_refs=[],
            approval_refs=([{"type": "approval", "ref": enforcement.approvalRef}] if enforcement.approvalRef else []),
            audit_refs=[],
            attempt_count=1,
            last_error_code=stale.reasonCode,
            trace_id=run.trace_id,
        )
        self.db.add(attempt)
        self.db.flush()
        if notice is not None:
            self._audit_legacy_notice(attempt, notice, context)
        if stale.status != "current":
            audit = self._write_attempt_audit(attempt, context, "ci.writeback.suppressed")
            attempt.audit_refs = [*attempt.audit_refs, self._audit_ref(audit)]
            self.db.commit()
            return self._serialize_attempt(attempt, idempotent=False)

        self._guard(
            context,
            resource_type="ci_writeback_attempt",
            resource_id=str(attempt.id),
            action="ci.writeback",
            mode=run.admission_mode,
            approval_ref=enforcement.approvalRef,
            head_current=True,
            execution_id=run.execution_id,
        )
        attempt.guardrail_event_refs = self._guardrail_refs(resource_id=str(attempt.id))
        pending_audit = self._write_attempt_audit(attempt, context, "ci.writeback.start")
        attempt.audit_refs = [*attempt.audit_refs, self._audit_ref(pending_audit)]
        self.db.commit()

        result = self._invoke_write(binding, run, conclusion, check_name, idempotency_key, context)
        persisted_attempt = self.db.get(CIWritebackAttemptRecord, attempt.id)
        if persisted_attempt is None:
            raise CIWritebackError("CI_WRITEBACK_ATTEMPT_LOST", status_code=503)
        return self._record_connector_result(persisted_attempt, binding, result, context, commit=True)

    def _map_ci_conclusion(
        self,
        run: AdmissionRunRecord,
        policy: CIEnforcementPolicyRecord,
    ) -> tuple[CIConclusion, EnforcementDecision]:
        result = dict(run.result_snapshot.get("admissionResult") or {})
        reason_codes = [str(item) for item in result.get("reasonCodes") or []]
        gate_result: str | None = None
        gate_ref: str | None = None
        if run.admission_mode == "enforce":
            gate = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == run.execution_id))
            if gate is None:
                status = "failure"
                reason_codes.append("CI_AUTHORITATIVE_GATE_UNAVAILABLE")
            else:
                gate_result = gate.overall.value
                gate_ref = f"gate-decision://{gate.id}"
                reason_codes.extend(str(item) for item in gate.reason_codes or [])
                status = {
                    "pass": "success",
                    "warn": "neutral",
                    "fail": "failure",
                    "blocked": "failure",
                }[gate_result]
        elif run.status == "cancelled":
            status = "cancelled"
            reason_codes.append("CI_ADMISSION_CANCELLED")
        elif run.status == "stale":
            status = "stale"
            reason_codes.append("CI_ADMISSION_STALE")
        else:
            status = "neutral"
            if run.admission_mode == "shadow":
                shadow = dict(result.get("shadowGate") or {})
                gate_result = str(shadow.get("decision")) if shadow.get("decision") else None
                reason_codes.append("CI_SHADOW_NON_BLOCKING")
            else:
                reason_codes.append("CI_OBSERVE_INFORMATIONAL")
        reason_codes = sorted(set(reason_codes))
        blocking = run.admission_mode == "enforce" and status == "failure"
        summary = self._plain_summary(run.admission_mode, status, gate_result)
        conclusion = CIConclusion.model_validate(
            {
                "status": status,
                "admissionMode": run.admission_mode,
                "gateResult": gate_result,
                "authoritative": run.admission_mode == "enforce",
                "blocking": blocking,
                "summary": summary,
                "reasonCodes": reason_codes,
                "evidenceLinks": [
                    {"label": "PR Admission run", "href": f"/admission-runs?runId={run.id}"},
                    {"label": "Execution evidence", "href": f"/executions/{run.execution_id}"},
                ],
                "platformRunLink": f"/admission-runs?runId={run.id}",
            }
        )
        approval_ref = f"approval://{policy.activation_approval_id}" if policy.activation_approval_id else None
        enforcement = EnforcementDecision.model_validate(
            {
                "mode": run.admission_mode,
                "authoritative": run.admission_mode == "enforce",
                "nonAuthoritative": run.admission_mode != "enforce",
                "blocksMerge": blocking,
                "gateDecisionRef": gate_ref,
                "approvalRef": approval_ref,
                "policyHash": policy.policy_hash,
                "branchProtectionConfigured": policy.branch_protection_configured,
                "reasonCodes": reason_codes,
            }
        )
        return conclusion, enforcement

    def _check_current_head(
        self,
        run: AdmissionRunRecord,
        pr_context: ScmPrContextRecord,
        binding: SkillConnectorBinding,
        context: ServiceContext,
    ) -> StaleRevisionResult:
        now = datetime.now(timezone.utc).isoformat()
        expected = run.source_head_sha.lower()
        database_head = pr_context.latest_head_sha.lower()
        if pr_context.state != "open":
            return StaleRevisionResult(
                status="unavailable",
                expectedHeadSha=expected,
                currentHeadSha=database_head,
                checkedAt=now,
                writeSuppressed=True,
                reasonCode="CI_PR_NOT_OPEN",
                connectorCallRef=None,
            )
        if database_head != expected:
            return StaleRevisionResult(
                status="stale",
                expectedHeadSha=expected,
                currentHeadSha=database_head,
                checkedAt=now,
                writeSuppressed=True,
                reasonCode="CI_STALE_HEAD_SHA",
                connectorCallRef=None,
            )
        runtime = self._connector(binding.connector_name)
        runtime_credentials = self._runtime_credentials(binding)
        if binding.connector_name != "mock-scm" and not runtime_credentials.get("token"):
            return StaleRevisionResult(
                status="unavailable",
                expectedHeadSha=expected,
                currentHeadSha=None,
                checkedAt=now,
                writeSuppressed=True,
                reasonCode="CI_CURRENT_HEAD_CREDENTIAL_UNAVAILABLE",
                connectorCallRef=None,
            )
        result = runtime.invoke(
            ConnectorOperationRequest(
                connector_name=binding.connector_name,
                operation="fetch_pull_request" if binding.connector_name != "gitlab" else "fetch_merge_request",
                payload={
                    "repository": self._provider_repository(run.repository_ref),
                    "pullNumber": run.pull_request_number,
                    "commitSha": database_head,
                },
                binding_snapshot=self._binding_snapshot(binding, run),
                runtime_credentials=runtime_credentials,
                trace_id=context.trace_id,
            )
        )
        call_ref = result.connector_call_ref
        if not result.succeeded:
            return StaleRevisionResult(
                status="unavailable",
                expectedHeadSha=expected,
                currentHeadSha=None,
                checkedAt=now,
                writeSuppressed=True,
                reasonCode="CI_CURRENT_HEAD_QUERY_UNAVAILABLE",
                connectorCallRef=call_ref,
            )
        provider_head = self._provider_head(binding.connector_name, result.data)
        if provider_head is None:
            return StaleRevisionResult(
                status="unavailable",
                expectedHeadSha=expected,
                currentHeadSha=None,
                checkedAt=now,
                writeSuppressed=True,
                reasonCode="CI_CURRENT_HEAD_RESPONSE_INVALID",
                connectorCallRef=call_ref,
            )
        if provider_head != expected:
            return StaleRevisionResult(
                status="stale",
                expectedHeadSha=expected,
                currentHeadSha=provider_head,
                checkedAt=now,
                writeSuppressed=True,
                reasonCode="CI_STALE_HEAD_SHA",
                connectorCallRef=call_ref,
            )
        return StaleRevisionResult(
            status="current",
            expectedHeadSha=expected,
            currentHeadSha=provider_head,
            checkedAt=now,
            writeSuppressed=False,
            reasonCode=None,
            connectorCallRef=call_ref,
        )

    def _invoke_write(
        self,
        binding: SkillConnectorBinding,
        run: AdmissionRunRecord,
        conclusion: CIConclusion,
        check_name: str,
        idempotency_key: str,
        context: ServiceContext,
    ) -> ConnectorOperationResult:
        runtime_credentials = self._runtime_credentials(binding)
        if binding.connector_name != "mock-scm" and not runtime_credentials.get("token"):
            return ConnectorOperationResult(succeeded=False, errors=["credential unavailable"])
        with traced_operation(
            self.db,
            trace_id=str(run.trace_id),
            execution_id=run.execution_id,
            root_span_name="admission.run",
            span_name="ci.writeback.connector",
            service_name="orchestrator-service",
            attributes={
                "admissionRunId": str(run.id),
                "provider": binding.connector_name,
                "headSha": run.source_head_sha,
                "status": conclusion.status,
                "closePullRequest": False,
                "merge": False,
                "deleteBranch": False,
                "modifyCode": False,
            },
        ):
            return self._connector(binding.connector_name).invoke(
                ConnectorOperationRequest(
                    connector_name=binding.connector_name,
                    operation="write_check",
                    payload={
                        "repository": self._provider_repository(run.repository_ref),
                        "pullNumber": run.pull_request_number,
                        "headSha": run.source_head_sha,
                        "idempotencyKey": idempotency_key,
                        "checkName": check_name,
                        "status": conclusion.status,
                        "title": check_name,
                        "summary": conclusion.summary,
                        "detailsUrl": conclusion.platformRunLink,
                        "reasonCodes": conclusion.reasonCodes,
                        "evidenceLinks": [item.model_dump(mode="json") for item in conclusion.evidenceLinks],
                    },
                    binding_snapshot=self._binding_snapshot(binding, run),
                    runtime_credentials=runtime_credentials,
                    trace_id=context.trace_id,
                )
            )

    def _record_connector_result(
        self,
        attempt: CIWritebackAttemptRecord,
        binding: SkillConnectorBinding,
        result: ConnectorOperationResult,
        context: ServiceContext,
        *,
        commit: bool,
    ) -> dict[str, Any]:
        if not result.succeeded:
            attempt.last_error_code = self._connector_error_code(result)
            attempt.status = (
                "unknown"
                if attempt.last_error_code == "CI_CONNECTOR_TIMEOUT_UNKNOWN_RESULT"
                else "write_failed"
            )
            attempt.response_snapshot = {"succeeded": False, "errorCode": attempt.last_error_code}
            attempt.connector_call_refs = [
                *attempt.connector_call_refs,
                *self._connector_refs(result, operation="write_check"),
            ]
            audit = self._write_attempt_audit(attempt, context, "ci.writeback.failed")
            attempt.audit_refs = [*attempt.audit_refs, self._audit_ref(audit)]
        else:
            response = self._minimal_provider_response(result.data)
            response_hash = canonical_hash(response)
            action_ref = ExternalActionRef.model_validate(
                {
                    "provider": binding.connector_name,
                    "externalId": str(response.get("id")) if response.get("id") is not None else None,
                    "url": str(response.get("url")) if response.get("url") else None,
                    "connectorCallRef": result.connector_call_ref
                    or f"{binding.connector_name}://write-check/{attempt.id}",
                    "responseHash": response_hash,
                }
            )
            attempt.status = str(attempt.conclusion_snapshot["status"])
            attempt.last_error_code = None
            attempt.response_snapshot = {"succeeded": True, "response": response, "responseHash": response_hash}
            attempt.external_action_ref = action_ref.model_dump(mode="json")
            attempt.connector_call_refs = [
                *attempt.connector_call_refs,
                *self._connector_refs(result, operation="write_check"),
            ]
            audit = self._write_attempt_audit(attempt, context, "ci.writeback.complete")
            attempt.audit_refs = [*attempt.audit_refs, self._audit_ref(audit)]
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        return self._serialize_attempt(attempt, idempotent=False)

    def _legacy_field_notice(self, execution_id: UUID) -> LegacySkillDecisionFieldNotice | None:
        rows = list(
            self.db.execute(
                select(SkillInvocation, SkillVersion, Skill)
                .join(SkillVersion, SkillVersion.id == SkillInvocation.skill_version_id)
                .join(Skill, Skill.id == SkillVersion.skill_ref_id)
                .where(SkillInvocation.execution_id == execution_id, Skill.skill_id == "ci-gate")
                .order_by(SkillInvocation.created_at.desc())
            )
        )
        fields: set[str] = set()
        version: SkillVersion | None = None
        for invocation, candidate_version, _skill in rows:
            snapshot = dict(invocation.output_snapshot or {})
            raw_result = snapshot.get("result")
            result = dict(raw_result) if isinstance(raw_result, dict) else {}
            raw_ci = result.get("ci")
            ci: dict[str, Any] = dict(raw_ci) if isinstance(raw_ci, dict) else {}
            for field in ("shouldMerge", "exitCode"):
                if field in result or field in ci:
                    fields.add(field)
                    version = candidate_version
        if not fields:
            return None
        return LegacySkillDecisionFieldNotice.model_validate(
            {
                "fieldsPresent": [field for field in ("shouldMerge", "exitCode") if field in fields],
                "skillVersion": version.version if version else None,
                "manifestHash": version.manifest_hash if version else None,
            }
        )

    def _audit_legacy_notice(
        self,
        attempt: CIWritebackAttemptRecord,
        notice: LegacySkillDecisionFieldNotice,
        context: ServiceContext,
    ) -> None:
        audit = write_audit_log(
            self.db,
            context.user.id,
            "ci.legacy_skill_decision_field.ignored",
            "ci_writeback_attempt",
            str(attempt.id),
            context.request_id,
            context.trace_id,
            details={
                "reasonCode": notice.reasonCode,
                "fieldsPresent": notice.fieldsPresent,
                "skillVersion": notice.skillVersion,
                "manifestHash": notice.manifestHash,
                "serviceConclusionPreserved": True,
            },
        )
        attempt.audit_refs = [*attempt.audit_refs, self._audit_ref(audit)]

    def _write_attempt_audit(
        self,
        attempt: CIWritebackAttemptRecord,
        context: ServiceContext,
        action: str,
    ) -> AuditLog:
        run = self.db.get(AdmissionRunRecord, attempt.admission_run_id)
        if run is None:
            raise CIWritebackError("CI_ADMISSION_RUN_NOT_FOUND", status_code=404)
        return write_audit_log(
            self.db,
            context.user.id,
            action,
            "ci_writeback_attempt",
            str(attempt.id),
            context.request_id,
            context.trace_id,
            execution_id=run.execution_id,
            details={
                "admissionRunId": str(attempt.admission_run_id),
                "provider": attempt.provider,
                "repositoryRef": attempt.repository_ref,
                "pullRequestNumber": attempt.pull_request_number,
                "headSha": attempt.head_sha,
                "checkName": attempt.check_name,
                "mode": attempt.admission_mode,
                "status": attempt.status,
                "policyHash": attempt.policy_hash,
                "requestHash": attempt.request_hash,
                "staleReasonCode": attempt.stale_revision_snapshot.get("reasonCode"),
                "externalActionRef": attempt.external_action_ref,
                "credentialMaterialPersisted": False,
                "closePullRequest": False,
                "merge": False,
                "deleteBranch": False,
                "modifyCode": False,
            },
        )

    def _serialize_attempt(self, row: CIWritebackAttemptRecord, *, idempotent: bool) -> dict[str, Any]:
        desired_status = str(row.conclusion_snapshot["status"])
        write_status = (
            "suppressed" if row.status == "stale" else (
                "failed" if row.status == "write_failed" else (
                    "unknown" if row.status == "unknown" else "completed"
                )
            )
        )
        reason_codes = list(row.conclusion_snapshot.get("reasonCodes") or [])
        if row.last_error_code:
            reason_codes.append(row.last_error_code)
        return CIWritebackResult.model_validate(
            {
                "writebackAttemptId": row.id,
                "admissionRunId": row.admission_run_id,
                "status": desired_status,
                "writeStatus": write_status,
                "checkName": row.check_name,
                "headSha": row.head_sha,
                "conclusion": row.conclusion_snapshot,
                "enforcement": row.enforcement_snapshot,
                "staleRevision": row.stale_revision_snapshot,
                "externalAction": row.external_action_ref,
                "legacyFieldNotice": row.legacy_field_notice,
                "reasonCodes": sorted(set(reason_codes)),
                "attemptCount": row.attempt_count,
                "idempotentReplay": idempotent,
            }
        ).model_dump(mode="json")

    @staticmethod
    def _plain_summary(mode: str, status: str, gate_result: str | None) -> str:
        if mode == "observe":
            return "This run collected admission evidence for review. It does not block merging."
        if mode == "shadow":
            return f"This Shadow run projected Gate result '{gate_result or 'unavailable'}'. It does not block merging."
        if status == "failure":
            return "The authoritative admission Gate did not pass. The CI check failed and includes evidence; the PR remains open."
        if status == "success":
            return "The authoritative admission Gate passed for this exact head revision."
        return "The authoritative admission Gate completed with a non-blocking warning."

    @staticmethod
    def _provider_repository(repository_ref: str) -> str:
        return repository_ref.split("://", 1)[1] if "://" in repository_ref else repository_ref

    @staticmethod
    def _provider_head(provider: str, data: dict[str, Any]) -> str | None:
        if provider == "github":
            raw_head = data.get("head")
            head: dict[str, Any] = dict(raw_head) if isinstance(raw_head, dict) else {}
            value = head.get("sha")
        elif provider == "gitlab":
            raw_diff_refs = data.get("diff_refs")
            diff_refs: dict[str, Any] = dict(raw_diff_refs) if isinstance(raw_diff_refs, dict) else {}
            value = data.get("sha") or diff_refs.get("head_sha")
        else:
            value = data.get("commitSha") or data.get("headSha")
        normalized = str(value or "").lower()
        return normalized if 7 <= len(normalized) <= 64 and all(ch in "0123456789abcdef" for ch in normalized) else None

    @staticmethod
    def _minimal_provider_response(data: dict[str, Any]) -> dict[str, Any]:
        allowlist = {"id", "status", "state", "conclusion", "name", "url", "html_url", "web_url", "target_url"}
        selected = {key: redact_sensitive_data(value) for key, value in data.items() if key in allowlist}
        if "url" not in selected:
            selected["url"] = selected.get("html_url") or selected.get("web_url") or selected.get("target_url")
        return selected

    @staticmethod
    def _connector_error_code(result: ConnectorOperationResult) -> str:
        message = " ".join(result.errors).lower()
        if "429" in message:
            return "CI_CONNECTOR_RATE_LIMITED"
        if "403" in message:
            return "CI_CONNECTOR_FORBIDDEN"
        if "timeout" in message:
            return "CI_CONNECTOR_TIMEOUT_UNKNOWN_RESULT"
        if "credential" in message:
            return "CI_CONNECTOR_CREDENTIAL_UNAVAILABLE"
        return "CI_CONNECTOR_WRITE_FAILED"

    @staticmethod
    def _connector_refs(result: ConnectorOperationResult, *, operation: str) -> list[dict[str, Any]]:
        if not result.connector_call_ref:
            return []
        return [{"type": "connector_call", "ref": result.connector_call_ref, "operation": operation, "succeeded": result.succeeded}]

    def _runtime_credentials(self, binding: SkillConnectorBinding) -> dict[str, Any]:
        validated = self.credentials.validate_binding(
            connector_name=binding.connector_name,
            secret_ref=binding.secret_ref,
            credential_ref=binding.credential_ref,
            scope=dict(binding.scope or {}),
        )
        return self.credentials.runtime_credentials_for_binding(validated, prefer_credential=True)

    def _binding_snapshot(self, binding: SkillConnectorBinding, run: AdmissionRunRecord) -> dict[str, Any]:
        body = {
            "connectorBindingId": str(binding.id),
            "connectorType": binding.connector_name,
            "tenantId": run.tenant_id,
            "workspaceId": run.workspace_id,
            "projectId": str(run.project_id),
            "repositoryRef": run.repository_ref,
            "scopeType": "project_repository",
            "bindingRevision": 1,
        }
        return self.connector_snapshot_builder.build(
            {**body, "configurationHash": canonical_hash(body)}
        )

    @staticmethod
    def _require_binding_scope(binding: SkillConnectorBinding, run: AdmissionRunRecord) -> None:
        scope = dict(binding.scope or {})
        required = {
            "projectId": str(run.project_id),
            "tenantId": run.tenant_id,
            "workspaceId": run.workspace_id,
        }
        if str(scope.get("projectId") or "") != required["projectId"]:
            raise CIWritebackError("CI_CONNECTOR_BINDING_SCOPE_MISMATCH")
        for key in ("tenantId", "workspaceId"):
            if scope.get(key) is not None and str(scope[key]) != required[key]:
                raise CIWritebackError("CI_CONNECTOR_BINDING_SCOPE_MISMATCH")
        repository_refs: set[str] = set()
        if scope.get("repositoryRef"):
            repository_refs.add(str(scope["repositoryRef"]))
        mappings = scope.get("repositoryBindings") or scope.get("repositories")
        if isinstance(mappings, list):
            repository_refs.update(
                str(item.get("repositoryRef") or item.get("ref") or "")
                for item in mappings
                if isinstance(item, dict)
            )
        repository_refs.discard("")
        if repository_refs and run.repository_ref not in repository_refs:
            raise CIWritebackError("CI_CONNECTOR_BINDING_SCOPE_MISMATCH")

    @staticmethod
    def _connector(provider: str):
        if provider == "github":
            return GitHubReadOnlyConnector()
        if provider == "gitlab":
            return GitLabReadOnlyConnector()
        if provider == "mock-scm":
            return MockScmConnector()
        raise CIWritebackError("CI_CONNECTOR_PROVIDER_UNSUPPORTED")

    @classmethod
    def _require_connector_capability(cls, provider: str, capability: str) -> None:
        contract = cls._connector(provider).contract
        match = next((item for item in contract.capabilities if item.name == capability), None)
        if match is None or match.read_only:
            raise CIWritebackError("CI_CONNECTOR_WRITE_CAPABILITY_UNAVAILABLE", status_code=503)

    def _policy(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        repository_ref: str,
        check_name: str,
    ) -> CIEnforcementPolicyRecord | None:
        return self.db.scalar(
            select(CIEnforcementPolicyRecord).where(
                CIEnforcementPolicyRecord.tenant_id == tenant_id,
                CIEnforcementPolicyRecord.workspace_id == workspace_id,
                CIEnforcementPolicyRecord.project_id == project_id,
                CIEnforcementPolicyRecord.repository_ref == repository_ref,
                CIEnforcementPolicyRecord.check_name == check_name,
            )
        )

    @staticmethod
    def _policy_projection(row: CIEnforcementPolicyRecord) -> dict[str, Any]:
        approval_ref = f"approval://{row.activation_approval_id}" if row.activation_approval_id else None
        ready = row.status == "active" and (row.mode != "enforce" or (row.branch_protection_configured and approval_ref is not None))
        projection = CIEnforcementPolicyProjection.model_validate(
            {
                "projectId": row.project_id,
                "repositoryRef": row.repository_ref,
                "checkName": row.check_name,
                "mode": row.mode,
                "status": row.status,
                "policyHash": row.policy_hash,
                "branchProtectionConfigured": row.branch_protection_configured,
                "approvalRef": approval_ref,
                "ready": ready,
                "unavailableReason": None
                if ready
                else (
                    "CI_ENFORCEMENT_APPROVAL_PENDING"
                    if row.status == "approval_pending"
                    else "CI_WRITEBACK_POLICY_DISABLED"
                ),
                "requiredCapabilities": ["ci.write", "enforce.manage", "ci.retry"],
            }
        )
        return projection.model_dump(mode="json")

    def _require_repository_context(
        self,
        project_id: UUID,
        repository_ref: str,
        scope: tuple[str, str],
    ) -> ScmPrContextRecord:
        row = self.db.scalar(
            select(ScmPrContextRecord).where(
                ScmPrContextRecord.project_id == project_id,
                ScmPrContextRecord.tenant_id == scope[0],
                ScmPrContextRecord.workspace_id == scope[1],
                ScmPrContextRecord.repository_ref == repository_ref,
            )
        )
        if row is None:
            raise CIWritebackError("CI_REPOSITORY_CONTEXT_NOT_FOUND", status_code=404)
        return row

    def _require_scope(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        capability: str,
    ) -> tuple[str, str]:
        if capability not in set(context.user.capabilities):
            raise CIWritebackError("CI_CAPABILITY_REQUIRED", status_code=403, field=capability)
        try:
            scope = ScopeAuthorizationService(self.db).resolve_project(project_id, context)
        except ScopeAuthorizationError as exc:
            raise CIWritebackError(
                "CI_PROJECT_NOT_FOUND" if exc.status_code != 409 else "CI_SCOPE_INVALID",
                status_code=exc.status_code,
                field=exc.field,
            ) from exc
        return scope.tenant_id, scope.workspace_id

    def _guard(
        self,
        context: ServiceContext,
        *,
        resource_type: str,
        resource_id: str,
        action: str,
        mode: str,
        approval_ref: str | None,
        head_current: bool,
        execution_id: UUID | None = None,
    ) -> None:
        self.guardrails.enforce(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type=resource_type,
                resource_id=resource_id,
                execution_id=execution_id,
                payload={
                    "resourceId": resource_id,
                    "mode": mode,
                    "approvalRef": approval_ref,
                    "headCurrent": head_current,
                    "closePullRequest": False,
                    "merge": False,
                    "deleteBranch": False,
                    "modifyCode": False,
                },
                metadata={"action": action},
            ),
            [CIWritebackGuard()],
        )
        self.db.flush()

    def _guardrail_refs(self, *, resource_id: str) -> list[dict[str, Any]]:
        rows = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(
                    GuardrailEvent.rule_id == "ci.writeback_controlled",
                )
                .order_by(GuardrailEvent.created_at.asc(), GuardrailEvent.id.asc())
            )
        )
        return [
            {"type": "guardrail_event", "ref": f"guardrail-event://{row.id}"}
            for row in rows
            if str((row.payload or {}).get("resourceId") or "") == resource_id
        ]

    @staticmethod
    def _audit_ref(row: AuditLog) -> dict[str, Any]:
        return {"type": "audit_log", "ref": f"audit-log://{row.id}", "action": row.action}


__all__ = ["CIWritebackError", "CIWritebackService"]

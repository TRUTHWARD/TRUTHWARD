# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import ApprovalStatus, ApprovalType
from agentic_qa.domain.models import Approval
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.infra.safe_projection import ConnectorBindingSafeProjectionBuilder
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
    paginate_query,
    paginate_result,
)
from agentic_qa.services.capability_service import require_capability


class ApprovalConflictError(ValueError):
    """Raised when an approval cannot transition from its current state."""


class ApprovalService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_approvals(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        approval_type: str | None = None,
        resource_type: str | None = None,
    ) -> dict[str, object]:
        self.expire_pending_approvals()
        statement = select(Approval).order_by(Approval.created_at.desc())
        if status:
            statement = statement.where(Approval.status == status)
        if approval_type:
            statement = statement.where(Approval.type == approval_type)
        if resource_type:
            statement = statement.where(Approval.resource_type == resource_type)
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result([self.serialize_approval(row) for row in rows], total, page, page_size)

    def get_approval(self, approval_id: UUID) -> dict[str, object]:
        self.expire_pending_approvals(approval_id=approval_id)
        return self.serialize_approval(self._require_approval(approval_id))

    def expire_pending_approvals(self, *, approval_id: UUID | None = None) -> int:
        statement = select(Approval).where(Approval.status == ApprovalStatus.PENDING)
        if approval_id is not None:
            statement = statement.where(Approval.id == approval_id)
        approvals = list(self.db.scalars(statement))
        now = datetime.now(timezone.utc)
        expired_count = 0
        for approval in approvals:
            expires_at_value = approval.payload.get("expiresAt")
            if not expires_at_value:
                continue
            try:
                expires_at = datetime.fromisoformat(str(expires_at_value).replace("Z", "+00:00"))
            except ValueError:
                continue
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at > now:
                continue
            approval.status = ApprovalStatus.EXPIRED
            approval.decided_at = now
            approval.decision_comment = "approval expired by policy"
            write_audit_log(
                self.db,
                None,
                "approval.expire",
                "approval",
                str(approval.id),
                str(approval.payload.get("requestId") or f"approval-expire:{approval.id}"),
                str(approval.payload.get("traceId") or uuid4()),
                {
                    "type": approval.type.value,
                    "resourceType": approval.resource_type,
                    "resourceId": approval.resource_id,
                    "expiresAt": expires_at.isoformat(),
                    "decision": ApprovalStatus.EXPIRED.value,
                },
            )
            expired_count += 1
        if expired_count:
            self.db.commit()
        return expired_count

    def request_execution_heal(self, execution_id: UUID, mode: str, context: ServiceContext) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.HEALING_PATCH,
            resource_type="execution",
            resource_id=str(execution_id),
            summary=f"Approval required before generating a healing patch for execution {execution_id}.",
            payload={
                "action": "execution.heal",
                "executionId": str(execution_id),
                "mode": mode,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "executionId": str(execution_id),
            "status": approval.status.value,
            "jobId": None,
        }

    def request_execution_retry(self, execution_id: UUID, scope: str, context: ServiceContext) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.MANUAL_RERUN,
            resource_type="execution",
            resource_id=str(execution_id),
            summary=f"Approval required before retrying execution {execution_id} with scope '{scope}'.",
            payload={
                "action": "execution.retry",
                "executionId": str(execution_id),
                "scope": scope,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "executionId": str(execution_id),
            "status": approval.status.value,
            "jobId": None,
        }

    def request_admission_review(
        self,
        *,
        admission_run_id: UUID,
        result_snapshot_hash: str | None,
        intent: str,
        comment: str | None,
        idempotency_key: str,
        context: ServiceContext,
    ) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="admission_run_review",
            resource_id=str(admission_run_id),
            summary=f"Governed human review requested for non-authoritative Admission run {admission_run_id}.",
            payload={
                "action": "admission.review",
                "admissionRunId": str(admission_run_id),
                "resultSnapshotHash": result_snapshot_hash,
                "intent": intent,
                "comment": comment,
                "idempotencyKey": idempotency_key,
                "nonAuthoritative": True,
                "mutatesCanonicalFinding": False,
                "mutatesGateDecision": False,
                "changesMergeState": False,
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def request_ci_enforcement_change(
        self,
        *,
        policy_id: UUID,
        project_id: UUID,
        repository_ref: str,
        check_name: str,
        target_mode: str,
        branch_protection_configured: bool,
        policy_hash: str,
        idempotency_key: str,
        reason: str,
        context: ServiceContext,
        commit: bool = True,
    ) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="ci_enforcement_policy",
            resource_id=str(policy_id),
            summary=f"Approval required before enabling CI Enforce for {repository_ref}.",
            payload={
                "action": "ci.enforcement.apply",
                "policyId": str(policy_id),
                "projectId": str(project_id),
                "repositoryRef": repository_ref,
                "checkName": check_name,
                "targetMode": target_mode,
                "branchProtectionConfigured": branch_protection_configured,
                "policyHash": policy_hash,
                "idempotencyKey": idempotency_key,
                "reason": reason,
                "requestedBy": str(context.user.id),
            },
            context=context,
            commit=commit,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def request_ci_writeback_retry(
        self,
        *,
        attempt_id: UUID,
        admission_run_id: UUID,
        request_hash: str,
        head_sha: str,
        policy_hash: str,
        idempotency_key: str,
        reason: str,
        context: ServiceContext,
    ) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="ci_writeback_retry",
            resource_id=str(attempt_id),
            summary=f"Approval required before retrying CI writeback attempt {attempt_id}.",
            payload={
                "action": "ci.writeback.retry",
                "attemptId": str(attempt_id),
                "admissionRunId": str(admission_run_id),
                "requestHash": request_hash,
                "headSha": head_sha,
                "policyHash": policy_hash,
                "idempotencyKey": idempotency_key,
                "reason": reason,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def request_accepted_risk(self, finding_id: UUID, comment: str | None, context: ServiceContext) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.ACCEPTED_RISK,
            resource_type="finding",
            resource_id=str(finding_id),
            summary=f"Approval required before marking finding {finding_id} as accepted risk.",
            payload={
                "action": "finding.accepted_risk",
                "findingId": str(finding_id),
                "status": "accepted_risk",
                "comment": comment,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "findingId": str(finding_id),
            "status": approval.status.value,
        }

    def request_visual_action_review(
        self,
        execution_id: UUID,
        attempt_id: UUID,
        action_id: str,
        reason: str,
        payload: dict[str, object],
        context: ServiceContext,
        *,
        commit: bool = True,
    ) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.VISUAL_ACTION,
            resource_type="execution",
            resource_id=str(execution_id),
            summary=f"Approval required before continuing visual action '{action_id}' for execution {execution_id}.",
            payload={
                "action": "visual_grounding.action_review",
                "executionId": str(execution_id),
                "attemptId": str(attempt_id),
                "actionId": action_id,
                "reason": reason,
                "requestedBy": str(context.user.id),
                **payload,
            },
            context=context,
            commit=commit,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "executionId": str(execution_id),
            "attemptId": str(attempt_id),
            "actionId": action_id,
            "status": approval.status.value,
        }

    def request_skill_invocation(
        self,
        *,
        skill_id: str,
        version: str,
        manifest_hash: str,
        request_payload: dict[str, object],
        context_refs: list[dict[str, object]],
        risk_profile: dict[str, object],
        policy_snapshot: dict[str, object],
        connector_binding_snapshot: dict[str, object],
        idempotency_key: str | None,
        context: ServiceContext,
        commit: bool = True,
    ) -> dict[str, object]:
        connector_binding_snapshot = ConnectorBindingSafeProjectionBuilder().build(
            connector_binding_snapshot
        )
        resource_id = idempotency_key or self._fingerprint_resource_id(
            {
                "skillId": skill_id,
                "version": version,
                "manifestHash": manifest_hash,
                "request": request_payload,
                "contextRefs": context_refs,
            }
        )
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="skill_invocation_request",
            resource_id=resource_id,
            summary=f"Approval required before invoking high-risk Skill '{skill_id}' version {version}.",
            payload={
                "action": "skill.invoke",
                "skillId": skill_id,
                "version": version,
                "manifestHash": manifest_hash,
                "request": request_payload,
                "contextRefs": context_refs,
                "riskProfile": risk_profile,
                "policySnapshot": policy_snapshot,
                "connectorBindingSnapshot": connector_binding_snapshot,
                "idempotencyKey": idempotency_key,
                "requestedBy": str(context.user.id),
            },
            context=context,
            commit=commit,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def request_capability_binding_lifecycle(
        self,
        *,
        binding_id: UUID,
        operation: str,
        current: dict[str, object] | None,
        proposed: dict[str, object],
        risk_reasons: list[str],
        guardrail_event_refs: list[dict[str, object]],
        audit_refs: list[dict[str, object]],
        context: ServiceContext,
        commit: bool = True,
    ) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="capability_binding",
            resource_id=str(binding_id),
            summary=f"Approval required before applying capability binding lifecycle change for {binding_id}.",
            payload={
                "action": "capability_binding.lifecycle_change",
                "bindingId": str(binding_id),
                "operation": operation,
                "current": current,
                "proposed": proposed,
                "riskReasons": risk_reasons,
                "guardrailEventRefs": guardrail_event_refs,
                "auditRefs": audit_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
            commit=commit,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def request_execution_plan_review(
        self,
        *,
        execution_plan_id: UUID,
        orchestration_run_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="execution_plan",
            resource_id=str(execution_plan_id),
            summary=f"Approval required before executing high-risk plan {execution_plan_id}.",
            payload={
                "action": "core_loop.execution_plan",
                "executionPlanId": str(execution_plan_id),
                "orchestrationRunId": str(orchestration_run_id),
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def request_gate_policy_review(
        self,
        *,
        project_id: UUID,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        version_id: UUID,
        content_hash: str,
        reason: str,
        context: ServiceContext,
        commit: bool = True,
    ) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="gate_policy_version_review",
            resource_id=str(version_id),
            summary=f"Approval required to review Gate Policy version {version_id}.",
            payload={
                "action": "gate_policy.review",
                "projectId": str(project_id),
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
                "policyId": str(policy_id),
                "versionId": str(version_id),
                "contentHash": content_hash,
                "reason": reason,
                "requestedBy": str(context.user.id),
                "activatesProduction": False,
            },
            context=context,
            commit=commit,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def request_gate_policy_lifecycle(
        self,
        *,
        project_id: UUID,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        version_id: UUID,
        content_hash: str,
        current_status: str,
        target_status: str,
        reason: str,
        context: ServiceContext,
        commit: bool = True,
    ) -> dict[str, object]:
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="gate_policy_version_lifecycle",
            resource_id=str(version_id),
            summary=f"Approval required for Gate Policy version {version_id} lifecycle change.",
            payload={
                "action": "gate_policy.lifecycle",
                "projectId": str(project_id),
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
                "policyId": str(policy_id),
                "versionId": str(version_id),
                "contentHash": content_hash,
                "currentStatus": current_status,
                "targetStatus": target_status,
                "reason": reason,
                "requestedBy": str(context.user.id),
                "activatesProduction": False,
            },
            context=context,
            commit=commit,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def request_gate_policy_deployment_change(
        self,
        *,
        action: str,
        request_id: UUID,
        project_id: UUID,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        version_id: UUID,
        content_hash: str,
        simulation_run_id: UUID | None,
        dataset_fingerprint: str | None,
        summary_hash: str | None,
        expected_binding_id: UUID | None,
        expected_version_id: UUID | None,
        request_hash: str,
        idempotency_key: str,
        reason: str,
        thresholds: dict[str, object],
        context: ServiceContext,
        commit: bool = True,
    ) -> dict[str, object]:
        if action not in {"activation", "rollback"}:
            raise ValueError("unsupported Gate Policy deployment action")
        resource_type = f"gate_policy_{action}_request"
        approval = self._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type=resource_type,
            resource_id=str(request_id),
            summary=f"Approval required for Gate Policy {action} request {request_id}.",
            payload={
                "action": f"gate_policy.{action}",
                "requestId": str(request_id),
                "projectId": str(project_id),
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
                "policyId": str(policy_id),
                "versionId": str(version_id),
                "contentHash": content_hash,
                "simulationRunId": str(simulation_run_id) if simulation_run_id else None,
                "datasetFingerprint": dataset_fingerprint,
                "summaryHash": summary_hash,
                "expectedBindingId": str(expected_binding_id) if expected_binding_id else None,
                "expectedVersionId": str(expected_version_id) if expected_version_id else None,
                "requestHash": request_hash,
                "idempotencyKey": idempotency_key,
                "reason": reason,
                "thresholds": thresholds,
                "mode": "enforce",
                "approvalRequired": True,
                "requestedBy": str(context.user.id),
            },
            context=context,
            commit=commit,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "status": approval.status.value,
        }

    def approve(self, approval_id: UUID, comment: str | None, context: ServiceContext) -> dict[str, object]:
        acquire_transaction_advisory_lock(
            self.db,
            "approval-decision",
            str(approval_id),
        )
        self.expire_pending_approvals(approval_id=approval_id)
        approval = self._require_approval(approval_id, for_update=True)
        self._require_gate_policy_review_capability(approval, context)
        self._ensure_pending(approval)
        approval.status = ApprovalStatus.APPROVED
        approval.decided_by = context.user.id
        approval.decision_comment = comment
        approval.decided_at = datetime.now(timezone.utc)
        try:
            action_result = self._apply_approved_action(approval, context)
            write_audit_log(
                self.db,
                str(context.user.id),
                "approval.approve",
                "approval",
                str(approval.id),
                context.request_id,
                context.trace_id,
                {"type": approval.type.value, "resourceType": approval.resource_type, "resourceId": approval.resource_id},
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return {
            **self.serialize_approval(approval),
            "actionResult": action_result,
        }

    def reject(self, approval_id: UUID, comment: str | None, context: ServiceContext) -> dict[str, object]:
        acquire_transaction_advisory_lock(
            self.db,
            "approval-decision",
            str(approval_id),
        )
        self.expire_pending_approvals(approval_id=approval_id)
        approval = self._require_approval(approval_id, for_update=True)
        self._require_gate_policy_review_capability(approval, context)
        self._ensure_pending(approval)
        approval.status = ApprovalStatus.REJECTED
        approval.decided_by = context.user.id
        approval.decision_comment = comment
        approval.decided_at = datetime.now(timezone.utc)
        action_result = None
        if approval.type == ApprovalType.OTHER and approval.payload.get("action") == "core_loop.execution_plan":
            from agentic_qa.services.orchestrator_service import OrchestratorService

            action_result = OrchestratorService(self.db).reject_execution_plan(
                UUID(str(approval.payload["orchestrationRunId"])),
                UUID(str(approval.payload["executionPlanId"])),
                context,
                approval_id=approval.id,
                decision="rejected",
            )
        if approval.type == ApprovalType.OTHER and approval.payload.get("action") == "capability_binding.lifecycle_change":
            from agentic_qa.services.skill_service import SkillService

            action_result = SkillService(self.db).record_capability_binding_lifecycle_decision(
                approval.payload,
                approval.id,
                "rejected",
                context,
            )
        write_audit_log(
            self.db,
            str(context.user.id),
            "approval.reject",
            "approval",
            str(approval.id),
            context.request_id,
            context.trace_id,
            {"type": approval.type.value, "resourceType": approval.resource_type, "resourceId": approval.resource_id},
        )
        self.db.commit()
        return {**self.serialize_approval(approval), "actionResult": action_result}

    def cancel(self, approval_id: UUID, comment: str | None, context: ServiceContext) -> dict[str, object]:
        acquire_transaction_advisory_lock(
            self.db,
            "approval-decision",
            str(approval_id),
        )
        self.expire_pending_approvals(approval_id=approval_id)
        approval = self._require_approval(approval_id, for_update=True)
        self._require_gate_policy_review_capability(approval, context)
        self._ensure_pending(approval)
        approval.status = ApprovalStatus.CANCELLED
        approval.decided_by = context.user.id
        approval.decision_comment = comment
        approval.decided_at = datetime.now(timezone.utc)
        action_result = None
        if approval.type == ApprovalType.OTHER and approval.payload.get("action") == "core_loop.execution_plan":
            from agentic_qa.services.orchestrator_service import OrchestratorService

            action_result = OrchestratorService(self.db).reject_execution_plan(
                UUID(str(approval.payload["orchestrationRunId"])),
                UUID(str(approval.payload["executionPlanId"])),
                context,
                approval_id=approval.id,
                decision="cancelled",
            )
        if approval.type == ApprovalType.OTHER and approval.payload.get("action") == "capability_binding.lifecycle_change":
            from agentic_qa.services.skill_service import SkillService

            action_result = SkillService(self.db).record_capability_binding_lifecycle_decision(
                approval.payload,
                approval.id,
                "cancelled",
                context,
            )
        write_audit_log(
            self.db,
            str(context.user.id),
            "approval.cancel",
            "approval",
            str(approval.id),
            context.request_id,
            context.trace_id,
            {"type": approval.type.value, "resourceType": approval.resource_type, "resourceId": approval.resource_id},
        )
        self.db.commit()
        return {**self.serialize_approval(approval), "actionResult": action_result}

    def serialize_approval(self, approval: Approval) -> dict[str, object]:
        return {
            "id": str(approval.id),
            "type": approval.type.value,
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "summary": approval.summary,
            "payload": redact_sensitive_data(approval.payload),
            "status": approval.status.value,
            "requestedBy": str(approval.requested_by) if approval.requested_by else None,
            "decidedBy": str(approval.decided_by) if approval.decided_by else None,
            "decisionComment": approval.decision_comment,
            "decidedAt": approval.decided_at.isoformat() if approval.decided_at else None,
            "createdAt": approval.created_at.isoformat(),
            "updatedAt": approval.updated_at.isoformat(),
        }

    def _get_or_create_pending_approval(
        self,
        *,
        approval_type: ApprovalType,
        resource_type: str,
        resource_id: str,
        summary: str,
        payload: dict[str, object],
        context: ServiceContext,
        commit: bool = True,
    ) -> Approval:
        payload = redact_sensitive_data(payload)
        acquire_transaction_advisory_lock(
            self.db,
            "approval-request",
            f"{approval_type.value}:{resource_type}:{resource_id}",
        )
        existing = self.db.scalar(
            select(Approval)
            .where(Approval.type == approval_type)
            .where(Approval.resource_type == resource_type)
            .where(Approval.resource_id == resource_id)
            .where(Approval.status == ApprovalStatus.PENDING)
            .order_by(Approval.created_at.desc())
        )
        if existing is not None:
            if existing.payload == payload:
                return existing
            raise ApprovalConflictError(
                "pending approval idempotency conflict for the same resource"
            )

        approval = Approval(
            id=uuid4(),
            type=approval_type,
            resource_type=resource_type,
            resource_id=resource_id,
            summary=summary,
            payload=payload,
            status=ApprovalStatus.PENDING,
            requested_by=context.user.id,
        )
        self.db.add(approval)
        self.db.flush()
        write_audit_log(
            self.db,
            str(context.user.id),
            "approval.request",
            "approval",
            str(approval.id),
            context.request_id,
            context.trace_id,
            {"type": approval.type.value, "resourceType": resource_type, "resourceId": resource_id},
        )
        if commit:
            self.db.commit()
            self.db.refresh(approval)
        return approval

    def _apply_approved_action(self, approval: Approval, context: ServiceContext) -> dict[str, object] | None:
        from agentic_qa.services.execution_service import ExecutionService

        action = str(approval.payload.get("action") or "")
        execution_service = ExecutionService(self.db)
        if approval.type == ApprovalType.HEALING_PATCH and action == "execution.heal":
            return execution_service.execute_approved_heal(
                UUID(str(approval.payload["executionId"])),
                str(approval.payload.get("mode") or "generate_patch"),
                context,
                approval_id=approval.id,
            )
        if approval.type == ApprovalType.MANUAL_RERUN and action == "execution.retry":
            return execution_service.execute_approved_retry(
                UUID(str(approval.payload["executionId"])),
                str(approval.payload.get("scope") or "all"),
                context,
                approval_id=approval.id,
            )
        if approval.type == ApprovalType.ACCEPTED_RISK and action == "finding.accepted_risk":
            return execution_service.execute_approved_finding_update(
                UUID(str(approval.payload["findingId"])),
                str(approval.payload.get("status") or "accepted_risk"),
                approval.payload.get("comment"),
                context,
                approval_id=approval.id,
            )
        if approval.type == ApprovalType.VISUAL_ACTION and action == "visual_grounding.action_review":
            return execution_service.execute_approved_visual_action_review(
                UUID(str(approval.payload["executionId"])),
                UUID(str(approval.payload["attemptId"])),
                context,
                approval_id=approval.id,
            )
        if approval.type == ApprovalType.OTHER and action == "skill.invoke":
            from agentic_qa.schemas.skills import SkillInvocationRequest
            from agentic_qa.services.skill_service import SkillService

            idempotency_key = approval.payload.get("idempotencyKey")
            request = SkillInvocationRequest(
                skillId=str(approval.payload["skillId"]),
                version=str(approval.payload.get("version") or "") or None,
                idempotencyKey=str(idempotency_key) if idempotency_key is not None else None,
                request=dict(approval.payload.get("request") or {}),
                contextRefs=list(approval.payload.get("contextRefs") or []),
                riskProfile=dict(approval.payload.get("riskProfile") or {}),
                policySnapshot=dict(approval.payload.get("policySnapshot") or {}),
                connectorBindingSnapshot=dict(approval.payload.get("connectorBindingSnapshot") or {}),
            )
            result = SkillService(self.db).create_invocation(request, context, commit=False)
            return {"skillInvocationId": result["id"], "skillInvocation": result}
        if approval.type == ApprovalType.OTHER and action == "capability_binding.lifecycle_change":
            from agentic_qa.services.skill_service import SkillService

            result = SkillService(self.db).execute_approved_capability_binding_lifecycle(
                approval.payload,
                approval.id,
                context,
            )
            return {"capabilityBindingId": result["id"], "capabilityBinding": result}
        if approval.type == ApprovalType.OTHER and action == "replay_repository.freeze":
            from agentic_qa.services.replay_repository_service import (
                ReplayRepositoryConflictError,
                ReplayRepositoryService,
            )

            try:
                replay = ReplayRepositoryService(self.db).execute_approved_freeze(
                    execution_id=UUID(str(approval.payload["executionId"])),
                    source_replay_export_hash=str(approval.payload["sourceReplayExportHash"]),
                    approval_id=approval.id,
                    context=context,
                )
            except ReplayRepositoryConflictError as exc:
                raise ApprovalConflictError(str(exc)) from exc
            return {"replayId": replay["replayId"], "replay": replay}
        if approval.type == ApprovalType.OTHER and action == "replay_repository.retention":
            from agentic_qa.services.replay_repository_service import (
                ReplayRepositoryConflictError,
                ReplayRepositoryService,
            )

            try:
                replay = ReplayRepositoryService(self.db).execute_approved_retention_action(
                    replay_id=str(approval.payload["replayId"]),
                    action=str(approval.payload["retentionAction"]),
                    retention_until=approval.payload.get("retentionUntil"),
                    approval_id=approval.id,
                    context=context,
                    expected_retention_state_hash=(
                        str(approval.payload["expectedRetentionStateHash"])
                        if approval.payload.get("expectedRetentionStateHash")
                        else None
                    ),
                )
            except ReplayRepositoryConflictError as exc:
                raise ApprovalConflictError(str(exc)) from exc
            return {"replayId": replay["replayId"], "replay": replay}
        if approval.type == ApprovalType.OTHER and action == "replay_repository.governance_policy.update":
            from agentic_qa.services.replay_repository_service import ReplayRepositoryService

            policy = ReplayRepositoryService(self.db).execute_approved_governance_policy_update(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
            return {"policy": policy}
        if approval.type == ApprovalType.OTHER and action == "audit_retention.apply":
            from agentic_qa.services.observability_service import ObservabilityService

            result = ObservabilityService(self.db).execute_approved_audit_retention_action(
                audit_log_id=UUID(str(approval.payload["auditLogId"])),
                action=str(approval.payload["retentionAction"]),
                retention_until=approval.payload.get("retentionUntil"),
                approval_id=approval.id,
                context=context,
            )
            return {"auditRetention": result}
        if approval.type == ApprovalType.OTHER and action == "model_governance.apply":
            from agentic_qa.services.model_service import ModelService

            result = ModelService(self.db).execute_approved_model_governance_action(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
            return {"modelGovernance": result}
        if approval.type == ApprovalType.OTHER and action == "routing_policy_governance.apply":
            from agentic_qa.services.routing_service import RoutingPolicyService

            result = RoutingPolicyService(self.db).execute_approved_routing_policy_governance_action(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
            return {"routingPolicyGovernance": result}
        if approval.type == ApprovalType.OTHER and action == "access_control.user_access_change":
            from agentic_qa.services.access_control_service import AccessControlService

            return AccessControlService(self.db).execute_approved_user_access_change(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "access_control.role_capability_change":
            from agentic_qa.services.access_control_service import AccessControlService

            return AccessControlService(self.db).execute_approved_role_capability_change(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "access_control.user_entitlement_change":
            from agentic_qa.services.access_control_service import AccessControlService

            return AccessControlService(self.db).execute_approved_user_entitlement_change(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "knowledge_promotion.supersede":
            from agentic_qa.services.correction_governance_service import CorrectionGovernanceService

            return CorrectionGovernanceService(self.db).execute_approved_knowledge_supersede(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action.startswith("graph_staleness."):
            # Approval records the decision only. The explicit P14 apply command
            # revalidates assessment/hash/expiry/lock before changing review or lifecycle state.
            return {
                "graphStalenessReviewId": approval.resource_id,
                "decision": "approved_pending_explicit_apply",
            }
        if approval.type == ApprovalType.OTHER and action == "core_loop.execution_plan":
            from agentic_qa.services.orchestrator_service import OrchestratorService

            return OrchestratorService(self.db).resume_approved_execution_plan(
                UUID(str(approval.payload["orchestrationRunId"])),
                UUID(str(approval.payload["executionPlanId"])),
                context,
                approval_id=approval.id,
            )
        if approval.type == ApprovalType.OTHER and action == "gate_policy.review":
            from agentic_qa.services.gate_policy_governance_service import GatePolicyGovernanceService

            return GatePolicyGovernanceService(self.db).execute_approved_review(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "gate_policy.lifecycle":
            from agentic_qa.services.gate_policy_governance_service import GatePolicyGovernanceService

            return GatePolicyGovernanceService(self.db).execute_approved_lifecycle(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "gate_policy.activation":
            from agentic_qa.services.gate_policy_deployment_service import GatePolicyDeploymentService

            return GatePolicyDeploymentService(self.db).execute_approved_activation(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "gate_policy.rollback":
            from agentic_qa.services.gate_policy_deployment_service import GatePolicyDeploymentService

            return GatePolicyDeploymentService(self.db).execute_approved_rollback(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "ci.enforcement.apply":
            from agentic_qa.services.ci_writeback_service import CIWritebackService

            return CIWritebackService(self.db).execute_approved_enforcement_change(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "ci.writeback.retry":
            from agentic_qa.services.ci_writeback_service import CIWritebackService

            return CIWritebackService(self.db).execute_approved_retry(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        if approval.type == ApprovalType.OTHER and action == "graph_promotion.review":
            # Approval remains a real human fact. The actual Promotion is a
            # separate, explicit Service mutation that re-evaluates every
            # frozen input and supplies this Approval id.
            return {
                "graphPromotionReview": {
                    "proposalId": str(approval.payload["proposalId"]),
                    "assessmentId": str(approval.payload["assessmentId"]),
                    "approvalId": str(approval.id),
                    "promotionPerformed": False,
                }
            }
        if approval.type == ApprovalType.OTHER and action == "graph_promotion.rollback_review":
            # Rollback is never executed by Approval itself. The rollback
            # command rechecks this immutable payload against the active base.
            return {
                "graphRollbackReview": {
                    "graphId": str(approval.payload["graphId"]),
                    "rollbackTargetVersionId": str(
                        approval.payload["rollbackTargetVersionId"]
                    ),
                    "approvalId": str(approval.id),
                    "rollbackPerformed": False,
                }
            }
        if approval.type == ApprovalType.OTHER and action == "graph_autonomy.configure":
            from agentic_qa.services.graph_promotion_service import GraphPromotionService

            return GraphPromotionService(self.db).execute_approved_autonomy_configuration(
                approval_payload=approval.payload,
                approval_id=approval.id,
                context=context,
            )
        return None

    def _ensure_pending(self, approval: Approval) -> None:
        if approval.status != ApprovalStatus.PENDING:
            raise ApprovalConflictError("approval is not pending")

    def _require_approval(
        self,
        approval_id: UUID,
        *,
        for_update: bool = False,
    ) -> Approval:
        if not for_update:
            approval = self.db.get(Approval, approval_id)
            if approval is None:
                raise ValueError("approval not found")
            return approval
        statement = select(Approval).where(Approval.id == approval_id)
        statement = statement.with_for_update()
        approval = self.db.scalar(statement)
        if approval is None:
            raise ValueError("approval not found")
        return approval

    def _fingerprint_resource_id(self, payload: dict[str, object]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return f"skill-request:{hashlib.sha256(encoded).hexdigest()}"

    @staticmethod
    def _require_gate_policy_review_capability(approval: Approval, context: ServiceContext) -> None:
        if approval.resource_type in {"gate_policy_version_review", "gate_policy_version_lifecycle"}:
            require_capability(context.user.capabilities, "gate_policy.review")
        if approval.resource_type == "gate_policy_activation_request":
            require_capability(context.user.capabilities, "gate_policy.activate")
        if approval.resource_type == "gate_policy_rollback_request":
            require_capability(context.user.capabilities, "gate_policy.rollback")
        if approval.resource_type == "canonical_graph_promotion":
            require_capability(context.user.capabilities, "graph.promotion.promote")
        if approval.resource_type == "canonical_graph_rollback":
            require_capability(context.user.capabilities, "graph.promotion.rollback")
        if approval.resource_type == "graph_autonomy_configuration":
            require_capability(context.user.capabilities, "graph.autonomy.configure")
        if approval.resource_type == "canonical_graph_staleness_review":
            capability = (
                "graph.staleness.deprecate"
                if approval.payload.get("action") == "graph_staleness.deprecate"
                else "graph.staleness.review"
            )
            require_capability(context.user.capabilities, capability)
        if approval.resource_type == "admission_run_review":
            require_capability(context.user.capabilities, "admission.review")
        if approval.resource_type == "ci_enforcement_policy":
            require_capability(context.user.capabilities, "enforce.manage")
        if approval.resource_type == "ci_writeback_retry":
            require_capability(context.user.capabilities, "ci.retry")
        if approval.resource_type == "lesson_promotion":
            require_capability(context.user.capabilities, "lesson.promote")
        if approval.resource_type in {"improvement_proposal", "improvement_rollback"}:
            require_capability(context.user.capabilities, "improvement.review")

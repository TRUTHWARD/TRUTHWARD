# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import GatePolicyMode, GatePolicyScopeType, GatePolicyStatus
from agentic_qa.domain.models import (
    Approval,
    GatePolicy,
    GatePolicyBinding,
    GatePolicyBindingHistory,
    GatePolicyGovernanceRequest,
    GatePolicySimulationRun,
    GatePolicyVersion,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailViolationError
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.guardrails.runtime.gate_policy import GatePolicyMutationGuard
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.schemas.gate_policy import validate_gate_policy_document
from agentic_qa.schemas.gate_policy_simulation import (
    ActivationRequest,
    ActivationResult,
    GateModeProjection,
    GateModeRequest,
    RollbackRequest,
    RollbackResult,
    RollbackTargetProjection,
)
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import ServiceContext, acquire_transaction_advisory_lock, canonical_hash
from agentic_qa.services.gate_policy_governance_service import (
    GatePolicyGovernanceError,
    GatePolicyGovernanceService,
)


CAPABILITY_READ = "gate_policy.read"
CAPABILITY_MODE_MANAGE = "gate_policy.mode.manage"
CAPABILITY_ACTIVATE = "gate_policy.activate"
CAPABILITY_ROLLBACK = "gate_policy.rollback"


class GatePolicyDeploymentService:
    """Service-owned Gate mode, activation, and rollback governance boundary."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_modes(
        self,
        *,
        project_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_READ)
        _project, tenant_id, workspace_id = GatePolicyGovernanceService(self.db)._project_scope(
            project_id, context, write=False
        )
        modes = []
        for mode in GatePolicyMode:
            binding = self._current_binding(
                tenant_id, workspace_id, project_id, mode, for_update=False
            )
            history = (
                self.db.scalar(
                    select(GatePolicyBindingHistory)
                    .where(
                        GatePolicyBindingHistory.tenant_id == tenant_id,
                        GatePolicyBindingHistory.workspace_id == workspace_id,
                        GatePolicyBindingHistory.project_id == project_id,
                        GatePolicyBindingHistory.mode == mode,
                    )
                    .order_by(GatePolicyBindingHistory.created_at.desc())
                )
                if binding is not None
                else None
            )
            modes.append(self._mode_projection(project_id, mode, binding, history))
        return {
            "schemaVersion": "phase8.gate-policy-modes.v1",
            "projectId": str(project_id),
            "items": modes,
            "rollbackTargets": self._rollback_targets(
                tenant_id, workspace_id, project_id, modes
            ),
            "semantics": {
                "observe": "display_only_no_authoritative_evaluation",
                "shadow": "parallel_non_authoritative",
                "enforce": "authoritative_for_new_executions_after_activation",
            },
            "computedBy": "backend",
        }

    def set_mode(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        payload: GateModeRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_MODE_MANAGE)
        governance = GatePolicyGovernanceService(self.db)
        policy, tenant_id, workspace_id = governance._scoped_policy(
            project_id, policy_id, context, write=True
        )
        version = governance._scoped_version(
            project_id, policy_id, version_id, context, write=True, for_update=True
        )
        if version.status != GatePolicyStatus.ACTIVE:
            raise GatePolicyGovernanceError("GATE_POLICY_MODE_VERSION_UNAVAILABLE", status_code=409)
        self._validate_immutable_version(version)
        mode = GatePolicyMode(payload.mode)
        request_hash = canonical_hash(
            {
                "projectId": str(project_id),
                "policyId": str(policy.id),
                "policyVersionId": str(version.id),
                "policyVersionHash": version.content_hash,
                "mode": mode.value,
                "expectedCurrentBindingId": (
                    str(payload.expectedCurrentBindingId) if payload.expectedCurrentBindingId else None
                ),
                "reason": payload.reason,
            }
        )
        acquire_transaction_advisory_lock(
            self.db, "gate-policy-mode", f"{tenant_id}:{workspace_id}:{project_id}:{mode.value}"
        )
        existing_history = self.db.scalar(
            select(GatePolicyBindingHistory).where(
                GatePolicyBindingHistory.tenant_id == tenant_id,
                GatePolicyBindingHistory.workspace_id == workspace_id,
                GatePolicyBindingHistory.action == "mode_change",
                GatePolicyBindingHistory.idempotency_key == payload.idempotencyKey,
            )
        )
        if existing_history is not None:
            if existing_history.request_hash != request_hash:
                raise GatePolicyGovernanceError(
                    "GATE_POLICY_IDEMPOTENCY_CONFLICT", status_code=409, field="idempotencyKey"
                )
            binding = self.db.get(GatePolicyBinding, existing_history.binding_id)
            return self._mode_projection(project_id, mode, binding, existing_history)
        current = self._current_binding(
            tenant_id, workspace_id, project_id, mode, for_update=True
        )
        self._require_expected_binding(current, payload.expectedCurrentBindingId)
        self._preflight(
            context,
            action="mode_change",
            resource_type="gate_policy_version",
            resource_id=version.id,
            payload={"mode": mode.value, "policyVersionId": str(version.id)},
        )
        now = datetime.now(timezone.utc)
        before = self._binding_snapshot(current)
        if current is not None:
            # Close the effective window without destroying as-of resolution
            # for executions created while this binding was authoritative.
            current.effective_until = now
            current.updated_by = context.user.id
        binding = self._new_binding(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            project_id=project_id,
            version=version,
            mode=mode,
            idempotency_key=f"mode:{payload.idempotencyKey}",
            now=now,
            actor_id=context.user.id,
        )
        self.db.add(binding)
        self.db.flush()
        history = GatePolicyBindingHistory(
            id=uuid4(),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            project_id=project_id,
            action="mode_change",
            mode=mode,
            status="applied",
            binding_id=binding.id,
            previous_binding_id=current.id if current else None,
            policy_version_id=version.id,
            previous_policy_version_id=current.policy_version_id if current else None,
            before_snapshot=before,
            after_snapshot=self._binding_snapshot(binding),
            idempotency_key=payload.idempotencyKey,
            request_hash=request_hash,
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
        )
        self.db.add(history)
        write_audit_log(
            self.db,
            str(context.user.id),
            "gate_policy.mode.change",
            "gate_policy_binding",
            str(binding.id),
            context.request_id,
            context.trace_id,
            {
                "projectId": str(project_id),
                "mode": mode.value,
                "policyVersionId": str(version.id),
                "policyVersionHash": version.content_hash,
                "previousBindingId": str(current.id) if current else None,
                "authoritative": False,
                "blocksGate": False,
            },
        )
        self.db.commit()
        return self._mode_projection(project_id, mode, binding, history)

    def request_activation(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        payload: ActivationRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_ACTIVATE)
        governance = GatePolicyGovernanceService(self.db)
        policy, tenant_id, workspace_id = governance._scoped_policy(
            project_id, policy_id, context, write=True
        )
        version = governance._scoped_version(
            project_id, policy_id, version_id, context, write=True, for_update=True
        )
        simulation = self._require_complete_simulation(
            project_id, policy.id, version, payload.simulationRunId
        )
        self._require_risk_thresholds(
            simulation,
            max_false_pass=payload.maxFalsePassRiskCount,
            max_new_block=payload.maxNewBlockCount,
        )
        current = self._current_binding(
            tenant_id, workspace_id, project_id, GatePolicyMode.ENFORCE, for_update=True
        )
        self._require_expected_binding(current, payload.expectedCurrentBindingId)
        self._require_expected_version(current, payload.expectedCurrentPolicyVersionId)
        request_hash = canonical_hash(
            {
                "projectId": str(project_id),
                "policyId": str(policy.id),
                "policyVersionId": str(version.id),
                "policyVersionHash": version.content_hash,
                "simulationRunId": str(simulation.id),
                "datasetFingerprint": simulation.dataset_fingerprint,
                "summaryHash": canonical_hash(simulation.summary),
                "expectedCurrentBindingId": str(payload.expectedCurrentBindingId) if payload.expectedCurrentBindingId else None,
                "expectedCurrentPolicyVersionId": str(payload.expectedCurrentPolicyVersionId) if payload.expectedCurrentPolicyVersionId else None,
                "maxFalsePassRiskCount": payload.maxFalsePassRiskCount,
                "maxNewBlockCount": payload.maxNewBlockCount,
                "reason": payload.reason,
            }
        )
        return self._request_approval_backed_change(
            action="activation",
            project_id=project_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            policy_id=policy.id,
            version=version,
            simulation=simulation,
            expected_binding=current,
            expected_version_id=payload.expectedCurrentPolicyVersionId,
            idempotency_key=payload.idempotencyKey,
            request_hash=request_hash,
            reason=payload.reason,
            thresholds={
                "maxFalsePassRiskCount": payload.maxFalsePassRiskCount,
                "maxNewBlockCount": payload.maxNewBlockCount,
            },
            context=context,
        )

    def request_rollback(
        self,
        *,
        project_id: UUID,
        payload: RollbackRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_ROLLBACK)
        governance = GatePolicyGovernanceService(self.db)
        _project, tenant_id, workspace_id = governance._project_scope(
            project_id, context, write=True
        )
        target = self.db.scalar(
            select(GatePolicyVersion)
            .join(GatePolicy, GatePolicyVersion.policy_id == GatePolicy.id)
            .where(
                GatePolicyVersion.id == payload.targetPolicyVersionId,
                GatePolicyVersion.tenant_id == tenant_id,
                GatePolicyVersion.workspace_id == workspace_id,
                GatePolicy.project_id == project_id,
            )
            .with_for_update()
        )
        if target is None:
            raise GatePolicyGovernanceError("GATE_POLICY_ROLLBACK_TARGET_NOT_FOUND", status_code=404)
        if target.status == GatePolicyStatus.ARCHIVED:
            raise GatePolicyGovernanceError("GATE_POLICY_ROLLBACK_TARGET_ARCHIVED", status_code=409)
        self._validate_immutable_version(target)
        current = self._current_binding(
            tenant_id, workspace_id, project_id, GatePolicyMode.ENFORCE, for_update=True
        )
        self._require_expected_binding(current, payload.expectedCurrentBindingId)
        self._require_expected_version(current, payload.expectedCurrentPolicyVersionId)
        if current is None or current.policy_version_id == target.id:
            raise GatePolicyGovernanceError("GATE_POLICY_ROLLBACK_TARGET_CURRENT", status_code=409)
        self._require_previously_enforced(
            tenant_id, workspace_id, project_id, target.id
        )
        request_hash = canonical_hash(
            {
                "projectId": str(project_id),
                "targetPolicyVersionId": str(target.id),
                "targetPolicyVersionHash": target.content_hash,
                "expectedCurrentBindingId": str(payload.expectedCurrentBindingId),
                "expectedCurrentPolicyVersionId": str(payload.expectedCurrentPolicyVersionId),
                "reason": payload.reason,
            }
        )
        return self._request_approval_backed_change(
            action="rollback",
            project_id=project_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            policy_id=target.policy_id,
            version=target,
            simulation=None,
            expected_binding=current,
            expected_version_id=payload.expectedCurrentPolicyVersionId,
            idempotency_key=payload.idempotencyKey,
            request_hash=request_hash,
            reason=payload.reason,
            thresholds={},
            context=context,
        )

    def execute_approved_activation(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_ACTIVATE)
        return self._execute_approved_change(
            action="activation",
            approval_payload=approval_payload,
            approval_id=approval_id,
            context=context,
        )

    def execute_approved_rollback(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_ROLLBACK)
        return self._execute_approved_change(
            action="rollback",
            approval_payload=approval_payload,
            approval_id=approval_id,
            context=context,
        )

    def _request_approval_backed_change(
        self,
        *,
        action: str,
        project_id: UUID,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        version: GatePolicyVersion,
        simulation: GatePolicySimulationRun | None,
        expected_binding: GatePolicyBinding | None,
        expected_version_id: UUID | None,
        idempotency_key: str,
        request_hash: str,
        reason: str,
        thresholds: dict[str, object],
        context: ServiceContext,
    ) -> dict[str, object]:
        acquire_transaction_advisory_lock(
            self.db,
            f"gate-policy-{action}-request",
            f"{tenant_id}:{workspace_id}:{idempotency_key}",
        )
        existing = self.db.scalar(
            select(GatePolicyGovernanceRequest).where(
                GatePolicyGovernanceRequest.tenant_id == tenant_id,
                GatePolicyGovernanceRequest.workspace_id == workspace_id,
                GatePolicyGovernanceRequest.operation == f"{action}_request",
                GatePolicyGovernanceRequest.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if existing.request_hash != request_hash or existing.project_id != project_id:
                raise GatePolicyGovernanceError(
                    "GATE_POLICY_IDEMPOTENCY_CONFLICT", status_code=409, field="idempotencyKey"
                )
            return self._existing_change_projection(action, existing)
        request_id = uuid4()
        self._preflight(
            context,
            action=f"{action}_request",
            resource_type=f"gate_policy_{action}_request",
            resource_id=request_id,
            payload={
                "mode": "enforce",
                "targetStatus": "active" if action == "activation" else None,
                "policyVersionId": str(version.id),
                "approvalRequired": True,
            },
        )
        approval_result = ApprovalService(self.db).request_gate_policy_deployment_change(
            action=action,
            request_id=request_id,
            project_id=project_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            policy_id=policy_id,
            version_id=version.id,
            content_hash=version.content_hash,
            simulation_run_id=simulation.id if simulation else None,
            dataset_fingerprint=simulation.dataset_fingerprint if simulation else None,
            summary_hash=canonical_hash(simulation.summary) if simulation else None,
            expected_binding_id=expected_binding.id if expected_binding else None,
            expected_version_id=expected_version_id,
            request_hash=request_hash,
            idempotency_key=idempotency_key,
            reason=reason,
            thresholds=thresholds,
            context=context,
            commit=False,
        )
        request = GatePolicyGovernanceRequest(
            id=request_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            project_id=project_id,
            operation=f"{action}_request",
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            resource_type=f"gate_policy_{action}_request",
            resource_id=str(request_id),
            approval_id=UUID(str(approval_result["approvalId"])),
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
        )
        self.db.add(request)
        write_audit_log(
            self.db,
            str(context.user.id),
            f"gate_policy.{action}.request",
            request.resource_type,
            str(request.id),
            context.request_id,
            context.trace_id,
            {
                "projectId": str(project_id),
                "policyId": str(policy_id),
                "policyVersionId": str(version.id),
                "policyVersionHash": version.content_hash,
                "simulationRunId": str(simulation.id) if simulation else None,
                "expectedBindingId": str(expected_binding.id) if expected_binding else None,
                "approvalId": approval_result["approvalId"],
                "mode": "enforce",
                "authoritative": False,
            },
        )
        self.db.commit()
        return self._pending_change_projection(action, request, version, simulation)

    def _execute_approved_change(
        self,
        *,
        action: str,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        try:
            request_id = UUID(str(approval_payload["requestId"]))
            project_id = UUID(str(approval_payload["projectId"]))
            policy_id = UUID(str(approval_payload["policyId"]))
            version_id = UUID(str(approval_payload["versionId"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_APPROVAL_PAYLOAD_INVALID", status_code=409
            ) from exc
        request = self.db.scalar(
            select(GatePolicyGovernanceRequest)
            .where(
                GatePolicyGovernanceRequest.id == request_id,
                GatePolicyGovernanceRequest.operation == f"{action}_request",
                GatePolicyGovernanceRequest.approval_id == approval_id,
            )
            .with_for_update()
        )
        if request is None or request.request_hash != approval_payload.get("requestHash"):
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_MISMATCH", status_code=409)
        if request.project_id != project_id:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_SCOPE_MISMATCH", status_code=409)
        acquire_transaction_advisory_lock(
            self.db,
            "gate-policy-enforce-binding",
            f"{request.tenant_id}:{request.workspace_id}:{project_id}",
        )
        version = self.db.scalar(
            select(GatePolicyVersion)
            .where(
                GatePolicyVersion.id == version_id,
                GatePolicyVersion.policy_id == policy_id,
                GatePolicyVersion.tenant_id == request.tenant_id,
                GatePolicyVersion.workspace_id == request.workspace_id,
            )
            .with_for_update()
        )
        if version is None or version.content_hash != approval_payload.get("contentHash"):
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_STALE", status_code=409)
        if action == "activation" and version.status != GatePolicyStatus.ACTIVE:
            raise GatePolicyGovernanceError("GATE_POLICY_ACTIVATION_VERSION_UNAVAILABLE", status_code=409)
        if action == "rollback":
            if version.status == GatePolicyStatus.ARCHIVED:
                raise GatePolicyGovernanceError("GATE_POLICY_ROLLBACK_TARGET_ARCHIVED", status_code=409)
            if version.status != GatePolicyStatus.ACTIVE:
                raise GatePolicyGovernanceError(
                    "GATE_POLICY_ROLLBACK_TARGET_UNAVAILABLE", status_code=409
                )
            self._require_previously_enforced(
                request.tenant_id, request.workspace_id, project_id, version.id
            )
        self._validate_immutable_version(version)
        current = self._current_binding(
            request.tenant_id,
            request.workspace_id,
            project_id,
            GatePolicyMode.ENFORCE,
            for_update=True,
        )
        expected_binding_id = self._uuid_or_none(approval_payload.get("expectedBindingId"))
        expected_version_id = self._uuid_or_none(approval_payload.get("expectedVersionId"))
        self._require_expected_binding(current, expected_binding_id)
        self._require_expected_version(current, expected_version_id)
        simulation = None
        if action == "activation":
            simulation_id = self._uuid_or_none(approval_payload.get("simulationRunId"))
            if simulation_id is None:
                raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_REQUIRED", status_code=409)
            simulation = self._require_complete_simulation(
                project_id, policy_id, version, simulation_id
            )
            if simulation.dataset_fingerprint != approval_payload.get("datasetFingerprint"):
                raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_STALE", status_code=409)
            if canonical_hash(simulation.summary) != approval_payload.get("summaryHash"):
                raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_STALE", status_code=409)
            raw_thresholds = approval_payload.get("thresholds")
            thresholds = dict(raw_thresholds) if isinstance(raw_thresholds, dict) else {}
            self._require_risk_thresholds(
                simulation,
                max_false_pass=int(thresholds.get("maxFalsePassRiskCount") or 0),
                max_new_block=int(thresholds.get("maxNewBlockCount") or 0),
            )
        self._preflight(
            context,
            action=f"{action}_apply",
            resource_type=request.resource_type,
            resource_id=request.id,
            payload={
                "mode": "enforce",
                "targetStatus": "active" if action == "activation" else None,
                "policyVersionId": str(version.id),
                "approvalId": str(approval_id),
            },
        )
        history = self.db.scalar(
            select(GatePolicyBindingHistory).where(
                GatePolicyBindingHistory.tenant_id == request.tenant_id,
                GatePolicyBindingHistory.workspace_id == request.workspace_id,
                GatePolicyBindingHistory.action == action,
                GatePolicyBindingHistory.idempotency_key == request.idempotency_key,
            )
        )
        if history is not None:
            return self._applied_change_projection(action, request, history, approval_id)
        now = datetime.now(timezone.utc)
        before = self._binding_snapshot(current)
        if current is not None:
            # Keep the superseded binding eligible for historical/as-of
            # resolution inside its now-closed effective window.
            current.effective_until = now
            current.updated_by = context.user.id
        binding = self._new_binding(
            tenant_id=request.tenant_id,
            workspace_id=request.workspace_id,
            project_id=project_id,
            version=version,
            mode=GatePolicyMode.ENFORCE,
            idempotency_key=f"{action}:{request.id}",
            now=now,
            actor_id=context.user.id,
        )
        self.db.add(binding)
        self.db.flush()
        history = GatePolicyBindingHistory(
            id=uuid4(),
            tenant_id=request.tenant_id,
            workspace_id=request.workspace_id,
            project_id=project_id,
            action=action,
            mode=GatePolicyMode.ENFORCE,
            status="applied",
            binding_id=binding.id,
            previous_binding_id=current.id if current else None,
            policy_version_id=version.id,
            previous_policy_version_id=current.policy_version_id if current else None,
            simulation_run_id=simulation.id if simulation else None,
            approval_id=approval_id,
            before_snapshot=before,
            after_snapshot=self._binding_snapshot(binding),
            idempotency_key=request.idempotency_key,
            request_hash=request.request_hash,
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
        )
        self.db.add(history)
        write_audit_log(
            self.db,
            str(context.user.id),
            f"gate_policy.{action}.applied",
            "gate_policy_binding",
            str(binding.id),
            context.request_id,
            context.trace_id,
            {
                "projectId": str(project_id),
                "policyVersionId": str(version.id),
                "policyVersionHash": version.content_hash,
                "bindingId": str(binding.id),
                "previousBindingId": str(current.id) if current else None,
                "simulationRunId": str(simulation.id) if simulation else None,
                "approvalId": str(approval_id),
                "mode": "enforce",
                "authoritative": True,
                "effectiveFor": "new_executions_after_activation",
            },
        )
        self.db.flush()
        return self._applied_change_projection(action, request, history, approval_id)

    def _current_binding(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        mode: GatePolicyMode,
        *,
        for_update: bool,
    ) -> GatePolicyBinding | None:
        now = datetime.now(timezone.utc)
        statement = select(GatePolicyBinding).where(
            GatePolicyBinding.tenant_id == tenant_id,
            GatePolicyBinding.workspace_id == workspace_id,
            GatePolicyBinding.scope_type == GatePolicyScopeType.PROJECT,
            GatePolicyBinding.scope_key == str(project_id),
            GatePolicyBinding.mode == mode,
            GatePolicyBinding.status == GatePolicyStatus.ACTIVE,
            GatePolicyBinding.effective_from <= now,
            (GatePolicyBinding.effective_until.is_(None) | (GatePolicyBinding.effective_until > now)),
        )
        if for_update:
            statement = statement.with_for_update()
        rows = list(self.db.scalars(statement.order_by(GatePolicyBinding.effective_from.desc())))
        if len(rows) > 1:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_ACTIVE_BINDING_CONFLICT", status_code=409
            )
        return rows[0] if rows else None

    def _rollback_targets(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        modes: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        current_version_id = next(
            (
                self._uuid_or_none(item.get("policyVersionId"))
                for item in modes
                if item.get("mode") == GatePolicyMode.ENFORCE.value
            ),
            None,
        )
        bindings = list(
            self.db.scalars(
                select(GatePolicyBinding)
                .where(
                    GatePolicyBinding.tenant_id == tenant_id,
                    GatePolicyBinding.workspace_id == workspace_id,
                    GatePolicyBinding.scope_type == GatePolicyScopeType.PROJECT,
                    GatePolicyBinding.scope_key == str(project_id),
                    GatePolicyBinding.mode == GatePolicyMode.ENFORCE,
                )
                .order_by(GatePolicyBinding.effective_from.desc())
            )
        )
        projections: list[dict[str, object]] = []
        seen: set[UUID] = set()
        for binding in bindings:
            if binding.policy_version_id in seen:
                continue
            seen.add(binding.policy_version_id)
            version = self.db.get(GatePolicyVersion, binding.policy_version_id)
            reason = None
            if binding.policy_version_id == current_version_id:
                reason = "current"
            elif version is None or version.status not in {
                GatePolicyStatus.ACTIVE,
                GatePolicyStatus.ARCHIVED,
            }:
                reason = "unavailable"
            elif version.status == GatePolicyStatus.ARCHIVED:
                reason = "archived"
            else:
                try:
                    self._validate_immutable_version(version)
                except GatePolicyGovernanceError:
                    reason = "corrupted"
            projections.append(
                RollbackTargetProjection.model_validate(
                    {
                        "policyId": binding.policy_id,
                        "policyVersionId": binding.policy_version_id,
                        "policyVersionHash": binding.policy_version_hash,
                        "previousBindingId": binding.id,
                        "lastEnforcedAt": self._aware(binding.effective_from),
                        "available": reason is None,
                        "unavailableReason": reason,
                    }
                ).model_dump(mode="json")
            )
        return projections

    def _require_previously_enforced(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        version_id: UUID,
    ) -> None:
        binding_id = self.db.scalar(
            select(GatePolicyBinding.id).where(
                GatePolicyBinding.tenant_id == tenant_id,
                GatePolicyBinding.workspace_id == workspace_id,
                GatePolicyBinding.scope_type == GatePolicyScopeType.PROJECT,
                GatePolicyBinding.scope_key == str(project_id),
                GatePolicyBinding.mode == GatePolicyMode.ENFORCE,
                GatePolicyBinding.policy_version_id == version_id,
            )
        )
        if binding_id is None:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_ROLLBACK_TARGET_NOT_PREVIOUSLY_ENFORCED",
                status_code=409,
            )

    @staticmethod
    def _new_binding(
        *,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        version: GatePolicyVersion,
        mode: GatePolicyMode,
        idempotency_key: str,
        now: datetime,
        actor_id: UUID,
    ) -> GatePolicyBinding:
        binding_id = uuid4()
        request_hash = canonical_hash(
            {
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
                "projectId": str(project_id),
                "policyId": str(version.policy_id),
                "policyVersionId": str(version.id),
                "policyVersionHash": version.content_hash,
                "mode": mode.value,
                "effectiveFrom": now.isoformat(),
                "status": "active",
            }
        )
        return GatePolicyBinding(
            id=binding_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            policy_id=version.policy_id,
            policy_version_id=version.id,
            policy_version_hash=version.content_hash,
            binding_ref=f"gate-policy-binding://{binding_id}",
            scope_type=GatePolicyScopeType.PROJECT,
            scope_id=str(project_id),
            scope_key=str(project_id),
            status=GatePolicyStatus.ACTIVE,
            mode=mode,
            effective_from=now,
            effective_until=None,
            capability_ref="capability://gate_policy.enforce" if mode == GatePolicyMode.ENFORCE else f"capability://gate_policy.{mode.value}",
            approval_policy_ref=(
                "approval-policy://gate-policy-enforce" if mode == GatePolicyMode.ENFORCE else None
            ),
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            created_by=actor_id,
            updated_by=actor_id,
        )

    def _require_complete_simulation(
        self,
        project_id: UUID,
        policy_id: UUID,
        version: GatePolicyVersion,
        simulation_id: UUID,
    ) -> GatePolicySimulationRun:
        simulation = self.db.scalar(
            select(GatePolicySimulationRun).where(
                GatePolicySimulationRun.id == simulation_id,
                GatePolicySimulationRun.project_id == project_id,
                GatePolicySimulationRun.policy_id == policy_id,
                GatePolicySimulationRun.policy_version_id == version.id,
                GatePolicySimulationRun.policy_version_hash == version.content_hash,
                GatePolicySimulationRun.run_type == "historical",
            )
        )
        if simulation is None:
            raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_NOT_FOUND", status_code=404)
        summary = simulation.summary or {}
        if simulation.status != "completed" or not summary.get("complete"):
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_INCOMPLETE",
                status_code=409,
                details={"status": simulation.status},
            )
        return simulation

    @staticmethod
    def _require_risk_thresholds(
        simulation: GatePolicySimulationRun,
        *,
        max_false_pass: int,
        max_new_block: int,
    ) -> None:
        summary = simulation.summary or {}
        false_pass = int(summary.get("falsePassRiskCount") or 0)
        new_blocks = int(summary.get("newBlockCount") or 0)
        if false_pass > max_false_pass or new_blocks > max_new_block:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_ACTIVATION_RISK_THRESHOLD_EXCEEDED",
                status_code=409,
                details={
                    "falsePassRiskCount": false_pass,
                    "newBlockCount": new_blocks,
                    "maxFalsePassRiskCount": max_false_pass,
                    "maxNewBlockCount": max_new_block,
                },
            )

    @staticmethod
    def _validate_immutable_version(version: GatePolicyVersion) -> None:
        try:
            document = validate_gate_policy_document(version.policy_snapshot)
        except (TypeError, ValueError) as exc:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_VERSION_CORRUPTED", status_code=409
            ) from exc
        if document.get("status") != "active" or canonical_hash(document) != version.content_hash:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_CORRUPTED", status_code=409)

    @staticmethod
    def _require_expected_binding(
        current: GatePolicyBinding | None,
        expected_binding_id: UUID | None,
    ) -> None:
        current_id = current.id if current else None
        if current_id != expected_binding_id:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_ACTIVE_BINDING_CHANGED",
                status_code=409,
                details={"currentBindingId": str(current_id) if current_id else None},
            )

    @staticmethod
    def _require_expected_version(
        current: GatePolicyBinding | None,
        expected_version_id: UUID | None,
    ) -> None:
        current_version_id = current.policy_version_id if current else None
        if current_version_id != expected_version_id:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_ACTIVE_VERSION_CHANGED",
                status_code=409,
                details={
                    "currentPolicyVersionId": (
                        str(current_version_id) if current_version_id else None
                    )
                },
            )

    def _existing_change_projection(
        self, action: str, request: GatePolicyGovernanceRequest
    ) -> dict[str, object]:
        history = self.db.scalar(
            select(GatePolicyBindingHistory).where(
                GatePolicyBindingHistory.tenant_id == request.tenant_id,
                GatePolicyBindingHistory.workspace_id == request.workspace_id,
                GatePolicyBindingHistory.action == action,
                GatePolicyBindingHistory.idempotency_key == request.idempotency_key,
            )
        )
        if history is not None and request.approval_id is not None:
            return self._applied_change_projection(action, request, history, request.approval_id)
        approval = self.db.get(Approval, request.approval_id) if request.approval_id else None
        if approval is None:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_MISMATCH", status_code=409)
        version_id = UUID(str(approval.payload["versionId"]))
        target = self.db.get(GatePolicyVersion, version_id)
        simulation_id = self._uuid_or_none(approval.payload.get("simulationRunId"))
        simulation = self.db.get(GatePolicySimulationRun, simulation_id) if simulation_id else None
        if target is None:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_NOT_FOUND", status_code=404)
        return self._pending_change_projection(action, request, target, simulation)

    def _pending_change_projection(
        self,
        action: str,
        request: GatePolicyGovernanceRequest,
        version: GatePolicyVersion,
        simulation: GatePolicySimulationRun | None,
    ) -> dict[str, object]:
        if request.approval_id is None:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_MISMATCH", status_code=409)
        common = {
            "status": "approval_pending",
            "projectId": request.project_id,
            "approvalId": request.approval_id,
            "bindingId": None,
            "traceRef": f"trace://{request.trace_id}",
            "authoritative": False,
        }
        if action == "activation":
            if simulation is None:
                raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_REQUIRED", status_code=409)
            return ActivationResult.model_validate(
                {
                    "activationRequestId": request.id,
                    "policyId": version.policy_id,
                    "policyVersionId": version.id,
                    "policyVersionHash": version.content_hash,
                    "simulationRunId": simulation.id,
                    "previousBindingId": None,
                    "effectiveFrom": None,
                    **common,
                }
            ).model_dump(mode="json")
        return RollbackResult.model_validate(
            {
                "rollbackRequestId": request.id,
                "targetPolicyVersionId": version.id,
                "replacedBindingId": None,
                "effectiveFrom": None,
                **common,
            }
        ).model_dump(mode="json")

    def _applied_change_projection(
        self,
        action: str,
        request: GatePolicyGovernanceRequest,
        history: GatePolicyBindingHistory,
        approval_id: UUID,
    ) -> dict[str, object]:
        binding = self.db.get(GatePolicyBinding, history.binding_id)
        version = self.db.get(GatePolicyVersion, history.policy_version_id)
        if binding is None or version is None:
            raise GatePolicyGovernanceError("GATE_POLICY_BINDING_HISTORY_CORRUPTED", status_code=409)
        common = {
            "status": "applied",
            "projectId": request.project_id,
            "approvalId": approval_id,
            "bindingId": binding.id,
            "traceRef": f"trace://{history.trace_id}",
            "authoritative": True,
            "effectiveFrom": self._aware(binding.effective_from),
        }
        if action == "activation":
            if history.simulation_run_id is None:
                raise GatePolicyGovernanceError("GATE_POLICY_BINDING_HISTORY_CORRUPTED", status_code=409)
            return ActivationResult.model_validate(
                {
                    "activationRequestId": request.id,
                    "policyId": version.policy_id,
                    "policyVersionId": version.id,
                    "policyVersionHash": version.content_hash,
                    "simulationRunId": history.simulation_run_id,
                    "previousBindingId": history.previous_binding_id,
                    **common,
                }
            ).model_dump(mode="json")
        return RollbackResult.model_validate(
            {
                "rollbackRequestId": request.id,
                "targetPolicyVersionId": version.id,
                "replacedBindingId": history.previous_binding_id,
                **common,
            }
        ).model_dump(mode="json")

    @staticmethod
    def _binding_snapshot(binding: GatePolicyBinding | None) -> dict[str, object]:
        if binding is None:
            return {}
        effective_from = GatePolicyDeploymentService._aware(binding.effective_from)
        if effective_from is None:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_BINDING_HISTORY_CORRUPTED", status_code=409
            )
        return {
            "bindingId": str(binding.id),
            "bindingRef": binding.binding_ref,
            "policyId": str(binding.policy_id),
            "policyVersionId": str(binding.policy_version_id),
            "policyVersionHash": binding.policy_version_hash,
            "scopeType": binding.scope_type.value,
            "scopeId": binding.scope_id,
            "mode": binding.mode.value,
            "status": binding.status.value,
            "effectiveFrom": effective_from.isoformat(),
            "effectiveUntil": (
                aware_effective_until.isoformat()
                if (aware_effective_until := GatePolicyDeploymentService._aware(binding.effective_until))
                else None
            ),
        }

    @staticmethod
    def _mode_projection(
        project_id: UUID,
        mode: GatePolicyMode,
        binding: GatePolicyBinding | None,
        history: GatePolicyBindingHistory | None,
    ) -> dict[str, object]:
        return GateModeProjection(
            projectId=project_id,
            mode=mode.value,
            bindingId=binding.id if binding else None,
            policyVersionId=binding.policy_version_id if binding else None,
            policyVersionHash=binding.policy_version_hash if binding else None,
            active=binding is not None,
            authoritative=mode == GatePolicyMode.ENFORCE and binding is not None,
            blocksGate=mode == GatePolicyMode.ENFORCE and binding is not None,
            effectiveFrom=(
                GatePolicyDeploymentService._aware(binding.effective_from) if binding else None
            ),
            historyRef=f"gate-policy-binding-history://{history.id}" if history else None,
        ).model_dump(mode="json")

    def _preflight(
        self,
        context: ServiceContext,
        *,
        action: str,
        resource_type: str,
        resource_id: UUID,
        payload: dict[str, object],
    ) -> None:
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type=resource_type,
            resource_id=str(resource_id),
            payload=payload,
            metadata={"action": action},
        )
        try:
            RuntimeGuardrailEngine(self.db).enforce(guardrail_context, [GatePolicyMutationGuard()])
        except GuardrailViolationError as exc:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_GUARDRAIL_BLOCKED",
                status_code=403,
                details={"ruleId": exc.result.rule_id, "decision": exc.result.decision.value},
            ) from exc

    @staticmethod
    def _require_capability(context: ServiceContext, capability: str) -> None:
        if capability not in set(context.user.capabilities):
            raise GatePolicyGovernanceError(
                "CAPABILITY_REQUIRED", status_code=403, details={"capability": capability}
            )

    @staticmethod
    def _uuid_or_none(value: object) -> UUID | None:
        try:
            return UUID(str(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _aware(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

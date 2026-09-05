# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from uuid import UUID
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import ApprovalType, ModelRole
from agentic_qa.domain.models import GuardrailEvent, ModelRoleBinding, RoutingPolicy
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime import ModelRoutingGuard, RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.schemas.routing import CreateRoutingPolicyRequest, UpdateRoutingPolicyRequest
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result
from agentic_qa.tools.model_gateway import ModelGatewayTool


class RoutingPolicyService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.model_gateway = ModelGatewayTool(db)
        self.guardrail_engine = RuntimeGuardrailEngine(db)

    def create_policy(self, payload, context: ServiceContext, *, commit: bool = True) -> dict[str, object]:
        policy = RoutingPolicy(
            id=uuid4(),
            name=payload.name,
            task_type=payload.taskType,
            risk_level=payload.riskLevel,
            requires_tools=payload.requiresTools,
            requires_vision=payload.requiresVision,
            requires_json=payload.requiresJson,
            data_sensitivity=payload.dataSensitivity,
            prefer_local=payload.preferLocal,
            challenger_required=payload.challengerRequired,
            fallback_required=payload.fallbackRequired,
            human_approval_required=payload.humanApprovalRequired,
            enabled=payload.enabled,
            metadata_json=payload.metadata,
        )
        self.db.add(policy)
        write_audit_log(self.db, str(context.user.id), "routing_policy.create", "routing_policy", str(policy.id), context.request_id, context.trace_id)
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        return {"id": str(policy.id)}

    def update_policy(self, policy_id: UUID, payload, context: ServiceContext, *, commit: bool = True) -> dict[str, object]:
        policy = self._require_policy(policy_id)
        if payload.name is not None:
            policy.name = payload.name
        if payload.taskType is not None:
            policy.task_type = payload.taskType
        if payload.riskLevel is not None:
            policy.risk_level = payload.riskLevel
        if payload.requiresTools is not None:
            policy.requires_tools = payload.requiresTools
        if payload.requiresVision is not None:
            policy.requires_vision = payload.requiresVision
        if payload.requiresJson is not None:
            policy.requires_json = payload.requiresJson
        if payload.dataSensitivity is not None:
            policy.data_sensitivity = payload.dataSensitivity
        if payload.preferLocal is not None:
            policy.prefer_local = payload.preferLocal
        if payload.challengerRequired is not None:
            policy.challenger_required = payload.challengerRequired
        if payload.fallbackRequired is not None:
            policy.fallback_required = payload.fallbackRequired
        if payload.humanApprovalRequired is not None:
            policy.human_approval_required = payload.humanApprovalRequired
        if payload.enabled is not None:
            policy.enabled = payload.enabled
        if payload.metadata is not None:
            policy.metadata_json = payload.metadata
        write_audit_log(self.db, str(context.user.id), "routing_policy.update", "routing_policy", str(policy.id), context.request_id, context.trace_id)
        if commit:
            self.db.commit()
            self.db.refresh(policy)
        else:
            self.db.flush()
        return self.serialize(policy)

    def delete_policy(self, policy_id: UUID, context: ServiceContext, *, commit: bool = True) -> dict[str, object]:
        policy = self._require_policy(policy_id)
        self.db.delete(policy)
        write_audit_log(self.db, str(context.user.id), "routing_policy.delete", "routing_policy", str(policy_id), context.request_id, context.trace_id)
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        return {"id": str(policy_id)}

    def list_policies(self, page: int, page_size: int) -> dict[str, object]:
        statement = select(RoutingPolicy).order_by(RoutingPolicy.created_at.desc())
        policies, total = paginate_query(self.db, statement, page, page_size)
        items = [self.serialize(policy) for policy in policies]
        return paginate_result(items, total, page, page_size)

    def preview(self, payload, context: ServiceContext) -> dict[str, object]:
        statement = select(RoutingPolicy).where(RoutingPolicy.enabled.is_(True)).order_by(RoutingPolicy.created_at.desc())
        chosen = next(
            (
                policy
                for policy in self.db.scalars(statement)
                if self._matches_preview(policy, payload)
            ),
            None,
        )
        roles = [ModelRole.PRIMARY.value]
        rationale = ["default primary model selected"]
        if chosen:
            if chosen.challenger_required:
                roles.append(ModelRole.CHALLENGER.value)
                rationale.append("policy requires challenger")
            if chosen.fallback_required:
                roles.append(ModelRole.LOCAL_FALLBACK.value)
                rationale.append("policy requires local fallback")
        selected_models = []
        for role_name in roles:
            role = ModelRole(role_name)
            model = self.model_gateway.select_model(payload.riskLevel, role)
            supported_roles = self._roles_for_model(model.id) if model else []
            selected_models.append(
                {
                    "role": role_name,
                    "modelId": str(model.id) if model else None,
                    "name": model.name if model else None,
                    "provider": model.provider.value if model else "stub",
                    "supportedRoles": supported_roles,
                    "roleSatisfied": role_name in supported_roles,
                    "resolution": "direct" if role_name in supported_roles else "fallback" if model else "missing",
                }
            )
        self.guardrail_engine.enforce(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="routing_policy",
                resource_id=str(chosen.id) if chosen else payload.taskType,
                payload={
                    "riskLevel": payload.riskLevel.value,
                    "selectedRoles": roles,
                    "selectedModels": selected_models,
                    "preferLocal": payload.preferLocal,
                },
            ),
            [ModelRoutingGuard()],
        )
        self.db.commit()
        return {
            "policyId": str(chosen.id) if chosen else None,
            "selectedRoles": roles,
            "selectedModels": selected_models,
            "rationale": rationale,
        }

    def request_routing_policy_governance_action(self, payload, context: ServiceContext) -> dict[str, object]:
        action = str(payload.action)
        policy_payload = self._validated_routing_policy_payload(action, payload.policyPayload)
        policy_id = payload.policyId
        current_policy = None
        if action == "create":
            if policy_id is not None:
                raise ValueError("policyId is not accepted for create")
        else:
            if policy_id is None:
                raise ValueError("policyId is required")
            current_policy = self._require_policy(policy_id)

        policy_outcome = self._routing_governance_policy_decision(action)
        guardrail_refs = self._record_routing_policy_guardrail(
            context,
            action=action,
            policy_id=policy_id,
            policy_payload=policy_payload,
            policy_outcome=policy_outcome,
        )
        request_audit = write_audit_log(
            self.db,
            str(context.user.id),
            "routing_policy_governance.request",
            "routing_policy_governance_action",
            str(policy_id) if policy_id else action,
            context.request_id,
            context.trace_id,
            {
                "action": action,
                "policyOutcome": policy_outcome,
                "guardrailEventRefs": guardrail_refs,
                "providerRoutingOwnedBy": "model-gateway",
            },
        )
        self.db.flush()
        audit_refs = [{"type": "audit_log", "id": str(request_audit.id), "action": request_audit.action}]
        resource_id = payload.idempotencyKey or self._routing_governance_resource_id(action, policy_id, policy_payload)
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="routing_policy_governance_action",
            resource_id=resource_id,
            summary=self._routing_governance_summary(action, policy_id, current_policy),
            payload={
                "action": "routing_policy_governance.apply",
                "governanceAction": action,
                "policyId": str(policy_id) if policy_id else None,
                "policyPayload": policy_payload,
                "reason": payload.reason,
                "metadata": payload.metadata,
                "approvalMode": policy_outcome["approvalMode"],
                "policyOutcome": policy_outcome,
                "guardrailEventRefs": guardrail_refs,
                "auditRefs": audit_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        self.db.commit()
        return {
            "approvalRequired": True,
            "approvalMode": policy_outcome["approvalMode"],
            "approvalId": str(approval.id),
            "status": approval.status.value,
            "workflow": "routing_policy_governance_action",
            "action": action,
            "policyId": str(policy_id) if policy_id else None,
            "guardrailEventRefs": guardrail_refs,
            "auditRefs": audit_refs,
        }

    def execute_approved_routing_policy_governance_action(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID | None,
        context: ServiceContext,
    ) -> dict[str, object]:
        action = str(approval_payload.get("governanceAction") or "")
        policy_payload = dict(approval_payload.get("policyPayload") or {})
        policy_id_value = approval_payload.get("policyId")
        policy_id = UUID(str(policy_id_value)) if policy_id_value else None
        if action == "create":
            request_payload = CreateRoutingPolicyRequest(**policy_payload)
            result = self.create_policy(request_payload, context, commit=False)
            resolved_policy_id = result["id"]
        elif action == "update":
            if policy_id is None:
                raise ValueError("policyId is required")
            request_payload = UpdateRoutingPolicyRequest(**policy_payload)
            result = self.update_policy(policy_id, request_payload, context, commit=False)
            resolved_policy_id = str(policy_id)
        elif action == "delete":
            if policy_id is None:
                raise ValueError("policyId is required")
            result = self.delete_policy(policy_id, context, commit=False)
            resolved_policy_id = str(policy_id)
        else:
            raise ValueError("unsupported routing policy governance action")

        action_audit = write_audit_log(
            self.db,
            str(context.user.id),
            "routing_policy_governance.apply",
            "routing_policy_governance_action",
            resolved_policy_id,
            context.request_id,
            context.trace_id,
            {
                "action": action,
                "approvalId": str(approval_id) if approval_id else None,
                "result": result,
                "policyOutcome": approval_payload.get("policyOutcome"),
            },
        )
        self.db.flush()
        return {
            "workflow": "routing_policy_governance_action",
            "status": "applied",
            "action": action,
            "policyId": resolved_policy_id,
            "result": result,
            "approvalRefs": [{"type": "approval", "id": str(approval_id), "state": "approved", "action": action}] if approval_id else [],
            "guardrailEventRefs": list(approval_payload.get("guardrailEventRefs") or []),
            "auditRefs": [{"type": "audit_log", "id": str(action_audit.id), "action": action_audit.action}],
        }

    def serialize(self, policy: RoutingPolicy) -> dict[str, object]:
        return {
            "id": str(policy.id),
            "name": policy.name,
            "taskType": policy.task_type,
            "riskLevel": policy.risk_level.value,
            "requiresTools": policy.requires_tools,
            "requiresVision": policy.requires_vision,
            "requiresJson": policy.requires_json,
            "dataSensitivity": policy.data_sensitivity,
            "preferLocal": policy.prefer_local,
            "challengerRequired": policy.challenger_required,
            "fallbackRequired": policy.fallback_required,
            "humanApprovalRequired": policy.human_approval_required,
            "enabled": policy.enabled,
            "metadata": policy.metadata_json,
            "createdAt": policy.created_at.isoformat(),
            "updatedAt": policy.updated_at.isoformat(),
        }

    def _validated_routing_policy_payload(self, action: str, policy_payload: dict[str, object]) -> dict[str, object]:
        try:
            if action == "create":
                return CreateRoutingPolicyRequest(**policy_payload).model_dump(mode="json", by_alias=True)
            if action == "update":
                return UpdateRoutingPolicyRequest(**policy_payload).model_dump(mode="json", by_alias=True, exclude_none=True)
            if action == "delete":
                return {}
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc
        raise ValueError("unsupported routing policy governance action")

    def _routing_governance_policy_decision(self, action: str) -> dict[str, object]:
        return {
            "approvalMode": "always",
            "approvalRequired": True,
            "policyOutcome": "approval-required",
            "reason": "routing_policy_governance_system_hard_rule",
            "action": f"routing_policy_governance.{action}",
            "riskLevel": "high",
            "systemHardRule": True,
            "providerRoutingOwnedBy": "model-gateway",
        }

    def _record_routing_policy_guardrail(
        self,
        context: ServiceContext,
        *,
        action: str,
        policy_id: UUID | None,
        policy_payload: dict[str, object],
        policy_outcome: dict[str, object],
    ) -> list[dict[str, object]]:
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type="routing_policy_governance_action",
            resource_id=str(policy_id) if policy_id else action,
            payload={
                "action": f"routing_policy_governance.{action}",
                "policyId": str(policy_id) if policy_id else None,
                "policyPayloadSummary": self._summarize_routing_policy_payload(policy_payload),
                "policyOutcome": policy_outcome,
                "providerRoutingOwnedBy": "model-gateway",
                "frontendRoutingLogicAllowed": False,
            },
        )
        self.guardrail_engine.record_result(
            guardrail_context,
            GuardrailResult(
                rule_id="routing_policy.mutation_preflight",
                decision=GuardrailDecision.ALLOW,
                reason="Routing policy mutation passed controlled model-gateway boundary preflight",
                evidence=[f"routing_policy_governance.{action}", str(policy_id) if policy_id else "new-policy"],
                metadata={"approvalMode": policy_outcome.get("approvalMode", "always")},
            ),
        )
        self.db.flush()
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.request_id == context.request_id)
                .where(GuardrailEvent.rule_id == "routing_policy.mutation_preflight")
                .order_by(GuardrailEvent.created_at.desc())
            )
        )
        return [{"type": "guardrail_event", "id": str(event.id), "ruleId": event.rule_id, "decision": event.decision.value} for event in events[:1]]

    def _routing_governance_resource_id(self, action: str, policy_id: UUID | None, policy_payload: dict[str, object]) -> str:
        fingerprint = hashlib.sha256(
            json.dumps({"action": action, "policyId": str(policy_id) if policy_id else None, "policyPayload": policy_payload}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return f"routing-policy-governance:{fingerprint}"

    def _routing_governance_summary(self, action: str, policy_id: UUID | None, policy: RoutingPolicy | None) -> str:
        if action == "create":
            return "Approval required before creating a routing policy."
        policy_name = policy.name if policy is not None else str(policy_id)
        return f"Approval required before applying routing policy governance action '{action}' to policy {policy_name}."

    def _summarize_routing_policy_payload(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "keys": sorted(payload.keys()),
            "taskType": payload.get("taskType"),
            "riskLevel": payload.get("riskLevel"),
            "requiresVision": payload.get("requiresVision"),
            "requiresJson": payload.get("requiresJson"),
            "preferLocal": payload.get("preferLocal"),
            "challengerRequired": payload.get("challengerRequired"),
            "fallbackRequired": payload.get("fallbackRequired"),
        }

    def _require_policy(self, policy_id: UUID) -> RoutingPolicy:
        policy = self.db.get(RoutingPolicy, policy_id)
        if policy is None:
            raise ValueError("routing policy not found")
        return policy

    def _roles_for_model(self, model_id: UUID) -> list[str]:
        bindings = self.db.scalars(
            select(ModelRoleBinding)
            .where(ModelRoleBinding.model_id == model_id)
            .where(ModelRoleBinding.enabled.is_(True))
        )
        return [binding.role.value for binding in bindings]

    def _matches_preview(self, policy: RoutingPolicy, payload) -> bool:
        return (
            policy.task_type == payload.taskType
            and policy.risk_level == payload.riskLevel
            and policy.requires_tools == payload.requiresTools
            and policy.requires_vision == payload.requiresVision
            and policy.requires_json == payload.requiresJson
            and policy.prefer_local == payload.preferLocal
        )

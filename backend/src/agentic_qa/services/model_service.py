# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from agentic_qa.domain.enums import ApprovalType, HealthStatus, ModelRole, ProviderType, RiskLevel
from agentic_qa.domain.models import Approval, GuardrailEvent, Model, ModelCapabilityScan, ModelHealthCheck, ModelRoleBinding
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.credentials import CredentialResolver
from agentic_qa.infra.settings import get_settings
from agentic_qa.schemas.models import CreateModelRequest, UpdateModelRequest, VisualTargetResolveOutput
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result
from agentic_qa.services.scope_service import ScopeAuthorizationService
from agentic_qa.tools.model_gateway import ModelGatewayTool


class ModelService:
    @staticmethod
    def community_direct_mutation_enabled() -> bool:
        return get_settings().deployment_profile == "oss"

    def __init__(self, db: Session) -> None:
        self.db = db

    def list_models(
        self,
        page: int,
        page_size: int,
        provider: str | None = None,
        role: str | None = None,
        *,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        statement = select(Model).order_by(Model.priority.desc(), Model.created_at.desc())
        if context is not None:
            authorized_ids = ScopeAuthorizationService(self.db).authorized_project_ids(context)
            scoped_models: ColumnElement[bool] = Model.project_id.in_(authorized_ids)
            if (
                get_settings().deployment_profile == "full"
                and {"admin", "system"}.intersection(context.user.roles)
            ):
                scoped_models = or_(Model.project_id.is_(None), scoped_models)
            statement = statement.where(scoped_models)
        if project_id is not None:
            if context is not None:
                ScopeAuthorizationService(self.db).resolve_project(
                    project_id,
                    context,
                    environment_id=environment_id,
                )
            statement = statement.where(Model.project_id == project_id)
        if environment_id is not None:
            statement = statement.where(Model.environment_id == environment_id)
        if provider:
            statement = statement.where(Model.provider == provider)
        if role:
            statement = (
                statement
                .join(ModelRoleBinding, ModelRoleBinding.model_id == Model.id)
                .where(ModelRoleBinding.role == role)
                .where(ModelRoleBinding.enabled.is_(True))
                .distinct()
            )
        models, total = paginate_query(self.db, statement, page, page_size)
        model_ids = [model.id for model in models]
        role_lookup = self._roles_for_models(model_ids)
        health_lookup = self._latest_health_checks(model_ids)
        scan_lookup = self._latest_capability_scans(model_ids)
        items = [
            self.serialize_model(
                model,
                role_lookup=role_lookup,
                health_lookup=health_lookup,
                capability_scan_lookup=scan_lookup,
            )
            for model in models
        ]
        return paginate_result(items, total, page, page_size)

    def get_model(self, model_id: UUID, context: ServiceContext | None = None) -> dict[str, object]:
        model = self._require_model(model_id)
        if context is not None:
            self._authorize_model_scope(model, context)
        return self.serialize_model(
            model,
            health_lookup=self._latest_health_checks([model.id]),
            capability_scan_lookup=self._latest_capability_scans([model.id]),
        )

    def create_model(self, payload, context: ServiceContext, *, commit: bool = True) -> dict[str, object]:
        scope = None
        if payload.projectId is not None:
            scope = ScopeAuthorizationService(self.db).resolve_project(
                payload.projectId,
                context,
                environment_id=payload.environmentId,
                write=True,
            )
        elif payload.environmentId is not None:
            raise ValueError("environmentId requires projectId")
        self._validate_credential_ref(payload.apiKeyRef, project_id=payload.projectId)
        model = Model(
            id=uuid4(),
            name=payload.name,
            project_id=scope.project.id if scope is not None else None,
            environment_id=scope.environment.id if scope is not None and scope.environment is not None else None,
            provider=payload.provider,
            model_name=payload.model,
            base_url=payload.baseUrl,
            api_key_ref=payload.apiKeyRef,
            priority=payload.priority,
            enabled=payload.enabled,
            config=payload.config.model_dump(mode="json", by_alias=True),
            capabilities=payload.capabilities.model_dump(mode="json", by_alias=True),
            created_by=context.user.id,
            health_status=HealthStatus.UNKNOWN,
        )
        self.db.add(model)
        self.db.flush()
        for role in payload.roles:
            self.db.add(
                ModelRoleBinding(
                    id=uuid4(),
                    model_id=model.id,
                    role=role,
                    weight=payload.priority,
                    enabled=True,
                )
            )
        write_audit_log(self.db, str(context.user.id), "model.create", "model", str(model.id), context.request_id, context.trace_id, {"name": payload.name})
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        return {"id": str(model.id)}

    def update_model(self, model_id: UUID, payload, context: ServiceContext, *, commit: bool = True) -> dict[str, object]:
        model = self._require_model(model_id)
        self._authorize_model_scope(model, context, write=True)
        target_project_id = payload.projectId or model.project_id
        target_environment_id = payload.environmentId if payload.environmentId is not None else model.environment_id
        if target_project_id is not None:
            scope = ScopeAuthorizationService(self.db).resolve_project(
                target_project_id,
                context,
                environment_id=target_environment_id,
                write=True,
            )
            model.project_id = scope.project.id
            model.environment_id = scope.environment.id if scope.environment is not None else None
        self._validate_credential_ref(payload.apiKeyRef, project_id=target_project_id)
        if payload.name is not None:
            model.name = payload.name
        if payload.provider is not None:
            model.provider = payload.provider
        if payload.model is not None:
            model.model_name = payload.model
        if payload.baseUrl is not None:
            model.base_url = payload.baseUrl
        if payload.apiKeyRef is not None:
            model.api_key_ref = payload.apiKeyRef
        if payload.priority is not None:
            model.priority = payload.priority
        if payload.enabled is not None:
            model.enabled = payload.enabled
        if payload.capabilities is not None:
            model.capabilities = payload.capabilities.model_dump(mode="json", by_alias=True)
        if payload.config is not None:
            model.config = payload.config.model_dump(mode="json", by_alias=True)
        if payload.roles is not None:
            self.db.execute(delete(ModelRoleBinding).where(ModelRoleBinding.model_id == model.id))
            for role in payload.roles:
                self.db.add(
                    ModelRoleBinding(
                        id=uuid4(),
                        model_id=model.id,
                        role=role,
                        weight=model.priority,
                        enabled=True,
                    )
                )
        write_audit_log(self.db, str(context.user.id), "model.update", "model", str(model.id), context.request_id, context.trace_id)
        if commit:
            self.db.commit()
            self.db.refresh(model)
        else:
            self.db.flush()
        return self.serialize_model(model)

    def delete_model(self, model_id: UUID, context: ServiceContext, *, commit: bool = True) -> dict[str, object]:
        model = self._require_model(model_id)
        self._authorize_model_scope(model, context, write=True)
        self.db.execute(delete(ModelRoleBinding).where(ModelRoleBinding.model_id == model.id))
        self.db.delete(model)
        write_audit_log(self.db, str(context.user.id), "model.delete", "model", str(model_id), context.request_id, context.trace_id)
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        return {"id": str(model_id)}

    def health_check(self, model_id: UUID, context: ServiceContext) -> dict[str, object]:
        model = self._require_model(model_id)
        self._authorize_model_scope(model, context, write=True)
        policy_outcome = self._model_observation_policy_decision("health_check")
        guardrail_refs = self._record_model_governance_guardrail(
            context,
            action="health_check",
            model_id=model_id,
            model_payload={},
            policy_outcome=policy_outcome,
        )
        probe_error: str | None
        if not model.enabled:
            probe_success = False
            probe_mode = "disabled"
            latency_ms = 0
            probe_error = "MODEL_DISABLED"
        else:
            probe = ModelGatewayTool(self.db).probe_model(model, timeout_seconds=5.0)
            probe_success = bool(probe["success"])
            probe_mode = str(probe["mode"])
            latency_value = probe["latencyMs"]
            if not isinstance(latency_value, (int, float)):
                raise ValueError("MODEL_PROBE_LATENCY_INVALID")
            latency_ms = int(latency_value)
            probe_error = str(probe["error"]) if probe.get("error") else None
        status = HealthStatus.HEALTHY if probe_success else HealthStatus.UNAVAILABLE
        health = {
            "status": status.value,
            "details": {
                "provider": model.provider.value,
                "model": model.model_name,
                "checkedBy": "model-gateway-live-probe",
                "probeMode": probe_mode,
                "error": probe_error,
            },
        }
        model.health_status = status
        model.last_health_check_at = datetime.now(timezone.utc)
        self.db.add(
            ModelHealthCheck(
                id=uuid4(),
                model_id=model.id,
                status=status,
                latency_ms=latency_ms,
                details=health["details"],
            )
        )
        audit_log = write_audit_log(
            self.db,
            str(context.user.id),
            "model.health_check",
            "model",
            str(model.id),
            context.request_id,
            context.trace_id,
            {"policyOutcome": policy_outcome, "guardrailEventRefs": guardrail_refs},
        )
        self.db.commit()
        return {
            "modelId": str(model.id),
            "status": status.value,
            "latencyMs": latency_ms,
            "details": health["details"],
            "guardrailEventRefs": guardrail_refs,
            "auditRefs": [{"type": "audit_log", "id": str(audit_log.id), "action": audit_log.action}],
        }

    def capability_scan(self, model_id: UUID, context: ServiceContext) -> dict[str, object]:
        model = self._require_model(model_id)
        self._authorize_model_scope(model, context, write=True)
        policy_outcome = self._model_observation_policy_decision("capability_scan")
        scanned_capabilities = {
            **model.capabilities,
            "provider": model.provider.value,
            "supportsRouting": True,
        }
        guardrail_refs = self._record_model_governance_guardrail(
            context,
            action="capability_scan",
            model_id=model_id,
            model_payload=scanned_capabilities,
            policy_outcome=policy_outcome,
        )
        scan = ModelCapabilityScan(
            id=uuid4(),
            model_id=model.id,
            scanner="model-gateway-config",
            capabilities=scanned_capabilities,
            details={
                "model": model.model_name,
                "provider": model.provider.value,
                "routingAuthority": "model-gateway",
            },
        )
        self.db.add(scan)
        audit_log = write_audit_log(
            self.db,
            str(context.user.id),
            "model.capability_scan",
            "model",
            str(model.id),
            context.request_id,
            context.trace_id,
            {"policyOutcome": policy_outcome, "guardrailEventRefs": guardrail_refs},
        )
        self.db.commit()
        return {
            "modelId": str(model.id),
            "scanId": str(scan.id),
            "capabilities": scanned_capabilities,
            "details": scan.details,
            "guardrailEventRefs": guardrail_refs,
            "auditRefs": [{"type": "audit_log", "id": str(audit_log.id), "action": audit_log.action}],
        }

    def model_governance_policy(self) -> dict[str, object]:
        approvals = list(
            self.db.scalars(
                select(Approval)
                .where(Approval.resource_type == "model_governance_action")
                .order_by(Approval.created_at.desc())
            )
        )
        return {
            "schemaVersion": "phase8.model-governance-policy.v1",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "supportedActions": ["create", "update", "delete", "health_check", "capability_scan"],
            "routingPolicyActions": ["create", "update", "delete"],
            "directMutationEndpoints": {
                "models": "disabled",
                "routingPolicies": "disabled",
                "errorCode": "MODEL_GOVERNANCE_DIRECT_MUTATION_DISABLED",
            },
            "capability": {
                "read": "authenticated",
                "manage": "model.governance.manage",
                "authorizationBoundary": "backend_service_api",
                "frontendBoundary": "ux_only",
            },
            "approval": {
                "approvalMode": "always",
                "requiredForActions": ["create", "update", "delete"],
                "approvalExecutionSurface": "existing_approval_flow",
                "approvalActionType": "model_governance.apply",
            },
            "guardrail": {
                "required": True,
                "ruleId": "model_governance.mutation_preflight",
            },
            "providerRouting": {
                "ownedBy": "model-gateway",
                "frontendRoutingLogicAllowed": False,
            },
            "approvalRefs": [
                {"type": "approval", "id": str(row.id), "status": row.status.value, "action": row.payload.get("governanceAction")}
                for row in approvals[:5]
            ],
        }

    def request_model_governance_action(self, payload, context: ServiceContext) -> dict[str, object]:
        action = str(payload.action)
        model_payload = self._validated_model_governance_payload(action, payload.modelPayload)
        model_id = payload.modelId
        current_model = None
        if action == "create":
            if model_id is not None:
                raise ValueError("modelId is not accepted for create")
        else:
            if model_id is None:
                raise ValueError("modelId is required")
            current_model = self._require_model(model_id)

        policy_outcome = self._model_governance_policy_decision(action)
        guardrail_refs = self._record_model_governance_guardrail(
            context,
            action=action,
            model_id=model_id,
            model_payload=model_payload,
            policy_outcome=policy_outcome,
        )
        request_audit = write_audit_log(
            self.db,
            str(context.user.id),
            "model_governance.request",
            "model_governance_action",
            str(model_id) if model_id else action,
            context.request_id,
            context.trace_id,
            {
                "action": action,
                "policyOutcome": policy_outcome,
                "guardrailEventRefs": guardrail_refs,
            },
        )
        self.db.flush()
        audit_refs = [{"type": "audit_log", "id": str(request_audit.id), "action": request_audit.action}]
        resource_id = payload.idempotencyKey or self._model_governance_resource_id(action, model_id, model_payload)
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="model_governance_action",
            resource_id=resource_id,
            summary=self._model_governance_summary(action, model_id, current_model),
            payload={
                "action": "model_governance.apply",
                "governanceAction": action,
                "modelId": str(model_id) if model_id else None,
                "modelPayload": model_payload,
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
            "workflow": "model_governance_action",
            "action": action,
            "modelId": str(model_id) if model_id else None,
            "guardrailEventRefs": guardrail_refs,
            "auditRefs": audit_refs,
        }

    def execute_approved_model_governance_action(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID | None,
        context: ServiceContext,
    ) -> dict[str, object]:
        action = str(approval_payload.get("governanceAction") or "")
        raw_model_payload = approval_payload.get("modelPayload")
        if raw_model_payload is None:
            model_payload: dict[str, object] = {}
        elif isinstance(raw_model_payload, dict):
            model_payload = dict(raw_model_payload)
        else:
            raise ValueError("modelPayload must be an object")
        model_id_value = approval_payload.get("modelId")
        model_id = UUID(str(model_id_value)) if model_id_value else None
        if action == "create":
            create_payload = CreateModelRequest.model_validate(model_payload)
            result = self.create_model(create_payload, context, commit=False)
            resolved_model_id = str(result["id"])
        elif action == "update":
            if model_id is None:
                raise ValueError("modelId is required")
            update_payload = UpdateModelRequest.model_validate(model_payload)
            result = self.update_model(model_id, update_payload, context, commit=False)
            resolved_model_id = str(model_id)
        elif action == "delete":
            if model_id is None:
                raise ValueError("modelId is required")
            result = self.delete_model(model_id, context, commit=False)
            resolved_model_id = str(model_id)
        else:
            raise ValueError("unsupported model governance action")

        action_audit = write_audit_log(
            self.db,
            str(context.user.id),
            "model_governance.apply",
            "model_governance_action",
            resolved_model_id,
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
            "workflow": "model_governance_action",
            "status": "applied",
            "action": action,
            "modelId": resolved_model_id,
            "result": result,
            "approvalRefs": [{"type": "approval", "id": str(approval_id), "state": "approved", "action": action}] if approval_id else [],
            "guardrailEventRefs": self._model_governance_approval_guardrail_refs(approval_id) if approval_id else [],
            "auditRefs": [{"type": "audit_log", "id": str(action_audit.id), "action": action_audit.action}],
        }

    def invoke_model(
        self,
        *,
        role: ModelRole,
        prompt: str,
        payload: dict[str, object],
        context: ServiceContext,
        provider: ProviderType | None = None,
        execution_id: UUID | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
        validator: object | None = None,
    ) -> dict[str, object]:
        if project_id is not None:
            ScopeAuthorizationService(self.db).resolve_project(
                project_id,
                context,
                environment_id=environment_id,
            )
        model_gateway = ModelGatewayTool(self.db)
        raw_response = model_gateway.invoke_json(
            trace_id=UUID(context.trace_id),
            execution_id=execution_id,
            role=role,
            prompt=prompt,
            payload=payload,
            validator=validator,
            provider=provider,
            request_id=context.request_id,
            project_id=project_id,
            environment_id=environment_id,
        )
        self.db.commit()
        return {
            **raw_response,
            "latencyMs": 0 if raw_response.get("mode") == "stub" else raw_response.get("latencyMs", 0),
            "promptTokens": raw_response.get("promptTokens"),
            "completionTokens": raw_response.get("completionTokens"),
            "totalTokens": raw_response.get("totalTokens"),
        }

    def resolve_visual_target(self, payload, context: ServiceContext) -> dict[str, object]:
        selected_model = self._select_visual_model(payload.modelSelector.role, payload.modelSelector.provider)
        if selected_model is not None and not bool(selected_model.capabilities.get("vision")):
            raise ValueError("selected model does not declare vision capability")
        request_payload = {
            "input": {
                "artifactRefs": [item.model_dump(mode="json") for item in payload.input.artifactRefs],
                "task": payload.input.task,
                "semanticTarget": payload.input.semanticTarget,
                "targetHints": payload.input.targetHints,
            },
            "metadata": payload.metadata,
        }
        raw_response = self.invoke_model(
            role=payload.modelSelector.role,
            prompt="Resolve visual target from redacted artifact refs. Return structured JSON.",
            payload=request_payload,
            provider=payload.modelSelector.provider,
            execution_id=payload.executionId,
            validator=VisualTargetResolveOutput,
            context=context,
        )
        output = self._extract_visual_output(raw_response)
        return {
            "modelId": raw_response.get("modelId"),
            "provider": raw_response.get("provider", "stub"),
            "output": output,
            "rawModelOutput": raw_response,
            "latencyMs": raw_response.get("latencyMs", 0),
        }

    def serialize_model(
        self,
        model: Model,
        role_lookup: dict[UUID, list[str]] | None = None,
        health_lookup: dict[UUID, dict[str, object]] | None = None,
        capability_scan_lookup: dict[UUID, dict[str, object]] | None = None,
    ) -> dict[str, object]:
        return {
            "id": str(model.id),
            "name": model.name,
            "projectId": str(model.project_id) if model.project_id else None,
            "environmentId": str(model.environment_id) if model.environment_id else None,
            "provider": model.provider.value,
            "model": model.model_name,
            "baseUrl": model.base_url,
            "apiKeyConfigured": bool(model.api_key_ref),
            "roles": (role_lookup or {}).get(model.id, self._roles_for_model(model.id)),
            "priority": model.priority,
            "enabled": model.enabled,
            "healthStatus": model.health_status.value,
            "capabilities": model.capabilities,
            "config": model.config,
            "lastHealthCheck": (health_lookup or {}).get(model.id),
            "lastCapabilityScan": (capability_scan_lookup or {}).get(model.id),
            "createdAt": model.created_at.isoformat(),
            "updatedAt": model.updated_at.isoformat(),
        }

    def _validated_model_governance_payload(self, action: str, model_payload: dict[str, object]) -> dict[str, object]:
        try:
            if action == "create":
                return CreateModelRequest.model_validate(model_payload).model_dump(mode="json", by_alias=True)
            if action == "update":
                return UpdateModelRequest.model_validate(model_payload).model_dump(mode="json", by_alias=True, exclude_none=True)
            if action == "delete":
                return {}
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc
        raise ValueError("unsupported model governance action")

    def _model_governance_policy_decision(self, action: str) -> dict[str, object]:
        return {
            "approvalMode": "always",
            "approvalRequired": True,
            "policyOutcome": "approval-required",
            "reason": "model_governance_system_hard_rule",
            "action": f"model_governance.{action}",
            "riskLevel": "high",
            "systemHardRule": True,
        }

    def _model_observation_policy_decision(self, action: str) -> dict[str, object]:
        return {
            "approvalMode": "policy_only",
            "approvalRequired": False,
            "policyOutcome": "approval-not-required",
            "reason": "model_governance_observation_action",
            "action": f"model_governance.{action}",
            "riskLevel": "medium",
            "systemHardRule": False,
        }

    def _record_model_governance_guardrail(
        self,
        context: ServiceContext,
        *,
        action: str,
        model_id: UUID | None,
        model_payload: dict[str, object],
        policy_outcome: dict[str, object],
    ) -> list[dict[str, object]]:
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type="model_governance_action",
            resource_id=str(model_id) if model_id else action,
            payload={
                "action": f"model_governance.{action}",
                "modelId": str(model_id) if model_id else None,
                "modelPayloadSummary": self._summarize_model_payload(model_payload),
                "policyOutcome": policy_outcome,
                "providerRoutingOwnedBy": "model-gateway",
            },
        )
        RuntimeGuardrailEngine(self.db).record_result(
            guardrail_context,
            GuardrailResult(
                rule_id="model_governance.mutation_preflight",
                decision=GuardrailDecision.ALLOW,
                reason="Model governance mutation passed controlled preflight",
                evidence=[f"model_governance.{action}", str(model_id) if model_id else "new-model"],
                metadata={"approvalMode": policy_outcome.get("approvalMode", "always")},
            ),
        )
        self.db.flush()
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.request_id == context.request_id)
                .where(GuardrailEvent.rule_id == "model_governance.mutation_preflight")
                .order_by(GuardrailEvent.created_at.desc())
            )
        )
        return [{"type": "guardrail_event", "id": str(event.id), "ruleId": event.rule_id, "decision": event.decision.value} for event in events[:1]]

    def _model_governance_approval_guardrail_refs(self, approval_id: UUID | None) -> list[dict[str, object]]:
        if approval_id is None:
            return []
        approval = self.db.get(Approval, approval_id)
        if approval is None:
            return []
        return list(approval.payload.get("guardrailEventRefs") or [])

    def _model_governance_resource_id(self, action: str, model_id: UUID | None, model_payload: dict[str, object]) -> str:
        fingerprint = hashlib.sha256(
            json.dumps({"action": action, "modelId": str(model_id) if model_id else None, "modelPayload": model_payload}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return f"model-governance:{fingerprint}"

    def _model_governance_summary(self, action: str, model_id: UUID | None, model: Model | None) -> str:
        if action == "create":
            return "Approval required before creating a model configuration."
        model_name = model.name if model is not None else str(model_id)
        return f"Approval required before applying model governance action '{action}' to model {model_name}."

    def _summarize_model_payload(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "keys": sorted(payload.keys()),
            "providerConfigured": payload.get("provider"),
            "roles": payload.get("roles"),
            "enabled": payload.get("enabled"),
            "priority": payload.get("priority"),
            "capabilityKeys": sorted((payload.get("capabilities") or {}).keys()) if isinstance(payload.get("capabilities"), dict) else [],
        }

    def _roles_for_model(self, model_id: UUID) -> list[str]:
        statement = select(ModelRoleBinding).where(ModelRoleBinding.model_id == model_id)
        return [binding.role.value for binding in self.db.scalars(statement)]

    def _roles_for_models(self, model_ids: list[UUID]) -> dict[UUID, list[str]]:
        if not model_ids:
            return {}
        role_lookup = {model_id: [] for model_id in model_ids}
        bindings = self.db.scalars(
            select(ModelRoleBinding)
            .where(ModelRoleBinding.model_id.in_(model_ids))
            .where(ModelRoleBinding.enabled.is_(True))
        )
        for binding in bindings:
            role_lookup[binding.model_id].append(binding.role.value)
        return role_lookup

    def _latest_health_checks(self, model_ids: list[UUID]) -> dict[UUID, dict[str, object]]:
        if not model_ids:
            return {}
        lookup: dict[UUID, dict[str, object]] = {}
        checks = self.db.scalars(
            select(ModelHealthCheck)
            .where(ModelHealthCheck.model_id.in_(model_ids))
            .order_by(ModelHealthCheck.checked_at.desc())
        )
        for check in checks:
            if check.model_id in lookup:
                continue
            lookup[check.model_id] = {
                "id": str(check.id),
                "status": check.status.value,
                "latencyMs": check.latency_ms,
                "details": check.details,
                "checkedAt": check.checked_at.isoformat(),
            }
        return lookup

    def _latest_capability_scans(self, model_ids: list[UUID]) -> dict[UUID, dict[str, object]]:
        if not model_ids:
            return {}
        lookup: dict[UUID, dict[str, object]] = {}
        scans = self.db.scalars(
            select(ModelCapabilityScan)
            .where(ModelCapabilityScan.model_id.in_(model_ids))
            .order_by(ModelCapabilityScan.scanned_at.desc())
        )
        for scan in scans:
            if scan.model_id in lookup:
                continue
            lookup[scan.model_id] = {
                "id": str(scan.id),
                "scanner": scan.scanner,
                "capabilities": scan.capabilities,
                "details": scan.details,
                "scannedAt": scan.scanned_at.isoformat(),
            }
        return lookup

    def _require_model(self, model_id: UUID) -> Model:
        model = self.db.get(Model, model_id)
        if model is None:
            raise ValueError("model not found")
        return model

    def _authorize_model_scope(self, model: Model, context: ServiceContext, *, write: bool = False) -> None:
        if model.project_id is None:
            if (
                get_settings().deployment_profile != "full"
                or not {"admin", "system"}.intersection(context.user.roles)
            ):
                raise ValueError("model not found")
            return
        ScopeAuthorizationService(self.db).resolve_project(
            model.project_id,
            context,
            environment_id=model.environment_id,
            write=write,
        )

    @staticmethod
    def _validate_credential_ref(api_key_ref: str | None, *, project_id: UUID | None) -> None:
        if api_key_ref is None:
            return
        CredentialResolver().validate_reference(
            api_key_ref,
            field_name="apiKeyRef",
            scope={"projectId": str(project_id) if project_id else None},
        )

    def _select_visual_model(self, role: ModelRole, provider: ProviderType | None) -> Model | None:
        return ModelGatewayTool(self.db).select_model(RiskLevel.MEDIUM, role, provider=provider)

    def _extract_visual_output(self, raw_response: dict[str, object]) -> dict[str, object]:
        candidate = raw_response.get("output")
        if isinstance(candidate, dict):
            return {
                "boundingBoxes": self._safe_list(candidate.get("boundingBoxes")),
                "recognizedText": self._safe_list(candidate.get("recognizedText")),
                "targetMatchConfidence": self._bounded_confidence(candidate.get("targetMatchConfidence")),
                "reasoningEvidenceRefs": self._safe_list(candidate.get("reasoningEvidenceRefs")),
                "riskSignals": self._safe_list(candidate.get("riskSignals")),
            }
        return {
            "boundingBoxes": [],
            "recognizedText": [],
            "targetMatchConfidence": 0.0,
            "reasoningEvidenceRefs": [],
            "riskSignals": [],
        }

    def _safe_list(self, value: object) -> list[object]:
        return list(value) if isinstance(value, list) else []

    def _bounded_confidence(self, value: object) -> float:
        try:
            confidence = float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(confidence, 1.0))

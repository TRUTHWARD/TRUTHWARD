# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import ApprovalType, UserStatus
from agentic_qa.domain.models import (
    Approval,
    AuditLog,
    CapabilityRegistry,
    EditionCapability,
    GuardrailEvent,
    RbacRoleCapability,
    User,
    UserEntitlement,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.access_control import (
    AccessControlRoleCapabilityRequest,
    AccessControlUserAccessChangeRequest,
    AccessControlUserEntitlementRequest,
)
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.capability_service import CapabilityService, VALID_EDITIONS
from agentic_qa.services.common import ServiceContext


class AccessControlConflictError(ValueError):
    """Raised when an access control workflow transition is invalid."""


class AccessControlService:
    """Service-owned Access Control workflow facade over existing Phase 8 auth tables."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.capabilities = CapabilityService(db)

    def projection(self) -> dict[str, object]:
        self.capabilities.ensure_seed_data()
        self.db.flush()
        users = list(self.db.scalars(select(User).order_by(User.created_at.asc())))
        capability_rows = list(self.db.scalars(select(CapabilityRegistry).order_by(CapabilityRegistry.category.asc(), CapabilityRegistry.capability_key.asc())))
        edition_rows = list(self.db.scalars(select(EditionCapability).order_by(EditionCapability.edition.asc(), EditionCapability.capability_key.asc())))
        role_rows = list(self.db.scalars(select(RbacRoleCapability).order_by(RbacRoleCapability.role_name.asc(), RbacRoleCapability.capability_key.asc())))
        entitlement_rows = list(self.db.scalars(select(UserEntitlement).order_by(UserEntitlement.created_at.desc())))
        return {
            "schemaVersion": "phase8.access-control.v1",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "capability": {
                "required": "access_control.manage",
                "guard": "backend",
                "riskLevel": "high",
                "approvalRequired": True,
                "guardrailRequired": True,
                "auditRequired": True,
            },
            "users": [self._serialize_user(user) for user in users],
            "capabilities": [self._serialize_capability(row) for row in capability_rows],
            "editionCapabilities": [self._serialize_edition_capability(row) for row in edition_rows],
            "roleCapabilities": [self._serialize_role_capability(row) for row in role_rows],
            "userEntitlements": [self._serialize_entitlement(row) for row in entitlement_rows],
            "workflows": [
                self._workflow_summary("user_access_change"),
                self._workflow_summary("role_capability_change"),
                self._workflow_summary("user_entitlement_change"),
            ],
            "approvalRefs": self._latest_access_control_approvals(),
            "guardrailEventRefs": self._latest_access_control_guardrails(),
            "auditRefs": self._latest_access_control_audits(),
            "readOnly": False,
        }

    def request_user_access_change(
        self,
        user_id: UUID,
        payload: AccessControlUserAccessChangeRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        user = self._require_user(user_id)
        requested_change = payload.model_dump(mode="json", exclude={"reason", "idempotencyKey", "metadata"})
        requested_change = {key: value for key, value in requested_change.items() if value is not None}
        if not requested_change:
            raise AccessControlConflictError("user access change must include edition, roles, or status")
        if "edition" in requested_change and requested_change["edition"] not in VALID_EDITIONS:
            raise AccessControlConflictError("unsupported user edition")
        if "status" in requested_change:
            requested_change["status"] = UserStatus(str(requested_change["status"])).value
        resource_id = self._resource_id("user-access", str(user.id), payload.idempotencyKey, requested_change)
        guardrail_refs = self._record_mutation_guardrail(
            context,
            resource_id=resource_id,
            action="access_control.user_access_change",
            payload={"targetUserId": str(user.id), "requestedChange": requested_change, "reason": payload.reason},
        )
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="access_control_change",
            resource_id=resource_id,
            summary=f"Approval required before changing access for user {user.email}.",
            payload={
                "action": "access_control.user_access_change",
                "targetUserId": str(user.id),
                "requestedChange": requested_change,
                "reason": payload.reason,
                "metadata": payload.metadata,
                "idempotencyKey": payload.idempotencyKey,
                "guardrailEventRefs": guardrail_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return self._approval_response(approval, "user_access_change", {"targetUser": self._serialize_user(user), "requestedChange": requested_change})

    def request_role_capability_change(
        self,
        payload: AccessControlRoleCapabilityRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        role_name = self._normalize_role_name(payload.roleName)
        capability = self._require_capability(payload.capabilityKey)
        requested_change = {
            "roleName": role_name,
            "capabilityKey": capability.capability_key,
            "effect": payload.effect,
        }
        resource_id = self._resource_id("role-capability", role_name, payload.idempotencyKey, requested_change)
        guardrail_refs = self._record_mutation_guardrail(
            context,
            resource_id=resource_id,
            action="access_control.role_capability_change",
            payload={"requestedChange": requested_change, "reason": payload.reason},
        )
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="access_control_change",
            resource_id=resource_id,
            summary=f"Approval required before changing role '{role_name}' capability '{capability.capability_key}'.",
            payload={
                "action": "access_control.role_capability_change",
                "requestedChange": requested_change,
                "reason": payload.reason,
                "metadata": payload.metadata,
                "idempotencyKey": payload.idempotencyKey,
                "guardrailEventRefs": guardrail_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return self._approval_response(approval, "role_capability_change", {"requestedChange": requested_change})

    def request_user_entitlement_change(
        self,
        payload: AccessControlUserEntitlementRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        user = self._require_user(payload.userId)
        capability = self._require_capability(payload.capabilityKey)
        requested_change = {
            "userId": str(user.id),
            "capabilityKey": capability.capability_key,
            "effect": payload.effect,
            "expiresAt": payload.expiresAt.isoformat() if payload.expiresAt else None,
        }
        resource_id = self._resource_id("user-entitlement", str(user.id), payload.idempotencyKey, requested_change)
        guardrail_refs = self._record_mutation_guardrail(
            context,
            resource_id=resource_id,
            action="access_control.user_entitlement_change",
            payload={"requestedChange": requested_change, "reason": payload.reason},
        )
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="access_control_change",
            resource_id=resource_id,
            summary=f"Approval required before changing entitlement '{capability.capability_key}' for user {user.email}.",
            payload={
                "action": "access_control.user_entitlement_change",
                "requestedChange": requested_change,
                "reason": payload.reason,
                "metadata": payload.metadata,
                "idempotencyKey": payload.idempotencyKey,
                "guardrailEventRefs": guardrail_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return self._approval_response(approval, "user_entitlement_change", {"targetUser": self._serialize_user(user), "requestedChange": requested_change})

    def execute_approved_user_access_change(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        user = self._require_user(UUID(str(approval_payload["targetUserId"])))
        requested_change = dict(approval_payload.get("requestedChange") or {})
        before = self._serialize_user(user)
        with traced_operation(
            self.db,
            context.trace_id,
            execution_id=None,
            root_span_name="access-control",
            span_name="access_control.user_access.apply",
            service_name="api-gateway",
            attributes={"approvalId": str(approval_id), "targetUserId": str(user.id)},
        ):
            if "edition" in requested_change:
                user.edition = str(requested_change["edition"])
            if "roles" in requested_change:
                user.roles = [str(role) for role in requested_change["roles"]]
            if "status" in requested_change:
                user.status = UserStatus(str(requested_change["status"]))
            self.db.flush()
            audit = self._audit(
                "access_control.user_access.apply",
                "user",
                str(user.id),
                context,
                {
                    "approvalId": str(approval_id),
                    "guardrailEventRefs": approval_payload.get("guardrailEventRefs") or [],
                    "before": before,
                    "after": self._serialize_user(user),
                },
            )
        return {
            "workflow": "user_access_change",
            "status": "applied",
            "approvalRefs": [{"type": "approval", "id": str(approval_id), "state": "approved"}],
            "guardrailEventRefs": approval_payload.get("guardrailEventRefs") or [],
            "auditRefs": [{"type": "audit_log", "id": str(audit.id), "action": audit.action}],
            "user": self._serialize_user(user),
        }

    def execute_approved_role_capability_change(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        requested_change = dict(approval_payload.get("requestedChange") or {})
        role_name = self._normalize_role_name(str(requested_change["roleName"]))
        capability = self._require_capability(str(requested_change["capabilityKey"]))
        effect = str(requested_change["effect"])
        with traced_operation(
            self.db,
            context.trace_id,
            execution_id=None,
            root_span_name="access-control",
            span_name="access_control.role_capability.apply",
            service_name="api-gateway",
            attributes={"approvalId": str(approval_id), "roleName": role_name, "capabilityKey": capability.capability_key},
        ):
            row = self.db.get(RbacRoleCapability, {"role_name": role_name, "capability_key": capability.capability_key})
            if row is None:
                row = RbacRoleCapability(role_name=role_name, capability_key=capability.capability_key, effect=effect)
                self.db.add(row)
            else:
                row.effect = effect
                row.updated_at = datetime.now(timezone.utc)
            self.db.flush()
            audit = self._audit(
                "access_control.role_capability.apply",
                "rbac_role_capability",
                f"{role_name}:{capability.capability_key}",
                context,
                {
                    "approvalId": str(approval_id),
                    "guardrailEventRefs": approval_payload.get("guardrailEventRefs") or [],
                    "requestedChange": requested_change,
                },
            )
        return {
            "workflow": "role_capability_change",
            "status": "applied",
            "approvalRefs": [{"type": "approval", "id": str(approval_id), "state": "approved"}],
            "guardrailEventRefs": approval_payload.get("guardrailEventRefs") or [],
            "auditRefs": [{"type": "audit_log", "id": str(audit.id), "action": audit.action}],
            "roleCapability": self._serialize_role_capability(row),
        }

    def execute_approved_user_entitlement_change(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        requested_change = dict(approval_payload.get("requestedChange") or {})
        user = self._require_user(UUID(str(requested_change["userId"])))
        capability = self._require_capability(str(requested_change["capabilityKey"]))
        expires_at = self._parse_optional_datetime(requested_change.get("expiresAt"))
        with traced_operation(
            self.db,
            context.trace_id,
            execution_id=None,
            root_span_name="access-control",
            span_name="access_control.user_entitlement.apply",
            service_name="api-gateway",
            attributes={"approvalId": str(approval_id), "targetUserId": str(user.id), "capabilityKey": capability.capability_key},
        ):
            row = self.db.scalar(
                select(UserEntitlement)
                .where(UserEntitlement.user_id == user.id)
                .where(UserEntitlement.capability_key == capability.capability_key)
            )
            if row is None:
                row = UserEntitlement(
                    user_id=user.id,
                    capability_key=capability.capability_key,
                    effect=str(requested_change["effect"]),
                    reason=str(approval_payload.get("reason") or ""),
                    expires_at=expires_at,
                )
                self.db.add(row)
            else:
                row.effect = str(requested_change["effect"])
                row.reason = str(approval_payload.get("reason") or "")
                row.expires_at = expires_at
            self.db.flush()
            audit = self._audit(
                "access_control.user_entitlement.apply",
                "user_entitlement",
                str(row.id),
                context,
                {
                    "approvalId": str(approval_id),
                    "guardrailEventRefs": approval_payload.get("guardrailEventRefs") or [],
                    "requestedChange": requested_change,
                },
            )
        return {
            "workflow": "user_entitlement_change",
            "status": "applied",
            "approvalRefs": [{"type": "approval", "id": str(approval_id), "state": "approved"}],
            "guardrailEventRefs": approval_payload.get("guardrailEventRefs") or [],
            "auditRefs": [{"type": "audit_log", "id": str(audit.id), "action": audit.action}],
            "userEntitlement": self._serialize_entitlement(row),
            "user": self._serialize_user(user),
        }

    def _serialize_user(self, user: User) -> dict[str, object]:
        edition, capabilities = self.capabilities.effective_capabilities_for_user(user.id, user.edition)
        return {
            "id": str(user.id),
            "name": user.name,
            "username": user.username,
            "email": user.email,
            "displayName": user.display_name,
            "roles": list(user.roles or []),
            "edition": edition,
            "status": user.status.value if hasattr(user.status, "value") else str(user.status),
            "effectiveCapabilities": capabilities,
            "createdAt": user.created_at.isoformat(),
            "updatedAt": user.updated_at.isoformat(),
        }

    def _serialize_capability(self, row: CapabilityRegistry) -> dict[str, object]:
        return {
            "capabilityKey": row.capability_key,
            "category": row.category,
            "description": row.description,
            "riskLevel": row.risk_level,
            "isActive": row.is_active,
            "reserved": row.capability_key == "knowledge.promote",
        }

    def _serialize_edition_capability(self, row: EditionCapability) -> dict[str, object]:
        return {
            "edition": row.edition,
            "capabilityKey": row.capability_key,
            "enabled": row.enabled,
            "createdAt": row.created_at.isoformat(),
        }

    def _serialize_role_capability(self, row: RbacRoleCapability) -> dict[str, object]:
        return {
            "roleName": row.role_name,
            "capabilityKey": row.capability_key,
            "effect": row.effect,
            "createdAt": row.created_at.isoformat(),
            "updatedAt": row.updated_at.isoformat(),
        }

    def _serialize_entitlement(self, row: UserEntitlement) -> dict[str, object]:
        return {
            "id": str(row.id),
            "userId": str(row.user_id),
            "capabilityKey": row.capability_key,
            "effect": row.effect,
            "reason": row.reason,
            "expiresAt": row.expires_at.isoformat() if row.expires_at else None,
            "createdAt": row.created_at.isoformat(),
        }

    def _workflow_summary(self, workflow_id: str) -> dict[str, object]:
        return {
            "workflowId": workflow_id,
            "capability": "access_control.manage",
            "riskLevel": "high",
            "approvalRequired": True,
            "guardrailRequired": True,
            "auditRequired": True,
            "backendGuard": "capability_dependency",
            "approvalSurface": "existing_approval_flow",
        }

    def _approval_response(self, approval: Approval, workflow: str, extra: dict[str, object]) -> dict[str, object]:
        return {
            "approvalRequired": True,
            "workflow": workflow,
            "approvalId": str(approval.id),
            "status": approval.status.value,
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            **extra,
        }

    def _require_user(self, user_id: UUID) -> User:
        user = self.db.get(User, user_id)
        if user is None:
            raise ValueError("user not found")
        return user

    def _require_capability(self, capability_key: str) -> CapabilityRegistry:
        self.capabilities.ensure_seed_data()
        capability = self.db.get(CapabilityRegistry, capability_key)
        if capability is None or not capability.is_active:
            raise ValueError("capability not found")
        if capability.capability_key == "knowledge.promote":
            raise AccessControlConflictError("knowledge.promote is reserved and inactive")
        return capability

    def _record_mutation_guardrail(
        self,
        context: ServiceContext,
        *,
        resource_id: str,
        action: str,
        payload: dict[str, object],
    ) -> list[dict[str, object]]:
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type="access_control",
            resource_id=resource_id,
            payload={"action": action, **payload},
        )
        RuntimeGuardrailEngine(self.db).record_result(
            guardrail_context,
            GuardrailResult(
                rule_id="access_control.mutation_preflight",
                decision=GuardrailDecision.ALLOW,
                reason="Access Control mutation passed governance preflight",
                evidence=[action],
                metadata={"approvalRequired": True, "riskLevel": "high"},
            ),
        )
        self.db.flush()
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.request_id == context.request_id)
                .where(GuardrailEvent.rule_id == "access_control.mutation_preflight")
                .order_by(GuardrailEvent.created_at.desc())
            )
        )
        return [{"type": "guardrail_event", "id": str(event.id), "ruleId": event.rule_id, "decision": event.decision.value} for event in events[:1]]

    def _audit(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        context: ServiceContext,
        details: dict[str, object],
    ) -> AuditLog:
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            action,
            resource_type,
            resource_id,
            context.request_id,
            context.trace_id,
            details,
        )
        self.db.flush()
        return audit

    def _latest_access_control_approvals(self) -> list[dict[str, object]]:
        rows = list(
            self.db.scalars(
                select(Approval)
                .where(Approval.resource_type == "access_control_change")
                .order_by(Approval.created_at.desc())
                .limit(10)
            )
        )
        return [
            {
                "type": "approval",
                "id": str(row.id),
                "status": row.status.value,
                "resourceId": row.resource_id,
                "action": row.payload.get("action"),
            }
            for row in rows
        ]

    def _latest_access_control_guardrails(self) -> list[dict[str, object]]:
        rows = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.rule_id == "access_control.mutation_preflight")
                .order_by(GuardrailEvent.created_at.desc())
                .limit(10)
            )
        )
        return [{"type": "guardrail_event", "id": str(row.id), "ruleId": row.rule_id, "decision": row.decision.value} for row in rows]

    def _latest_access_control_audits(self) -> list[dict[str, object]]:
        rows = list(
            self.db.scalars(
                select(AuditLog)
                .where(AuditLog.action.like("access_control.%"))
                .order_by(AuditLog.created_at.desc())
                .limit(10)
            )
        )
        return [{"type": "audit_log", "id": str(row.id), "action": row.action, "resourceType": row.resource_type} for row in rows]

    def _resource_id(self, prefix: str, target: str, idempotency_key: str, payload: dict[str, object]) -> str:
        fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        return f"{prefix}:{target}:{idempotency_key}:{fingerprint}"

    def _normalize_role_name(self, role_name: str) -> str:
        normalized = role_name.strip().lower()
        if not normalized:
            raise AccessControlConflictError("roleName is required")
        return normalized

    def _parse_optional_datetime(self, value: object) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        parsed = datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

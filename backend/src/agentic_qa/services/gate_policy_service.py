# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from agentic_qa.domain.enums import GatePolicyScopeType, GatePolicyStatus
from agentic_qa.domain.models import GatePolicy, GatePolicyBinding, GatePolicyVersion
from agentic_qa.schemas.gate_policy import GATE_POLICY_SCHEMA_VERSION, validate_gate_policy_document
from agentic_qa.services.common import acquire_transaction_advisory_lock, canonical_hash
from agentic_qa.services.gate_policy_repository import GatePolicyRepository


class GatePolicyDataError(ValueError):
    """Stable, redacted error for the internal Gate Policy data boundary."""

    def __init__(self, code: str, *, field: str | None = None, details: dict[str, object] | None = None) -> None:
        self.code = code
        self.field = field
        self.details = details or {}
        super().__init__(code)

    def as_dict(self) -> dict[str, object]:
        return {
            "errorCode": self.code,
            "field": self.field,
            "details": dict(self.details),
        }


class GatePolicyService:
    """Owns Gate Policy draft/version/binding persistence only.

    This service deliberately does not resolve bindings, evaluate Gate inputs,
    activate policy state, write Gate decisions, or execute Approval/Guardrail.
    """

    def __init__(self, db: Session, repository: GatePolicyRepository | None = None) -> None:
        self.db = db
        self.repository = repository or GatePolicyRepository(db)

    def create_policy(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        policy_key: str,
        name: str,
        description: str | None = None,
        actor_id: UUID | None = None,
        policy_id: UUID | None = None,
        project_id: UUID | None = None,
        commit: bool = True,
    ) -> GatePolicy:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        policy_key = policy_key.strip()
        name = name.strip()
        if not re.match(r"^[a-z][a-z0-9_.-]{2,127}$", policy_key):
            raise GatePolicyDataError("GATE_POLICY_KEY_INVALID", field="policyKey")
        if not name or len(name) > 255:
            raise GatePolicyDataError("GATE_POLICY_NAME_INVALID", field="name")
        if description is not None and len(description) > 2000:
            raise GatePolicyDataError("GATE_POLICY_DESCRIPTION_INVALID", field="description")

        acquire_transaction_advisory_lock(
            self.db,
            "gate-policy",
            f"{tenant_id}:{workspace_id}:{policy_key}",
        )
        existing = self.repository.find_policy_by_key(tenant_id, workspace_id, policy_key)
        if existing is not None:
            if (
                (policy_id is None or existing.id == policy_id)
                and existing.project_id == project_id
                and existing.name == name
                and existing.description == description
            ):
                return self._complete(existing, commit=commit)
            raise GatePolicyDataError("GATE_POLICY_IDEMPOTENCY_CONFLICT", field="policyKey")

        resolved_id = policy_id or uuid4()
        record = GatePolicy(
            id=resolved_id,
            project_id=project_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            policy_key=policy_key,
            policy_ref=f"gate-policy://{resolved_id}",
            name=name,
            description=description,
            status=GatePolicyStatus.DRAFT,
            created_by=actor_id,
            updated_by=actor_id,
        )
        self.repository.add(record)
        return self._persist(record, commit=commit, conflict_code="GATE_POLICY_CREATE_CONFLICT")

    def get_policy(self, *, tenant_id: str, workspace_id: str, policy_id: UUID) -> GatePolicy:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        record = self.repository.find_policy(tenant_id, workspace_id, policy_id)
        if record is None:
            raise GatePolicyDataError("GATE_POLICY_NOT_FOUND")
        return record

    def update_policy_draft(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        expected_lock_version: int,
        name: str | None = None,
        description: str | None = None,
        actor_id: UUID | None = None,
        commit: bool = True,
    ) -> GatePolicy:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        record = self.repository.find_policy(tenant_id, workspace_id, policy_id, for_update=True)
        if record is None:
            raise GatePolicyDataError("GATE_POLICY_NOT_FOUND")
        if record.status != GatePolicyStatus.DRAFT:
            raise GatePolicyDataError("GATE_POLICY_IMMUTABLE")
        self._require_lock(record.lock_version, expected_lock_version)
        if name is not None:
            resolved_name = name.strip()
            if not resolved_name or len(resolved_name) > 255:
                raise GatePolicyDataError("GATE_POLICY_NAME_INVALID", field="name")
            record.name = resolved_name
        if description is not None:
            if len(description) > 2000:
                raise GatePolicyDataError("GATE_POLICY_DESCRIPTION_INVALID", field="description")
            record.description = description
        record.updated_by = actor_id
        return self._persist(record, commit=commit, conflict_code="GATE_POLICY_LOCK_CONFLICT")

    def delete_policy_draft(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        expected_lock_version: int,
        commit: bool = True,
    ) -> None:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        record = self.repository.find_policy(tenant_id, workspace_id, policy_id, for_update=True)
        if record is None:
            raise GatePolicyDataError("GATE_POLICY_NOT_FOUND")
        if record.status != GatePolicyStatus.DRAFT:
            raise GatePolicyDataError("GATE_POLICY_IMMUTABLE")
        self._require_lock(record.lock_version, expected_lock_version)
        if self.repository.policy_has_versions(tenant_id, workspace_id, policy_id):
            raise GatePolicyDataError("GATE_POLICY_DELETE_BLOCKED_BY_VERSION")
        self._delete(record, commit=commit, conflict_code="GATE_POLICY_DELETE_CONFLICT")

    def create_version(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        document: dict[str, Any],
        expected_content_hash: str | None = None,
        capability_ref: str | None = None,
        approval_policy_ref: str | None = None,
        actor_id: UUID | None = None,
        commit: bool = True,
    ) -> GatePolicyVersion:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        policy = self.repository.find_policy(tenant_id, workspace_id, policy_id)
        if policy is None:
            raise GatePolicyDataError("GATE_POLICY_NOT_FOUND")
        if policy.status != GatePolicyStatus.DRAFT:
            raise GatePolicyDataError("GATE_POLICY_IMMUTABLE")
        normalized = self._validate_document(document)
        self._validate_document_identity(normalized, policy)
        if normalized["status"] != GatePolicyStatus.DRAFT.value:
            raise GatePolicyDataError("GATE_POLICY_ACTIVATION_NOT_SUPPORTED", field="status")
        self._validate_reference(capability_ref, "capabilityRef")
        self._validate_reference(approval_policy_ref, "approvalPolicyRef")
        content_hash = canonical_hash(normalized)
        if expected_content_hash is not None and expected_content_hash != content_hash:
            raise GatePolicyDataError("GATE_POLICY_HASH_MISMATCH", field="contentHash")

        version_number = int(normalized["version"]["versionNumber"])
        version_id = self._uuid(normalized["version"]["versionId"], "version.versionId")
        acquire_transaction_advisory_lock(
            self.db,
            "gate-policy-version",
            f"{tenant_id}:{workspace_id}:{policy_id}:{version_number}",
        )
        existing = self.repository.find_version_by_number(
            tenant_id,
            workspace_id,
            policy_id,
            version_number,
        )
        if existing is not None:
            if existing.id == version_id and existing.content_hash == content_hash:
                return self._complete(existing, commit=commit)
            raise GatePolicyDataError("GATE_POLICY_VERSION_CONFLICT", field="version.versionNumber")
        duplicate_hash = self.repository.find_version_by_hash(
            tenant_id,
            workspace_id,
            policy_id,
            content_hash,
        )
        if duplicate_hash is not None:
            raise GatePolicyDataError("GATE_POLICY_VERSION_DUPLICATE", field="contentHash")

        record = GatePolicyVersion(
            id=version_id,
            policy_id=policy.id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            version_number=version_number,
            version_ref=f"gate-policy-version://{version_id}",
            schema_version=GATE_POLICY_SCHEMA_VERSION,
            status=GatePolicyStatus.DRAFT,
            policy_snapshot=normalized,
            content_hash=content_hash,
            capability_ref=capability_ref,
            approval_policy_ref=approval_policy_ref,
            created_by=actor_id,
            updated_by=actor_id,
        )
        self.repository.add(record)
        return self._persist(record, commit=commit, conflict_code="GATE_POLICY_VERSION_CONFLICT")

    def update_draft_version(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        expected_lock_version: int,
        document: dict[str, Any],
        expected_content_hash: str | None = None,
        actor_id: UUID | None = None,
        commit: bool = True,
    ) -> GatePolicyVersion:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        version = self.repository.find_version(tenant_id, workspace_id, version_id, for_update=True)
        if version is None:
            raise GatePolicyDataError("GATE_POLICY_VERSION_NOT_FOUND")
        if version.status != GatePolicyStatus.DRAFT:
            raise GatePolicyDataError("GATE_POLICY_VERSION_IMMUTABLE")
        self._require_lock(version.lock_version, expected_lock_version)
        policy = self.repository.find_policy(tenant_id, workspace_id, version.policy_id)
        if policy is None:
            raise GatePolicyDataError("GATE_POLICY_NOT_FOUND")
        normalized = self._validate_document(document)
        self._validate_document_identity(normalized, policy)
        if self._uuid(normalized["version"]["versionId"], "version.versionId") != version.id:
            raise GatePolicyDataError("GATE_POLICY_VERSION_ID_MISMATCH", field="version.versionId")
        if int(normalized["version"]["versionNumber"]) != version.version_number:
            raise GatePolicyDataError("GATE_POLICY_VERSION_NUMBER_MISMATCH", field="version.versionNumber")
        if normalized["status"] != GatePolicyStatus.DRAFT.value:
            raise GatePolicyDataError("GATE_POLICY_ACTIVATION_NOT_SUPPORTED", field="status")
        content_hash = canonical_hash(normalized)
        if expected_content_hash is not None and expected_content_hash != content_hash:
            raise GatePolicyDataError("GATE_POLICY_HASH_MISMATCH", field="contentHash")
        if content_hash == version.content_hash:
            return self._complete(version, commit=commit)
        duplicate_hash = self.repository.find_version_by_hash(
            tenant_id,
            workspace_id,
            version.policy_id,
            content_hash,
        )
        if duplicate_hash is not None and duplicate_hash.id != version.id:
            raise GatePolicyDataError("GATE_POLICY_VERSION_DUPLICATE", field="contentHash")
        version.policy_snapshot = normalized
        version.content_hash = content_hash
        version.validation_status = "not_validated"
        version.validation_report = {}
        version.validated_at = None
        version.validated_by = None
        version.governance_status = "draft"
        version.current_approval_id = None
        version.submitted_at = None
        version.submitted_by = None
        version.updated_by = actor_id
        return self._persist(version, commit=commit, conflict_code="GATE_POLICY_LOCK_CONFLICT")

    def get_version(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
    ) -> GatePolicyVersion:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        record = self.repository.find_version(tenant_id, workspace_id, version_id)
        if record is None:
            raise GatePolicyDataError("GATE_POLICY_VERSION_NOT_FOUND")
        return record

    def delete_draft_version(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        expected_lock_version: int,
        commit: bool = True,
    ) -> None:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        record = self.repository.find_version(tenant_id, workspace_id, version_id, for_update=True)
        if record is None:
            raise GatePolicyDataError("GATE_POLICY_VERSION_NOT_FOUND")
        if record.status != GatePolicyStatus.DRAFT:
            raise GatePolicyDataError("GATE_POLICY_VERSION_IMMUTABLE")
        self._require_lock(record.lock_version, expected_lock_version)
        if self.repository.version_has_bindings(tenant_id, workspace_id, version_id):
            raise GatePolicyDataError("GATE_POLICY_VERSION_DELETE_BLOCKED_BY_BINDING")
        self._delete(record, commit=commit, conflict_code="GATE_POLICY_VERSION_DELETE_CONFLICT")

    def create_binding(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        policy_version_id: UUID,
        policy_version_hash: str,
        scope_type: str,
        scope_id: str | None,
        effective_from: datetime,
        effective_until: datetime | None,
        idempotency_key: str,
        capability_ref: str | None = None,
        approval_policy_ref: str | None = None,
        actor_id: UUID | None = None,
        binding_id: UUID | None = None,
        commit: bool = True,
    ) -> GatePolicyBinding:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        version = self.repository.find_version(tenant_id, workspace_id, policy_version_id)
        if version is None:
            raise GatePolicyDataError("GATE_POLICY_VERSION_NOT_FOUND")
        if version.status == GatePolicyStatus.DRAFT:
            raise GatePolicyDataError("GATE_POLICY_VERSION_NOT_IMMUTABLE")
        if version.content_hash != policy_version_hash:
            raise GatePolicyDataError("GATE_POLICY_HASH_MISMATCH", field="policyVersionHash")
        resolved_scope, resolved_scope_id, scope_key = self._binding_scope(
            scope_type,
            scope_id,
            workspace_id,
        )
        effective_from = self._aware_datetime(effective_from, "effectiveFrom")
        if effective_until is not None:
            effective_until = self._aware_datetime(effective_until, "effectiveUntil")
            if effective_until <= effective_from:
                raise GatePolicyDataError("GATE_POLICY_EFFECTIVE_WINDOW_INVALID", field="effectiveUntil")
        idempotency_key = idempotency_key.strip()
        if not idempotency_key or len(idempotency_key) > 255:
            raise GatePolicyDataError("GATE_POLICY_IDEMPOTENCY_KEY_INVALID", field="idempotencyKey")
        self._validate_reference(capability_ref, "capabilityRef")
        self._validate_reference(approval_policy_ref, "approvalPolicyRef")
        request_hash = canonical_hash(
            {
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
                "policyId": str(version.policy_id),
                "policyVersionId": str(version.id),
                "policyVersionHash": policy_version_hash,
                "scopeType": resolved_scope.value,
                "scopeId": resolved_scope_id,
                "effectiveFrom": effective_from.astimezone(timezone.utc).isoformat(),
                "effectiveUntil": effective_until.astimezone(timezone.utc).isoformat() if effective_until else None,
                "capabilityRef": capability_ref,
                "approvalPolicyRef": approval_policy_ref,
                "status": GatePolicyStatus.DRAFT.value,
            }
        )
        acquire_transaction_advisory_lock(
            self.db,
            "gate-policy-binding",
            f"{tenant_id}:{workspace_id}:{idempotency_key}",
        )
        existing = self.repository.find_binding_by_idempotency_key(
            tenant_id,
            workspace_id,
            idempotency_key,
        )
        if existing is not None:
            if existing.request_hash == request_hash and (binding_id is None or binding_id == existing.id):
                return self._complete(existing, commit=commit)
            raise GatePolicyDataError("GATE_POLICY_BINDING_IDEMPOTENCY_CONFLICT", field="idempotencyKey")
        scope_existing = self.repository.find_effective_scope_binding(
            tenant_id,
            workspace_id,
            version.policy_id,
            resolved_scope.value,
            scope_key,
            effective_from,
        )
        if scope_existing is not None:
            if scope_existing.request_hash == request_hash:
                return self._complete(scope_existing, commit=commit)
            raise GatePolicyDataError("GATE_POLICY_BINDING_CONFLICT")

        resolved_id = binding_id or uuid4()
        record = GatePolicyBinding(
            id=resolved_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            policy_id=version.policy_id,
            policy_version_id=version.id,
            policy_version_hash=version.content_hash,
            binding_ref=f"gate-policy-binding://{resolved_id}",
            scope_type=resolved_scope,
            scope_id=resolved_scope_id,
            scope_key=scope_key,
            status=GatePolicyStatus.DRAFT,
            effective_from=effective_from,
            effective_until=effective_until,
            capability_ref=capability_ref,
            approval_policy_ref=approval_policy_ref,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            created_by=actor_id,
            updated_by=actor_id,
        )
        self.repository.add(record)
        return self._persist(record, commit=commit, conflict_code="GATE_POLICY_BINDING_CONFLICT")

    def update_binding_draft(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        binding_id: UUID,
        expected_lock_version: int,
        effective_until: datetime | None,
        capability_ref: str | None,
        approval_policy_ref: str | None,
        actor_id: UUID | None = None,
        commit: bool = True,
    ) -> GatePolicyBinding:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        binding = self.repository.find_binding(tenant_id, workspace_id, binding_id, for_update=True)
        if binding is None:
            raise GatePolicyDataError("GATE_POLICY_BINDING_NOT_FOUND")
        if binding.status != GatePolicyStatus.DRAFT:
            raise GatePolicyDataError("GATE_POLICY_BINDING_IMMUTABLE")
        self._require_lock(binding.lock_version, expected_lock_version)
        if effective_until is not None:
            effective_until = self._aware_datetime(effective_until, "effectiveUntil")
            effective_from = binding.effective_from
            if effective_from.tzinfo is None:
                effective_from = effective_from.replace(tzinfo=timezone.utc)
            if effective_until <= effective_from:
                raise GatePolicyDataError("GATE_POLICY_EFFECTIVE_WINDOW_INVALID", field="effectiveUntil")
        self._validate_reference(capability_ref, "capabilityRef")
        self._validate_reference(approval_policy_ref, "approvalPolicyRef")
        binding.effective_until = effective_until
        binding.capability_ref = capability_ref
        binding.approval_policy_ref = approval_policy_ref
        binding.updated_by = actor_id
        binding.request_hash = canonical_hash(
            {
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
                "policyId": str(binding.policy_id),
                "policyVersionId": str(binding.policy_version_id),
                "policyVersionHash": binding.policy_version_hash,
                "scopeType": binding.scope_type.value,
                "scopeId": binding.scope_id,
                "effectiveFrom": binding.effective_from.isoformat(),
                "effectiveUntil": effective_until.astimezone(timezone.utc).isoformat() if effective_until else None,
                "capabilityRef": capability_ref,
                "approvalPolicyRef": approval_policy_ref,
                "status": GatePolicyStatus.DRAFT.value,
            }
        )
        return self._persist(binding, commit=commit, conflict_code="GATE_POLICY_LOCK_CONFLICT")

    def delete_binding_draft(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        binding_id: UUID,
        expected_lock_version: int,
        commit: bool = True,
    ) -> None:
        tenant_id, workspace_id = self._scope_context(tenant_id, workspace_id)
        record = self.repository.find_binding(tenant_id, workspace_id, binding_id, for_update=True)
        if record is None:
            raise GatePolicyDataError("GATE_POLICY_BINDING_NOT_FOUND")
        if record.status != GatePolicyStatus.DRAFT:
            raise GatePolicyDataError("GATE_POLICY_BINDING_IMMUTABLE")
        self._require_lock(record.lock_version, expected_lock_version)
        self._delete(record, commit=commit, conflict_code="GATE_POLICY_BINDING_DELETE_CONFLICT")

    def freeze_reference(
        self,
        version: GatePolicyVersion,
        binding: GatePolicyBinding | None = None,
    ) -> dict[str, object]:
        """Build the stable P02 input without resolving or evaluating anything."""

        if binding is not None and (
            binding.policy_version_id != version.id
            or binding.policy_version_hash != version.content_hash
            or binding.tenant_id != version.tenant_id
            or binding.workspace_id != version.workspace_id
        ):
            raise GatePolicyDataError("GATE_POLICY_BINDING_VERSION_MISMATCH")
        return {
            "policyId": str(version.policy_id),
            "policyVersionId": str(version.id),
            "policyVersionRef": version.version_ref,
            "schemaVersion": version.schema_version,
            "contentHash": version.content_hash,
            "bindingId": str(binding.id) if binding else None,
            "bindingRef": binding.binding_ref if binding else None,
            "tenantId": version.tenant_id,
            "workspaceId": version.workspace_id,
        }

    def _validate_document(self, document: dict[str, Any]) -> dict[str, Any]:
        try:
            return validate_gate_policy_document(document)
        except ValidationError as exc:
            errors = exc.errors(include_url=False, include_input=False)
            first: Mapping[str, Any] = errors[0] if errors else {}
            location = ".".join(str(part) for part in first.get("loc", ())) or None
            error_type = str(first.get("type") or "validation_error")
            raise GatePolicyDataError(
                "GATE_POLICY_SCHEMA_INVALID",
                field=location,
                details={"issueType": error_type},
            ) from exc
        except (TypeError, ValueError) as exc:
            raise GatePolicyDataError("GATE_POLICY_SCHEMA_INVALID") from exc

    def _validate_document_identity(self, document: dict[str, Any], policy: GatePolicy) -> None:
        identity = document["identity"]
        scope = document["scope"]
        if self._uuid(identity["policyId"], "identity.policyId") != policy.id:
            raise GatePolicyDataError("GATE_POLICY_ID_MISMATCH", field="identity.policyId")
        if identity["policyKey"] != policy.policy_key:
            raise GatePolicyDataError("GATE_POLICY_KEY_MISMATCH", field="identity.policyKey")
        if identity["name"] != policy.name or identity["description"] != policy.description:
            raise GatePolicyDataError("GATE_POLICY_IDENTITY_MISMATCH", field="identity")
        if scope["tenantId"] != policy.tenant_id or scope["workspaceId"] != policy.workspace_id:
            raise GatePolicyDataError("GATE_POLICY_SCOPE_MISMATCH", field="scope")

    @staticmethod
    def _scope_context(tenant_id: str, workspace_id: str) -> tuple[str, str]:
        tenant_id = tenant_id.strip()
        workspace_id = workspace_id.strip()
        if not tenant_id or len(tenant_id) > 128:
            raise GatePolicyDataError("GATE_POLICY_TENANT_INVALID", field="tenantId")
        if not workspace_id or len(workspace_id) > 128:
            raise GatePolicyDataError("GATE_POLICY_WORKSPACE_INVALID", field="workspaceId")
        return tenant_id, workspace_id

    @staticmethod
    def _uuid(value: object, field: str) -> UUID:
        try:
            return UUID(str(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise GatePolicyDataError("GATE_POLICY_ID_INVALID", field=field) from exc

    @staticmethod
    def _validate_reference(value: str | None, field: str) -> None:
        if value is None:
            return
        if len(value) > 500 or not re.match(r"^[a-z][a-z0-9+.-]*://\S+$", value):
            raise GatePolicyDataError("GATE_POLICY_REFERENCE_INVALID", field=field)

    @staticmethod
    def _binding_scope(
        scope_type: str,
        scope_id: str | None,
        workspace_id: str,
    ) -> tuple[GatePolicyScopeType, str | None, str]:
        try:
            resolved = GatePolicyScopeType(scope_type)
        except ValueError as exc:
            raise GatePolicyDataError("GATE_POLICY_SCOPE_TYPE_INVALID", field="scopeType") from exc
        resolved_id = scope_id.strip() if scope_id is not None else None
        if resolved == GatePolicyScopeType.GLOBAL:
            if resolved_id:
                raise GatePolicyDataError("GATE_POLICY_SCOPE_ID_FORBIDDEN", field="scopeId")
            return resolved, None, "global"
        if not resolved_id or len(resolved_id) > 255:
            raise GatePolicyDataError("GATE_POLICY_SCOPE_ID_REQUIRED", field="scopeId")
        if resolved == GatePolicyScopeType.WORKSPACE and resolved_id != workspace_id:
            raise GatePolicyDataError("GATE_POLICY_WORKSPACE_SCOPE_MISMATCH", field="scopeId")
        return resolved, resolved_id, resolved_id

    @staticmethod
    def _aware_datetime(value: datetime, field: str) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise GatePolicyDataError("GATE_POLICY_TIMEZONE_REQUIRED", field=field)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require_lock(actual: int, expected: int) -> None:
        if expected < 1 or actual != expected:
            raise GatePolicyDataError(
                "GATE_POLICY_LOCK_CONFLICT",
                field="lockVersion",
                details={"expectedLockVersion": expected},
            )

    def _persist(self, record: Any, *, commit: bool, conflict_code: str):
        try:
            self.repository.flush()
            return self._complete(record, commit=commit)
        except StaleDataError as exc:
            self.db.rollback()
            raise GatePolicyDataError("GATE_POLICY_LOCK_CONFLICT", field="lockVersion") from exc
        except IntegrityError as exc:
            self.db.rollback()
            raise GatePolicyDataError(conflict_code) from exc
        except ValueError as exc:
            self.db.rollback()
            if "immutable" in str(exc).lower() or "publishing" in str(exc).lower():
                raise GatePolicyDataError("GATE_POLICY_VERSION_IMMUTABLE") from exc
            raise

    def _complete(self, record: Any, *, commit: bool):
        if commit:
            try:
                self.db.commit()
                self.db.refresh(record)
            except StaleDataError as exc:
                self.db.rollback()
                raise GatePolicyDataError("GATE_POLICY_LOCK_CONFLICT", field="lockVersion") from exc
            except IntegrityError as exc:
                self.db.rollback()
                raise GatePolicyDataError("GATE_POLICY_CONFLICT") from exc
        return record

    def _delete(self, record: Any, *, commit: bool, conflict_code: str) -> None:
        try:
            self.repository.delete(record)
            self.repository.flush()
            if commit:
                self.db.commit()
        except StaleDataError as exc:
            self.db.rollback()
            raise GatePolicyDataError("GATE_POLICY_LOCK_CONFLICT", field="lockVersion") from exc
        except IntegrityError as exc:
            self.db.rollback()
            raise GatePolicyDataError(conflict_code) from exc

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from typing import Any
from uuid import UUID, uuid5

from pydantic import ValidationError

from agentic_qa.domain.enums import GatePolicyStatus
from agentic_qa.domain.models import GatePolicyBinding
from agentic_qa.schemas.gate_policy import (
    GATE_POLICY_SCHEMA_VERSION,
    GatePolicyFallbackReasonValue,
    GatePolicyResolutionRequestContract,
    GatePolicyResolutionResultContract,
    GatePolicyResolutionSnapshotContract,
    validate_gate_policy_document,
)
from agentic_qa.services.common import canonical_hash
from agentic_qa.services.gate_policy_repository import GatePolicyRepository


GATE_POLICY_SCOPE_PRECEDENCE = (
    "environment",
    "project",
    "workspace",
    "stage",
    "domain",
    "global",
)

_DEFAULT_NAMESPACE = UUID("3a921d6b-e7f6-5bf9-a30d-51c7e6b84ce1")
_SAFE_REF = re.compile(r"^[a-z][a-z0-9+.-]*://\S+$")


class GatePolicyResolutionError(ValueError):
    """Stable fail-closed error without policy metadata or foreign-scope data."""

    def __init__(
        self,
        code: str,
        *,
        fallback_reason: GatePolicyFallbackReasonValue,
        scope: str | None = None,
        resolution_trace: list[dict[str, object]] | None = None,
    ) -> None:
        self.code = code
        self.fallback_reason = fallback_reason
        self.scope = scope
        self.resolution_trace = deepcopy(resolution_trace or [])
        super().__init__(code)

    def as_dict(self) -> dict[str, object]:
        return {
            "errorCode": self.code,
            "fallbackReason": self.fallback_reason,
            "scope": self.scope,
            "resolutionTrace": deepcopy(self.resolution_trace),
        }


class _CandidateValidationError(ValueError):
    def __init__(self, code: str, reason: GatePolicyFallbackReasonValue) -> None:
        self.code = code
        self.reason = reason
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ResolvedGatePolicy:
    source: str
    policy_id: str
    policy_ref: str
    policy_key: str
    version_id: str
    version_ref: str
    version_number: int
    content_hash: str
    policy_snapshot: dict[str, Any]
    scope_type: str
    scope_id: str | None
    binding: GatePolicyBinding | None = None


class DefaultPolicyProvider:
    """Loads the single packaged default and validates each contextual instance."""

    def __init__(self, template_loader: Callable[[], str] | None = None) -> None:
        self._template_loader = template_loader or self._load_packaged_template

    def resolve(self, request: GatePolicyResolutionRequestContract) -> ResolvedGatePolicy:
        try:
            raw = json.loads(self._template_loader())
            if not isinstance(raw, dict):
                raise ValueError("default policy template must be an object")
            # The source file itself must remain a valid gate-policy.v1 document.
            template = validate_gate_policy_document(raw)
            contextual = deepcopy(template)
            identity_seed = f"{request.tenantId}\x1f{request.workspaceId}\x1fbuiltin.default.compatibility"
            policy_id = str(uuid5(_DEFAULT_NAMESPACE, identity_seed))
            version_id = str(uuid5(_DEFAULT_NAMESPACE, identity_seed + "\x1fversion:1"))
            contextual["identity"]["policyId"] = policy_id
            contextual["version"]["versionId"] = version_id
            contextual["scope"]["tenantId"] = request.tenantId
            contextual["scope"]["workspaceId"] = request.workspaceId
            validated = validate_gate_policy_document(contextual)
            if validated["status"] != GatePolicyStatus.ACTIVE.value:
                raise ValueError("default policy must be active")
        except (json.JSONDecodeError, OSError, TypeError, ValueError, ValidationError) as exc:
            raise GatePolicyResolutionError(
                "GATE_POLICY_BUILTIN_DEFAULT_INVALID",
                fallback_reason="schema_invalid",
                scope="builtin_default",
            ) from exc

        return ResolvedGatePolicy(
            source="builtin_default",
            policy_id=policy_id,
            policy_ref=f"builtin-gate-policy://{policy_id}",
            policy_key=str(validated["identity"]["policyKey"]),
            version_id=version_id,
            version_ref=f"builtin-gate-policy-version://{version_id}",
            version_number=int(validated["version"]["versionNumber"]),
            content_hash=canonical_hash(validated),
            policy_snapshot=validated,
            scope_type="builtin_default",
            scope_id=None,
            binding=None,
        )

    @staticmethod
    def _load_packaged_template() -> str:
        return (
            resources.files("agentic_qa.gate_policies")
            .joinpath("builtin_default_gate_policy.json")
            .read_text(encoding="utf-8")
        )


class GatePolicyResolutionSnapshotBuilder:
    """Builds and verifies complete, canonical, DB-independent resolution freezes."""

    def build(
        self,
        *,
        request: GatePolicyResolutionRequestContract,
        resolved: ResolvedGatePolicy,
        fallback_reason: GatePolicyFallbackReasonValue,
        resolution_trace: list[dict[str, object]],
    ) -> tuple[dict[str, Any], str]:
        binding_snapshot: dict[str, object] | None = None
        if resolved.binding is not None:
            binding = resolved.binding
            binding_snapshot = {
                "bindingId": str(binding.id),
                "bindingRef": resolved_binding_ref(binding),
                "status": GatePolicyStatus.ACTIVE.value,
                "scopeType": _enum_value(binding.scope_type),
                "scopeId": binding.scope_id,
                "effectiveFrom": _storage_time(binding.effective_from),
                "effectiveUntil": _storage_time(binding.effective_until),
                "policyId": str(binding.policy_id),
                "policyVersionId": str(binding.policy_version_id),
                "policyVersionHash": binding.policy_version_hash,
            }
        payload = {
            "schemaVersion": "phase8.gate-policy-resolution-snapshot.v1",
            "request": request.model_dump(mode="json"),
            "source": resolved.source,
            "policyId": resolved.policy_id,
            "policyRef": resolved.policy_ref,
            "policyKey": resolved.policy_key,
            "policyVersionId": resolved.version_id,
            "policyVersionRef": resolved.version_ref,
            "policyVersionNumber": resolved.version_number,
            "policySchemaVersion": GATE_POLICY_SCHEMA_VERSION,
            "policyVersionHash": resolved.content_hash,
            "binding": binding_snapshot,
            "resolvedScope": {"type": resolved.scope_type, "scopeId": resolved.scope_id},
            "fallbackReason": fallback_reason,
            "resolutionTrace": deepcopy(resolution_trace),
            "policy": deepcopy(resolved.policy_snapshot),
        }
        try:
            snapshot = GatePolicyResolutionSnapshotContract.model_validate(payload).model_dump(mode="json")
        except (ValidationError, TypeError, ValueError) as exc:
            raise GatePolicyResolutionError(
                "GATE_POLICY_RESOLUTION_SNAPSHOT_INVALID",
                fallback_reason="schema_invalid",
                scope=resolved.scope_type,
                resolution_trace=resolution_trace,
            ) from exc
        policy_hash = canonical_hash(snapshot["policy"])
        if policy_hash != snapshot["policyVersionHash"]:
            raise GatePolicyResolutionError(
                "GATE_POLICY_HASH_MISMATCH",
                fallback_reason="hash_mismatch",
                scope=resolved.scope_type,
                resolution_trace=resolution_trace,
            )
        return snapshot, canonical_hash(snapshot)

    def verify(self, snapshot: dict[str, Any], expected_snapshot_hash: str) -> dict[str, Any]:
        try:
            normalized = GatePolicyResolutionSnapshotContract.model_validate(snapshot).model_dump(mode="json")
            policy = validate_gate_policy_document(normalized["policy"])
        except (ValidationError, TypeError, ValueError) as exc:
            raise GatePolicyResolutionError(
                "GATE_POLICY_RESOLUTION_SNAPSHOT_INVALID",
                fallback_reason="schema_invalid",
            ) from exc
        if canonical_hash(policy) != normalized["policyVersionHash"]:
            raise GatePolicyResolutionError(
                "GATE_POLICY_HASH_MISMATCH",
                fallback_reason="hash_mismatch",
                scope=str(normalized["resolvedScope"]["type"]),
                resolution_trace=normalized["resolutionTrace"],
            )
        if canonical_hash(normalized) != expected_snapshot_hash:
            raise GatePolicyResolutionError(
                "GATE_POLICY_RESOLUTION_SNAPSHOT_HASH_MISMATCH",
                fallback_reason="hash_mismatch",
                scope=str(normalized["resolvedScope"]["type"]),
                resolution_trace=normalized["resolutionTrace"],
            )
        return normalized


class GatePolicyResolver:
    """Read-only deterministic Gate Policy selector; it never evaluates or writes Gate."""

    def __init__(
        self,
        repository: GatePolicyRepository,
        *,
        default_policy_provider: DefaultPolicyProvider | None = None,
        snapshot_builder: GatePolicyResolutionSnapshotBuilder | None = None,
    ) -> None:
        self.repository = repository
        self.default_policy_provider = default_policy_provider or DefaultPolicyProvider()
        self.snapshot_builder = snapshot_builder or GatePolicyResolutionSnapshotBuilder()

    def resolve(
        self,
        request: GatePolicyResolutionRequestContract | dict[str, Any],
    ) -> GatePolicyResolutionResultContract:
        try:
            normalized_request = GatePolicyResolutionRequestContract.model_validate(request)
        except ValidationError as exc:
            raise GatePolicyResolutionError(
                "GATE_POLICY_RESOLUTION_REQUEST_INVALID",
                fallback_reason="context_incomplete",
            ) from exc

        context = {
            "environment": normalized_request.environment,
            "project": normalized_request.projectId,
            "workspace": normalized_request.workspaceId,
            "stage": normalized_request.stage,
            "domain": normalized_request.domain,
            "global": "global",
        }
        scope_keys = {scope: value for scope, value in context.items() if value is not None}
        try:
            candidates = self.repository.list_resolution_candidates(
                normalized_request.tenantId,
                normalized_request.workspaceId,
                scope_keys,
            )
        except Exception as exc:
            raise GatePolicyResolutionError(
                "GATE_POLICY_RESOLUTION_DB_FAILURE",
                fallback_reason="db_failure",
            ) from exc

        candidates = sorted(candidates, key=_candidate_sort_key)
        candidates_by_scope: dict[str, list[GatePolicyBinding]] = {
            scope: [] for scope in GATE_POLICY_SCOPE_PRECEDENCE
        }
        for binding in candidates:
            scope_type = _enum_value(binding.scope_type)
            if binding.tenant_id != normalized_request.tenantId or binding.workspace_id != normalized_request.workspaceId:
                raise GatePolicyResolutionError(
                    "GATE_POLICY_CROSS_TENANT_BINDING",
                    fallback_reason="cross_tenant",
                    scope=scope_type if scope_type in candidates_by_scope else None,
                )
            if scope_type not in candidates_by_scope:
                raise GatePolicyResolutionError(
                    "GATE_POLICY_BINDING_SCOPE_MISMATCH",
                    fallback_reason="scope_mismatch",
                )
            expected_scope_id = context[scope_type]
            expected_scope_key = "global" if scope_type == "global" else expected_scope_id
            expected_binding_scope_id = None if scope_type == "global" else expected_scope_id
            if (
                expected_scope_id is None
                or str(binding.scope_key) != str(expected_scope_key)
                or binding.scope_id != expected_binding_scope_id
            ):
                raise GatePolicyResolutionError(
                    "GATE_POLICY_BINDING_SCOPE_MISMATCH",
                    fallback_reason="scope_mismatch",
                    scope=scope_type,
                    resolution_trace=[
                        _trace_entry(
                            scope=scope_type,
                            scope_id=None if scope_type == "global" else str(expected_scope_id),
                            outcome="error",
                            reason="scope_mismatch",
                            candidates=[binding],
                        )
                    ],
                )
            if _enum_value(binding.status) not in {status.value for status in GatePolicyStatus}:
                raise GatePolicyResolutionError(
                    "GATE_POLICY_BINDING_STATUS_INVALID",
                    fallback_reason="schema_invalid",
                    scope=scope_type,
                )
            candidates_by_scope[scope_type].append(binding)

        trace: list[dict[str, object]] = []
        evaluation_time = normalized_request.evaluationTime
        for scope in GATE_POLICY_SCOPE_PRECEDENCE:
            requested_scope_id = context[scope]
            if requested_scope_id is None:
                trace.append(
                    _trace_entry(
                        scope=scope,
                        scope_id=None,
                        outcome="skipped",
                        reason="context_incomplete",
                        candidates=[],
                    )
                )
                continue

            scoped_candidates = candidates_by_scope[scope]
            if not scoped_candidates:
                trace.append(
                    _trace_entry(
                        scope=scope,
                        scope_id=None if scope == "global" else str(requested_scope_id),
                        outcome="skipped",
                        reason=f"{scope}_missing",  # type: ignore[arg-type]
                        candidates=[],
                    )
                )
                continue

            active: list[GatePolicyBinding] = []
            for binding in scoped_candidates:
                if _enum_value(binding.status) != GatePolicyStatus.ACTIVE.value:
                    continue
                try:
                    if _is_effective(binding, evaluation_time):
                        active.append(binding)
                except ValueError as exc:
                    error_trace = [
                        *trace,
                        _trace_entry(
                            scope=scope,
                            scope_id=None if scope == "global" else str(requested_scope_id),
                            outcome="error",
                            reason="schema_invalid",
                            candidates=scoped_candidates,
                        ),
                    ]
                    raise GatePolicyResolutionError(
                        "GATE_POLICY_BINDING_EFFECTIVE_WINDOW_INVALID",
                        fallback_reason="schema_invalid",
                        scope=scope,
                        resolution_trace=error_trace,
                    ) from exc

            if not active:
                active_status_count = sum(
                    _enum_value(binding.status) == GatePolicyStatus.ACTIVE.value
                    for binding in scoped_candidates
                )
                reason: GatePolicyFallbackReasonValue = (
                    "not_effective" if active_status_count else "disabled"
                )
                trace.append(
                    _trace_entry(
                        scope=scope,
                        scope_id=None if scope == "global" else str(requested_scope_id),
                        outcome="skipped",
                        reason=reason,
                        candidates=scoped_candidates,
                    )
                )
                continue

            resolved_candidates: list[ResolvedGatePolicy] = []
            for binding in active:
                try:
                    resolved_candidates.append(
                        self._validate_candidate(binding, normalized_request, scope, str(requested_scope_id))
                    )
                except _CandidateValidationError as exc:
                    trace_candidates = [] if exc.reason == "cross_tenant" else active
                    error_trace = [
                        *trace,
                        _trace_entry(
                            scope=scope,
                            scope_id=None if scope == "global" else str(requested_scope_id),
                            outcome="error",
                            reason=exc.reason,
                            candidates=trace_candidates,
                        ),
                    ]
                    raise GatePolicyResolutionError(
                        exc.code,
                        fallback_reason=exc.reason,
                        scope=scope,
                        resolution_trace=error_trace,
                    ) from exc

            if len(resolved_candidates) != 1:
                error_trace = [
                    *trace,
                    _trace_entry(
                        scope=scope,
                        scope_id=None if scope == "global" else str(requested_scope_id),
                        outcome="error",
                        reason="conflict",
                        candidates=active,
                    ),
                ]
                raise GatePolicyResolutionError(
                    "GATE_POLICY_RESOLUTION_CONFLICT",
                    fallback_reason="conflict",
                    scope=scope,
                    resolution_trace=error_trace,
                )

            trace.append(
                _trace_entry(
                    scope=scope,
                    scope_id=None if scope == "global" else str(requested_scope_id),
                    outcome="selected",
                    reason="explicit_selection",
                    candidates=active,
                )
            )
            return self._result(
                normalized_request,
                resolved_candidates[0],
                fallback_reason="explicit_selection",
                trace=trace,
            )

        try:
            resolved_default = self.default_policy_provider.resolve(normalized_request)
        except GatePolicyResolutionError as exc:
            error_trace = [
                *trace,
                _trace_entry(
                    scope="builtin_default",
                    scope_id=None,
                    outcome="error",
                    reason=exc.fallback_reason,
                    candidates=[],
                ),
            ]
            raise GatePolicyResolutionError(
                exc.code,
                fallback_reason=exc.fallback_reason,
                scope="builtin_default",
                resolution_trace=error_trace,
            ) from exc
        trace.append(
            _trace_entry(
                scope="builtin_default",
                scope_id=None,
                outcome="fallback",
                reason="builtin_default",
                candidates=[],
            )
        )
        return self._result(
            normalized_request,
            resolved_default,
            fallback_reason="builtin_default",
            trace=trace,
        )

    def _validate_candidate(
        self,
        binding: GatePolicyBinding,
        request: GatePolicyResolutionRequestContract,
        expected_scope: str,
        expected_scope_id: str,
    ) -> ResolvedGatePolicy:
        if binding.tenant_id != request.tenantId or binding.workspace_id != request.workspaceId:
            raise _CandidateValidationError(
                "GATE_POLICY_CROSS_TENANT_BINDING",
                "cross_tenant",
            )
        scope_type = _enum_value(binding.scope_type)
        expected_id = None if expected_scope == "global" else expected_scope_id
        if scope_type != expected_scope or binding.scope_id != expected_id:
            raise _CandidateValidationError("GATE_POLICY_BINDING_SCOPE_MISMATCH", "scope_mismatch")
        try:
            version = self.repository.find_version(
                request.tenantId,
                request.workspaceId,
                binding.policy_version_id,
            )
        except Exception as exc:
            raise _CandidateValidationError("GATE_POLICY_RESOLUTION_DB_FAILURE", "db_failure") from exc
        if version is None or _enum_value(version.status) != GatePolicyStatus.ACTIVE.value:
            raise _CandidateValidationError("GATE_POLICY_VERSION_UNAVAILABLE", "version_unavailable")
        if version.tenant_id != request.tenantId or version.workspace_id != request.workspaceId:
            raise _CandidateValidationError("GATE_POLICY_CROSS_TENANT_VERSION", "cross_tenant")
        if binding.policy_id != version.policy_id:
            raise _CandidateValidationError("GATE_POLICY_BINDING_VERSION_MISMATCH", "schema_invalid")
        if version.schema_version != GATE_POLICY_SCHEMA_VERSION:
            raise _CandidateValidationError("GATE_POLICY_SCHEMA_VERSION_UNSUPPORTED", "schema_invalid")
        try:
            policy_snapshot = validate_gate_policy_document(dict(version.policy_snapshot))
        except (ValidationError, TypeError, ValueError) as exc:
            raise _CandidateValidationError("GATE_POLICY_SCHEMA_INVALID", "schema_invalid") from exc
        if policy_snapshot["schemaVersion"] != GATE_POLICY_SCHEMA_VERSION:
            raise _CandidateValidationError("GATE_POLICY_SCHEMA_VERSION_UNSUPPORTED", "schema_invalid")
        if policy_snapshot["status"] != GatePolicyStatus.ACTIVE.value:
            raise _CandidateValidationError("GATE_POLICY_VERSION_UNAVAILABLE", "version_unavailable")
        if (
            policy_snapshot["scope"]["tenantId"] != request.tenantId
            or policy_snapshot["scope"]["workspaceId"] != request.workspaceId
        ):
            raise _CandidateValidationError("GATE_POLICY_CROSS_TENANT_POLICY", "cross_tenant")
        if (
            str(policy_snapshot["identity"]["policyId"]) != str(version.policy_id)
            or str(policy_snapshot["version"]["versionId"]) != str(version.id)
            or int(policy_snapshot["version"]["versionNumber"]) != version.version_number
        ):
            raise _CandidateValidationError("GATE_POLICY_VERSION_IDENTITY_MISMATCH", "schema_invalid")
        computed_hash = canonical_hash(policy_snapshot)
        if computed_hash != version.content_hash or binding.policy_version_hash != version.content_hash:
            raise _CandidateValidationError("GATE_POLICY_HASH_MISMATCH", "hash_mismatch")
        try:
            policy = self.repository.find_policy(
                request.tenantId,
                request.workspaceId,
                version.policy_id,
            )
        except Exception as exc:
            raise _CandidateValidationError("GATE_POLICY_RESOLUTION_DB_FAILURE", "db_failure") from exc
        if policy is None:
            raise _CandidateValidationError("GATE_POLICY_VERSION_UNAVAILABLE", "version_unavailable")
        if policy.tenant_id != request.tenantId or policy.workspace_id != request.workspaceId:
            raise _CandidateValidationError("GATE_POLICY_CROSS_TENANT_POLICY", "cross_tenant")
        if policy.policy_key != policy_snapshot["identity"]["policyKey"]:
            raise _CandidateValidationError("GATE_POLICY_VERSION_IDENTITY_MISMATCH", "schema_invalid")
        if not _valid_ref(policy.policy_ref, "gate-policy://"):
            raise _CandidateValidationError("GATE_POLICY_REFERENCE_INVALID", "schema_invalid")
        if not _valid_ref(version.version_ref, "gate-policy-version://"):
            raise _CandidateValidationError("GATE_POLICY_REFERENCE_INVALID", "schema_invalid")
        if not _valid_ref(binding.binding_ref, "gate-policy-binding://"):
            raise _CandidateValidationError("GATE_POLICY_REFERENCE_INVALID", "schema_invalid")
        return ResolvedGatePolicy(
            source="binding",
            policy_id=str(policy.id),
            policy_ref=policy.policy_ref,
            policy_key=policy.policy_key,
            version_id=str(version.id),
            version_ref=version.version_ref,
            version_number=version.version_number,
            content_hash=version.content_hash,
            policy_snapshot=policy_snapshot,
            scope_type=scope_type,
            scope_id=expected_id,
            binding=binding,
        )

    def _result(
        self,
        request: GatePolicyResolutionRequestContract,
        resolved: ResolvedGatePolicy,
        *,
        fallback_reason: GatePolicyFallbackReasonValue,
        trace: list[dict[str, object]],
    ) -> GatePolicyResolutionResultContract:
        snapshot, snapshot_hash = self.snapshot_builder.build(
            request=request,
            resolved=resolved,
            fallback_reason=fallback_reason,
            resolution_trace=trace,
        )
        binding = resolved.binding
        return GatePolicyResolutionResultContract.model_validate(
            {
                "schemaVersion": "phase8.gate-policy-resolution-result.v1",
                "source": resolved.source,
                "resolvedPolicyId": resolved.policy_id,
                "resolvedPolicyRef": resolved.policy_ref,
                "resolvedPolicyKey": resolved.policy_key,
                "resolvedPolicyVersionId": resolved.version_id,
                "resolvedPolicyVersionRef": resolved.version_ref,
                "resolvedPolicyVersionNumber": resolved.version_number,
                "resolvedPolicyVersionHash": resolved.content_hash,
                "resolvedBindingId": str(binding.id) if binding else None,
                "resolvedBindingRef": resolved_binding_ref(binding) if binding else None,
                "resolvedScope": {"type": resolved.scope_type, "scopeId": resolved.scope_id},
                "fallbackReason": fallback_reason,
                "resolutionTrace": deepcopy(trace),
                "snapshot": snapshot,
                "snapshotHash": snapshot_hash,
                "writesGateDecision": False,
            }
        )


def _trace_entry(
    *,
    scope: str,
    scope_id: str | None,
    outcome: str,
    reason: GatePolicyFallbackReasonValue,
    candidates: list[GatePolicyBinding],
) -> dict[str, object]:
    safe_refs = sorted(
        resolved_binding_ref(candidate)
        for candidate in candidates
        if _valid_ref(candidate.binding_ref, "gate-policy-binding://")
    )
    return {
        "scope": scope,
        "requestedScopeId": scope_id,
        "outcome": outcome,
        "reason": reason,
        "candidateCount": len(candidates),
        "checkedBindingRefs": safe_refs,
    }


def _enum_value(value: object) -> str:
    return str(getattr(value, "value", value))


def _storage_time(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_effective(binding: GatePolicyBinding, evaluation_time: datetime) -> bool:
    effective_from = _storage_time(binding.effective_from)
    effective_until = _storage_time(binding.effective_until)
    if effective_from is None:
        raise ValueError("effectiveFrom is required")
    if effective_until is not None and effective_until <= effective_from:
        raise ValueError("effective window is invalid")
    return effective_from <= evaluation_time and (
        effective_until is None or evaluation_time < effective_until
    )


def _candidate_sort_key(binding: GatePolicyBinding) -> tuple[str, str, str, str]:
    effective_from = _storage_time(binding.effective_from)
    return (
        _enum_value(binding.scope_type),
        str(binding.scope_key),
        effective_from.isoformat() if effective_from else "",
        str(binding.id),
    )


def _valid_ref(value: object, prefix: str) -> bool:
    resolved = str(value or "")
    return len(resolved) <= 500 and resolved.startswith(prefix) and bool(_SAFE_REF.match(resolved))


def resolved_binding_ref(binding: GatePolicyBinding) -> str:
    """Return a stable same-tenant ref; callers validate it before snapshots."""

    return str(binding.binding_ref)

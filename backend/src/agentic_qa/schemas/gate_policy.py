# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


GATE_POLICY_SCHEMA_VERSION = "gate-policy.v1"
MAX_GATE_POLICY_BYTES = 64 * 1024
MAX_GATE_POLICY_DEPTH = 12
MAX_GATE_POLICY_RULES = 256

GatePolicyStatusValue = Literal["draft", "active", "disabled", "deprecated", "archived"]
GatePolicyScopeValue = Literal["global", "workspace", "project", "environment", "stage", "domain"]
GatePolicyDecisionValue = Literal["pass", "warn", "fail", "blocked"]
GatePolicyInputValue = Literal["normalizedFindings", "metrics", "approvalState", "policySnapshot"]
GatePolicyThreshold = str | int | float | bool | None | list[str | int | float | bool]
GatePolicyResolutionScopeValue = GatePolicyScopeValue | Literal["builtin_default"]
GatePolicyFallbackReasonValue = Literal[
    "explicit_selection",
    "environment_missing",
    "project_missing",
    "workspace_missing",
    "stage_missing",
    "domain_missing",
    "global_missing",
    "disabled",
    "not_effective",
    "version_unavailable",
    "hash_mismatch",
    "conflict",
    "context_incomplete",
    "schema_invalid",
    "scope_mismatch",
    "cross_tenant",
    "db_failure",
    "builtin_default",
]


class _StrictGatePolicyModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


class GatePolicyIdentityContract(_StrictGatePolicyModel):
    policyId: str = Field(min_length=1, max_length=64)
    policyKey: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)


class GatePolicyVersionContract(_StrictGatePolicyModel):
    versionId: str = Field(min_length=1, max_length=64)
    versionNumber: int = Field(ge=1, le=2_147_483_647)


class GatePolicyScopeContract(_StrictGatePolicyModel):
    type: GatePolicyScopeValue
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    scopeId: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_scope_identity(self) -> "GatePolicyScopeContract":
        if self.type == "global" and self.scopeId is not None:
            raise ValueError("global scope must not carry scopeId")
        if self.type != "global" and not self.scopeId:
            raise ValueError("non-global scope requires scopeId")
        if self.type == "workspace" and self.scopeId != self.workspaceId:
            raise ValueError("workspace scopeId must match workspaceId")
        return self


class GatePolicyEvidenceRequirementContract(_StrictGatePolicyModel):
    minimumCount: int = Field(default=0, ge=0, le=1000)
    requiredTypes: list[
        Literal["artifact", "finding", "metric", "trace", "replay", "approval"]
    ] = Field(default_factory=list, max_length=16)


class GatePolicyConfidenceRequirementContract(_StrictGatePolicyModel):
    minimum: float = Field(ge=0.0, le=1.0)
    missingDecision: GatePolicyDecisionValue = "blocked"


class GatePolicyApprovalRequirementContract(_StrictGatePolicyModel):
    required: bool = False
    approvalTypes: list[Literal["accepted_risk", "gate_override", "other"]] = Field(
        default_factory=list,
        max_length=16,
    )
    policyRef: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_approval_reference(self) -> "GatePolicyApprovalRequirementContract":
        if self.required and not self.approvalTypes:
            raise ValueError("required approval must declare approvalTypes")
        if self.policyRef and not re.match(r"^[a-z][a-z0-9+.-]*://\S+$", self.policyRef):
            raise ValueError("policyRef must be a stable reference URI")
        return self


class GatePolicyRuleContract(_StrictGatePolicyModel):
    ruleId: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    priority: int = Field(ge=0, le=1_000_000)
    category: Literal["functional", "performance", "security", "completeness", "confidence", "evidence"]
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    metric: str | None = Field(default=None, min_length=1, max_length=160)
    operator: Literal["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "exists", "not_exists"]
    threshold: GatePolicyThreshold = None
    decision: GatePolicyDecisionValue
    reasonCode: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    evidenceRequirement: GatePolicyEvidenceRequirementContract | None = None
    confidenceRequirement: GatePolicyConfidenceRequirementContract | None = None
    approvalRequirement: GatePolicyApprovalRequirementContract | None = None

    @model_validator(mode="after")
    def validate_declarative_predicate(self) -> "GatePolicyRuleContract":
        if self.operator in {"exists", "not_exists"} and self.threshold is not None:
            raise ValueError("exists/not_exists rules must not define threshold")
        if self.operator not in {"exists", "not_exists"} and self.threshold is None:
            raise ValueError("comparison rules require threshold")
        if self.operator in {"in", "not_in"} and not isinstance(self.threshold, list):
            raise ValueError("in/not_in rules require an array threshold")
        if self.operator in {"gt", "gte", "lt", "lte"} and (
            not isinstance(self.threshold, (int, float)) or isinstance(self.threshold, bool)
        ):
            raise ValueError("ordered comparison rules require a numeric threshold")
        if isinstance(self.threshold, list) and not self.threshold:
            raise ValueError("array threshold must not be empty")
        if self.metric and self.category != "performance":
            raise ValueError("metric predicates belong to performance rules")
        if self.severity and self.category not in {"functional", "security"}:
            raise ValueError("severity predicates belong to functional or security rules")
        return self


class GatePolicyAggregationContract(_StrictGatePolicyModel):
    strategy: Literal["decision_order"] = "decision_order"
    decisionOrder: list[GatePolicyDecisionValue] = Field(min_length=4, max_length=4)
    defaultDecision: GatePolicyDecisionValue
    tieBreaker: Literal["highest_priority", "first_rule"] = "highest_priority"

    @model_validator(mode="after")
    def validate_decision_order(self) -> "GatePolicyAggregationContract":
        if len(set(self.decisionOrder)) != len(self.decisionOrder):
            raise ValueError("decisionOrder entries must be unique")
        if set(self.decisionOrder) != {"pass", "warn", "fail", "blocked"}:
            raise ValueError("decisionOrder must contain every Gate decision exactly once")
        return self


class GatePolicyCompletenessContract(_StrictGatePolicyModel):
    requireAllInputs: bool
    missingInputDecision: GatePolicyDecisionValue


class GatePolicyConfidenceContract(_StrictGatePolicyModel):
    minimum: float = Field(ge=0.0, le=1.0)
    belowThresholdDecision: GatePolicyDecisionValue


class GatePolicyEvidenceContract(_StrictGatePolicyModel):
    minimumCount: int = Field(ge=0, le=1000)
    requiredTypes: list[
        Literal["artifact", "finding", "metric", "trace", "replay", "approval"]
    ] = Field(default_factory=list, max_length=16)
    missingEvidenceDecision: GatePolicyDecisionValue


class GatePolicyContract(_StrictGatePolicyModel):
    schemaVersion: Literal["gate-policy.v1"]
    identity: GatePolicyIdentityContract
    version: GatePolicyVersionContract
    status: GatePolicyStatusValue
    scope: GatePolicyScopeContract
    requiredInputs: list[GatePolicyInputValue] = Field(min_length=1, max_length=4)
    rules: list[GatePolicyRuleContract] = Field(min_length=1, max_length=MAX_GATE_POLICY_RULES)
    aggregation: GatePolicyAggregationContract
    completeness: GatePolicyCompletenessContract
    confidence: GatePolicyConfidenceContract
    evidence: GatePolicyEvidenceContract
    metadata: dict[str, Any] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_policy_safety(self) -> "GatePolicyContract":
        if len(set(self.requiredInputs)) != len(self.requiredInputs):
            raise ValueError("requiredInputs entries must be unique")
        rule_ids = [rule.ruleId for rule in self.rules]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("ruleId must be unique within a Gate Policy version")

        payload = self.model_dump(mode="json")
        if _json_depth(payload) > MAX_GATE_POLICY_DEPTH:
            raise ValueError(f"Gate Policy exceeds maximum depth {MAX_GATE_POLICY_DEPTH}")
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_GATE_POLICY_BYTES:
            raise ValueError(f"Gate Policy exceeds maximum size {MAX_GATE_POLICY_BYTES} bytes")
        if _contains_forbidden_field(payload):
            raise ValueError("Gate Policy contains an executable, provider-specific, or secret-like field")
        if _contains_executable_text(payload):
            raise ValueError("Gate Policy contains executable text")
        return self


class GatePolicyResolutionRequestContract(_StrictGatePolicyModel):
    schemaVersion: Literal["phase8.gate-policy-resolution-request.v1"]
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: str | None = Field(min_length=1, max_length=255)
    environment: str | None = Field(min_length=1, max_length=255)
    stage: str | None = Field(min_length=1, max_length=255)
    domain: str | None = Field(min_length=1, max_length=255)
    evaluationTime: datetime

    @field_validator("evaluationTime")
    @classmethod
    def normalize_evaluation_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluationTime must include an explicit timezone")
        return value.astimezone(timezone.utc)


class GatePolicyResolvedScopeContract(_StrictGatePolicyModel):
    type: GatePolicyResolutionScopeValue
    scopeId: str | None = Field(max_length=255)

    @model_validator(mode="after")
    def validate_resolution_scope(self) -> "GatePolicyResolvedScopeContract":
        if self.type in {"global", "builtin_default"} and self.scopeId is not None:
            raise ValueError("global and builtin_default resolution scopes must not carry scopeId")
        if self.type not in {"global", "builtin_default"} and not self.scopeId:
            raise ValueError("scoped resolution requires scopeId")
        return self


class GatePolicyResolutionTraceEntryContract(_StrictGatePolicyModel):
    scope: GatePolicyResolutionScopeValue
    requestedScopeId: str | None = Field(max_length=255)
    outcome: Literal["selected", "skipped", "fallback", "error"]
    reason: GatePolicyFallbackReasonValue
    candidateCount: int = Field(ge=0, le=100_000)
    checkedBindingRefs: list[str] = Field(max_length=256)


class GatePolicyResolvedBindingSnapshotContract(_StrictGatePolicyModel):
    bindingId: str = Field(min_length=1, max_length=64)
    bindingRef: str = Field(pattern=r"^gate-policy-binding://\S+$", max_length=500)
    status: Literal["active"]
    scopeType: GatePolicyScopeValue
    scopeId: str | None = Field(max_length=255)
    effectiveFrom: datetime
    effectiveUntil: datetime | None
    policyId: str = Field(min_length=1, max_length=64)
    policyVersionId: str = Field(min_length=1, max_length=64)
    policyVersionHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("effectiveFrom", "effectiveUntil")
    @classmethod
    def normalize_effective_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("binding effective times must include an explicit timezone")
        return value.astimezone(timezone.utc)


class GatePolicyResolutionSnapshotContract(_StrictGatePolicyModel):
    schemaVersion: Literal["phase8.gate-policy-resolution-snapshot.v1"]
    request: GatePolicyResolutionRequestContract
    source: Literal["binding", "builtin_default", "simulation", "shadow"]
    policyId: str = Field(min_length=1, max_length=64)
    policyRef: str = Field(pattern=r"^(?:gate-policy|builtin-gate-policy)://\S+$", max_length=500)
    policyKey: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    policyVersionId: str = Field(min_length=1, max_length=64)
    policyVersionRef: str = Field(
        pattern=r"^(?:gate-policy-version|builtin-gate-policy-version)://\S+$",
        max_length=500,
    )
    policyVersionNumber: int = Field(ge=1, le=2_147_483_647)
    policySchemaVersion: Literal["gate-policy.v1"]
    policyVersionHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    binding: GatePolicyResolvedBindingSnapshotContract | None
    resolvedScope: GatePolicyResolvedScopeContract
    fallbackReason: GatePolicyFallbackReasonValue
    resolutionTrace: list[GatePolicyResolutionTraceEntryContract] = Field(min_length=1, max_length=8)
    policy: GatePolicyContract

    @model_validator(mode="after")
    def validate_frozen_identity(self) -> "GatePolicyResolutionSnapshotContract":
        if self.policy.identity.policyId != self.policyId:
            raise ValueError("resolved policy identity does not match frozen policy")
        if self.policy.identity.policyKey != self.policyKey:
            raise ValueError("resolved policy key does not match frozen policy")
        if self.policy.version.versionId != self.policyVersionId:
            raise ValueError("resolved version identity does not match frozen policy")
        if self.policy.version.versionNumber != self.policyVersionNumber:
            raise ValueError("resolved version number does not match frozen policy")
        if self.policy.scope.tenantId != self.request.tenantId:
            raise ValueError("frozen policy tenant does not match resolution request")
        if self.policy.scope.workspaceId != self.request.workspaceId:
            raise ValueError("frozen policy workspace does not match resolution request")
        if self.source == "binding" and self.binding is None:
            raise ValueError("binding resolution requires a frozen binding")
        if self.source in {"builtin_default", "simulation", "shadow"} and self.binding is not None:
            raise ValueError(f"{self.source} resolution must not carry a binding")
        if self.binding is not None:
            if self.binding.policyId != self.policyId:
                raise ValueError("binding policy identity does not match resolved policy")
            if self.binding.policyVersionId != self.policyVersionId:
                raise ValueError("binding version identity does not match resolved version")
            if self.binding.policyVersionHash != self.policyVersionHash:
                raise ValueError("binding hash does not match resolved version")
        return self


class GatePolicyResolutionResultContract(_StrictGatePolicyModel):
    schemaVersion: Literal["phase8.gate-policy-resolution-result.v1"]
    source: Literal["binding", "builtin_default"]
    resolvedPolicyId: str = Field(min_length=1, max_length=64)
    resolvedPolicyRef: str = Field(pattern=r"^(?:gate-policy|builtin-gate-policy)://\S+$", max_length=500)
    resolvedPolicyKey: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    resolvedPolicyVersionId: str = Field(min_length=1, max_length=64)
    resolvedPolicyVersionRef: str = Field(
        pattern=r"^(?:gate-policy-version|builtin-gate-policy-version)://\S+$",
        max_length=500,
    )
    resolvedPolicyVersionNumber: int = Field(ge=1, le=2_147_483_647)
    resolvedPolicyVersionHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    resolvedBindingId: str | None = Field(max_length=64)
    resolvedBindingRef: str | None = Field(
        pattern=r"^gate-policy-binding://\S+$",
        max_length=500,
    )
    resolvedScope: GatePolicyResolvedScopeContract
    fallbackReason: GatePolicyFallbackReasonValue
    resolutionTrace: list[GatePolicyResolutionTraceEntryContract] = Field(min_length=1, max_length=8)
    snapshot: GatePolicyResolutionSnapshotContract
    snapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    writesGateDecision: Literal[False]

    @model_validator(mode="after")
    def validate_result_matches_snapshot(self) -> "GatePolicyResolutionResultContract":
        snapshot = self.snapshot
        expected = (
            (self.source, snapshot.source, "source"),
            (self.resolvedPolicyId, snapshot.policyId, "policyId"),
            (self.resolvedPolicyRef, snapshot.policyRef, "policyRef"),
            (self.resolvedPolicyKey, snapshot.policyKey, "policyKey"),
            (self.resolvedPolicyVersionId, snapshot.policyVersionId, "policyVersionId"),
            (self.resolvedPolicyVersionRef, snapshot.policyVersionRef, "policyVersionRef"),
            (self.resolvedPolicyVersionNumber, snapshot.policyVersionNumber, "policyVersionNumber"),
            (self.resolvedPolicyVersionHash, snapshot.policyVersionHash, "policyVersionHash"),
            (self.resolvedScope, snapshot.resolvedScope, "resolvedScope"),
            (self.fallbackReason, snapshot.fallbackReason, "fallbackReason"),
            (self.resolutionTrace, snapshot.resolutionTrace, "resolutionTrace"),
        )
        for actual, frozen, field_name in expected:
            if actual != frozen:
                raise ValueError(f"resolution result {field_name} does not match snapshot")
        binding = snapshot.binding
        if self.resolvedBindingId != (binding.bindingId if binding else None):
            raise ValueError("resolution result bindingId does not match snapshot")
        if self.resolvedBindingRef != (binding.bindingRef if binding else None):
            raise ValueError("resolution result bindingRef does not match snapshot")
        if self.writesGateDecision is not False:
            raise ValueError("Gate Policy Resolver must not write a Gate decision")
        return self


_FORBIDDEN_FIELD_NAMES = {
    "apikey",
    "accesstoken",
    "accesstokenref",
    "command",
    "commands",
    "credential",
    "credentialref",
    "eval",
    "exec",
    "executable",
    "expression",
    "modelprovider",
    "password",
    "privatekey",
    "provider",
    "providerschema",
    "script",
    "scripts",
    "secret",
    "secretref",
    "shell",
    "sql",
    "token",
}
_SECRET_FIELD_MARKERS = ("secret", "password", "token", "credential", "apikey", "privatekey", "accesskey")
_EXECUTABLE_TEXT = re.compile(
    r"(?:^#!|\beval\s*\(|\bexec\s*\(|\bpowershell(?:\.exe)?\b|\b(?:ba|z|k)?sh\s+-c\b|\bselect\s+.+\s+from\b|\binsert\s+into\b|\bupdate\s+.+\s+set\b|\bdelete\s+from\b)",
    re.IGNORECASE | re.DOTALL,
)
_SECRET_VALUE_TEXT = re.compile(
    r"(?:-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bsk-[A-Za-z0-9_-]{20,}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@)",
    re.IGNORECASE,
)


def _normalized_field_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _contains_forbidden_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = _normalized_field_name(key)
            if normalized_key in _FORBIDDEN_FIELD_NAMES or any(
                marker in normalized_key for marker in _SECRET_FIELD_MARKERS
            ):
                return True
            if _contains_forbidden_field(child):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_field(child) for child in value)
    return False


def _contains_executable_text(value: Any) -> bool:
    if isinstance(value, str):
        return bool(_EXECUTABLE_TEXT.search(value) or _SECRET_VALUE_TEXT.search(value))
    if isinstance(value, dict):
        return any(_contains_executable_text(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_executable_text(child) for child in value)
    return False


def _json_depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_json_depth(child) for child in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_json_depth(child) for child in value), default=0)
    return 0


def validate_gate_policy_document(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a declarative Gate Policy without executing it."""

    return GatePolicyContract.model_validate(payload).model_dump(mode="json")

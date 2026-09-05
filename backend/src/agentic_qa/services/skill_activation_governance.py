# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import inspect
import json
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.domain.models import Skill, SkillVersion
from agentic_qa.runtime.qa_harness.context_builder import (
    canonical_content_hash,
    contains_unsafe_snapshot_material,
)
from agentic_qa.services.extension_point_contracts import (
    ExtensionPointContractError,
    ExtensionPointContractRegistry,
    SKILL_RESULT_REQUIRED_FIELDS,
)
from agentic_qa.services.skill_runtime import ManagedSkillRuntimeRegistry


SKILL_VERSION_GOVERNANCE_STATUSES = frozenset(
    {"draft", "active", "rejected", "deprecated", "archived"}
)
ACTIVATABLE_SKILL_VERSION_STATUSES = frozenset({"draft", "active"})
MANIFEST_REQUIRED_FIELDS = frozenset(
    {
        "skillId",
        "version",
        "capabilities",
        "inputSchema",
        "outputSchema",
        "allowedTools",
        "allowedConnectors",
        "riskProfile",
        "approvalPolicy",
        "dataAccessPolicy",
        "replayPolicy",
        "extensionPoints",
        "compatibility",
    }
)


class _StrictGovernanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SkillActivationCheck(_StrictGovernanceModel):
    name: str = Field(min_length=1, max_length=120)
    status: Literal["passed", "failed", "warning"]
    reasonCode: str | None = Field(default=None, max_length=160)
    evidence: dict[str, Any] = Field(default_factory=dict)


class SkillActivationValidationReport(_StrictGovernanceModel):
    schemaVersion: Literal["phase8.skill-activation-validation.v1"] = (
        "phase8.skill-activation-validation.v1"
    )
    validationId: UUID
    bindingId: UUID | None = None
    skillVersionId: UUID
    extensionPointId: str
    passed: bool
    checks: list[SkillActivationCheck]
    failures: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    evaluatedManifestHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evaluatedAt: datetime
    scope: dict[str, Any]
    limitations: list[str] = Field(default_factory=list)
    reportHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_report(self) -> "SkillActivationValidationReport":
        payload = self.model_dump(mode="json", exclude={"reportHash"})
        if contains_unsafe_snapshot_material(payload):
            raise ValueError("SKILL_ACTIVATION_VALIDATION_SECRET_SCAN_BLOCKED")
        if self.reportHash != canonical_content_hash(payload):
            raise ValueError("SKILL_ACTIVATION_VALIDATION_HASH_MISMATCH")
        if self.passed != (not self.failures):
            raise ValueError("SKILL_ACTIVATION_VALIDATION_STATUS_MISMATCH")
        return self


class SkillShadowComparisonReport(_StrictGovernanceModel):
    schemaVersion: Literal["phase8.skill-binding-shadow.v1"] = (
        "phase8.skill-binding-shadow.v1"
    )
    shadowId: UUID
    bindingId: UUID
    extensionPointId: str
    nonAuthoritative: Literal[True] = True
    status: Literal["completed", "partial", "failed", "unavailable", "blocked"]
    activationEligible: bool
    baselineSkillVersionId: UUID
    baselineManifestHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    candidateSkillVersionId: UUID
    candidateManifestHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    adapter: dict[str, Any]
    sampleCount: int = Field(ge=0)
    minimumRequiredSamples: int = Field(ge=1)
    authoritativeInvocationRefs: list[str] = Field(default_factory=list)
    candidateInvocationRefs: list[str] = Field(default_factory=list)
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    failureReasons: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    scope: dict[str, Any]
    evaluatedAt: datetime
    reportHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_report(self) -> "SkillShadowComparisonReport":
        payload = self.model_dump(mode="json", exclude={"reportHash"})
        if contains_unsafe_snapshot_material(payload):
            raise ValueError("SKILL_SHADOW_SECRET_SCAN_BLOCKED")
        if self.reportHash != canonical_content_hash(payload):
            raise ValueError("SKILL_SHADOW_HASH_MISMATCH")
        if self.activationEligible and self.status != "completed":
            raise ValueError("SKILL_SHADOW_ELIGIBILITY_STATUS_INVALID")
        return self


def manifest_snapshot_hash(snapshot: dict[str, object]) -> str:
    encoded = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class SkillVersionActivationValidator:
    """Service-side preflight for a version that may affect Binding resolution."""

    def __init__(
        self,
        *,
        runtime_registry: ManagedSkillRuntimeRegistry,
        extension_point_contracts: ExtensionPointContractRegistry,
    ) -> None:
        self.runtime_registry = runtime_registry
        self.extension_point_contracts = extension_point_contracts

    def validate(
        self,
        *,
        skill: Skill,
        version: SkillVersion,
        extension_point_id: str,
        scope: dict[str, object],
        binding_id: UUID | None,
        required_capability_satisfied: bool,
        scope_authorized: bool,
        authorized_context_available: bool,
        runtime_contract: dict[str, str | None],
    ) -> SkillActivationValidationReport:
        checks: list[SkillActivationCheck] = []

        def record(
            name: str,
            passed: bool,
            reason_code: str,
            evidence: dict[str, object] | None = None,
            *,
            warning: bool = False,
        ) -> None:
            status: Literal["passed", "failed", "warning"] = (
                "warning" if warning else "passed" if passed else "failed"
            )
            checks.append(
                SkillActivationCheck(
                    name=name,
                    status=status,
                    reasonCode=None if passed and not warning else reason_code,
                    evidence=evidence or {},
                )
            )

        snapshot = version.manifest_snapshot if isinstance(version.manifest_snapshot, dict) else {}
        missing_fields = sorted(MANIFEST_REQUIRED_FIELDS - set(snapshot))
        record(
            "manifest.required_fields",
            not missing_fields,
            "SKILL_ACTIVATION_MANIFEST_INCOMPLETE",
            {"missingFields": missing_fields},
        )
        calculated_hash = manifest_snapshot_hash(snapshot)
        record(
            "manifest.hash",
            calculated_hash == version.manifest_hash,
            "SKILL_ACTIVATION_MANIFEST_HASH_CONFLICT",
            {"calculatedHash": calculated_hash, "storedHash": version.manifest_hash},
        )
        legal_status = version.governance_status in SKILL_VERSION_GOVERNANCE_STATUSES
        record(
            "governance.status_legal",
            legal_status,
            "SKILL_ACTIVATION_GOVERNANCE_STATUS_INVALID",
            {"governanceStatus": version.governance_status},
        )
        record(
            "governance.status_activatable",
            legal_status and version.governance_status in ACTIVATABLE_SKILL_VERSION_STATUSES,
            "SKILL_ACTIVATION_VERSION_NOT_ACTIVATABLE",
            {"governanceStatus": version.governance_status},
        )
        record(
            "manifest.skill_identity",
            snapshot.get("skillId") == skill.skill_id
            and snapshot.get("version") == version.version,
            "SKILL_ACTIVATION_MANIFEST_IDENTITY_MISMATCH",
            {"skillId": skill.skill_id, "version": version.version},
        )

        contract = None
        try:
            contract = self.extension_point_contracts.require_bindable(extension_point_id)
        except ExtensionPointContractError as exc:
            record(
                "extension_point.bindable",
                False,
                "SKILL_ACTIVATION_EXTENSION_POINT_NOT_BINDABLE",
                {"error": str(exc)},
            )
        else:
            record(
                "extension_point.bindable",
                True,
                "SKILL_ACTIVATION_EXTENSION_POINT_NOT_BINDABLE",
                {"extensionPointId": extension_point_id},
            )

        extension_compatible = extension_point_id in set(version.extension_points or [])
        record(
            "extension_point.compatibility",
            extension_compatible,
            "SKILL_ACTIVATION_EXTENSION_POINT_INCOMPATIBLE",
            {"declaredExtensionPoints": sorted(version.extension_points or [])},
        )
        contract_compatible = False
        contract_error: str | None = None
        if contract is not None and extension_compatible:
            try:
                self.extension_point_contracts.validate_version_contract(
                    extension_point_id,
                    input_schema=version.input_schema,
                    output_schema=version.output_schema,
                    compatibility=version.compatibility,
                )
            except (ExtensionPointContractError, ValueError) as exc:
                contract_error = str(exc)
            else:
                contract_compatible = True
        record(
            "schema.input_compatibility",
            contract_compatible,
            "SKILL_ACTIVATION_INPUT_SCHEMA_INCOMPATIBLE",
            {"error": contract_error},
        )
        output_schema = version.output_schema if isinstance(version.output_schema, dict) else {}
        output_compatible = contract_compatible and SKILL_RESULT_REQUIRED_FIELDS.issubset(
            output_schema
        )
        record(
            "schema.output_and_skill_result",
            output_compatible,
            "SKILL_ACTIVATION_OUTPUT_SCHEMA_INCOMPATIBLE",
            {
                "requiredSkillResultFields": sorted(SKILL_RESULT_REQUIRED_FIELDS),
                "declaredFields": sorted(output_schema),
            },
        )

        adapter = None
        adapter_error: str | None = None
        try:
            adapter = self.runtime_registry.validate(
                adapter_id=runtime_contract.get("runtimeAdapter"),
                result_kind=runtime_contract.get("runtimeResultKind"),
                extension_point_id=extension_point_id,
            )
        except ValueError as exc:
            adapter_error = str(exc)
        record(
            "runtime.adapter_registered",
            adapter is not None,
            "SKILL_ACTIVATION_RUNTIME_ADAPTER_UNREGISTERED",
            {"runtimeAdapter": runtime_contract.get("runtimeAdapter"), "error": adapter_error},
        )
        result_kind_compatible = bool(
            contract
            and runtime_contract.get("runtimeResultKind")
            in contract.allowed_runtime_result_kinds
        )
        record(
            "runtime.result_kind",
            result_kind_compatible,
            "SKILL_ACTIVATION_RUNTIME_RESULT_KIND_INCOMPATIBLE",
            {"runtimeResultKind": runtime_contract.get("runtimeResultKind")},
        )
        adapter_parameters: list[str] = []
        adapter_boundary_safe = False
        if adapter is not None:
            try:
                parameters = inspect.signature(adapter.handler).parameters
                adapter_parameters = list(parameters)
                adapter_boundary_safe = len(parameters) == 3 and not {
                    "db",
                    "database",
                    "session",
                    "db_session",
                }.intersection(name.lower() for name in parameters)
            except (TypeError, ValueError):
                adapter_boundary_safe = False
        record(
            "runtime.adapter_db_session_boundary",
            adapter_boundary_safe,
            "SKILL_ACTIVATION_ADAPTER_DB_SESSION_FORBIDDEN",
            {"handlerParameters": adapter_parameters},
        )
        execution_boundary_safe = (
            extension_point_id != "EXECUTE.automated_execution"
            or (
                runtime_contract.get("runtimeResultKind") == "runner_result"
                and adapter is not None
                and adapter.extension_points is not None
                and extension_point_id in adapter.extension_points
            )
        )
        record(
            "runtime.execution_runner_boundary",
            execution_boundary_safe,
            "SKILL_ACTIVATION_EXECUTION_RUNNER_BOUNDARY_BYPASS",
            {"extensionPointId": extension_point_id},
        )

        record(
            "authorization.required_capability",
            required_capability_satisfied,
            "SKILL_ACTIVATION_CAPABILITY_REQUIRED",
            {"requiredCapability": contract.required_capability if contract else None},
        )
        record(
            "authorization.scope",
            scope_authorized,
            "SKILL_ACTIVATION_SCOPE_DENIED",
            {"scopeHash": canonical_content_hash(scope)},
        )
        record(
            "authorization.context_requirements",
            authorized_context_available,
            "SKILL_ACTIVATION_CONTEXT_UNAVAILABLE",
            {"requiredAvailable": authorized_context_available},
        )

        capabilities = version.capabilities if isinstance(version.capabilities, dict) else {}
        record(
            "manifest.required_capabilities",
            bool(capabilities),
            "SKILL_ACTIVATION_CAPABILITIES_INVALID",
            {"declared": bool(capabilities)},
        )
        allowed_tools_valid = isinstance(version.allowed_tools, list) and all(
            isinstance(item, str) and bool(item.strip()) for item in version.allowed_tools
        )
        record(
            "manifest.allowed_tools",
            allowed_tools_valid,
            "SKILL_ACTIVATION_ALLOWED_TOOLS_INVALID",
            {"count": len(version.allowed_tools or [])},
        )
        allowed_connectors_valid = isinstance(version.allowed_connectors, list) and all(
            isinstance(item, str) and bool(item.strip())
            for item in version.allowed_connectors
        )
        record(
            "manifest.allowed_connectors",
            allowed_connectors_valid,
            "SKILL_ACTIVATION_ALLOWED_CONNECTORS_INVALID",
            {"count": len(version.allowed_connectors or [])},
        )
        data_policy = (
            version.data_access_policy
            if isinstance(version.data_access_policy, dict)
            else {}
        )
        data_policy_valid = bool(data_policy) and not any(
            bool(data_policy.get(key))
            for key in ("writeDb", "writeMemory", "writeGate")
        )
        record(
            "manifest.data_access_policy",
            data_policy_valid,
            "SKILL_ACTIVATION_DATA_ACCESS_POLICY_INVALID",
            {"writePrivilegesDenied": data_policy_valid},
        )
        replay_policy = (
            version.replay_policy if isinstance(version.replay_policy, dict) else {}
        )
        replay_policy_valid = bool(replay_policy.get("freezeManifest")) and bool(
            replay_policy.get("freezeInputOutput")
        )
        record(
            "manifest.replay_policy",
            replay_policy_valid,
            "SKILL_ACTIVATION_REPLAY_POLICY_INVALID",
            {
                "freezeManifest": bool(replay_policy.get("freezeManifest")),
                "freezeInputOutput": bool(replay_policy.get("freezeInputOutput")),
            },
        )
        risk_profile = (
            version.risk_profile if isinstance(version.risk_profile, dict) else {}
        )
        risk_level = str(risk_profile.get("level") or "").lower()
        risk_valid = risk_level in {"low", "medium", "high"}
        record(
            "manifest.risk_profile",
            risk_valid,
            "SKILL_ACTIVATION_RISK_PROFILE_INVALID",
            {"riskLevel": risk_level},
        )
        approval_policy = (
            version.approval_policy
            if isinstance(version.approval_policy, dict)
            else {}
        )
        approval_policy_valid = "required" in approval_policy and isinstance(
            approval_policy.get("required"), bool
        )
        record(
            "manifest.approval_policy",
            approval_policy_valid,
            "SKILL_ACTIVATION_APPROVAL_POLICY_INVALID",
            {"manifestRequired": approval_policy.get("required")},
        )
        if risk_level in {"medium", "high"} and not bool(
            approval_policy.get("required")
        ):
            record(
                "manifest.approval_policy_platform_override",
                True,
                "SKILL_ACTIVATION_PLATFORM_APPROVAL_OVERRIDE",
                {"riskLevel": risk_level, "platformRequiresApproval": True},
                warning=True,
            )

        failures = [
            str(item.reasonCode)
            for item in checks
            if item.status == "failed" and item.reasonCode
        ]
        warnings = [
            str(item.reasonCode)
            for item in checks
            if item.status == "warning" and item.reasonCode
        ]
        evaluated_at = datetime.now(timezone.utc)
        report_payload: dict[str, Any] = {
            "schemaVersion": "phase8.skill-activation-validation.v1",
            "validationId": uuid4(),
            "bindingId": binding_id,
            "skillVersionId": version.id,
            "extensionPointId": extension_point_id,
            "passed": not failures,
            "checks": checks,
            "failures": failures,
            "warnings": warnings,
            "evidenceRefs": [],
            "evaluatedManifestHash": calculated_hash,
            "evaluatedAt": evaluated_at,
            "scope": scope,
            "limitations": [],
        }
        draft = SkillActivationValidationReport.model_construct(
            **report_payload,
            reportHash="sha256:" + "0" * 64,
        )
        report_payload["reportHash"] = canonical_content_hash(
            draft.model_dump(mode="json", exclude={"reportHash"})
        )
        return SkillActivationValidationReport.model_validate(report_payload)


__all__ = [
    "ACTIVATABLE_SKILL_VERSION_STATUSES",
    "MANIFEST_REQUIRED_FIELDS",
    "SKILL_VERSION_GOVERNANCE_STATUSES",
    "SkillActivationCheck",
    "SkillActivationValidationReport",
    "SkillShadowComparisonReport",
    "SkillVersionActivationValidator",
    "manifest_snapshot_hash",
]

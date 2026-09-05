# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, model_validator

from agentic_qa.runtime.qa_harness.context_builder import canonical_content_hash
from agentic_qa.runtime.qa_harness.extension_descriptors import (
    ExtensionCompatibilityChecker,
    ExtensionCompatibilityRequirement,
    ExtensionCompatibilityResult,
    ExtensionDescriptor,
    ExtensionKind,
)


class _StrictProfileModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class QaProfileBudgetDefaults(_StrictProfileModel):
    maxTurns: int = Field(ge=1, le=100)
    maxModelCalls: int = Field(ge=0, le=100)
    maxSkillInvocations: int = Field(ge=0, le=100)
    maxToolCalls: int = Field(ge=0, le=1000)
    timeoutSeconds: float = Field(gt=0.0, le=3600.0)


class QaProfileRequirement(ExtensionCompatibilityRequirement):
    extensionPointId: str | None = Field(default=None, max_length=160)
    modelRole: str | None = Field(default=None, max_length=80)
    domain: str | None = Field(default=None, max_length=80)
    operation: str | None = Field(default=None, max_length=120)


class QaProfile(_StrictProfileModel):
    profileId: str = Field(min_length=1, max_length=160)
    version: str = Field(min_length=1, max_length=80)
    profileHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    supportedDomains: list[str] = Field(min_length=1, max_length=20)
    extensionPointRequirements: list[QaProfileRequirement] = Field(
        default_factory=list, max_length=50
    )
    modelRoleRequirements: list[QaProfileRequirement] = Field(
        default_factory=list, max_length=20
    )
    runnerRequirements: list[QaProfileRequirement] = Field(
        default_factory=list, max_length=50
    )
    connectorRequirements: list[QaProfileRequirement] = Field(
        default_factory=list, max_length=50
    )
    sandboxProfile: QaProfileRequirement
    storageRequirements: list[QaProfileRequirement] = Field(
        default_factory=list, max_length=20
    )
    evaluationSuite: list[QaProfileRequirement] = Field(
        default_factory=list, max_length=50
    )
    budgetDefaults: QaProfileBudgetDefaults
    stopConditions: list[str] = Field(default_factory=list, max_length=50)
    riskPolicyRefs: list[str] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_profile_contract(self, info: ValidationInfo) -> "QaProfile":
        requirements = self.all_requirements()
        requirement_ids = [item.requirementId for item in requirements]
        if len(set(requirement_ids)) != len(requirement_ids):
            raise ValueError("QA Profile requirementId values must be unique")
        for item in self.extensionPointRequirements:
            if item.kind != ExtensionKind.SKILL or not item.extensionPointId:
                raise ValueError("extensionPointRequirements require Skill kind and extensionPointId")
            if item.extensionId is not None:
                raise ValueError("QA Profile must not select a concrete Skill identity")
        for item in self.modelRoleRequirements:
            if item.kind != ExtensionKind.MODEL_ADAPTER or not item.modelRole:
                raise ValueError("modelRoleRequirements require model_adapter kind and modelRole")
        if self.sandboxProfile.kind != ExtensionKind.SANDBOX_ADAPTER:
            raise ValueError("sandboxProfile must reference a sandbox_adapter")
        if any(item.kind != ExtensionKind.TOOL_ADAPTER for item in self.runnerRequirements):
            raise ValueError("runnerRequirements must use tool_adapter kind")
        if any(item.kind != ExtensionKind.CONNECTOR for item in self.connectorRequirements):
            raise ValueError("connectorRequirements must use connector kind")
        if any(item.kind != ExtensionKind.STORAGE_ADAPTER for item in self.storageRequirements):
            raise ValueError("storageRequirements must use storage_adapter kind")
        if any(item.kind != ExtensionKind.EVALUATOR for item in self.evaluationSuite):
            raise ValueError("evaluationSuite must use evaluator kind")
        if _contains_control_override(self.metadata):
            raise ValueError("QA Profile metadata cannot override control authorities")
        expected_hash = qa_profile_hash(self.model_dump(mode="json", exclude={"profileHash"}))
        if not (info.context or {}).get("skip_profile_hash") and self.profileHash != expected_hash:
            raise ValueError("QA Profile hash mismatch")
        return self

    def all_requirements(self) -> list[QaProfileRequirement]:
        return [
            *self.extensionPointRequirements,
            *self.modelRoleRequirements,
            *self.runnerRequirements,
            *self.connectorRequirements,
            self.sandboxProfile,
            *self.storageRequirements,
            *self.evaluationSuite,
        ]


class QaProfileExtensionSelection(_StrictProfileModel):
    requirementId: str = Field(min_length=1, max_length=255)
    extensionId: str = Field(min_length=1, max_length=255)
    extensionRef: str = Field(min_length=1, max_length=1000)
    bindingRef: str | None = Field(default=None, max_length=1000)
    fallbackReason: str | None = Field(default=None, max_length=255)
    authorityScope: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class QaProfileResolvedExtension(_StrictProfileModel):
    requirementId: str
    requestedKind: ExtensionKind
    requestedExtensionPointId: str | None
    requestedModelRole: str | None
    requestedExtensionId: str | None
    resolvedExtensionId: str | None
    resolvedExtensionRef: str | None
    bindingRef: str | None
    fallbackReason: str | None
    compatibility: ExtensionCompatibilityResult


class QaProfileResolutionSnapshot(_StrictProfileModel):
    schemaVersion: Literal["qa-profile-resolution.v1"] = "qa-profile-resolution.v1"
    profileId: str
    profileVersion: str
    profileHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    resolutionStatus: Literal["resolved", "degraded", "unavailable"]
    scope: dict[str, Any]
    requestedExtensions: list[dict[str, Any]]
    resolutions: list[QaProfileResolvedExtension]
    resolvedSkillRefs: list[str]
    resolvedModelRefs: list[str]
    resolvedRunnerRefs: list[str]
    resolvedConnectorRefs: list[str]
    resolvedSandboxRefs: list[str]
    resolvedStorageRefs: list[str]
    resolvedEvaluatorRefs: list[str]
    bindingRefs: list[str]
    fallbackReasons: list[dict[str, str]]
    compatibilityResults: list[dict[str, Any]]
    warnings: list[str]
    limitations: list[str]
    controlBoundary: dict[str, bool]
    resolutionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_resolution_hash(self) -> "QaProfileResolutionSnapshot":
        expected = canonical_content_hash(
            self.model_dump(mode="json", exclude={"resolutionHash"})
        )
        if self.resolutionHash != expected:
            raise ValueError("QA Profile resolution hash mismatch")
        return self


class QaProfileResolver:
    """Resolves expected capabilities only; it never invokes an extension."""

    def __init__(self, checker: ExtensionCompatibilityChecker | None = None) -> None:
        self.checker = checker or ExtensionCompatibilityChecker()

    def resolve(
        self,
        profile: QaProfile,
        *,
        scope: Mapping[str, Any],
        catalog: Mapping[str, ExtensionDescriptor],
        selections: Mapping[str, QaProfileExtensionSelection],
        requested_domains: list[str] | None = None,
    ) -> QaProfileResolutionSnapshot:
        normalized_scope = _normalized_scope(scope)
        limitations: list[str] = []
        warnings: list[str] = []
        unsupported_domains = sorted(
            set(requested_domains or []) - set(profile.supportedDomains)
        )
        if unsupported_domains:
            limitations.append(
                "PROFILE_DOMAIN_UNSUPPORTED:" + ",".join(unsupported_domains)
            )

        resolved: list[QaProfileResolvedExtension] = []
        for requirement in profile.all_requirements():
            selection = selections.get(requirement.requirementId)
            scope_error = _selection_scope_error(normalized_scope, selection)
            descriptor = (
                catalog.get(selection.extensionId)
                if selection is not None and scope_error is None
                else None
            )
            compatibility = self.checker.check(
                requirement,
                descriptor,
                catalog=catalog,
            )
            if scope_error:
                compatibility = ExtensionCompatibilityResult(
                    compatible=False,
                    reasonCodes=[
                        *compatibility.reasonCodes,
                        scope_error,
                    ],
                    resolvedDependencies=compatibility.resolvedDependencies,
                    unavailableDependencies=compatibility.unavailableDependencies,
                    warnings=compatibility.warnings,
                )
            warnings.extend(compatibility.warnings)
            if not compatibility.compatible and requirement.required:
                limitations.extend(compatibility.reasonCodes)
            resolved.append(
                QaProfileResolvedExtension(
                    requirementId=requirement.requirementId,
                    requestedKind=requirement.kind,
                    requestedExtensionPointId=requirement.extensionPointId,
                    requestedModelRole=requirement.modelRole,
                    requestedExtensionId=requirement.extensionId,
                    resolvedExtensionId=descriptor.extensionId if descriptor else None,
                    resolvedExtensionRef=selection.extensionRef if selection else None,
                    bindingRef=selection.bindingRef if selection else None,
                    fallbackReason=selection.fallbackReason if selection else None,
                    compatibility=compatibility,
                )
            )

        required_incompatible = any(
            not item.compatibility.compatible
            and next(
                requirement.required
                for requirement in profile.all_requirements()
                if requirement.requirementId == item.requirementId
            )
            for item in resolved
        )
        resolution_status: Literal["resolved", "degraded", "unavailable"]
        if unsupported_domains or required_incompatible:
            resolution_status = "unavailable"
        elif warnings or any(not item.compatibility.compatible for item in resolved):
            resolution_status = "degraded"
        else:
            resolution_status = "resolved"

        def refs(kind: ExtensionKind) -> list[str]:
            return _unique(
                [
                    str(item.resolvedExtensionRef)
                    for item in resolved
                    if item.requestedKind == kind and item.resolvedExtensionRef
                ]
            )

        payload: dict[str, Any] = {
            "schemaVersion": "qa-profile-resolution.v1",
            "profileId": profile.profileId,
            "profileVersion": profile.version,
            "profileHash": profile.profileHash,
            "resolutionStatus": resolution_status,
            "scope": normalized_scope,
            "requestedExtensions": [
                item.model_dump(mode="json") for item in profile.all_requirements()
            ],
            "resolutions": [item.model_dump(mode="json") for item in resolved],
            "resolvedSkillRefs": refs(ExtensionKind.SKILL),
            "resolvedModelRefs": refs(ExtensionKind.MODEL_ADAPTER),
            "resolvedRunnerRefs": refs(ExtensionKind.TOOL_ADAPTER),
            "resolvedConnectorRefs": refs(ExtensionKind.CONNECTOR),
            "resolvedSandboxRefs": refs(ExtensionKind.SANDBOX_ADAPTER),
            "resolvedStorageRefs": refs(ExtensionKind.STORAGE_ADAPTER),
            "resolvedEvaluatorRefs": refs(ExtensionKind.EVALUATOR),
            "bindingRefs": _unique(
                [str(item.bindingRef) for item in resolved if item.bindingRef]
            ),
            "fallbackReasons": [
                {
                    "requirementId": item.requirementId,
                    "reason": str(item.fallbackReason),
                }
                for item in resolved
                if item.fallbackReason
            ],
            "compatibilityResults": [
                {
                    "requirementId": item.requirementId,
                    **item.compatibility.model_dump(mode="json"),
                }
                for item in resolved
            ],
            "warnings": _unique(warnings),
            "limitations": _unique(limitations),
            "controlBoundary": {
                "overridesAuth": False,
                "overridesScope": False,
                "overridesLicense": False,
                "overridesCapability": False,
                "overridesApproval": False,
                "overridesGuardrail": False,
                "overridesKillSwitch": False,
                "executesSkill": False,
                "selectsProvider": False,
            },
        }
        payload["resolutionHash"] = canonical_content_hash(payload)
        return QaProfileResolutionSnapshot.model_validate(payload)


class BuiltinQaProfileCatalog:
    def __init__(self) -> None:
        self._profiles = {
            profile.profileId: profile
            for profile in (
                _web_regression_profile(),
                _api_testing_profile(),
                _security_review_profile(),
                _pr_admission_profile(),
            )
        }

    def get(self, profile_id: str) -> QaProfile:
        try:
            return self._profiles[profile_id]
        except KeyError as exc:
            raise ValueError(f"QA Profile not found: {profile_id}") from exc

    def list_profiles(self) -> list[QaProfile]:
        return [self._profiles[key] for key in sorted(self._profiles)]


def build_qa_profile(payload: Mapping[str, Any]) -> QaProfile:
    normalized = dict(payload)
    normalized.pop("profileHash", None)
    provisional = QaProfile.model_validate(
        {**normalized, "profileHash": "sha256:" + "0" * 64},
        context={"skip_profile_hash": True},
    )
    canonical_payload = provisional.model_dump(mode="json", exclude={"profileHash"})
    return QaProfile.model_validate(
        {**canonical_payload, "profileHash": qa_profile_hash(canonical_payload)}
    )


def qa_profile_hash(payload: Mapping[str, Any]) -> str:
    return canonical_content_hash(dict(payload))


def _web_regression_profile() -> QaProfile:
    return build_qa_profile(
        {
            "profileId": "web-regression",
            "version": "1.0.0",
            "supportedDomains": ["functional", "performance", "security"],
            "extensionPointRequirements": [
                _skill_requirement("prepare-test-plan", "PREPARE.test_plan"),
                _skill_requirement("prepare-test-case", "PREPARE.test_case"),
            ],
            "modelRoleRequirements": [_model_requirement("primary-json", "PRIMARY")],
            "runnerRequirements": [
                _requirement(
                    "web-runner",
                    ExtensionKind.TOOL_ADAPTER,
                    extension_id="playwright",
                    domain="functional",
                    required=False,
                    required_capabilities=["domain"],
                )
            ],
            "connectorRequirements": [],
            "sandboxProfile": _sandbox_requirement(required=False),
            "storageRequirements": [_storage_requirement("artifact-storage.local")],
            "evaluationSuite": [_evaluation_requirement("coverage-review.v1")],
            "budgetDefaults": {
                "maxTurns": 4,
                "maxModelCalls": 3,
                "maxSkillInvocations": 3,
                "maxToolCalls": 0,
                "timeoutSeconds": 120,
            },
            "stopConditions": ["require_evidence", "coverage_review"],
            "riskPolicyRefs": ["guardrail://runtime", "approval://existing-policy"],
            "metadata": {
                "internalOnly": True,
                "publicConfigurable": False,
                "purpose": "bounded requirement-to-plan-to-test-case regression generation",
            },
        }
    )


def _api_testing_profile() -> QaProfile:
    return build_qa_profile(
        {
            "profileId": "api-testing",
            "version": "1.0.0",
            "supportedDomains": ["functional", "performance", "security"],
            "extensionPointRequirements": [
                _skill_requirement("api-test-plan", "PREPARE.test_plan"),
                _skill_requirement("api-test-cases", "PREPARE.test_case"),
                _skill_requirement("api-execution", "EXECUTE.automated_execution"),
            ],
            "modelRoleRequirements": [_model_requirement("api-primary-json", "PRIMARY")],
            "runnerRequirements": [
                _requirement(
                    "api-runner",
                    ExtensionKind.TOOL_ADAPTER,
                    extension_id="sandbox-python-unittest",
                    domain="functional",
                )
            ],
            "connectorRequirements": [
                _requirement(
                    "api-context-connector",
                    ExtensionKind.CONNECTOR,
                    extension_id="mcp",
                    required=False,
                )
            ],
            "sandboxProfile": _sandbox_requirement(),
            "storageRequirements": [_storage_requirement("artifact-storage.local")],
            "evaluationSuite": [_evaluation_requirement("api-contract-evaluation.v1")],
            "budgetDefaults": {
                "maxTurns": 8,
                "maxModelCalls": 4,
                "maxSkillInvocations": 5,
                "maxToolCalls": 4,
                "timeoutSeconds": 300,
            },
            "stopConditions": ["require_evidence", "contract_complete", "budget_exhausted"],
            "riskPolicyRefs": ["guardrail://runtime", "sandbox://default-deny"],
            "metadata": {"internalOnly": True, "publicConfigurable": False},
        }
    )


def _security_review_profile() -> QaProfile:
    return build_qa_profile(
        {
            "profileId": "security-review",
            "version": "1.0.0",
            "supportedDomains": ["security"],
            "extensionPointRequirements": [
                _skill_requirement("security-scope", "PREPARE.regression_scope"),
                _skill_requirement("security-execution", "EXECUTE.automated_execution"),
                _skill_requirement("security-analysis", "ANALYZE.security_analysis"),
            ],
            "modelRoleRequirements": [_model_requirement("security-primary-json", "PRIMARY")],
            "runnerRequirements": [
                _requirement(
                    "security-sast-runner",
                    ExtensionKind.TOOL_ADAPTER,
                    extension_id="sandbox-semgrep",
                    domain="security",
                ),
                _requirement(
                    "security-dast-runner",
                    ExtensionKind.TOOL_ADAPTER,
                    extension_id="zap",
                    domain="security",
                    required=False,
                ),
            ],
            "connectorRequirements": [],
            "sandboxProfile": _sandbox_requirement(),
            "storageRequirements": [_storage_requirement("artifact-storage.local")],
            "evaluationSuite": [_evaluation_requirement("security-evidence-evaluation.v1")],
            "budgetDefaults": {
                "maxTurns": 8,
                "maxModelCalls": 4,
                "maxSkillInvocations": 6,
                "maxToolCalls": 6,
                "timeoutSeconds": 600,
            },
            "stopConditions": ["require_evidence", "normalize_required", "budget_exhausted"],
            "riskPolicyRefs": ["guardrail://security", "approval://existing-policy"],
            "metadata": {"internalOnly": True, "publicConfigurable": False},
        }
    )


def _pr_admission_profile() -> QaProfile:
    return build_qa_profile(
        {
            "profileId": "pr-admission",
            "version": "1.0.0",
            "supportedDomains": ["functional", "performance", "security"],
            "extensionPointRequirements": [
                _skill_requirement("admission-scope", "PREPARE.regression_scope"),
                _skill_requirement("admission-execution", "EXECUTE.automated_execution"),
                _skill_requirement("admission-triage", "ANALYZE.finding_triage"),
            ],
            "modelRoleRequirements": [_model_requirement("admission-primary-json", "PRIMARY")],
            "runnerRequirements": [
                _requirement(
                    "admission-scan-runner",
                    ExtensionKind.TOOL_ADAPTER,
                    extension_id="sandbox-semgrep",
                    domain="security",
                )
            ],
            "connectorRequirements": [
                _requirement(
                    "admission-scm-read",
                    ExtensionKind.CONNECTOR,
                    extension_id="github",
                    operation="read_pr",
                    required_capabilities=["operations.fetch_pull_request"],
                )
            ],
            "sandboxProfile": _sandbox_requirement(),
            "storageRequirements": [
                _storage_requirement("artifact-storage.local"),
                _storage_requirement("replay-storage.local"),
            ],
            "evaluationSuite": [_evaluation_requirement("admission-shadow-evaluation.v1")],
            "budgetDefaults": {
                "maxTurns": 10,
                "maxModelCalls": 5,
                "maxSkillInvocations": 8,
                "maxToolCalls": 8,
                "timeoutSeconds": 900,
            },
            "stopConditions": ["require_evidence", "current_head_required", "budget_exhausted"],
            "riskPolicyRefs": ["guardrail://admission", "approval://existing-policy"],
            "metadata": {"internalOnly": True, "publicConfigurable": False},
        }
    )


def _skill_requirement(requirement_id: str, extension_point_id: str) -> dict[str, Any]:
    return {
        "requirementId": requirement_id,
        "kind": ExtensionKind.SKILL.value,
        "extensionPointId": extension_point_id,
        "inputSchemaRef": "skill-request.v1",
        "outputSchemaRef": "skill-result.v1",
        "requiredScopeSupport": ["project"],
        "dataAccessPolicy": {"writeDb": False, "writeMemory": False, "writeGate": False},
        "replayPolicy": {"freezeInputOutput": True},
    }


def _model_requirement(requirement_id: str, role: str) -> dict[str, Any]:
    return {
        "requirementId": requirement_id,
        "kind": ExtensionKind.MODEL_ADAPTER.value,
        "extensionId": f"model-gateway.role.{role}",
        "modelRole": role,
        "inputSchemaRef": "model-gateway-structured-request.v1",
        "outputSchemaRef": "agent-output.v1",
        "requiredCapabilities": ["json"],
        "acceptedHealthStatus": ["healthy", "unknown"],
        "dataAccessPolicy": {"providerRoutingOutsideGateway": False},
        "replayPolicy": {"freezeNormalizedOutput": True},
    }


def _sandbox_requirement(*, required: bool = True) -> dict[str, Any]:
    return {
        "requirementId": "default-deny-sandbox",
        "kind": ExtensionKind.SANDBOX_ADAPTER.value,
        "extensionId": "p21-default-deny-v1",
        "inputSchemaRef": "sandbox-profile.v1",
        "networkRequirement": "none",
        "sandboxRequirements": {
            "readOnlySource": True,
            "readOnlyRootFilesystem": True,
            "hostPathAccess": False,
            "dockerSocketAccess": False,
            "noNewPrivileges": True,
            "dropAllCapabilities": True,
        },
        "required": required,
    }


def _storage_requirement(extension_id: str) -> dict[str, Any]:
    return {
        "requirementId": extension_id,
        "kind": ExtensionKind.STORAGE_ADAPTER.value,
        "extensionId": extension_id,
        "requiredCapabilities": ["contentHash"],
        "replayPolicy": {"stableContentHash": True},
    }


def _evaluation_requirement(extension_id: str) -> dict[str, Any]:
    return {
        "requirementId": extension_id,
        "kind": ExtensionKind.EVALUATOR.value,
        "extensionId": extension_id,
        "inputSchemaRef": "evaluation-input.v1",
        "outputSchemaRef": "evaluation-result.v1",
    }


def _requirement(
    requirement_id: str,
    kind: ExtensionKind,
    *,
    extension_id: str,
    domain: str | None = None,
    operation: str | None = None,
    required: bool = True,
    required_capabilities: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "requirementId": requirement_id,
        "kind": kind.value,
        "extensionId": extension_id,
        "domain": domain,
        "operation": operation,
        "required": required,
        "requiredCapabilities": required_capabilities or [],
    }


def _normalized_scope(scope: Mapping[str, Any]) -> dict[str, Any]:
    allowed = (
        "tenantId",
        "workspaceId",
        "projectId",
        "environmentId",
        "environment",
        "stage",
        "domain",
    )
    return {key: scope.get(key) for key in allowed if scope.get(key) is not None}


def _selection_scope_error(
    request_scope: Mapping[str, Any],
    selection: QaProfileExtensionSelection | None,
) -> str | None:
    if selection is None:
        return None
    authority_scope = selection.authorityScope
    for key, code in (
        ("tenantId", "CROSS_TENANT_EXTENSION_INHERITANCE_DENIED"),
        ("workspaceId", "CROSS_WORKSPACE_EXTENSION_INHERITANCE_DENIED"),
    ):
        selected = authority_scope.get(key)
        requested = request_scope.get(key)
        if selected is not None and (requested is None or str(selected) != str(requested)):
            return code
    return None


def _contains_control_override(value: object) -> bool:
    forbidden = {
        "authoverride",
        "scopeoverride",
        "licenseoverride",
        "capabilityoverride",
        "approvaloverride",
        "guardrailoverride",
        "killswitchoverride",
        "disableguardrail",
        "bypassapproval",
        "bypasscapability",
        "bypassauth",
        "bypassscope",
    }
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = "".join(character for character in str(key).lower() if character.isalnum())
            if normalized in forbidden or _contains_control_override(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_control_override(item) for item in value)
    return False


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


__all__ = [
    "BuiltinQaProfileCatalog",
    "QaProfile",
    "QaProfileBudgetDefaults",
    "QaProfileExtensionSelection",
    "QaProfileRequirement",
    "QaProfileResolutionSnapshot",
    "QaProfileResolver",
    "build_qa_profile",
    "qa_profile_hash",
]

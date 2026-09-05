# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.runtime.qa_harness.context_builder import canonical_content_hash


class _StrictExtensionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ExtensionKind(StrEnum):
    AGENT_STRATEGY = "agent_strategy"
    SKILL = "skill"
    MODEL_ADAPTER = "model_adapter"
    TOOL_ADAPTER = "tool_adapter"
    CONNECTOR = "connector"
    CONTEXT_PROVIDER = "context_provider"
    SANDBOX_ADAPTER = "sandbox_adapter"
    STORAGE_ADAPTER = "storage_adapter"
    EVALUATOR = "evaluator"


class ExtensionLifecycleStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"


class ExtensionHealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ExtensionDependency(_StrictExtensionModel):
    extensionId: str = Field(min_length=1, max_length=255)
    kind: ExtensionKind | None = None
    version: str | None = Field(default=None, max_length=120)
    required: bool = True
    capabilities: list[str] = Field(default_factory=list, max_length=100)


class ExtensionDescriptor(_StrictExtensionModel):
    """Read-only projection over an existing extension authority."""

    extensionId: str = Field(min_length=1, max_length=255)
    kind: ExtensionKind
    version: str = Field(min_length=1, max_length=120)
    contractVersion: Literal["extension-descriptor.v1"] = "extension-descriptor.v1"
    displayName: str = Field(min_length=1, max_length=255)
    lifecycleStatus: ExtensionLifecycleStatus
    sourceAuthority: str = Field(min_length=1, max_length=255)
    manifestHash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    packageHash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    capabilities: dict[str, Any] = Field(default_factory=dict)
    dependencies: list[ExtensionDependency] = Field(default_factory=list, max_length=200)
    inputSchemaRef: str | None = Field(default=None, max_length=500)
    outputSchemaRef: str | None = Field(default=None, max_length=500)
    riskProfile: dict[str, Any] = Field(default_factory=dict)
    dataAccessPolicy: dict[str, Any] = Field(default_factory=dict)
    sandboxPolicy: dict[str, Any] = Field(default_factory=dict)
    replayPolicy: dict[str, Any] = Field(default_factory=dict)
    scopeSupport: list[str] = Field(default_factory=list, max_length=20)
    healthStatus: ExtensionHealthStatus
    limitations: list[str] = Field(default_factory=list, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_frozen_identity(self) -> "ExtensionDescriptor":
        if not self.manifestHash and not self.packageHash:
            raise ValueError("ExtensionDescriptor requires manifestHash or packageHash")
        if len(set(self.scopeSupport)) != len(self.scopeSupport):
            raise ValueError("scopeSupport must be unique")
        return self


class ExtensionCompatibilityRequirement(_StrictExtensionModel):
    requirementId: str = Field(min_length=1, max_length=255)
    kind: ExtensionKind
    extensionId: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=120)
    contractVersion: str = Field(default="extension-descriptor.v1", max_length=120)
    inputSchemaRef: str | None = Field(default=None, max_length=500)
    outputSchemaRef: str | None = Field(default=None, max_length=500)
    requiredCapabilities: list[str] = Field(default_factory=list, max_length=100)
    requiredDependencies: list[str] = Field(default_factory=list, max_length=100)
    requiresVision: bool = False
    sandboxRequirements: dict[str, Any] = Field(default_factory=dict)
    networkRequirement: Literal["unspecified", "none", "allowlist", "required"] = (
        "unspecified"
    )
    requiredScopeSupport: list[str] = Field(default_factory=list, max_length=20)
    dataAccessPolicy: dict[str, Any] = Field(default_factory=dict)
    replayPolicy: dict[str, Any] = Field(default_factory=dict)
    acceptedHealthStatus: list[ExtensionHealthStatus] = Field(
        default_factory=lambda: [
            ExtensionHealthStatus.HEALTHY,
            ExtensionHealthStatus.UNKNOWN,
            ExtensionHealthStatus.DEGRADED,
        ],
        min_length=1,
        max_length=4,
    )
    required: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExtensionCompatibilityResult(_StrictExtensionModel):
    compatible: bool
    reasonCodes: list[str] = Field(default_factory=list)
    resolvedDependencies: list[str] = Field(default_factory=list)
    unavailableDependencies: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ExtensionDescriptorProjector:
    """Projects allowlisted authority data without mutating its source."""

    @staticmethod
    def skill(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        skill_status = str(authority.get("skillStatus") or "active")
        version_status = str(authority.get("governanceStatus") or "active")
        status = _aggregate_lifecycle(skill_status, version_status)
        dependencies = [
            *[
                ExtensionDependency(
                    extensionId=str(item),
                    kind=ExtensionKind.TOOL_ADAPTER,
                    required=False,
                )
                for item in authority.get("allowedTools", [])
            ],
            *[
                ExtensionDependency(
                    extensionId=str(item),
                    kind=ExtensionKind.CONNECTOR,
                    required=False,
                )
                for item in authority.get("allowedConnectors", [])
            ],
        ]
        compatibility = _mapping(authority.get("compatibility"))
        return ExtensionDescriptor(
            extensionId=str(authority["skillId"]),
            kind=ExtensionKind.SKILL,
            version=str(authority["version"]),
            displayName=str(authority.get("displayName") or authority["skillId"]),
            lifecycleStatus=status,
            sourceAuthority="skills/skill_versions",
            manifestHash=str(authority["manifestHash"]),
            capabilities=_mapping(authority.get("capabilities")),
            dependencies=dependencies,
            inputSchemaRef=str(compatibility.get("input") or "skill-request.v1"),
            outputSchemaRef=str(compatibility.get("output") or "skill-result.v1"),
            riskProfile=_mapping(authority.get("riskProfile")),
            dataAccessPolicy=_mapping(authority.get("dataAccessPolicy")),
            sandboxPolicy=_mapping(authority.get("sandboxPolicy")),
            replayPolicy=_mapping(authority.get("replayPolicy")),
            scopeSupport=["global", "workspace", "project", "environment", "stage", "domain"],
            healthStatus=(
                ExtensionHealthStatus.HEALTHY
                if status == ExtensionLifecycleStatus.ACTIVE
                else ExtensionHealthStatus.UNAVAILABLE
            ),
            limitations=[str(item) for item in authority.get("limitations", [])],
            metadata={
                "skillVersionId": authority.get("skillVersionId"),
                "extensionPoints": list(authority.get("extensionPoints", [])),
                "runtimeAdapter": compatibility.get("runtimeAdapter"),
                "runtimeResultKind": compatibility.get("runtimeResultKind"),
                "readOnlyProjection": True,
            },
        )

    @staticmethod
    def agent_strategy(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        agent_id = str(authority.get("name") or authority.get("agentId"))
        frozen = {
            "name": agent_id,
            "inputSchema": _mapping(authority.get("inputSchema")),
            "outputSchema": _mapping(authority.get("outputSchema")),
            "allowedTools": list(authority.get("allowedTools", [])),
            "allowedSkills": list(authority.get("allowedSkills", [])),
            "preferredModelRole": authority.get("preferredModelRole"),
        }
        return ExtensionDescriptor(
            extensionId=agent_id,
            kind=ExtensionKind.AGENT_STRATEGY,
            version=str(authority.get("version") or "1.0.0"),
            displayName=str(authority.get("displayName") or agent_id),
            lifecycleStatus=ExtensionLifecycleStatus.ACTIVE,
            sourceAuthority="AgentCatalog/BaseAgent.metadata",
            packageHash=canonical_content_hash(frozen),
            capabilities={
                "modelRole": authority.get("preferredModelRole"),
                "structuredOutput": True,
            },
            dependencies=[
                *[
                    ExtensionDependency(
                        extensionId=str(item),
                        kind=ExtensionKind.TOOL_ADAPTER,
                        required=False,
                    )
                    for item in authority.get("allowedTools", [])
                ],
                *[
                    ExtensionDependency(
                        extensionId=str(item),
                        kind=ExtensionKind.SKILL,
                        required=False,
                    )
                    for item in authority.get("allowedSkills", [])
                ],
            ],
            inputSchemaRef=str(authority.get("inputSchemaRef") or "agent-input.v1"),
            outputSchemaRef=str(authority.get("outputSchemaRef") or "agent-output.v1"),
            riskProfile={"decisionOnly": True},
            dataAccessPolicy={"writeDb": False, "directCapabilityExecution": False},
            replayPolicy={"freezeOutput": True, "freezeModelInvocationRef": True},
            scopeSupport=["global", "workspace", "project", "environment"],
            healthStatus=ExtensionHealthStatus.HEALTHY,
            metadata={"description": authority.get("description"), "readOnlyProjection": True},
        )

    @staticmethod
    def model_adapter(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        adapter_id = str(authority["adapterId"])
        health = ExtensionHealthStatus(str(authority.get("healthStatus") or "unknown"))
        enabled = bool(authority.get("enabled", True))
        return ExtensionDescriptor(
            extensionId=adapter_id,
            kind=ExtensionKind.MODEL_ADAPTER,
            version=str(authority.get("version") or "1.0.0"),
            displayName=str(authority.get("displayName") or adapter_id),
            lifecycleStatus=(
                ExtensionLifecycleStatus.ACTIVE
                if enabled and health != ExtensionHealthStatus.UNAVAILABLE
                else ExtensionLifecycleStatus.DISABLED
                if not enabled
                else ExtensionLifecycleStatus.UNAVAILABLE
            ),
            sourceAuthority="model-gateway/ModelAdapter",
            packageHash=canonical_content_hash(dict(authority)),
            capabilities=_mapping(authority.get("capabilities")),
            dependencies=[],
            inputSchemaRef=str(
                authority.get("inputSchemaRef") or "model-gateway-structured-request.v1"
            ),
            outputSchemaRef=str(authority.get("outputSchemaRef") or "agent-output.v1"),
            riskProfile={"providerSelectionOwner": "model-gateway"},
            dataAccessPolicy={"providerRoutingOutsideGateway": False},
            replayPolicy={"freezeModelInvocation": True, "freezeNormalizedOutput": True},
            scopeSupport=["global", "workspace", "project", "environment"],
            healthStatus=health,
            limitations=[str(item) for item in authority.get("limitations", [])],
            metadata={
                "modelRole": authority.get("modelRole"),
                "providerSelectionDeferred": bool(
                    authority.get("providerSelectionDeferred", False)
                ),
                "readOnlyProjection": True,
            },
        )

    @staticmethod
    def tool_adapter(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        runner_id = str(authority["runnerId"])
        return ExtensionDescriptor(
            extensionId=runner_id,
            kind=ExtensionKind.TOOL_ADAPTER,
            version=str(authority.get("version") or "runner-protocol.v1"),
            displayName=str(authority.get("displayName") or runner_id),
            lifecycleStatus=ExtensionLifecycleStatus.ACTIVE,
            sourceAuthority="RunnerRegistry/RunnerAdapter",
            packageHash=canonical_content_hash(dict(authority)),
            capabilities={
                **_mapping(authority.get("capabilities")),
                "domain": authority.get("domain"),
                "parallelism": bool(authority.get("supportsParallelism", False)),
            },
            dependencies=[
                ExtensionDependency(
                    extensionId=str(item), kind=ExtensionKind.SANDBOX_ADAPTER
                )
                for item in authority.get("sandboxDependencies", [])
            ],
            inputSchemaRef="runner-execution-request.v1",
            outputSchemaRef="runner-execution-result.v1",
            riskProfile={"executionOnly": True},
            dataAccessPolicy={"writeDb": False, "businessDecision": False},
            sandboxPolicy=_mapping(authority.get("sandboxPolicy")),
            replayPolicy={"freezeRequest": True, "freezeResultRefs": True},
            scopeSupport=["global", "workspace", "project", "environment"],
            healthStatus=ExtensionHealthStatus(
                str(authority.get("healthStatus") or "healthy")
            ),
            limitations=[str(item) for item in authority.get("limitations", [])],
            metadata={
                "defaultTimeoutSeconds": authority.get("defaultTimeoutSeconds"),
                "registered": True,
                "readOnlyProjection": True,
            },
        )

    @staticmethod
    def connector(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        connector_name = str(authority["connectorName"])
        capabilities = {
            str(item.get("name")): {
                "readOnly": bool(item.get("readOnly", True)),
                "riskLevel": str(item.get("riskLevel") or "low"),
            }
            for item in authority.get("capabilities", [])
            if isinstance(item, Mapping) and item.get("name")
        }
        return ExtensionDescriptor(
            extensionId=connector_name,
            kind=ExtensionKind.CONNECTOR,
            version=str(authority.get("version") or "connector-contract.v1"),
            displayName=str(authority.get("displayName") or connector_name),
            lifecycleStatus=ExtensionLifecycleStatus(
                str(authority.get("lifecycleStatus") or "active")
            ),
            sourceAuthority="ConnectorRuntimeRegistry/ConnectorRuntimeContract",
            packageHash=canonical_content_hash(dict(authority)),
            capabilities={"operations": capabilities, "protocol": authority.get("protocol")},
            dependencies=[],
            inputSchemaRef="connector-operation-request.v1",
            outputSchemaRef="connector-operation-result.v1",
            riskProfile={
                "maxRisk": max(
                    (str(item["riskLevel"]) for item in capabilities.values()),
                    default="low",
                )
            },
            dataAccessPolicy={"databaseAccess": False, "credentialRefsOnly": True},
            replayPolicy={"freezeBindingProjection": True, "providerRawResponse": False},
            scopeSupport=["workspace", "project", "environment"],
            healthStatus=ExtensionHealthStatus(
                str(authority.get("healthStatus") or "unknown")
            ),
            limitations=[str(item) for item in authority.get("limitations", [])],
            metadata={
                "credentialSchemes": sorted(
                    str(item) for item in authority.get("credentialSchemes", [])
                ),
                "readOnlyProjection": True,
            },
        )

    @staticmethod
    def context_provider(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        provider_id = str(authority["providerId"])
        return ExtensionDescriptor(
            extensionId=provider_id,
            kind=ExtensionKind.CONTEXT_PROVIDER,
            version=str(authority.get("version") or "1.0.0"),
            displayName=str(authority.get("displayName") or provider_id),
            lifecycleStatus=ExtensionLifecycleStatus.ACTIVE,
            sourceAuthority="AuthorizedContextBuilder",
            packageHash=canonical_content_hash(dict(authority)),
            capabilities=_mapping(authority.get("capabilities")),
            dependencies=[],
            inputSchemaRef="service-authorized-context.v1",
            outputSchemaRef="harness-context-block.v1",
            riskProfile={"untrustedInput": True},
            dataAccessPolicy={"authorizedRefsOnly": True, "secretMaterial": False},
            replayPolicy={"freezeSourceRefAndHash": True},
            scopeSupport=["workspace", "project", "environment"],
            healthStatus=ExtensionHealthStatus.HEALTHY,
            metadata={"readOnlyProjection": True},
        )

    @staticmethod
    def sandbox_adapter(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        profile_id = str(authority["profileId"])
        sandbox_policy = {
            key: value
            for key, value in dict(authority).items()
            if key not in {"healthStatus", "limitations"}
        }
        return ExtensionDescriptor(
            extensionId=profile_id,
            kind=ExtensionKind.SANDBOX_ADAPTER,
            version=str(authority.get("schemaVersion") or "phase8.sandbox-profile.v1"),
            displayName=str(authority.get("displayName") or profile_id),
            lifecycleStatus=ExtensionLifecycleStatus.ACTIVE,
            sourceAuthority="SandboxProfile",
            packageHash=canonical_content_hash(sandbox_policy),
            capabilities={
                "engine": authority.get("engine"),
                "networkMode": authority.get("networkMode"),
                "defaultDeny": authority.get("networkMode") == "none",
            },
            dependencies=[],
            inputSchemaRef="sandbox-profile.v1",
            outputSchemaRef="sandbox-execution-envelope.v1",
            riskProfile={"untrustedCode": True},
            dataAccessPolicy={
                "hostPathAccess": authority.get("hostPathAccess", False),
                "dockerSocketAccess": authority.get("dockerSocketAccess", False),
                "secretRefsOnly": True,
            },
            sandboxPolicy=sandbox_policy,
            replayPolicy={"freezeProfile": True},
            scopeSupport=["global", "workspace", "project", "environment"],
            healthStatus=ExtensionHealthStatus(
                str(authority.get("healthStatus") or "healthy")
            ),
            limitations=[str(item) for item in authority.get("limitations", [])],
            metadata={"readOnlyProjection": True},
        )

    @staticmethod
    def storage_adapter(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        adapter_id = str(authority["adapterId"])
        return ExtensionDescriptor(
            extensionId=adapter_id,
            kind=ExtensionKind.STORAGE_ADAPTER,
            version=str(authority.get("version") or "storage-adapter.v1"),
            displayName=str(authority.get("displayName") or adapter_id),
            lifecycleStatus=ExtensionLifecycleStatus.ACTIVE,
            sourceAuthority=str(
                authority.get("sourceAuthority")
                or "ArtifactStorageAdapter/ReplayStorageAdapter"
            ),
            packageHash=canonical_content_hash(dict(authority)),
            capabilities=_mapping(authority.get("capabilities")),
            dependencies=[],
            inputSchemaRef="storage-write-request.v1",
            outputSchemaRef="storage-ref.v1",
            riskProfile={"serviceOwnedPersistence": True},
            dataAccessPolicy={"businessServiceUsesAdapterOnly": True},
            replayPolicy={"stableContentHash": True},
            scopeSupport=["global", "workspace", "project", "environment"],
            healthStatus=ExtensionHealthStatus(
                str(authority.get("healthStatus") or "healthy")
            ),
            limitations=[str(item) for item in authority.get("limitations", [])],
            metadata={"readOnlyProjection": True},
        )

    @staticmethod
    def evaluator(authority: Mapping[str, Any]) -> ExtensionDescriptor:
        evaluator_id = str(authority["evaluatorId"])
        return ExtensionDescriptor(
            extensionId=evaluator_id,
            kind=ExtensionKind.EVALUATOR,
            version=str(authority.get("version") or "1.0.0"),
            displayName=str(authority.get("displayName") or evaluator_id),
            lifecycleStatus=ExtensionLifecycleStatus.ACTIVE,
            sourceAuthority="QA Harness built-in evaluation descriptor",
            packageHash=canonical_content_hash(dict(authority)),
            capabilities=_mapping(authority.get("capabilities")),
            dependencies=[],
            inputSchemaRef=str(authority.get("inputSchemaRef") or "evaluation-input.v1"),
            outputSchemaRef=str(authority.get("outputSchemaRef") or "evaluation-result.v1"),
            riskProfile={"authoritativeDecision": False},
            dataAccessPolicy={"writeGate": False, "writeMemory": False},
            replayPolicy={"freezeEvaluationInputs": True, "freezeResult": True},
            scopeSupport=["global", "workspace", "project", "environment"],
            healthStatus=ExtensionHealthStatus(
                str(authority.get("healthStatus") or "healthy")
            ),
            limitations=[str(item) for item in authority.get("limitations", [])],
            metadata={"readOnlyProjection": True},
        )


class ExtensionCompatibilityChecker:
    """Deterministic, fail-closed compatibility check for projected extensions."""

    def check(
        self,
        requirement: ExtensionCompatibilityRequirement,
        descriptor: ExtensionDescriptor | None,
        *,
        catalog: Mapping[str, ExtensionDescriptor] | None = None,
    ) -> ExtensionCompatibilityResult:
        reasons: list[str] = []
        resolved_dependencies: list[str] = []
        unavailable_dependencies: list[str] = []
        warnings: list[str] = []
        if descriptor is None:
            code = "EXTENSION_NOT_FOUND" if requirement.required else "OPTIONAL_EXTENSION_UNAVAILABLE"
            return ExtensionCompatibilityResult(
                compatible=not requirement.required,
                reasonCodes=[code],
                unavailableDependencies=[requirement.extensionId or requirement.requirementId],
                warnings=[] if requirement.required else [code],
            )

        if descriptor.kind != requirement.kind:
            reasons.append("EXTENSION_KIND_INCOMPATIBLE")
        if requirement.extensionId and descriptor.extensionId != requirement.extensionId:
            reasons.append("EXTENSION_ID_INCOMPATIBLE")
        if requirement.version and descriptor.version != requirement.version:
            reasons.append("EXTENSION_VERSION_INCOMPATIBLE")
        if descriptor.lifecycleStatus == ExtensionLifecycleStatus.DEGRADED:
            warnings.append("EXTENSION_LIFECYCLE_DEGRADED")
        elif descriptor.lifecycleStatus != ExtensionLifecycleStatus.ACTIVE:
            reasons.append("EXTENSION_LIFECYCLE_UNUSABLE")
        if descriptor.contractVersion != requirement.contractVersion:
            reasons.append("EXTENSION_CONTRACT_VERSION_INCOMPATIBLE")
        if (
            requirement.inputSchemaRef
            and descriptor.inputSchemaRef != requirement.inputSchemaRef
        ):
            reasons.append("EXTENSION_INPUT_SCHEMA_INCOMPATIBLE")
        if (
            requirement.outputSchemaRef
            and descriptor.outputSchemaRef != requirement.outputSchemaRef
        ):
            reasons.append("EXTENSION_OUTPUT_SCHEMA_INCOMPATIBLE")

        for capability in requirement.requiredCapabilities:
            if not _capability_available(descriptor.capabilities, capability):
                reasons.append(f"EXTENSION_CAPABILITY_UNAVAILABLE:{capability}")
        if requirement.requiresVision and not _capability_available(
            descriptor.capabilities, "vision"
        ):
            reasons.append("MODEL_VISION_CAPABILITY_UNAVAILABLE")

        dependencies = {
            item.extensionId: item
            for item in descriptor.dependencies
            if item.required
        }
        for dependency_id in [
            *requirement.requiredDependencies,
            *dependencies.keys(),
        ]:
            if dependency_id in resolved_dependencies or dependency_id in unavailable_dependencies:
                continue
            dependency = (catalog or {}).get(dependency_id)
            if dependency is None or dependency.lifecycleStatus not in {
                ExtensionLifecycleStatus.ACTIVE,
                ExtensionLifecycleStatus.DEGRADED,
            } or dependency.healthStatus == ExtensionHealthStatus.UNAVAILABLE:
                unavailable_dependencies.append(dependency_id)
                reasons.append(f"EXTENSION_DEPENDENCY_UNAVAILABLE:{dependency_id}")
            else:
                resolved_dependencies.append(dependency_id)

        for key, expected in requirement.sandboxRequirements.items():
            if not _policy_value_matches(descriptor.sandboxPolicy, key, expected):
                reasons.append(f"SANDBOX_REQUIREMENT_INCOMPATIBLE:{key}")
        network_mode = str(
            descriptor.sandboxPolicy.get("networkMode")
            or descriptor.capabilities.get("networkMode")
            or "unspecified"
        )
        if requirement.networkRequirement == "none" and network_mode != "none":
            reasons.append("NETWORK_REQUIREMENT_INCOMPATIBLE")
        elif requirement.networkRequirement == "allowlist" and network_mode != "allowlist":
            reasons.append("NETWORK_REQUIREMENT_INCOMPATIBLE")
        elif requirement.networkRequirement == "required" and network_mode in {
            "none",
            "unspecified",
        }:
            reasons.append("NETWORK_REQUIREMENT_INCOMPATIBLE")

        for scope in requirement.requiredScopeSupport:
            if scope not in descriptor.scopeSupport:
                reasons.append(f"EXTENSION_SCOPE_UNSUPPORTED:{scope}")
        for key, expected in requirement.dataAccessPolicy.items():
            if not _policy_value_matches(descriptor.dataAccessPolicy, key, expected):
                reasons.append(f"DATA_ACCESS_POLICY_INCOMPATIBLE:{key}")
        for key, expected in requirement.replayPolicy.items():
            if not _policy_value_matches(descriptor.replayPolicy, key, expected):
                reasons.append(f"REPLAY_POLICY_INCOMPATIBLE:{key}")

        if descriptor.healthStatus not in requirement.acceptedHealthStatus:
            reasons.append("EXTENSION_HEALTH_UNACCEPTABLE")
        elif descriptor.healthStatus == ExtensionHealthStatus.DEGRADED:
            warnings.append("EXTENSION_HEALTH_DEGRADED")
        if descriptor.healthStatus == ExtensionHealthStatus.UNAVAILABLE:
            reasons.append("EXTENSION_HEALTH_UNAVAILABLE")

        return ExtensionCompatibilityResult(
            compatible=not reasons,
            reasonCodes=_unique(reasons),
            resolvedDependencies=_unique(resolved_dependencies),
            unavailableDependencies=_unique(unavailable_dependencies),
            warnings=_unique(warnings),
        )


def _mapping(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _aggregate_lifecycle(*statuses: str) -> ExtensionLifecycleStatus:
    normalized = {str(item).lower() for item in statuses}
    if "rejected" in normalized:
        return ExtensionLifecycleStatus.UNAVAILABLE
    for status in (
        ExtensionLifecycleStatus.ARCHIVED,
        ExtensionLifecycleStatus.DEPRECATED,
        ExtensionLifecycleStatus.DISABLED,
        ExtensionLifecycleStatus.DRAFT,
        ExtensionLifecycleStatus.UNAVAILABLE,
        ExtensionLifecycleStatus.DEGRADED,
    ):
        if status.value in normalized:
            return status
    return (
        ExtensionLifecycleStatus.ACTIVE
        if normalized.issubset({"active"})
        else ExtensionLifecycleStatus.UNAVAILABLE
    )


def _capability_available(capabilities: Mapping[str, Any], key: str) -> bool:
    if key in capabilities:
        value = capabilities[key]
        return _available_value(value)
    current: object = capabilities
    for segment in key.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return False
        current = current[segment]
    return _available_value(current)


def _available_value(value: object) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str) and value in {"", "unavailable"}:
        return False
    return True


def _policy_value_matches(policy: Mapping[str, Any], key: str, expected: object) -> bool:
    current: object = policy
    for segment in key.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return False
        current = current[segment]
    return current == expected


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


__all__ = [
    "ExtensionCompatibilityChecker",
    "ExtensionCompatibilityRequirement",
    "ExtensionCompatibilityResult",
    "ExtensionDependency",
    "ExtensionDescriptor",
    "ExtensionDescriptorProjector",
    "ExtensionHealthStatus",
    "ExtensionKind",
    "ExtensionLifecycleStatus",
]

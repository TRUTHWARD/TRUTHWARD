# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.runtime.qa_harness.context_builder import context_envelope_hash
from agentic_qa.runtime.qa_harness.contracts import HarnessContextBlock


class SkillContextPlatformControls(BaseModel):
    """Immutable-in-contract controls that external context cannot override."""

    model_config = ConfigDict(extra="forbid", strict=True)

    contextTreatment: Literal["untrusted_data_not_instructions"]
    platformControlsMutable: Literal[False]
    protectedFields: list[
        Literal[
            "allowedExtensionPoints",
            "approval",
            "authorization",
            "providerRouting",
            "guardrail",
        ]
    ] = Field(min_length=5, max_length=5)

    @model_validator(mode="after")
    def verify_protected_fields(self) -> "SkillContextPlatformControls":
        expected = [
            "allowedExtensionPoints",
            "approval",
            "authorization",
            "providerRouting",
            "guardrail",
        ]
        if self.protectedFields != expected:
            raise ValueError("Skill Context protectedFields cannot be modified")
        return self


class SkillContextEnvelope(BaseModel):
    """Frozen, Service-authorized context delivered to a managed Skill runtime."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schemaVersion: Literal["phase8.skill-context-envelope.v1"] = "phase8.skill-context-envelope.v1"
    extensionPointId: str = Field(min_length=1, max_length=160)
    skillVersionId: str = Field(min_length=1, max_length=160)
    manifestHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    scopeSnapshot: dict[str, Any] = Field(default_factory=dict)
    blocks: list[HarnessContextBlock] = Field(default_factory=list, max_length=50)
    totalBytes: int = Field(ge=0)
    estimatedUnits: int = Field(ge=0)
    requiredAvailable: bool
    limitations: list[str] = Field(default_factory=list, max_length=200)
    platformControls: SkillContextPlatformControls
    envelopeHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_hash(self) -> "SkillContextEnvelope":
        payload = self.model_dump(mode="json")
        if context_envelope_hash(payload) != self.envelopeHash:
            raise ValueError("Skill Context Envelope hash mismatch")
        return self

    def summary(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schemaVersion,
            "envelopeHash": self.envelopeHash,
            "requiredAvailable": self.requiredAvailable,
            "totalBytes": self.totalBytes,
            "estimatedUnits": self.estimatedUnits,
            "contextRefs": [
                {
                    "sourceRef": block.sourceRef,
                    "sourceType": block.sourceType,
                    "contentHash": block.contentHash,
                    "sourceVersion": block.sourceVersion,
                    "revision": block.revision,
                    "scopeSnapshot": block.scopeSnapshot,
                    "freshness": block.freshness,
                    "trustBoundary": block.trustBoundary,
                    "redactionStatus": block.redactionStatus,
                    "redactionPolicyVersion": block.redactionPolicyVersion,
                    "available": block.available,
                    "unavailableReason": block.unavailableReason,
                }
                for block in self.blocks
            ],
            "limitations": list(self.limitations),
        }


class SkillManifestResponse(BaseModel):
    skillId: str
    version: str
    manifestHash: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    inputSchema: dict[str, Any] = Field(default_factory=dict)
    outputSchema: dict[str, Any] = Field(default_factory=dict)
    allowedTools: list[str] = Field(default_factory=list)
    allowedConnectors: list[str] = Field(default_factory=list)
    riskProfile: dict[str, Any] = Field(default_factory=dict)
    approvalPolicy: dict[str, Any] = Field(default_factory=dict)
    dataAccessPolicy: dict[str, Any] = Field(default_factory=dict)
    replayPolicy: dict[str, Any] = Field(default_factory=dict)
    extensionPoints: list[str] = Field(default_factory=list)
    compatibility: dict[str, Any] = Field(default_factory=dict)
    runtime: dict[str, Any] = Field(default_factory=dict)


class SkillCatalogItem(SkillManifestResponse):
    id: UUID | None = None
    displayName: str
    status: str = "active"


class SkillInvocationRequest(BaseModel):
    skillId: str
    version: str | None = None
    extensionPointId: str | None = None
    sourceWorkflow: str | None = None
    idempotencyKey: str | None = None
    request: dict[str, Any] = Field(default_factory=dict)
    contextRefs: list[dict[str, Any]] = Field(default_factory=list)
    riskProfile: dict[str, Any] = Field(default_factory=dict)
    policySnapshot: dict[str, Any] = Field(default_factory=dict)
    connectorBindingSnapshot: dict[str, Any] = Field(default_factory=dict)
    executionId: UUID | None = None
    agentRunId: UUID | None = None


class SkillInvocationResponse(BaseModel):
    id: UUID
    skillId: str
    version: str
    manifestHash: str
    status: str
    idempotencyKey: str | None = None
    traceId: UUID | None = None
    executionId: UUID | None = None
    agentRunId: UUID | None = None
    extensionPointId: str | None = None
    bindingId: UUID | None = None
    sourceWorkflow: str | None = None
    inputSnapshot: dict[str, Any] = Field(default_factory=dict)
    outputSnapshot: dict[str, Any] = Field(default_factory=dict)
    policySnapshot: dict[str, Any] = Field(default_factory=dict)
    resolutionSnapshot: dict[str, Any] = Field(default_factory=dict)
    connectorBindingSnapshot: dict[str, Any] = Field(default_factory=dict)
    approvalRefs: list[dict[str, Any]] = Field(default_factory=list)
    artifactRefs: list[dict[str, Any]] = Field(default_factory=list)
    toolCallRefs: list[dict[str, Any]] = Field(default_factory=list)
    connectorCallRefs: list[dict[str, Any]] = Field(default_factory=list)
    approvalRequired: bool = False
    approvalEnvelope: dict[str, Any] | None = None
    createdAt: datetime
    updatedAt: datetime


class ConnectorBindingRequest(BaseModel):
    connectorName: str
    secretRef: str
    credentialRef: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    status: str = "active"


class ConnectorBindingUpdateRequest(BaseModel):
    secretRef: str | None = None
    credentialRef: str | None = None
    scope: dict[str, Any] | None = None
    status: str | None = None


class ConnectorBindingResponse(BaseModel):
    id: UUID
    connectorName: str
    secretConfigured: bool
    credentialConfigured: bool
    scope: dict[str, Any] = Field(default_factory=dict)
    projectId: str | None = None
    environmentId: str | None = None
    configurationHash: str
    redactionPolicyVersion: str
    status: str
    createdAt: datetime
    updatedAt: datetime


class CommunityBindingLifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    action: Literal["enable", "disable"]
    expectedStateHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    idempotencyKey: str = Field(min_length=8, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")


class CapabilityBindingRequest(BaseModel):
    extensionPointId: str
    skillId: str
    version: str | None = None
    manifestHash: str | None = None
    scopeType: str = "global"
    scopeId: str | None = None
    projectId: str | None = None
    environment: str | None = None
    stage: str | None = None
    domain: str | None = None
    status: str = "draft"
    priority: int = 0
    bindingConfig: dict[str, Any] = Field(default_factory=dict)


class CapabilityBindingUpdateRequest(BaseModel):
    skillId: str | None = None
    version: str | None = None
    manifestHash: str | None = None
    scopeType: str | None = None
    status: str | None = None
    priority: int | None = None
    scopeId: str | None = None
    projectId: str | None = None
    environment: str | None = None
    stage: str | None = None
    domain: str | None = None
    bindingConfig: dict[str, Any] | None = None


class CapabilityBindingResponse(BaseModel):
    schemaVersion: str = "phase8.capability-binding.v1"
    stateHash: str | None = None
    communityLifecycle: dict[str, Any] = Field(default_factory=dict)
    id: UUID
    extensionPointId: str
    skillId: str
    skillVersionId: UUID
    version: str
    manifestHash: str
    scopeType: str
    scopeId: str | None = None
    projectId: str | None = None
    environment: str | None = None
    stage: str | None = None
    domain: str | None = None
    status: str
    priority: int
    bindingConfig: dict[str, Any] = Field(default_factory=dict)
    pendingChange: dict[str, Any] = Field(default_factory=dict)
    approvalRefs: list[dict[str, Any]] = Field(default_factory=list)
    guardrailEventRefs: list[dict[str, Any]] = Field(default_factory=list)
    auditRefs: list[dict[str, Any]] = Field(default_factory=list)
    approvalRequired: bool = False
    approvalEnvelope: dict[str, Any] | None = None
    createdAt: datetime
    updatedAt: datetime


class WorkflowCapabilityGraphNode(BaseModel):
    lifecycleStage: str
    extensionPointId: str
    label: str
    bindable: bool
    currentBindingSummary: dict[str, Any] | None = None
    requiredCapability: str | None = None
    requiredEdition: str | None = None
    unavailableReason: str | None = None


class WorkflowCapabilityGraphResponse(BaseModel):
    schemaVersion: str = "phase8.workflow-capability-graph.v1"
    nodes: list[WorkflowCapabilityGraphNode]
    scope: dict[str, Any] = Field(default_factory=dict)

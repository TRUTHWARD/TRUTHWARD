# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_qa.domain.enums import HealthStatus, ModelRole, ProviderType


class ModelCapabilities(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    tools: bool = False
    vision: bool = False
    supports_json: bool = Field(default=False, alias="json")
    longContext: bool = False
    streaming: bool = False
    local: bool = False


class ModelConfigPayload(BaseModel):
    timeoutMs: int = 30000
    maxRetries: int = 2
    temperature: float = 0.2


class CreateModelRequest(BaseModel):
    name: str
    projectId: UUID | None = None
    environmentId: UUID | None = None
    provider: ProviderType
    model: str
    baseUrl: str | None = None
    apiKeyRef: str | None = None
    roles: list[ModelRole]
    priority: int = 100
    enabled: bool = True
    capabilities: ModelCapabilities = Field(default_factory=ModelCapabilities)
    config: ModelConfigPayload = Field(default_factory=ModelConfigPayload)


class UpdateModelRequest(BaseModel):
    name: str | None = None
    projectId: UUID | None = None
    environmentId: UUID | None = None
    provider: ProviderType | None = None
    model: str | None = None
    baseUrl: str | None = None
    apiKeyRef: str | None = None
    roles: list[ModelRole] | None = None
    priority: int | None = None
    enabled: bool | None = None
    capabilities: ModelCapabilities | None = None
    config: ModelConfigPayload | None = None


ModelGovernanceAction = Literal["create", "update", "delete"]


class ModelGovernanceActionRequest(BaseModel):
    action: ModelGovernanceAction
    modelId: UUID | None = None
    modelPayload: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    idempotencyKey: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    projectId: UUID | None = Field(default=None, alias="project_id")
    environmentId: UUID | None = Field(default=None, alias="environment_id")
    provider: ProviderType
    model: str = Field(alias="model_name")
    baseUrl: str | None = Field(default=None, alias="base_url")
    roles: list[ModelRole]
    priority: int
    enabled: bool
    healthStatus: HealthStatus = Field(alias="health_status")
    capabilities: dict[str, Any]
    config: dict[str, Any]
    createdAt: datetime = Field(alias="created_at")
    updatedAt: datetime = Field(alias="updated_at")


class ModelHealthCheckResponse(BaseModel):
    modelId: UUID
    status: HealthStatus
    latencyMs: int
    details: dict[str, Any]


class CapabilityScanResponse(BaseModel):
    modelId: UUID
    capabilities: dict[str, Any]


class ModelSelectorRequest(BaseModel):
    role: ModelRole
    provider: ProviderType | None = None


class ChatMessage(BaseModel):
    role: str
    content: str


class ModelInvokeRequest(BaseModel):
    modelSelector: ModelSelectorRequest
    taskType: str
    messages: list[ChatMessage] = Field(default_factory=list)
    systemPrompt: str | None = None
    temperature: float = 0.2
    maxTokens: int = 2000
    requiresJson: bool = False
    traceId: UUID | None = None
    executionId: UUID | None = None
    projectId: UUID | None = None
    environmentId: UUID | None = None
    agentRunId: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelInvokeWithToolsRequest(ModelInvokeRequest):
    tools: list[dict[str, Any]] = Field(default_factory=list)
    toolChoice: str = "auto"
    allowedToolNames: list[str] = Field(default_factory=list)
    toolCallLimit: int = 3


VisualArtifactType = Literal[
    "screenshot",
    "dom_snapshot",
    "accessibility_tree",
    "vision_annotation",
    "ocr_output",
]


class MultimodalArtifactRef(BaseModel):
    artifactId: UUID
    artifactType: VisualArtifactType


class VisualTargetResolveInput(BaseModel):
    artifactRefs: list[MultimodalArtifactRef] = Field(default_factory=list)
    task: str = Field(default="resolve_visual_target", pattern="^resolve_visual_target$")
    semanticTarget: dict[str, Any] = Field(default_factory=dict)
    targetHints: dict[str, Any] = Field(default_factory=dict)


class VisualTargetResolveRequest(BaseModel):
    modelSelector: ModelSelectorRequest
    input: VisualTargetResolveInput
    traceId: UUID | None = None
    executionId: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VisualTargetResolveOutput(BaseModel):
    boundingBoxes: list[dict[str, Any]] = Field(default_factory=list)
    recognizedText: list[dict[str, Any]] = Field(default_factory=list)
    targetMatchConfidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoningEvidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    riskSignals: list[dict[str, Any]] = Field(default_factory=list)


class VisualTargetResolveResponse(BaseModel):
    modelId: UUID | None = None
    provider: str
    output: VisualTargetResolveOutput
    rawModelOutput: dict[str, Any]
    latencyMs: int


class ModelInvokeResponse(BaseModel):
    modelInvocationId: UUID | None = None
    modelId: UUID | None = None
    provider: str
    mode: Literal["live", "stub"]
    status: Literal["completed", "degraded", "failed", "invalid"]
    success: bool
    outputText: str
    outputJson: dict[str, Any] | None = None
    limitations: list[str] = Field(default_factory=list)
    fallbackUsed: bool = False
    fallbackReason: str | None = None
    finishReason: str
    usage: dict[str, int | None]
    latencyMs: int
    toolCalls: list[dict[str, Any]] = Field(default_factory=list)

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from agentic_qa.domain.enums import RiskLevel, TestDomain


RequirementIntakeSourceType = Literal["paste", "upload", "ocr_upload", "external_link", "connector"]
RequirementIntakeDraftSourceType = Literal["paste", "external_link", "connector"]
RequirementIntakeBatchJsonSourceType = Literal["paste", "external_link", "connector"]


class RequirementIntakeDraftCreateRequest(BaseModel):
    sourceType: RequirementIntakeDraftSourceType = "paste"
    name: str = Field(min_length=1, max_length=255)
    rawContent: str | None = Field(default=None, min_length=1)
    sourceUri: str | None = Field(default=None, min_length=1, max_length=2048)
    connectorBindingId: UUID | None = None
    externalDocumentId: str | None = Field(default=None, min_length=1, max_length=255)
    sourceRef: str | None = Field(default=None, max_length=255)
    environment: str = Field(default="local", min_length=1, max_length=100)
    projectId: UUID | None = None
    environmentId: UUID | None = None
    domains: list[TestDomain] = Field(
        default_factory=lambda: [TestDomain.FUNCTIONAL, TestDomain.PERFORMANCE, TestDomain.SECURITY]
    )
    riskLevel: RiskLevel = RiskLevel.MEDIUM
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_source_payload(self) -> "RequirementIntakeDraftCreateRequest":
        if self.sourceType == "paste" and not (self.rawContent or "").strip():
            raise ValueError("rawContent is required for paste sourceType")
        if self.sourceType == "external_link" and not (self.sourceUri or "").strip():
            raise ValueError("sourceUri is required for external_link sourceType")
        if self.sourceType == "connector":
            if self.connectorBindingId is None:
                raise ValueError("connectorBindingId is required for connector sourceType")
            if not (self.externalDocumentId or self.sourceRef or "").strip():
                raise ValueError("externalDocumentId or sourceRef is required for connector sourceType")
        return self


class RequirementIntakePreviewCreateRequest(BaseModel):
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequirementIntakeSelectableRequirementItem(BaseModel):
    itemId: str
    ordinal: int
    requirement: str
    acceptanceCriteria: list[str] = Field(default_factory=list)
    sourceRef: str
    sourceUri: str | None = None
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    artifactRefs: list[dict[str, Any]] = Field(default_factory=list)
    selectedByDefault: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequirementIntakeConfirmRequest(BaseModel):
    selectedRequirementItems: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequirementIntakeBatchSourceCreateRequest(BaseModel):
    sourceType: RequirementIntakeBatchJsonSourceType
    sourceKey: str | None = Field(default=None, min_length=1, max_length=180)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    rawContent: str | None = Field(default=None, min_length=1)
    sourceUri: str | None = Field(default=None, min_length=1, max_length=2048)
    connectorBindingId: UUID | None = None
    externalDocumentId: str | None = Field(default=None, min_length=1, max_length=255)
    sourceRef: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_batch_source_payload(self) -> "RequirementIntakeBatchSourceCreateRequest":
        if self.sourceType == "paste" and not (self.rawContent or "").strip():
            raise ValueError("rawContent is required for paste batch source")
        if self.sourceType == "external_link" and not (self.sourceUri or "").strip():
            raise ValueError("sourceUri is required for external_link batch source")
        if self.sourceType == "connector":
            if self.connectorBindingId is None:
                raise ValueError("connectorBindingId is required for connector batch source")
            if not (self.externalDocumentId or self.sourceRef or "").strip():
                raise ValueError("externalDocumentId or sourceRef is required for connector batch source")
        return self


class RequirementIntakeBatchCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    idempotencyKey: str | None = Field(default=None, min_length=1, max_length=120)
    environment: str = Field(default="local", min_length=1, max_length=100)
    projectId: UUID | None = None
    environmentId: UUID | None = None
    domains: list[TestDomain] = Field(
        default_factory=lambda: [TestDomain.FUNCTIONAL, TestDomain.PERFORMANCE, TestDomain.SECURITY]
    )
    riskLevel: RiskLevel = RiskLevel.MEDIUM
    metadata: dict[str, Any] = Field(default_factory=dict)
    sources: list[RequirementIntakeBatchSourceCreateRequest] = Field(min_length=1)


class RequirementIntakeBatchConfirmRequest(BaseModel):
    sourceIds: list[UUID] | None = None
    selectedRequirementItemsBySource: dict[str, list[str]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequirementIntakeBatchSourceRetryRequest(BaseModel):
    source: RequirementIntakeBatchSourceCreateRequest | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequirementIntakeOcrProjection(BaseModel):
    status: Literal["ready", "review_required", "blocked"]
    confidence: float = Field(ge=0.0, le=1.0)
    reviewRequired: bool
    blocked: bool
    reviewReasons: list[str] = Field(default_factory=list)
    adapter: str
    pageCount: int = Field(ge=0)
    lineCount: int = Field(ge=0)
    readyConfidenceThreshold: float = Field(ge=0.0, le=1.0)
    blockConfidenceThreshold: float = Field(ge=0.0, le=1.0)
    traceRefs: list[str] = Field(default_factory=list)
    pages: list[dict[str, Any]] = Field(default_factory=list)


class RequirementIntakeDraftResponse(BaseModel):
    draftId: UUID
    sourceType: RequirementIntakeSourceType
    sourceRef: str
    sourceUri: str | None
    name: str
    rawContent: str
    normalizedDocument: str
    storageRef: str | None
    contentHash: str | None
    mimeType: str | None
    byteSize: int | None
    artifactRefs: list[dict[str, Any]]
    evidenceRefs: list[dict[str, Any]]
    redactionStatus: str
    environment: str
    projectId: UUID | None
    environmentId: UUID | None
    domains: list[str]
    riskLevel: str
    status: str
    traceId: UUID | None
    skillInvocationId: UUID | None
    connectorBindingSnapshot: dict[str, Any]
    connectorCallRefs: list[dict[str, Any]]
    ocr: RequirementIntakeOcrProjection | None = None
    metadata: dict[str, Any]
    createdAt: str
    updatedAt: str


class RequirementIntakePreviewResponse(BaseModel):
    previewId: UUID
    draftId: UUID
    sourceType: RequirementIntakeSourceType
    sourceRef: str
    sourceUri: str | None
    document: str
    storageRef: str | None
    contentHash: str | None
    mimeType: str | None
    byteSize: int | None
    artifactRefs: list[dict[str, Any]]
    evidenceRefs: list[dict[str, Any]]
    redactionStatus: str
    requirements: list[str]
    acceptanceCriteria: list[str]
    requirementItems: list[RequirementIntakeSelectableRequirementItem]
    pipelinePayload: dict[str, Any]
    warnings: list[str]
    status: str
    linkedRequirementVersionId: UUID | None
    linkedPipelineId: UUID | None
    confirmedAt: str | None
    traceId: UUID | None
    skillInvocationId: UUID | None
    connectorBindingSnapshot: dict[str, Any]
    connectorCallRefs: list[dict[str, Any]]
    ocr: RequirementIntakeOcrProjection | None = None
    metadata: dict[str, Any]
    createdAt: str
    updatedAt: str


class RequirementIntakeConfirmResponse(BaseModel):
    draft: RequirementIntakeDraftResponse
    preview: RequirementIntakePreviewResponse
    pipeline: dict[str, Any]


class RequirementIntakeBatchSourceResponse(BaseModel):
    batchSourceId: UUID
    batchId: UUID
    ordinal: int
    sourceType: RequirementIntakeSourceType
    sourceKey: str
    status: str
    draftId: UUID | None
    previewId: UUID | None
    linkedRequirementVersionId: UUID | None
    linkedPipelineId: UUID | None
    errorMessage: str | None
    artifactRefs: list[dict[str, Any]]
    evidenceRefs: list[dict[str, Any]]
    retryCount: int
    draft: RequirementIntakeDraftResponse | None = None
    preview: RequirementIntakePreviewResponse | None = None
    metadata: dict[str, Any]
    createdAt: str
    updatedAt: str


class RequirementIntakeBatchResponse(BaseModel):
    batchId: UUID
    name: str
    idempotencyKey: str | None
    status: str
    environment: str
    projectId: UUID | None
    environmentId: UUID | None
    domains: list[str]
    riskLevel: str
    summary: dict[str, Any]
    traceId: UUID | None
    metadata: dict[str, Any]
    sources: list[RequirementIntakeBatchSourceResponse]
    createdAt: str
    updatedAt: str

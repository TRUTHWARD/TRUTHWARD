# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


ProjectionAvailability = Literal["available", "partial", "unavailable"]
GraphIdentityLevel = Literal["observed", "candidate", "canonical"]
CoverageStatus = Literal[
    "covered", "partial", "uncovered", "not_applicable", "unknown"
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


class StableProjectionRef(_StrictModel):
    type: str = Field(min_length=1, max_length=80)
    id: str = Field(min_length=1, max_length=500)
    ref: str | None = Field(default=None, max_length=500)
    label: str | None = Field(default=None, max_length=500)
    available: bool = True
    unavailableReason: str | None = Field(default=None, max_length=160)
    redacted: bool = False


class ProjectionPage(_StrictModel):
    pageSize: int = Field(ge=1, le=200)
    returned: int = Field(ge=0, le=200)
    nextCursor: str | None = Field(default=None, max_length=500)
    hasMore: bool


class CegCapabilityProjection(_StrictModel):
    read: bool
    candidateRead: bool
    coverageRead: bool
    stalenessRead: bool
    evidenceRead: bool
    rawRead: bool
    proposeCorrection: bool
    readOnly: Literal[True]
    backendAuthorization: Literal[True]


class CoverageBadgeProjection(_StrictModel):
    status: CoverageStatus
    ratio: float | None = Field(default=None, ge=0.0, le=1.0)
    covered: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)
    snapshotId: UUID | None = None
    snapshotRef: str | None = Field(default=None, max_length=500)
    computedAt: datetime | None = None
    reasonCodes: list[str] = Field(default_factory=list, max_length=128)


class StalenessBadgeProjection(_StrictModel):
    status: Literal["fresh", "suspect", "stale", "invalid", "unknown"]
    assessmentId: UUID | None = None
    assessedAt: datetime | None = None
    reasonCodes: list[str] = Field(default_factory=list, max_length=128)
    automaticPromotionEligible: bool
    autonomySuspended: bool


class LearningModeProjection(_StrictModel):
    graphLearningMode: Literal[
        "learn_only", "human_supervised", "controlled_autonomy"
    ]
    autonomyPaused: bool
    pauseReasonCode: str | None = Field(default=None, max_length=120)
    bindingId: UUID | None = None
    policyVersionId: UUID | None = None
    fallbackReason: str = Field(min_length=1, max_length=120)


class GraphSummaryItem(_StrictModel):
    graphId: UUID
    graphRef: str = Field(min_length=1, max_length=500)
    graphKey: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    projectId: UUID
    environmentId: UUID | None = None
    scopeType: Literal["project", "environment"]
    scopeId: UUID
    status: str = Field(min_length=1, max_length=80)
    graphVersionId: UUID | None = None
    graphVersionRef: str | None = Field(default=None, max_length=500)
    versionNumber: int | None = Field(default=None, ge=1)
    versionStatus: str | None = Field(default=None, max_length=80)
    versionSource: GraphIdentityLevel | None = None
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    topology: dict[str, int]
    staleness: StalenessBadgeProjection
    coverage: CoverageBadgeProjection
    learning: LearningModeProjection
    updatedAt: datetime
    sourceRefs: list[StableProjectionRef] = Field(min_length=1, max_length=1024)


class GraphSummaryProjection(_StrictModel):
    schemaVersion: Literal["phase8.ceg-graph-summary-projection.v1"]
    generatedAt: datetime
    projectId: UUID
    availability: ProjectionAvailability
    unavailableReason: str | None = Field(default=None, max_length=160)
    filters: dict[str, Any]
    capabilities: CegCapabilityProjection
    items: list[GraphSummaryItem] = Field(default_factory=list, max_length=200)
    page: ProjectionPage
    readOnly: Literal[True]
    frontendAuthoritative: Literal[False]

    @model_validator(mode="after")
    def unavailable_is_not_empty_success(self) -> "GraphSummaryProjection":
        if self.availability == "unavailable" and not self.unavailableReason:
            raise ValueError("unavailable Graph Summary requires unavailableReason")
        return self


class PromotionEligibilityProjection(_StrictModel):
    eligible: bool | None
    automaticPromotionAllowed: bool
    humanReviewRequired: bool
    reasonCodes: list[str] = Field(default_factory=list, max_length=128)
    assessmentId: UUID | None = None
    promotionType: str | None = Field(default=None, max_length=80)
    humanApproval: bool | None = None
    policyDecisionRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=512)
    approvalRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=512)

    @model_validator(mode="after")
    def automatic_is_never_human(self) -> "PromotionEligibilityProjection":
        if self.promotionType == "policy_approved_auto_promotion" and self.humanApproval:
            raise ValueError("policy auto promotion cannot be represented as human approval")
        return self


class PathProjectionItem(_StrictModel):
    graphId: UUID
    graphVersionId: UUID
    pathId: UUID
    pathRef: str = Field(min_length=1, max_length=500)
    pathKey: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    identity: GraphIdentityLevel
    riskLevel: Literal["low", "medium", "high"]
    applicability: dict[str, Any]
    applicabilityStatus: Literal["applicable", "excluded", "unknown"]
    confidence: float = Field(ge=0.0, le=1.0)
    stepCount: int = Field(ge=0)
    capabilityRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=1024)
    coverage: CoverageBadgeProjection
    promotion: PromotionEligibilityProjection
    sourceRefs: list[StableProjectionRef] = Field(min_length=1, max_length=4096)


class PathProjection(_StrictModel):
    schemaVersion: Literal["phase8.ceg-path-projection.v1"]
    generatedAt: datetime
    projectId: UUID
    graphId: UUID
    graphVersionId: UUID
    availability: ProjectionAvailability
    unavailableReason: str | None = Field(default=None, max_length=160)
    filters: dict[str, Any]
    capabilities: CegCapabilityProjection
    items: list[PathProjectionItem] = Field(default_factory=list, max_length=200)
    page: ProjectionPage
    sourceRefs: list[StableProjectionRef] = Field(min_length=1, max_length=1024)
    readOnly: Literal[True]
    frontendAuthoritative: Literal[False]


class NodeProjectionItem(_StrictModel):
    nodeId: UUID
    nodeRef: str = Field(min_length=1, max_length=500)
    semanticKey: str = Field(min_length=1, max_length=256)
    nodeType: str = Field(min_length=1, max_length=40)
    label: str = Field(min_length=1, max_length=500)
    riskLevel: Literal["low", "medium", "high"]
    identity: GraphIdentityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    attributes: dict[str, Any]
    sourceRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=1024)


class EdgeProjectionItem(_StrictModel):
    edgeId: UUID
    edgeRef: str = Field(min_length=1, max_length=500)
    edgeType: str = Field(min_length=1, max_length=80)
    sourceNodeId: UUID
    targetNodeId: UUID
    condition: dict[str, Any] | None = None
    riskLevel: Literal["low", "medium", "high"]
    reviewStatus: str = Field(min_length=1, max_length=80)
    identity: GraphIdentityLevel
    sourceRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=1024)


class StepProjectionItem(_StrictModel):
    stepId: UUID
    stepRef: str = Field(min_length=1, max_length=500)
    order: int = Field(ge=1)
    nodeId: UUID
    viaEdgeId: UUID | None = None
    conditions: list[dict[str, Any]] = Field(default_factory=list, max_length=512)
    outcome: str | None = Field(default=None, max_length=80)
    retryCount: int = Field(default=0, ge=0)
    fallbackTypes: list[str] = Field(default_factory=list, max_length=128)
    verificationStatus: str | None = Field(default=None, max_length=80)
    exceptionRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=512)
    sourceRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=2048)


class NodeDetailProjection(_StrictModel):
    schemaVersion: Literal["phase8.ceg-node-detail-projection.v1"]
    generatedAt: datetime
    projectId: UUID
    graphId: UUID
    graphVersionId: UUID
    pathId: UUID
    availability: ProjectionAvailability
    unavailableReason: str | None = Field(default=None, max_length=160)
    path: PathProjectionItem
    nodes: list[NodeProjectionItem] = Field(default_factory=list, max_length=10_000)
    edges: list[EdgeProjectionItem] = Field(default_factory=list, max_length=20_000)
    steps: list[StepProjectionItem] = Field(default_factory=list, max_length=10_000)
    orphanNodeRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=10_000)
    cycleDetected: bool
    truncated: bool
    limits: dict[str, int]
    sourceRefs: list[StableProjectionRef] = Field(min_length=1, max_length=20_000)
    readOnly: Literal[True]
    frontendAuthoritative: Literal[False]


class EvidenceProjectionItem(_StrictModel):
    evidenceId: str = Field(min_length=1, max_length=500)
    type: str = Field(min_length=1, max_length=80)
    ref: str | None = Field(default=None, max_length=500)
    title: str = Field(min_length=1, max_length=500)
    summary: str | None = None
    status: str = Field(min_length=1, max_length=80)
    occurredAt: datetime | None = None
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    sourceRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=2048)
    redacted: bool
    rawProjection: dict[str, Any] | None = None
    unavailableReason: str | None = Field(default=None, max_length=160)


class VersionHistoryProjection(_StrictModel):
    graphVersionId: UUID
    versionRef: str = Field(min_length=1, max_length=500)
    versionNumber: int = Field(ge=1)
    parentVersionId: UUID | None = None
    status: str = Field(min_length=1, max_length=80)
    identity: GraphIdentityLevel
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    promotionType: str | None = Field(default=None, max_length=80)
    humanApproval: bool | None = None
    createdAt: datetime
    sourceRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=1024)


class EvidenceProjection(_StrictModel):
    schemaVersion: Literal["phase8.ceg-evidence-projection.v1"]
    generatedAt: datetime
    projectId: UUID
    graphId: UUID
    graphVersionId: UUID
    pathId: UUID | None = None
    availability: ProjectionAvailability
    unavailableReason: str | None = Field(default=None, max_length=160)
    capabilities: CegCapabilityProjection
    items: list[EvidenceProjectionItem] = Field(default_factory=list, max_length=200)
    proposals: list[dict[str, Any]] = Field(default_factory=list, max_length=512)
    promotions: list[dict[str, Any]] = Field(default_factory=list, max_length=512)
    stalenessReviews: list[dict[str, Any]] = Field(default_factory=list, max_length=512)
    rollbackRefs: list[StableProjectionRef] = Field(default_factory=list, max_length=512)
    versionHistory: list[VersionHistoryProjection] = Field(default_factory=list, max_length=2048)
    traceability: dict[str, Any] | None = None
    page: ProjectionPage
    sourceRefs: list[StableProjectionRef] = Field(min_length=1, max_length=20_000)
    redaction: dict[str, Any]
    readOnly: Literal[True]
    frontendAuthoritative: Literal[False]

    @model_validator(mode="after")
    def raw_projection_requires_capability(self) -> "EvidenceProjection":
        if not self.capabilities.rawRead and any(item.rawProjection for item in self.items):
            raise ValueError("raw projection must be removed without rawRead capability")
        for promotion in self.promotions:
            if (
                promotion.get("promotionType") == "policy_approved_auto_promotion"
                and promotion.get("humanApproval") is True
            ):
                raise ValueError("automatic promotion cannot be represented as human approval")
        return self


__all__ = [
    "EvidenceProjection",
    "GraphSummaryProjection",
    "NodeDetailProjection",
    "PathProjection",
]

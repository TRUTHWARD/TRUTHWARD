# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


CoverageItemStatus = Literal["covered", "partial", "uncovered", "excluded", "unknown"]
CoverageDimension = Literal[
    "requirement",
    "canonical_path",
    "node",
    "risk",
    "change_impact",
]
CoverageResultStatus = Literal[
    "covered",
    "partial",
    "uncovered",
    "not_applicable",
    "unknown",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


class TraceabilityRef(_StrictModel):
    type: str = Field(min_length=1, max_length=80)
    id: str = Field(min_length=1, max_length=500)
    ref: str | None = Field(default=None, max_length=500)
    label: str | None = Field(default=None, max_length=255)
    status: str | None = Field(default=None, max_length=80)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    available: bool = True
    unavailableReason: str | None = Field(default=None, max_length=160)
    redacted: bool = False


class TraceabilityLink(_StrictModel):
    linkId: str = Field(pattern=r"^trace-link:[a-f0-9]{64}$")
    source: TraceabilityRef
    target: TraceabilityRef
    relationType: str = Field(min_length=1, max_length=80)
    authority: TraceabilityRef
    status: Literal["confirmed", "system_verified", "stale", "invalid", "unknown"]
    evidenceRefs: list[TraceabilityRef] = Field(default_factory=list, max_length=128)


class TraceabilitySegment(_StrictModel):
    stage: Literal[
        "requirement",
        "capability",
        "code",
        "graph_path",
        "test",
        "execution",
        "evidence",
        "finding",
        "gate",
        "replay",
    ]
    refs: list[TraceabilityRef] = Field(default_factory=list, max_length=10_000)
    status: Literal["available", "partial", "unavailable", "not_applicable"]
    reasonCodes: list[str] = Field(default_factory=list, max_length=128)


class TraceabilityChain(_StrictModel):
    chainId: str = Field(pattern=r"^trace-chain:[a-f0-9]{64}$")
    canonicalPathRef: TraceabilityRef | None = None
    segments: list[TraceabilitySegment] = Field(min_length=10, max_length=10)
    linkIds: list[str] = Field(default_factory=list, max_length=50_000)
    complete: bool
    reasonCodes: list[str] = Field(default_factory=list, max_length=256)


class TraceabilityProjection(_StrictModel):
    schemaVersion: Literal["phase8.graph-traceability-projection.v1"]
    generatedAt: datetime
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: UUID
    graphId: UUID
    graphVersionId: UUID
    graphVersionRef: str = Field(pattern=r"^ceg-version://[^\s]+$", max_length=500)
    graphContentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    graphStatus: str = Field(min_length=1, max_length=80)
    stalenessStatus: Literal["fresh", "suspect", "stale", "invalid", "unknown"]
    stalenessAssessmentRef: str | None = Field(default=None, max_length=500)
    stalenessAssessmentHash: str | None = Field(
        default=None, pattern=r"^sha256:[a-f0-9]{64}$"
    )
    requirementVersionId: UUID
    requirementVersionRef: str = Field(min_length=1, max_length=500)
    requirementContentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    executionId: UUID | None = None
    links: list[TraceabilityLink] = Field(default_factory=list, max_length=100_000)
    chains: list[TraceabilityChain] = Field(default_factory=list, max_length=10_000)
    missingLinks: list[dict[str, Any]] = Field(default_factory=list, max_length=50_000)
    sourceRefs: list[TraceabilityRef] = Field(default_factory=list, max_length=10_000)
    evidenceRefsRedacted: bool


class GraphCoverageInput(_StrictModel):
    schemaVersion: Literal["phase8.graph-coverage-input.v1"]
    algorithmVersion: str = Field(min_length=1, max_length=80)
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: UUID
    graphId: UUID
    graphVersionId: UUID
    graphContentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    requirementVersionId: UUID
    requirementContentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    executionId: UUID | None = None
    stalenessStatus: Literal["fresh", "suspect", "stale", "invalid", "unknown"]
    stalenessAssessmentRef: str | None = Field(default=None, max_length=500)
    stalenessAssessmentHash: str | None = Field(
        default=None, pattern=r"^sha256:[a-f0-9]{64}$"
    )
    topologyHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    sourceStateHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    coverageProofRef: TraceabilityRef
    changeRefs: list[TraceabilityRef] = Field(default_factory=list, max_length=20_000)
    sourceRefs: list[TraceabilityRef] = Field(default_factory=list, max_length=20_000)


class GraphCoverageItem(_StrictModel):
    entityRef: TraceabilityRef
    status: CoverageItemStatus
    reasonCodes: list[str] = Field(default_factory=list, max_length=128)
    evidenceRefs: list[TraceabilityRef] = Field(default_factory=list, max_length=128)
    riskLevel: Literal["low", "medium", "high"] | None = None
    weight: int = Field(default=1, ge=1, le=100)


class GraphCoverageMetric(_StrictModel):
    dimension: CoverageDimension
    total: int = Field(ge=0)
    applicable: int = Field(ge=0)
    covered: int = Field(ge=0)
    partial: int = Field(ge=0)
    uncovered: int = Field(ge=0)
    excluded: int = Field(ge=0)
    unknown: int = Field(ge=0)
    coverageRatio: float | None = Field(default=None, ge=0.0, le=1.0)
    partialCreditRatio: float | None = Field(default=None, ge=0.0, le=1.0)
    weightedCoverageRatio: float | None = Field(default=None, ge=0.0, le=1.0)
    status: CoverageResultStatus
    denominatorExplanation: str = Field(min_length=1, max_length=500)
    exclusionReasons: list[dict[str, Any]] = Field(default_factory=list, max_length=10_000)
    items: list[GraphCoverageItem] = Field(default_factory=list, max_length=50_000)

    @model_validator(mode="after")
    def validate_counts(self) -> "GraphCoverageMetric":
        if self.total != self.covered + self.partial + self.uncovered + self.excluded + self.unknown:
            raise ValueError("Coverage total must equal covered + partial + uncovered + excluded + unknown")
        if self.applicable != self.covered + self.partial + self.uncovered:
            raise ValueError("Coverage applicable must equal covered + partial + uncovered")
        if self.total != len(self.items):
            raise ValueError("Coverage total must equal item count")
        if self.unknown and self.coverageRatio is not None:
            raise ValueError("Coverage with unknown inputs must not expose a complete coverageRatio")
        if self.applicable == 0 and self.coverageRatio is not None:
            raise ValueError("Coverage without an applicable denominator must use null coverageRatio")
        return self


class GraphCoverageGap(_StrictModel):
    gapId: str = Field(pattern=r"^coverage-gap:[a-f0-9]{64}$")
    dimension: CoverageDimension
    entityRef: TraceabilityRef
    status: Literal["partial", "uncovered", "unknown"]
    reasonCode: str = Field(min_length=1, max_length=160)
    severity: Literal["critical", "high", "medium", "low", "info"]
    evidenceRefs: list[TraceabilityRef] = Field(min_length=1, max_length=128)
    rawFindingRef: str = Field(pattern=r"^graph-coverage://[^\s]+$", max_length=500)
    dedupeKey: str = Field(min_length=1, max_length=255)
    findingCandidate: dict[str, Any]


class GraphCoverageResult(_StrictModel):
    schemaVersion: Literal["phase8.graph-coverage-result.v1"]
    computedAt: datetime
    algorithmVersion: str = Field(min_length=1, max_length=80)
    inputFingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    snapshotRef: str = Field(pattern=r"^graph-coverage://snapshots/[^\s]+$", max_length=500)
    snapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    coverageProofRef: TraceabilityRef
    status: CoverageResultStatus
    metrics: list[GraphCoverageMetric] = Field(min_length=5, max_length=5)
    gaps: list[GraphCoverageGap] = Field(default_factory=list, max_length=100_000)
    rawFindingRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=100_000)
    findingCandidates: list[dict[str, Any]] = Field(default_factory=list, max_length=100_000)
    normalizedFindingRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=100_000)
    traceabilityProjection: TraceabilityProjection
    replayable: bool
    frontendAuthoritative: Literal[False]

    @model_validator(mode="after")
    def validate_gap_boundary(self) -> "GraphCoverageResult":
        if self.normalizedFindingRefs:
            raise ValueError("Graph Coverage must not create canonical findingRefs before NORMALIZE")
        if len(self.gaps) != len(self.rawFindingRefs) or len(self.gaps) != len(self.findingCandidates):
            raise ValueError("Every Coverage Gap requires one rawFindingRef and findingCandidate")
        return self

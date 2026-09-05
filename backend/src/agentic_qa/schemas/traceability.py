# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from agentic_qa.domain.enums import (
    CoverageRiskStatus,
    CoverageStatus,
    FindingSeverity,
    ProofEdgeCurrentStatus,
    ProofStatus,
    TraceabilityRelationSource,
    TraceabilityRelationStatus,
)


class MissingLink(BaseModel):
    code: str
    fromType: str
    fromId: str
    expectedTargetType: str
    severity: FindingSeverity
    blocksCoverage: bool = True


class TraceabilityNode(BaseModel):
    type: str
    id: str
    label: str | None = None
    status: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TraceabilityRelationView(BaseModel):
    id: UUID | None = None
    table: str
    sourceType: str
    sourceId: str
    targetType: str
    targetId: str
    relationType: str
    status: TraceabilityRelationStatus
    source: TraceabilityRelationSource
    confidence: float = Field(ge=0.0, le=1.0)
    scopeId: str
    stale: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class TraceabilityPathResponse(BaseModel):
    schemaVersion: str = "phase8.traceability-path.v1"
    sourceType: str
    sourceId: str
    upstreamPath: list[TraceabilityNode] = Field(default_factory=list)
    downstreamPath: list[TraceabilityNode] = Field(default_factory=list)
    relationStatus: list[TraceabilityRelationView] = Field(default_factory=list)
    missingLinks: list[MissingLink] = Field(default_factory=list)
    staleLinks: list[TraceabilityRelationView] = Field(default_factory=list)


class CoverageScope(BaseModel):
    schemaVersion: str = "phase8.requirement-scope.v1"
    requirementVersionId: UUID
    requirementVersionIds: list[UUID] = Field(default_factory=list)
    requirementItemRefs: list[dict[str, Any]] = Field(default_factory=list)
    scopeItemRefs: list[dict[str, Any]] = Field(default_factory=list)
    scopeId: str
    selectedRequirementItemIds: list[str] = Field(default_factory=list)
    activeInScopeRequirementItems: int
    filters: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CoverageSummaryResponse(BaseModel):
    schemaVersion: str = "phase8.coverage-summary.v1"
    requirementVersionId: UUID
    requirementVersionIds: list[UUID] = Field(default_factory=list)
    scope: CoverageScope
    status: CoverageStatus
    reason: str | None = None
    requirementCoverage: float | None = None
    testPointCoverage: float | None = None
    testCaseCoverage: float | None = None
    evidenceCoverage: float | None = None
    findingTraceCoverage: float | None = None
    gateImpactCoverage: float | None = None
    missingLinks: list[MissingLink] = Field(default_factory=list)
    calculatedAt: datetime

    @model_validator(mode="after")
    def ensure_coverage_values_are_ratios_or_null(self) -> "CoverageSummaryResponse":
        for field_name in (
            "requirementCoverage",
            "testPointCoverage",
            "testCaseCoverage",
            "evidenceCoverage",
            "findingTraceCoverage",
            "gateImpactCoverage",
        ):
            value = getattr(self, field_name)
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{field_name} must be null or between 0 and 1")
        return self


class CoverageMatrixRow(BaseModel):
    requirement: str
    requirementVersion: str
    requirementItem: dict[str, Any]
    testPoints: list[dict[str, Any]] = Field(default_factory=list)
    testCases: list[dict[str, Any]] = Field(default_factory=list)
    executionTasks: list[dict[str, Any]] = Field(default_factory=list)
    evidenceArtifacts: list[dict[str, Any]] = Field(default_factory=list)
    rawFindings: list[dict[str, Any]] = Field(default_factory=list)
    normalizedFindings: list[dict[str, Any]] = Field(default_factory=list)
    gateImpact: list[dict[str, Any]] = Field(default_factory=list)
    coverageStatus: CoverageStatus
    riskStatus: CoverageRiskStatus
    missingLinks: list[MissingLink] = Field(default_factory=list)


class Pagination(BaseModel):
    page: int = Field(ge=1)
    pageSize: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class CoverageMatrixFilters(BaseModel):
    coverageStatus: CoverageStatus | None = None
    riskStatus: CoverageRiskStatus | None = None
    missingLinkCode: str | None = None
    requirementItemId: str | None = None


class CoverageMatrixResponse(BaseModel):
    schemaVersion: str = "phase8.coverage-matrix.v1"
    requirementVersionId: UUID
    requirementVersionIds: list[UUID] = Field(default_factory=list)
    summary: CoverageSummaryResponse
    rows: list[CoverageMatrixRow]
    missingLinks: list[MissingLink] = Field(default_factory=list)
    status: CoverageStatus
    scope: CoverageScope
    calculatedAt: datetime
    pagination: Pagination
    filters: CoverageMatrixFilters


class TraceabilitySnapshot(BaseModel):
    schemaVersion: str = "phase8.traceability-snapshot.v1"
    traceabilitySnapshotRef: str
    traceabilitySnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    requirementScope: dict[str, Any] | None = None
    coverageSummarySnapshot: dict[str, Any]
    coverageMatrixSnapshotRef: str
    createdAt: datetime


class RelationRef(BaseModel):
    table: str
    id: str
    status: TraceabilityRelationStatus
    source: TraceabilityRelationSource
    scopeId: str
    confidence: float = Field(ge=0.0, le=1.0)


class ProofEdge(BaseModel):
    relationRef: RelationRef
    sourceId: str
    targetId: str
    relationType: str
    frozenStatus: TraceabilityRelationStatus
    currentStatus: ProofEdgeCurrentStatus


class CoverageProofChain(BaseModel):
    testPointId: str | None
    testCaseId: str | None
    executionTaskId: str | None
    proofEdges: list[ProofEdge] = Field(default_factory=list)
    evidenceArtifactRefs: list[dict[str, Any]] = Field(default_factory=list)
    rawFindingRefs: list[dict[str, Any]] = Field(default_factory=list)
    normalizedFindingRefs: list[dict[str, Any]] = Field(default_factory=list)
    gateDecisionRef: str | None
    gateInputSnapshotRef: str | None
    policySnapshotRef: str | None
    approvalRefs: list[dict[str, Any]] = Field(default_factory=list)
    traceRefs: list[str] = Field(default_factory=list)
    auditRefs: list[dict[str, Any]] = Field(default_factory=list)
    traceabilitySnapshotRef: str
    traceabilitySnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    coverageMatrixSnapshotRef: str
    coverageMatrixSnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    replayExportRef: str | None
    replayExportHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    proofIssues: list[str] = Field(default_factory=list)


class CoverageProofBundle(BaseModel):
    schemaVersion: str = "phase8.coverage-proof-bundle.v1"
    generatedAt: datetime
    requirementVersionId: UUID
    primaryRequirementVersionId: UUID | None = None
    requirementVersionIds: list[UUID] = Field(default_factory=list)
    requirementItemId: str
    requirementScope: dict[str, Any] | None = None
    coverageStatus: CoverageStatus
    proofStatus: ProofStatus
    proofChain: list[CoverageProofChain] = Field(default_factory=list)
    proofIssues: list[str] = Field(default_factory=list)
    traceId: str | None

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_qa.infra.redaction import contains_unsafe_control_characters, redact_sensitive_text


IMPACT_ALGORITHM_VERSION = "p18.impact-propagation.v1"
MAPPING_SCHEMA_VERSION = "phase8.capability-mapping.v1"
IMPACT_REQUEST_SCHEMA_VERSION = "phase8.impact-request.v1"
IMPACT_RESULT_SCHEMA_VERSION = "phase8.impact-result.v1"

MappingSource = Literal[
    "manual",
    "explicit_configuration",
    "verified_traceability",
    "static_symbol_coverage",
    "historical_evidence",
    "ai_suggestion",
]
CanonicalMappingSource = Literal[
    "manual",
    "explicit_configuration",
    "verified_traceability",
    "static_symbol_coverage",
    "historical_evidence",
]
RiskLevel = Literal["low", "medium", "high"]


class _StrictImpactModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


class ImpactRef(_StrictImpactModel):
    type: str = Field(min_length=1, max_length=80)
    ref: str = Field(min_length=1, max_length=1000)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("ref")
    @classmethod
    def safe_ref(cls, value: str) -> str:
        if contains_unsafe_control_characters(value) or redact_sensitive_text(value) != value:
            raise ValueError("impact refs must not contain control characters or sensitive values")
        return value


class CapabilityMappingCreateRequest(_StrictImpactModel):
    schemaVersion: Literal["phase8.capability-mapping-create.v1"] = (
        "phase8.capability-mapping-create.v1"
    )
    sourceEntityType: Literal["requirement", "code_path", "code_symbol", "test"]
    sourceEntityRef: str = Field(min_length=1, max_length=1000)
    capabilityRef: str = Field(min_length=1, max_length=1000)
    mappingSource: CanonicalMappingSource
    confidence: float = Field(ge=0.0, le=1.0)
    evidenceRefs: list[ImpactRef] = Field(min_length=1, max_length=100)
    repositoryRef: str | None = Field(default=None, max_length=1000)
    graphVersionId: UUID | None = None
    idempotencyKey: str = Field(min_length=8, max_length=255)

    @field_validator("mappingSource", mode="before")
    @classmethod
    def reject_ai_canonical_source(cls, value: object) -> object:
        if value == "ai_suggestion":
            raise ValueError("AI suggestions cannot be written as canonical Capability Mappings")
        return value

    @model_validator(mode="after")
    def canonical_only(self) -> "CapabilityMappingCreateRequest":
        if self.sourceEntityType.startswith("code_") and not self.repositoryRef:
            raise ValueError("code mappings require repositoryRef")
        for value in (self.sourceEntityRef, self.capabilityRef, self.repositoryRef or ""):
            if contains_unsafe_control_characters(value) or redact_sensitive_text(value) != value:
                raise ValueError("mapping identities must not contain sensitive values")
        return self


class CapabilityMappingContract(_StrictImpactModel):
    schemaVersion: Literal["phase8.capability-mapping.v1"]
    mappingId: str
    mappingKey: str
    version: int = Field(ge=1)
    projectId: str
    sourceEntityType: str
    sourceEntityRef: str
    capabilityRef: str
    mappingSource: CanonicalMappingSource
    sourcePriority: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    status: Literal["active", "superseded", "disabled"]
    repositoryRef: str | None
    graphVersionId: str | None
    evidenceRefs: list[ImpactRef] = Field(min_length=1)
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    traceId: str
    createdAt: datetime
    createdBy: str | None


class ImpactRequestContract(_StrictImpactModel):
    schemaVersion: Literal["phase8.impact-request.v1"]
    changeSetIds: list[UUID] = Field(min_length=1, max_length=100)
    graphId: UUID
    graphVersionId: UUID
    maxDepth: int = Field(default=8, ge=1, le=12)
    maxVisitedNodes: int = Field(default=5000, ge=1, le=10000)
    includeAiSuggestions: bool = False
    idempotencyKey: str = Field(min_length=8, max_length=255)

    @field_validator("changeSetIds")
    @classmethod
    def unique_change_sets(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("changeSetIds must be unique")
        return value


class PropagationStep(_StrictImpactModel):
    order: int = Field(ge=0)
    entityType: str
    entityRef: str
    viaRelation: str | None
    direction: Literal["seed", "forward", "reverse", "mapping"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidenceRefs: list[ImpactRef]


class ImpactedEntity(_StrictImpactModel):
    entityType: Literal["capability", "risk_domain"]
    entityRef: str
    label: str | None
    riskLevel: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    mappingSource: MappingSource | Literal["graph_propagation"]
    evidenceRefs: list[ImpactRef]
    propagationPath: list[PropagationStep]


class ImpactedPath(_StrictImpactModel):
    pathId: str
    pathRef: str
    name: str
    riskLevel: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    evidenceRefs: list[ImpactRef]
    propagationPath: list[PropagationStep]


class ImpactedTest(_StrictImpactModel):
    testRef: str
    testKind: str | None
    riskLevel: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    evidenceRefs: list[ImpactRef]
    propagationPath: list[PropagationStep]


class ImpactUncertainty(_StrictImpactModel):
    code: str = Field(min_length=1, max_length=120)
    areaType: Literal["change", "mapping", "graph", "path", "test", "model", "scope"]
    areaRef: str | None
    messageKey: str
    riskLevel: RiskLevel
    evidenceRefs: list[ImpactRef]
    reviewRequired: bool


class ImpactFallbackReason(_StrictImpactModel):
    code: Literal[
        "FULL_REGRESSION_RECOMMENDED",
        "SECURITY_REVIEW_RECOMMENDED",
        "MANUAL_MAPPING_REVIEW_REQUIRED",
        "GRAPH_REFRESH_REQUIRED",
        "MODEL_SUGGESTION_UNAVAILABLE",
    ]
    reason: str
    recommendedAction: Literal[
        "full_regression",
        "security_review",
        "mapping_review",
        "graph_refresh",
        "manual_analysis",
    ]


class AiMappingSuggestion(_StrictImpactModel):
    sourceEntityRef: str
    suggestedCapabilityRef: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1, max_length=1000)
    evidenceRefs: list[ImpactRef]
    canonical: Literal[False] = False
    reviewRequired: Literal[True] = True


class ImpactResultContract(_StrictImpactModel):
    schemaVersion: Literal["phase8.impact-result.v1"]
    impactResultId: str
    projectId: str
    status: Literal["complete", "partial", "unknown"]
    inputFingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    deduplicated: bool
    riskLevel: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    changeSetRefs: list[ImpactRef]
    graphRef: ImpactRef
    graphVersionRef: ImpactRef
    graphStaleness: Literal["fresh", "suspect", "stale", "invalid", "unknown"]
    graphAssessmentRef: ImpactRef | None
    mappingSnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    mappingVersionRefs: list[ImpactRef]
    algorithmVersion: Literal["p18.impact-propagation.v1"]
    modelInvocationRefs: list[ImpactRef]
    guardrailEventRefs: list[ImpactRef]
    impactedCapabilities: list[ImpactedEntity]
    impactedPaths: list[ImpactedPath]
    impactedTests: list[ImpactedTest]
    impactedRiskDomains: list[ImpactedEntity]
    unknownAreas: list[ImpactUncertainty]
    recommendedFallbacks: list[ImpactFallbackReason]
    aiSuggestions: list[AiMappingSuggestion]
    reviewRequired: bool
    approvalRef: ImpactRef | None
    truncated: bool
    visitedNodeCount: int = Field(ge=0)
    traceId: str
    auditRefs: list[ImpactRef]
    replaySnapshot: dict[str, Any]
    createdAt: datetime

    @model_validator(mode="after")
    def unknown_is_not_no_impact(self) -> "ImpactResultContract":
        if not self.impactedCapabilities and not self.impactedPaths and not self.impactedTests:
            if not self.unknownAreas or not self.recommendedFallbacks or self.status != "unknown":
                raise ValueError("empty impact must be unknown with a conservative fallback")
        if self.aiSuggestions and any(item.canonical for item in self.aiSuggestions):
            raise ValueError("AI suggestions must remain non-canonical")
        return self


class AiSuggestionEnvelope(_StrictImpactModel):
    suggestions: list[AiMappingSuggestion] = Field(default_factory=list, max_length=100)


__all__ = [
    "AiMappingSuggestion",
    "AiSuggestionEnvelope",
    "CapabilityMappingContract",
    "CapabilityMappingCreateRequest",
    "CanonicalMappingSource",
    "IMPACT_ALGORITHM_VERSION",
    "ImpactRequestContract",
    "ImpactResultContract",
    "ImpactRef",
    "MappingSource",
]

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_qa.infra.redaction import contains_unsafe_control_characters, redact_sensitive_text


SELECTIVE_REPLAY_ALGORITHM_VERSION = "p19.selective-replay.v1"
SELECTIVE_REPLAY_REQUEST_SCHEMA_VERSION = "phase8.selective-replay-request.v1"
SELECTIVE_REPLAY_PLAN_SCHEMA_VERSION = "phase8.selective-replay-plan.v1"

RiskLevel = Literal["low", "medium", "high"]


class _StrictReplayModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


class ReplayPlanRef(_StrictReplayModel):
    type: str = Field(min_length=1, max_length=80)
    ref: str = Field(min_length=1, max_length=1000)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("ref")
    @classmethod
    def safe_ref(cls, value: str) -> str:
        if contains_unsafe_control_characters(value) or redact_sensitive_text(value) != value:
            raise ValueError("Selective Replay refs must not contain sensitive values")
        return value


class ReplayPlanBudget(_StrictReplayModel):
    maxTests: int = Field(ge=1, le=10_000)
    maxEstimatedSeconds: int = Field(ge=1, le=86_400)
    overflowBehavior: Literal["conservative_fallback", "preserve_high_risk"]


class SelectiveReplayRequest(_StrictReplayModel):
    schemaVersion: Literal["phase8.selective-replay-request.v1"]
    impactResultId: UUID
    baseExecutionId: UUID
    coverageSnapshotId: UUID
    environmentId: UUID | None = None
    policyRefs: list[ReplayPlanRef] = Field(default_factory=list, max_length=100)
    budget: ReplayPlanBudget
    confidenceThreshold: float = Field(default=0.75, ge=0.5, le=1.0)
    ttlMinutes: int = Field(default=60, ge=5, le=1_440)
    expectedHeadRevision: str | None = Field(default=None, min_length=1, max_length=255)
    idempotencyKey: str = Field(min_length=8, max_length=255)


class ReplaySelectionReason(_StrictReplayModel):
    code: Literal[
        "DIRECT_IMPACT",
        "DEPENDENCY_PROPAGATION",
        "HIGH_RISK_NEIGHBORHOOD",
        "HISTORICAL_FAILURE",
        "OPEN_FINDING",
        "REQUIREMENT_CHANGE",
        "SMOKE_BASELINE",
        "CONSERVATIVE_FALLBACK",
    ]
    category: Literal["impact", "risk", "history", "baseline", "fallback"]
    priority: int = Field(ge=0, le=1000)
    explanationKey: str = Field(min_length=1, max_length=160)
    sourceRefs: list[ReplayPlanRef] = Field(default_factory=list, max_length=256)


class SelectedReplayPath(_StrictReplayModel):
    pathId: str = Field(min_length=1, max_length=255)
    pathRef: str = Field(min_length=1, max_length=1000)
    name: str = Field(min_length=1, max_length=500)
    riskLevel: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    selectionReasonCodes: list[str] = Field(min_length=1, max_length=16)
    evidenceRefs: list[ReplayPlanRef] = Field(default_factory=list, max_length=256)


class SelectedReplayTest(_StrictReplayModel):
    testRef: str = Field(min_length=1, max_length=1000)
    assetId: str | None = Field(default=None, max_length=255)
    taskRef: str | None = Field(default=None, max_length=1000)
    domain: str = Field(min_length=1, max_length=80)
    riskLevel: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    selectionReasonCodes: list[str] = Field(min_length=1, max_length=16)
    estimatedSeconds: int = Field(ge=1, le=86_400)
    evidenceRefs: list[ReplayPlanRef] = Field(default_factory=list, max_length=256)


class ReplayExcludedTest(_StrictReplayModel):
    testRef: str = Field(min_length=1, max_length=1000)
    riskLevel: RiskLevel
    reasonCode: str = Field(min_length=1, max_length=160)
    evidenceRefs: list[ReplayPlanRef] = Field(default_factory=list, max_length=256)


class ReplayPlanUnknown(_StrictReplayModel):
    code: str = Field(min_length=1, max_length=160)
    areaRef: str | None = Field(default=None, max_length=1000)
    riskLevel: RiskLevel
    sourceRefs: list[ReplayPlanRef] = Field(default_factory=list, max_length=256)


class ReplayPlanRiskSummary(_StrictReplayModel):
    overallRisk: RiskLevel
    selectedByRisk: dict[str, int]
    highRiskOmitted: Literal[False]
    approvalRequiredForExecution: bool


class ReplayPlanCoverageSummary(_StrictReplayModel):
    status: Literal["covered", "partial", "uncovered", "not_applicable", "unknown"]
    pathCoverageRatio: float | None = Field(default=None, ge=0.0, le=1.0)
    changeImpactCoverageRatio: float | None = Field(default=None, ge=0.0, le=1.0)
    gapCount: int = Field(ge=0)
    sourceRef: ReplayPlanRef | None


class ReplayEstimatedCost(_StrictReplayModel):
    selectedTestCount: int = Field(ge=1)
    estimatedSeconds: int = Field(ge=1)
    withinBudget: bool
    overBudgetByTests: int = Field(ge=0)
    overBudgetBySeconds: int = Field(ge=0)


class ReplayFallback(_StrictReplayModel):
    used: bool
    reasonCodes: list[str] = Field(default_factory=list, max_length=64)
    strategy: Literal["none", "existing_regression_plan"]
    sourcePlanRef: ReplayPlanRef | None
    conservativeSelectionPreserved: bool


class ReplayPlanValidity(_StrictReplayModel):
    state: Literal["active", "expired", "stale"]
    reasonCodes: list[str] = Field(default_factory=list, max_length=16)
    requiresRegeneration: bool


class SelectiveReplayPlan(_StrictReplayModel):
    schemaVersion: Literal["phase8.selective-replay-plan.v1"]
    planId: UUID
    projectId: UUID
    status: Literal["ready", "fallback"]
    impactResultRef: ReplayPlanRef
    changeSetRefs: list[ReplayPlanRef] = Field(min_length=1, max_length=100)
    graphRef: ReplayPlanRef
    graphVersionRef: ReplayPlanRef
    graphAssessmentRef: ReplayPlanRef | None
    coverageSnapshotRef: ReplayPlanRef | None
    policyRefs: list[ReplayPlanRef] = Field(min_length=1, max_length=100)
    baseExecutionRef: ReplayPlanRef
    environmentRef: ReplayPlanRef | None
    algorithmVersion: Literal["p19.selective-replay.v1"]
    inputFingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    selectedPaths: list[SelectedReplayPath] = Field(default_factory=list, max_length=50_000)
    selectedTests: list[SelectedReplayTest] = Field(min_length=1, max_length=10_000)
    selectionReasons: list[ReplaySelectionReason] = Field(min_length=1, max_length=100)
    riskSummary: ReplayPlanRiskSummary
    coverageSummary: ReplayPlanCoverageSummary
    excludedTests: list[ReplayExcludedTest] = Field(default_factory=list, max_length=50_000)
    unknownAreas: list[ReplayPlanUnknown] = Field(default_factory=list, max_length=10_000)
    budget: ReplayPlanBudget
    estimatedCost: ReplayEstimatedCost
    fallback: ReplayFallback
    planHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    expiresAt: datetime
    validity: ReplayPlanValidity
    createdAt: datetime
    createdBy: UUID | None
    guardrailEventRefs: list[ReplayPlanRef]
    auditRefs: list[ReplayPlanRef]
    replaySnapshot: dict
    deduplicated: bool
    readOnly: Literal[True]
    executionCreated: Literal[False]
    frontendAuthoritative: Literal[False]

    @model_validator(mode="after")
    def conservative_non_empty_boundary(self) -> "SelectiveReplayPlan":
        if self.fallback.used and self.fallback.strategy != "existing_regression_plan":
            raise ValueError("fallback must reuse the existing regression planner")
        if not self.fallback.used and self.fallback.strategy != "none":
            raise ValueError("non-fallback plans must use strategy=none")
        if self.riskSummary.highRiskOmitted is not False:
            raise ValueError("Selective Replay must never omit known high-risk coverage")
        return self


__all__ = [
    "ReplayPlanBudget",
    "ReplayPlanRef",
    "SELECTIVE_REPLAY_ALGORITHM_VERSION",
    "SelectiveReplayPlan",
    "SelectiveReplayRequest",
]

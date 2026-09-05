# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ImprovementTargetType = Literal[
    "skill",
    "gate_policy",
    "graph",
    "graph_learning_policy",
    "test_case",
    "test_step",
    "tool_config",
    "connector_config",
]
ImprovementRisk = Literal["low", "medium", "high", "critical"]
ImprovementStatus = Literal[
    "draft",
    "validation_failed",
    "validated",
    "review_pending",
    "review_approved",
    "review_rejected",
    "routed",
    "effectiveness_pending",
    "effective",
    "ineffective",
    "inconclusive",
    "rollback_pending",
    "rollback_routed",
    "partial",
    "failed",
    "archived",
]

_SECRET_KEY = re.compile(
    r"(?i)(password|passwd|authorization|api[_-]?key|private[_-]?key|"
    r"client[_-]?secret|access[_-]?token|refresh[_-]?token|credential|secret)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._~+/=-]{8,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)"
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


def ensure_secret_free(value: Any, *, path: str = "structuredChange") -> Any:
    """Reject secret-bearing proposal material instead of persisting or replaying it."""
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                raise ValueError(f"{path}.{key} is a credential/secret field and is not allowed")
            ensure_secret_free(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            ensure_secret_free(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ValueError(f"{path} contains secret material")
    return value


class ImprovementTargetIdentity(_StrictModel):
    targetId: str = Field(min_length=1, max_length=255)
    targetKey: str = Field(min_length=1, max_length=255)
    baseVersion: str = Field(min_length=1, max_length=255)
    baseHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class ImprovementChangeSpec(_StrictModel):
    schemaVersion: Literal["phase8.improvement-change-spec.v1"] = (
        "phase8.improvement-change-spec.v1"
    )
    summary: str = Field(min_length=1, max_length=2_000)
    operations: list[dict[str, Any]] = Field(min_length=1, max_length=1_000)
    authorityRequest: dict[str, Any] = Field(default_factory=dict)
    rollbackSpec: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_secret_material(self) -> "ImprovementChangeSpec":
        ensure_secret_free(self.model_dump(mode="json"))
        return self


class SimulationEvidence(_StrictModel):
    required: bool = True
    status: Literal["passed", "failed", "insufficient", "unavailable"]
    sampleSize: int = Field(ge=0, le=10_000_000)
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=512)
    metrics: dict[str, float] = Field(default_factory=dict, max_length=64)

    @model_validator(mode="after")
    def require_pass_evidence(self) -> "SimulationEvidence":
        if self.status == "passed" and (self.sampleSize < 1 or not self.evidenceRefs):
            raise ValueError("passed simulation evidence requires samples and evidence refs")
        ensure_secret_free(self.evidenceRefs, path="validationPlan.evidenceRefs")
        return self


class ImprovementValidationPlan(_StrictModel):
    schemaVersion: Literal["phase8.improvement-validation-plan.v1"] = (
        "phase8.improvement-validation-plan.v1"
    )
    requiredChecks: list[str] = Field(min_length=1, max_length=128)
    minimumSamples: int = Field(default=1, ge=1, le=10_000_000)
    historicalSimulation: SimulationEvidence
    counterexampleRegression: SimulationEvidence | None = None
    compatibilityEvidenceRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=512)
    replayRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=512)
    effectivenessMetrics: list[
        Literal[
            "false_positive_rate",
            "false_negative_rate",
            "coverage",
            "failure_rate",
            "latency_ms",
            "auto_promotion_conflict_rate",
            "auto_promotion_rollback_rate",
        ]
    ] = Field(min_length=1, max_length=16)

    @field_validator("requiredChecks")
    @classmethod
    def unique_checks(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("validation checks must be unique")
        return value


class EffectivenessWindow(_StrictModel):
    startsAt: datetime
    endsAt: datetime
    minimumSamples: int = Field(default=1, ge=1, le=10_000_000)

    @model_validator(mode="after")
    def ordered_window(self) -> "EffectivenessWindow":
        if self.endsAt <= self.startsAt:
            raise ValueError("effectiveness window end must be after start")
        return self


class CreateImprovementProposalRequest(_StrictModel):
    sourceLessonIds: list[UUID] = Field(min_length=1, max_length=100)
    targetType: ImprovementTargetType
    target: ImprovementTargetIdentity
    changeSpec: ImprovementChangeSpec
    rationale: str = Field(min_length=1, max_length=4_000)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1, max_length=512)
    requestedRisk: ImprovementRisk
    confidence: float = Field(ge=0.0, le=1.0)
    validationPlan: ImprovementValidationPlan
    effectivenessWindow: EffectivenessWindow
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_target_specific_plan(self) -> "CreateImprovementProposalRequest":
        ensure_secret_free(self.evidenceRefs, path="evidenceRefs")
        if not self.validationPlan.historicalSimulation.required:
            raise ValueError("every Improvement Proposal requires historical simulation")
        required_checks = set(self.validationPlan.requiredChecks)
        target_required = {
            "skill": {"historical_simulation", "schema_compatibility"},
            "gate_policy": {"historical_simulation", "gate_hard_rules_preserved"},
            "graph": {"historical_simulation", "target_base_unchanged"},
            "graph_learning_policy": {
                "historical_simulation",
                "counterexample_regression",
                "no_threshold_relaxation",
                "automatic_apply_disabled",
            },
            "test_case": {"historical_simulation", "target_base_unchanged"},
            "test_step": {"historical_simulation", "target_base_unchanged"},
            "tool_config": {"historical_simulation", "secret_free"},
            "connector_config": {"historical_simulation", "secret_free"},
        }[self.targetType]
        if not target_required.issubset(required_checks):
            raise ValueError(
                f"{self.targetType} validation plan is missing required target checks"
            )
        if self.targetType == "graph_learning_policy":
            counterexample = self.validationPlan.counterexampleRegression
            if counterexample is None or not counterexample.required:
                raise ValueError(
                    "Graph Learning Policy proposals require counterexample regression"
                )
        return self


class UpdateImprovementProposalRequest(_StrictModel):
    expectedLockVersion: int = Field(ge=1)
    changeSpec: ImprovementChangeSpec
    rationale: str = Field(min_length=1, max_length=4_000)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1, max_length=512)
    requestedRisk: ImprovementRisk
    confidence: float = Field(ge=0.0, le=1.0)
    validationPlan: ImprovementValidationPlan
    effectivenessWindow: EffectivenessWindow


class ValidateImprovementProposalRequest(_StrictModel):
    expectedLockVersion: int = Field(ge=1)
    idempotencyKey: str = Field(min_length=1, max_length=255)


class SubmitImprovementReviewRequest(_StrictModel):
    expectedLockVersion: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=2_000)
    idempotencyKey: str = Field(min_length=1, max_length=255)


class RouteImprovementProposalRequest(_StrictModel):
    expectedLockVersion: int = Field(ge=1)
    idempotencyKey: str = Field(min_length=1, max_length=255)


class RecordImprovementEffectivenessRequest(_StrictModel):
    targetOutcomeRef: dict[str, Any]
    beforeMetrics: dict[str, float] = Field(min_length=1, max_length=64)
    afterMetrics: dict[str, float] = Field(min_length=1, max_length=64)
    sampleSize: int = Field(ge=1, le=10_000_000)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1, max_length=512)
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def metric_keys_match(self) -> "RecordImprovementEffectivenessRequest":
        if set(self.beforeMetrics) != set(self.afterMetrics):
            raise ValueError("before/after effectiveness metrics must have identical keys")
        ensure_secret_free(self.targetOutcomeRef, path="targetOutcomeRef")
        ensure_secret_free(self.evidenceRefs, path="effectiveness.evidenceRefs")
        return self


class RequestImprovementRollbackRequest(_StrictModel):
    expectedLockVersion: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=2_000)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1, max_length=512)
    idempotencyKey: str = Field(min_length=1, max_length=255)


class ImprovementValidationResultContract(_StrictModel):
    schemaVersion: Literal["phase8.improvement-validation-result.v1"]
    validationResultId: str
    proposalId: str
    proposalVersion: int = Field(ge=1)
    status: Literal["passed", "failed", "insufficient", "unavailable"]
    checks: list[dict[str, Any]] = Field(min_length=1)
    historicalSimulation: dict[str, Any]
    counterexampleRegression: dict[str, Any] | None
    evidenceRefs: list[dict[str, Any]]
    resultHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    validatorVersion: str = Field(min_length=1)
    validatedAt: str


class ImprovementEffectivenessResultContract(_StrictModel):
    schemaVersion: Literal["phase8.improvement-effectiveness-result.v1"]
    effectivenessResultId: str
    proposalId: str
    status: Literal["effective", "ineffective", "inconclusive"]
    beforeMetrics: dict[str, float]
    afterMetrics: dict[str, float]
    deltas: dict[str, float]
    sampleSize: int = Field(ge=1)
    rollbackRequired: bool
    targetOutcomeRef: dict[str, Any]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    measuredAt: str


class ImprovementProposalContract(_StrictModel):
    schemaVersion: Literal["phase8.improvement-proposal.v1"]
    proposalId: str
    projectId: str
    sourceLessonRefs: list[dict[str, Any]] = Field(min_length=1)
    targetType: ImprovementTargetType
    target: ImprovementTargetIdentity
    changeSpec: ImprovementChangeSpec
    changeHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    rationale: str
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    requestedRisk: ImprovementRisk
    evaluatedRisk: ImprovementRisk
    confidence: float = Field(ge=0.0, le=1.0)
    validationPlan: ImprovementValidationPlan
    validationRefs: list[dict[str, Any]]
    status: ImprovementStatus
    approvalRefs: list[dict[str, Any]]
    routeRefs: list[dict[str, Any]]
    effectivenessRefs: list[dict[str, Any]]
    rollbackRefs: list[dict[str, Any]]
    traceRefs: list[str]
    auditRefs: list[dict[str, Any]]
    effectivenessWindow: EffectivenessWindow
    lockVersion: int = Field(ge=1)
    createdAt: str
    updatedAt: str
    readOnly: bool
    productionAppliedByProposalService: Literal[False]
    automaticSelfEvolution: Literal[False]


__all__ = [
    "CreateImprovementProposalRequest",
    "ImprovementChangeSpec",
    "ImprovementEffectivenessResultContract",
    "ImprovementProposalContract",
    "ImprovementTargetIdentity",
    "ImprovementTargetType",
    "ImprovementValidationPlan",
    "ImprovementValidationResultContract",
    "RecordImprovementEffectivenessRequest",
    "RequestImprovementRollbackRequest",
    "RouteImprovementProposalRequest",
    "SubmitImprovementReviewRequest",
    "UpdateImprovementProposalRequest",
    "ValidateImprovementProposalRequest",
    "ensure_secret_free",
]

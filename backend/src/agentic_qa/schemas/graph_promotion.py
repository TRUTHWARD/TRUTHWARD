# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


GraphLearningMode = Literal["learn_only", "human_supervised", "controlled_autonomy"]
GraphCorrectionEntity = Literal["node", "edge", "path"]
GraphCorrectionOperationType = Literal["add", "update", "remove", "reorder"]
GraphRisk = Literal["low", "medium", "high"]
EligibilityState = Literal["passed", "failed", "unknown", "unavailable"]

MAX_GRAPH_CORRECTION_OPERATIONS = 2_000
MAX_GRAPH_PROMOTION_REFS = 512
_SECRET_MARKERS = re.compile(
    r"(?i)(password|passwd|authorization|bearer\s|api[_-]?key|private[_-]?key|client[_-]?secret|cookie)"
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


def _ensure_redacted(value: Any, label: str) -> Any:
    encoded = json.dumps(value, sort_keys=True, default=str)
    if _SECRET_MARKERS.search(encoded):
        raise ValueError(f"{label} must not contain secret material")
    return value


class GraphCorrectionOperation(_StrictModel):
    operationId: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    entityType: GraphCorrectionEntity
    operation: GraphCorrectionOperationType
    targetId: UUID | None = None
    stableKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    expectedLockVersion: int | None = Field(default=None, ge=1)
    value: dict[str, Any] = Field(default_factory=dict, max_length=64)

    @model_validator(mode="after")
    def validate_operation_shape(self) -> "GraphCorrectionOperation":
        if self.operation == "add" and self.targetId is not None:
            raise ValueError("add correction must use stableKey instead of an existing targetId")
        if self.operation != "add" and self.targetId is None:
            raise ValueError(f"{self.operation} correction requires targetId")
        if self.operation in {"update", "remove", "reorder"} and self.expectedLockVersion is None:
            raise ValueError(f"{self.operation} correction requires expectedLockVersion")
        if self.operation == "remove" and self.value:
            raise ValueError("remove correction must not carry value")
        if self.operation == "reorder" and self.entityType != "path":
            raise ValueError("reorder is only valid for a path")
        _ensure_redacted(self.value, "Graph correction value")
        return self


class GraphCorrectionPatch(_StrictModel):
    operations: list[GraphCorrectionOperation] = Field(
        min_length=1, max_length=MAX_GRAPH_CORRECTION_OPERATIONS
    )

    @model_validator(mode="after")
    def validate_unique_operations(self) -> "GraphCorrectionPatch":
        ids = [item.operationId for item in self.operations]
        if len(ids) != len(set(ids)):
            raise ValueError("Graph correction operationId values must be unique")
        return self


class CreateGraphCorrectionProposalRequest(_StrictModel):
    schemaVersion: Literal["phase8.graph-correction-proposal.v1"] = (
        "phase8.graph-correction-proposal.v1"
    )
    graphId: UUID
    baseVersionId: UUID
    baseVersionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    baseVersionLockVersion: int = Field(ge=1)
    candidateVersionId: UUID
    candidateVersionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    candidateBuildId: UUID
    patch: GraphCorrectionPatch
    riskLevel: GraphRisk
    rationaleCode: str = Field(pattern=r"^GRAPH_CORRECTION_[A-Z0-9_]+$", max_length=120)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_GRAPH_PROMOTION_REFS)
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @field_validator("evidenceRefs")
    @classmethod
    def validate_evidence(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return _ensure_redacted(value, "Graph correction evidence")


class UpdateGraphCorrectionProposalRequest(_StrictModel):
    expectedLockVersion: int = Field(ge=1)
    patch: GraphCorrectionPatch
    riskLevel: GraphRisk
    rationaleCode: str = Field(pattern=r"^GRAPH_CORRECTION_[A-Z0-9_]+$", max_length=120)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_GRAPH_PROMOTION_REFS)


class ValidateGraphCorrectionRequest(_StrictModel):
    expectedLockVersion: int = Field(ge=1)
    validatorVersion: str = Field(
        default="graph-correction-validator.v1",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,79}$",
    )
    idempotencyKey: str = Field(min_length=1, max_length=255)


class EligibilityEvidenceRequest(_StrictModel):
    replayRepositoryIds: list[str] = Field(default_factory=list, max_length=128)
    shadowRunIds: list[UUID] = Field(default_factory=list, max_length=128)


class AssessGraphPromotionRequest(_StrictModel):
    expectedProposalLockVersion: int = Field(ge=1)
    evidence: EligibilityEvidenceRequest = Field(default_factory=EligibilityEvidenceRequest)
    idempotencyKey: str = Field(min_length=1, max_length=255)


class SubmitGraphPromotionReviewRequest(_StrictModel):
    assessmentId: UUID
    expectedProposalLockVersion: int = Field(ge=1)
    idempotencyKey: str = Field(min_length=1, max_length=255)
    expiresAt: datetime | None = None
    comment: str | None = Field(default=None, max_length=2_000)


class PromoteGraphRequest(_StrictModel):
    assessmentId: UUID
    expectedProposalLockVersion: int = Field(ge=1)
    expectedBaseVersionId: UUID
    expectedBaseVersionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approvalId: UUID | None = None
    idempotencyKey: str = Field(min_length=1, max_length=255)


class PauseGraphAutonomyRequest(_StrictModel):
    paused: bool
    expectedLockVersion: int = Field(ge=1)
    reasonCode: str = Field(pattern=r"^GRAPH_AUTONOMY_[A-Z0-9_]+$", max_length=120)


class ConfigureGraphAutonomyRequest(_StrictModel):
    schemaVersion: Literal["phase8.graph-autonomy-configuration.v1"] = (
        "phase8.graph-autonomy-configuration.v1"
    )
    targetMode: GraphLearningMode
    expectedLockVersion: int = Field(ge=1)
    reasonCode: str = Field(pattern=r"^GRAPH_AUTONOMY_[A-Z0-9_]+$", max_length=120)
    idempotencyKey: str = Field(min_length=1, max_length=255)


class RequestGraphRollbackReviewRequest(_StrictModel):
    rollbackTargetVersionId: UUID
    expectedActiveVersionId: UUID
    expectedActiveVersionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reasonCode: str = Field(pattern=r"^GRAPH_ROLLBACK_[A-Z0-9_]+$", max_length=120)
    idempotencyKey: str = Field(min_length=1, max_length=255)
    expiresAt: datetime | None = None
    comment: str | None = Field(default=None, max_length=2_000)


class RollbackGraphPromotionRequest(_StrictModel):
    rollbackTargetVersionId: UUID
    expectedActiveVersionId: UUID
    expectedActiveVersionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reasonCode: str = Field(pattern=r"^GRAPH_ROLLBACK_[A-Z0-9_]+$", max_length=120)
    approvalId: UUID
    idempotencyKey: str = Field(min_length=1, max_length=255)


class CreateGraphLearningPolicyRequest(_StrictModel):
    schemaVersion: Literal["phase8.graph-learning-policy.v1"] = (
        "phase8.graph-learning-policy.v1"
    )
    policyKey: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    status: Literal["draft", "active"] = "active"
    minIndependentSuccesses: int = Field(default=3, ge=2, le=1_000)
    minDistinctTimeWindows: int = Field(default=2, ge=1, le=100)
    minDistinctRevisions: int = Field(default=1, ge=1, le=100)
    minDistinctEnvironments: int = Field(default=1, ge=1, le=100)
    minVerificationCoverage: float = Field(default=1.0, ge=0.95, le=1.0)
    minConfidence: float = Field(default=0.9, ge=0.8, le=1.0)
    minEvidenceRefs: int = Field(default=1, ge=1, le=10_000)
    minShadowSamples: int = Field(default=3, ge=1, le=10_000)
    allowedFallbackTypes: list[str] = Field(default_factory=list, max_length=16)
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @field_validator("allowedFallbackTypes")
    @classmethod
    def validate_fallbacks(cls, value: list[str]) -> list[str]:
        forbidden = {"coordinate", "screen_coordinate", "unsafe", "destructive", "external_write"}
        if forbidden.intersection({item.lower() for item in value}):
            raise ValueError("Graph learning policy cannot allow dangerous fallbacks")
        return sorted(set(value))


class CreateGraphLearningBindingRequest(_StrictModel):
    policyVersionId: UUID
    policyVersionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    scopeType: Literal["project", "environment"]
    environmentId: UUID | None = None
    graphLearningMode: GraphLearningMode = "human_supervised"
    status: Literal["active", "disabled"] = "active"
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_scope(self) -> "CreateGraphLearningBindingRequest":
        if self.scopeType == "project" and self.environmentId is not None:
            raise ValueError("project learning Binding must not carry environmentId")
        if self.scopeType == "environment" and self.environmentId is None:
            raise ValueError("environment learning Binding requires environmentId")
        return self


class EligibilityCheck(_StrictModel):
    code: str = Field(pattern=r"^GRAPH_ELIGIBILITY_[A-Z0-9_]+$", max_length=120)
    state: EligibilityState
    passed: bool
    actual: Any = None
    required: Any = None
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_GRAPH_PROMOTION_REFS)

    @model_validator(mode="after")
    def validate_fail_closed(self) -> "EligibilityCheck":
        if self.passed != (self.state == "passed"):
            raise ValueError("Eligibility passed is true only for state=passed")
        return self


class PromotionEligibilityAssessment(_StrictModel):
    schemaVersion: Literal["phase8.graph-promotion-eligibility.v1"] = (
        "phase8.graph-promotion-eligibility.v1"
    )
    assessmentId: UUID
    proposalId: UUID
    graphId: UUID
    candidateVersionId: UUID
    baseVersionId: UUID
    learningMode: GraphLearningMode
    riskLevel: GraphRisk
    eligible: bool
    automaticPromotionAllowed: bool
    humanReviewRequired: bool
    checks: list[EligibilityCheck] = Field(min_length=1)
    reasonCodes: list[str] = Field(min_length=1)
    policyVersionId: UUID | None
    policyVersionHash: str
    bindingId: UUID | None
    eligibilityHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evaluatedAt: datetime


class GraphPromotionResult(_StrictModel):
    schemaVersion: Literal["phase8.graph-promotion-result.v1"] = (
        "phase8.graph-promotion-result.v1"
    )
    promotionId: UUID
    proposalId: UUID
    graphId: UUID
    beforeVersionId: UUID
    beforeVersionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    targetVersionId: UUID
    targetVersionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    promotionType: Literal[
        "human_approved_promotion",
        "policy_approved_auto_promotion",
        "human_approved_rollback",
    ]
    actorType: Literal["human", "system"]
    actorRef: str = Field(min_length=1, max_length=500)
    humanApproval: bool
    approvalRefs: list[dict[str, Any]]
    policyDecisionRefs: list[dict[str, Any]]
    assessmentId: UUID
    rollbackTargetVersionId: UUID | None
    status: Literal["promoted", "rolled_back"]
    promotedAt: datetime
    idempotencyKey: str

    @model_validator(mode="after")
    def distinguish_policy_and_human_decisions(self) -> "GraphPromotionResult":
        automatic = self.promotionType == "policy_approved_auto_promotion"
        if automatic and (
            self.humanApproval
            or self.approvalRefs
            or self.actorType != "system"
            or self.actorRef != "system://controlled-graph-promotion"
        ):
            raise ValueError("automatic Graph Promotion must not fabricate human Approval")
        if not automatic and (
            not self.humanApproval
            or not self.approvalRefs
            or self.actorType != "human"
            or not self.actorRef.startswith("user://users/")
        ):
            raise ValueError("human Graph Promotion requires a real Approval ref")
        return self


__all__ = [
    "AssessGraphPromotionRequest",
    "ConfigureGraphAutonomyRequest",
    "CreateGraphCorrectionProposalRequest",
    "CreateGraphLearningBindingRequest",
    "CreateGraphLearningPolicyRequest",
    "EligibilityCheck",
    "GraphCorrectionOperation",
    "GraphCorrectionPatch",
    "GraphLearningMode",
    "GraphPromotionResult",
    "PauseGraphAutonomyRequest",
    "PromoteGraphRequest",
    "PromotionEligibilityAssessment",
    "RequestGraphRollbackReviewRequest",
    "RollbackGraphPromotionRequest",
    "SubmitGraphPromotionReviewRequest",
    "UpdateGraphCorrectionProposalRequest",
    "ValidateGraphCorrectionRequest",
]

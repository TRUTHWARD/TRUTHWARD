# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


LessonType = Literal[
    "false_positive",
    "false_negative",
    "repeated_failure",
    "flaky",
    "environment_issue",
    "test_issue",
    "human_override",
    "graph_correction",
    "gate_disagreement",
    "admission_outcome",
    "auto_promotion_conflict",
    "auto_promotion_rollback",
    "promotion_policy_too_strict",
    "promotion_policy_too_loose",
]
LessonStatus = Literal[
    "candidate",
    "under_review",
    "accepted",
    "rejected",
    "promoted",
    "expired",
]
LessonImpact = Literal["low", "medium", "high", "critical"]
LessonSourceKind = Literal[
    "finding",
    "admission_run",
    "gate_decision",
    "graph_correction",
    "graph_promotion",
    "domain_event",
]
FeedbackType = Literal["confirm", "refute", "supplement", "uncertain"]


class LessonScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["project", "environment", "repository"] = "project"
    id: str = Field(min_length=1, max_length=1000)


class LessonSourceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: LessonSourceKind
    id: str = Field(min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=255)
    expectedHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")


class StructuredLessonObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observationType: Literal["fact", "signal", "context"]
    field: str = Field(min_length=1, max_length=160)
    value: Any
    sourceRef: str | None = Field(default=None, max_length=1000)


class CreateLessonCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lessonType: LessonType
    sourceEvent: LessonSourceEvent
    scope: LessonScope
    summary: str = Field(min_length=1, max_length=2000)
    observations: list[StructuredLessonObservation] = Field(min_length=1, max_length=100)
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    rawRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    confidence: float = Field(ge=0.0, le=1.0)
    frequency: int = Field(default=1, ge=1, le=1_000_000)
    impact: LessonImpact
    dedupeKey: str = Field(min_length=1, max_length=255)
    expiresAt: datetime | None = None


class LessonFeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feedbackType: FeedbackType
    reason: str = Field(min_length=1, max_length=4000)
    observations: list[StructuredLessonObservation] = Field(default_factory=list, max_length=100)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1, max_length=100)
    idempotencyKey: str = Field(min_length=1, max_length=255)


class LessonReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["accepted", "rejected", "needs_evidence"]
    confirmedFact: bool
    reason: str = Field(min_length=1, max_length=4000)
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    expectedLockVersion: int = Field(ge=1)
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def require_confirmed_evidence_for_acceptance(self) -> "LessonReviewRequest":
        if self.decision == "accepted" and (not self.confirmedFact or not self.evidenceRefs):
            raise ValueError("accepted Lesson review requires a confirmed fact and evidence")
        if self.decision != "accepted" and self.confirmedFact:
            raise ValueError("only an accepted Lesson review may confirm a fact")
        return self


class LessonPromotionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    memoryType: Literal["episodic", "semantic", "procedural"] = "semantic"
    reason: str = Field(min_length=1, max_length=4000)
    expectedLockVersion: int = Field(ge=1)
    idempotencyKey: str = Field(min_length=1, max_length=255)


class FeedbackTaxonomyContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.feedback-taxonomy.v1"]
    taxonomyId: str = Field(min_length=1)
    lessonType: LessonType
    sourceKinds: list[LessonSourceKind] = Field(min_length=1)
    descriptionKey: str = Field(min_length=1)
    reviewRequired: Literal[True]
    promotionEligible: bool


class LessonEvidenceContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.lesson-evidence.v1"]
    lessonEvidenceId: str
    candidateId: str
    evidenceRef: dict[str, Any]
    rawRef: dict[str, Any]
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    retentionState: Literal["active", "missing", "purged", "expired"]
    classification: Literal["public", "internal", "confidential", "restricted"]
    redactionStatus: Literal["not_required", "redacted", "unavailable"]
    capturedAt: str

    @model_validator(mode="after")
    def require_stable_refs(self) -> "LessonEvidenceContract":
        if not self.evidenceRef or not self.rawRef:
            raise ValueError("Lesson evidence requires both evidenceRef and rawRef")
        return self


class LessonCandidateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.lesson-candidate.v1"]
    candidateId: str
    projectId: str
    lessonType: LessonType
    sourceEvent: LessonSourceEvent
    sourceEventHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    scope: LessonScope
    summary: str = Field(min_length=1)
    observations: list[StructuredLessonObservation] = Field(min_length=1)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    rawRefs: list[dict[str, Any]] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    frequency: int = Field(ge=1)
    impact: LessonImpact
    status: LessonStatus
    dedupeKey: str = Field(min_length=1)
    clusterKey: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    clusterSize: int = Field(ge=1)
    feedbackSummary: dict[str, int]
    feedbackConflict: bool
    reviewRefs: list[dict[str, Any]]
    promotionRefs: list[dict[str, Any]]
    traceRefs: list[str]
    auditRefs: list[dict[str, Any]]
    lockVersion: int = Field(ge=1)
    expiresAt: str | None
    createdAt: str
    updatedAt: str
    readOnly: bool


class LessonReviewContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.lesson-review.v1"]
    lessonReviewId: str
    candidateId: str
    decision: Literal["accepted", "rejected", "needs_evidence"]
    confirmedFact: bool
    reason: str = Field(min_length=1)
    evidenceRefs: list[dict[str, Any]]
    reviewerRef: dict[str, Any]
    idempotencyKey: str
    candidateLockVersion: int = Field(ge=1)
    reviewedAt: str


class PromotionResultContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.lesson-promotion-result.v1"]
    promotionResultId: str
    candidateId: str
    status: Literal["approval_pending", "promoted", "rejected", "failed", "partial"]
    memoryType: Literal["episodic", "semantic", "procedural"]
    memoryRef: dict[str, Any]
    approvalRefs: list[dict[str, Any]]
    approvalState: Literal["pending", "satisfied", "not_required", "rejected"]
    guardrailEventRefs: list[dict[str, Any]]
    auditRefs: list[dict[str, Any]]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    rawRefs: list[dict[str, Any]] = Field(min_length=1)
    policySnapshot: dict[str, Any]
    projectionState: Literal["skipped", "projected", "projection_failed"]
    reasonCode: str | None
    idempotencyKey: str
    traceId: str
    createdAt: str

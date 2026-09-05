# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


TimelineLifecycleStage = Literal[
    "PREPARE",
    "EXECUTE",
    "OBSERVE",
    "ANALYZE",
    "NORMALIZE",
    "GATE",
]

TimelineVisibility = Literal["full", "redacted", "restricted"]

TIMELINE_STAGES: tuple[TimelineLifecycleStage, ...] = (
    "PREPARE",
    "EXECUTE",
    "OBSERVE",
    "ANALYZE",
    "NORMALIZE",
    "GATE",
)
TIMELINE_STAGE_INDEX = {
    stage: index for index, stage in enumerate(TIMELINE_STAGES)
}


def timeline_event_sort_tuple(
    lifecycle_stage: TimelineLifecycleStage,
    occurred_at: datetime,
    source_sequence: int,
    event_id: str,
) -> tuple[int, datetime, int, str]:
    """One stable ordering authority shared by read-only event projections."""

    return (
        TIMELINE_STAGE_INDEX[lifecycle_stage],
        occurred_at,
        source_sequence,
        event_id,
    )


def timeline_event_sort_key(
    lifecycle_stage: TimelineLifecycleStage,
    occurred_at: datetime,
    source_sequence: int,
    event_id: str,
) -> str:
    stage_index, timestamp, sequence, stable_id = timeline_event_sort_tuple(
        lifecycle_stage,
        occurred_at,
        source_sequence,
        event_id,
    )
    return (
        f"{stage_index:02d}|{timestamp.isoformat()}|"
        f"{sequence:012d}|{stable_id}"
    )


class TimelineQuery(BaseModel):
    """Validated execution-scoped filters for the authoritative timeline."""

    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.decision-timeline-query.v1"] = (
        "phase8.decision-timeline-query.v1"
    )
    executionId: UUID
    traceId: UUID | None = None
    lifecycleStages: list[TimelineLifecycleStage] = Field(default_factory=list)
    eventTypes: list[str] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)
    actorTypes: list[str] = Field(default_factory=list)
    occurredAfter: datetime | None = None
    occurredBefore: datetime | None = None
    cursor: str | None = Field(default=None, max_length=4096)
    snapshotAt: datetime | None = None
    pageSize: int = Field(default=50, ge=1, le=200)

    @model_validator(mode="after")
    def validate_time_window(self) -> "TimelineQuery":
        if (
            self.occurredAfter is not None
            and self.occurredBefore is not None
            and self.occurredAfter > self.occurredBefore
        ):
            raise ValueError("occurredAfter must not be after occurredBefore")
        return self


class TimelineUnavailableReason(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: Literal[
        "PERMISSION_RESTRICTED",
        "SOURCE_NOT_RECORDED_OR_RETAINED",
        "SOURCE_PENDING",
        "EXECUTION_NOT_REACHED",
        "EXECUTION_IN_PROGRESS",
        "LEGACY_SCOPE_UNAVAILABLE",
        "LEGACY_STAGE_LINK_MISSING",
        "REFERENCE_NOT_FOUND",
        "REFERENCE_RETAINED_OR_PURGED",
        "CROSS_SCOPE_REFERENCE_BLOCKED",
    ]
    sourceType: str
    detailKey: str
    lifecycleStage: TimelineLifecycleStage | None = None
    referenceType: str | None = None
    referenceId: str | None = None
    retryable: bool = False


class TimelineReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    referenceType: str
    referenceId: str
    relationship: str
    available: bool = True
    visibility: TimelineVisibility = "full"
    unavailableReasonCode: str | None = None
    href: str | None = None


class ExplanationMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messageKey: str
    parameters: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict
    )


class ExplanationPlainView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.execution-explanation-plain.v1"]
    eventId: str
    sourceRefs: list[TimelineReference]
    available: Literal[True]
    requiredCapability: Literal["replay.read"]
    unavailableReasonCode: None = None
    reasonCode: str
    sourceMessageKey: str
    whatHappened: ExplanationMessage
    why: ExplanationMessage
    impact: ExplanationMessage
    nextAction: ExplanationMessage
    evidenceCount: int = Field(ge=0)
    cegPathMeaning: ExplanationMessage | None = None


class ExplanationPolicyProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policyId: str | None = None
    versionId: str | None = None
    versionHash: str | None = None


class ExplanationProfessionalView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.execution-explanation-professional.v1"]
    eventId: str
    sourceRefs: list[TimelineReference]
    available: bool
    requiredCapability: Literal["audit.logs.read"]
    unavailableReasonCode: Literal["PERMISSION_RESTRICTED"] | None = None
    reasonCode: str | None = None
    reasonCodes: list[str] = Field(default_factory=list)
    ruleIds: list[str] = Field(default_factory=list)
    policy: ExplanationPolicyProjection | None = None
    promotionType: str | None = None
    graphLearningMode: str | None = None
    policyDecisionRefs: list[TimelineReference] = Field(default_factory=list)
    approvalState: str | None = None
    humanApproved: bool = False
    approvalRefs: list[TimelineReference] = Field(default_factory=list)
    findingRefs: list[TimelineReference] = Field(default_factory=list)
    metricRefs: list[TimelineReference] = Field(default_factory=list)
    evidenceRefs: list[TimelineReference] = Field(default_factory=list)
    integrityStatus: Literal["complete", "partial", "unavailable"] | None = None


class ExplanationRawSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sourceType: str
    sourceTimestamp: datetime
    projectedAt: datetime
    integrityStatus: Literal["complete", "partial", "unavailable"]
    retentionStatus: Literal["retained", "partial", "unavailable"]


class ExplanationRawView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.execution-explanation-raw.v1"]
    eventId: str
    sourceRefs: list[TimelineReference]
    available: bool
    requiredCapability: Literal["replay.export.read"]
    unavailableReasonCode: Literal["PERMISSION_RESTRICTED"] | None = None
    redactionStatus: Literal["backend_redacted"]
    labelKey: Literal["executionExplanation.authorizedRedactedRaw"]
    source: ExplanationRawSource | None = None
    projection: dict[str, object] | None = None
    truncated: bool = False


class ExplainViewProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.execution-explanation-views.v1"]
    eventId: str
    sourceRefs: list[TimelineReference]
    availableViews: list[Literal["plain", "professional", "raw"]]
    plain: ExplanationPlainView
    professional: ExplanationProfessionalView
    raw: ExplanationRawView


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    eventId: str
    eventType: str
    lifecycleStage: TimelineLifecycleStage
    sequence: int = Field(ge=1)
    sourceSequence: int | None = None
    sortKey: str
    occurredAt: datetime
    status: str
    actorType: str
    actorRef: TimelineReference | None = None
    plainSummaryKey: str
    professionalSummary: str | None
    refs: list[TimelineReference]
    explainView: ExplainViewProjection
    traceId: UUID | None = None
    executionId: UUID
    skillInvocationId: UUID | None = None
    toolCallId: UUID | None = None
    connectorCallId: UUID | None = None
    agentRunId: UUID | None = None
    modelInvocationId: UUID | None = None
    gateDecisionId: UUID | None = None
    approvalId: UUID | None = None
    replayId: str | None = None
    visibility: TimelineVisibility
    unavailableReason: TimelineUnavailableReason | None = None
    cegEventKind: Literal[
        "observed",
        "candidate",
        "validation",
        "promotion",
        "suspension",
        "rollback",
    ] | None = None
    graphLearningMode: str | None = None
    promotionType: str | None = None
    policyDecisionRefs: list[TimelineReference] = Field(default_factory=list)
    approvalRefs: list[TimelineReference] = Field(default_factory=list)


class TimelineStageGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lifecycleStage: TimelineLifecycleStage
    sequence: int = Field(ge=1, le=6)
    status: Literal[
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
        "unavailable",
    ]
    eventCount: int = Field(ge=0)
    pageEventCount: int = Field(ge=0)
    events: list[TimelineEvent]
    unavailableReason: TimelineUnavailableReason | None = None


class TimelinePagination(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pageSize: int = Field(ge=1, le=200)
    totalEvents: int = Field(ge=0)
    returnedEvents: int = Field(ge=0)
    hasMore: bool
    nextCursor: str | None = None
    snapshotAt: datetime


class TimelineProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.decision-timeline.v1"]
    generatedAt: datetime
    executionId: UUID
    projectId: UUID | None
    authoritative: Literal[True]
    readOnly: Literal[True]
    writesDecision: Literal[False]
    sortOrder: list[str]
    appliedFilters: dict[str, object]
    capabilityProjection: dict[str, bool]
    stageGroups: list[TimelineStageGroup] = Field(min_length=6, max_length=6)
    unavailableReasons: list[TimelineUnavailableReason]
    pagination: TimelinePagination


__all__ = [
    "ExplainViewProjection",
    "ExplanationMessage",
    "ExplanationPlainView",
    "ExplanationProfessionalView",
    "ExplanationRawView",
    "TimelineEvent",
    "TimelineLifecycleStage",
    "TimelinePagination",
    "TimelineProjection",
    "TimelineQuery",
    "TimelineReference",
    "TimelineStageGroup",
    "TimelineUnavailableReason",
    "TimelineVisibility",
    "TIMELINE_STAGE_INDEX",
    "TIMELINE_STAGES",
    "timeline_event_sort_key",
    "timeline_event_sort_tuple",
]

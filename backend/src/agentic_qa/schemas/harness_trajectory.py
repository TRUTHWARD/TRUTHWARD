# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.schemas.decision_timeline import TimelineLifecycleStage


HarnessTrajectoryEventType = Literal[
    "HARNESS_RUN_STARTED",
    "CONTEXT_ASSEMBLED",
    "PROFILE_RESOLVED",
    "EXTENSIONS_RESOLVED",
    "MODEL_SELECTED",
    "MODEL_INVOKED",
    "MODEL_DEGRADED",
    "AGENT_STEP_COMPLETED",
    "AGENT_OUTPUT_REJECTED",
    "SKILL_INTENT_PRODUCED",
    "SKILL_BINDING_RESOLVED",
    "SKILL_INVOCATION_STARTED",
    "SKILL_INVOCATION_COMPLETED",
    "TOOL_CALLED",
    "CONNECTOR_CALLED",
    "OBSERVATION_RECEIVED",
    "TURN_COMPLETED",
    "APPROVAL_REQUIRED",
    "GUARDRAIL_BLOCKED",
    "HARNESS_RUN_COMPLETED",
    "HARNESS_RUN_DEGRADED",
    "HARNESS_RUN_BLOCKED",
    "HARNESS_RUN_FAILED",
    "HARNESS_RUN_CANCELLED",
    "DOMAIN_EVENT_RECORDED",
    "EVIDENCE_RECORDED",
    "FINDING_NORMALIZED",
    "GATE_DECIDED",
    "AUDIT_RECORDED",
    "REPLAY_FROZEN",
]


class _StrictTrajectoryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HarnessTrajectoryAnchor(_StrictTrajectoryModel):
    rootTraceId: UUID | None = None
    workflowRunId: UUID | None = None
    executionId: UUID | None = None
    planId: UUID | None = None
    admissionRunId: UUID | None = None

    @model_validator(mode="after")
    def require_one_anchor(self) -> "HarnessTrajectoryAnchor":
        selected = [
            ("root_trace", self.rootTraceId),
            ("workflow_run", self.workflowRunId),
            ("execution", self.executionId),
            ("plan", self.planId),
            ("admission_run", self.admissionRunId),
        ]
        if sum(value is not None for _, value in selected) != 1:
            raise ValueError("exactly one Harness Trajectory anchor is required")
        return self

    def selected(self) -> tuple[str, UUID]:
        for name, value in (
            ("root_trace", self.rootTraceId),
            ("workflow_run", self.workflowRunId),
            ("execution", self.executionId),
            ("plan", self.planId),
            ("admission_run", self.admissionRunId),
        ):
            if value is not None:
                return name, value
        raise AssertionError("validated trajectory anchor has no selected value")


class HarnessTrajectoryReference(_StrictTrajectoryModel):
    referenceType: str = Field(min_length=1, max_length=120)
    referenceId: str = Field(min_length=1, max_length=1000)
    relationship: str = Field(min_length=1, max_length=120)
    available: bool = True
    redactionStatus: Literal["not_required", "backend_redacted", "unavailable"] = (
        "not_required"
    )
    unavailableReasonCode: str | None = Field(default=None, max_length=160)

    @model_validator(mode="after")
    def validate_availability(self) -> "HarnessTrajectoryReference":
        if self.available and self.redactionStatus == "unavailable":
            raise ValueError("available reference cannot have unavailable redaction status")
        if not self.available and not self.unavailableReasonCode:
            raise ValueError("unavailable reference requires unavailableReasonCode")
        return self


class HarnessTrajectoryEvent(_StrictTrajectoryModel):
    eventId: str = Field(min_length=1, max_length=1000)
    occurredAt: datetime
    persistedAt: datetime
    sequence: int = Field(ge=1)
    sourceSequence: int = Field(default=0, ge=0)
    sortKey: str = Field(min_length=1, max_length=2000)
    lifecycleStage: TimelineLifecycleStage
    eventType: HarnessTrajectoryEventType
    actorType: str = Field(min_length=1, max_length=120)
    actorRef: HarnessTrajectoryReference | None = None
    sourceRefs: list[HarnessTrajectoryReference] = Field(min_length=1, max_length=100)
    inputRefs: list[HarnessTrajectoryReference] = Field(default_factory=list, max_length=500)
    outputRefs: list[HarnessTrajectoryReference] = Field(default_factory=list, max_length=500)
    evidenceRefs: list[HarnessTrajectoryReference] = Field(default_factory=list, max_length=500)
    traceRefs: list[HarnessTrajectoryReference] = Field(default_factory=list, max_length=500)
    guardrailRefs: list[HarnessTrajectoryReference] = Field(default_factory=list, max_length=500)
    approvalRefs: list[HarnessTrajectoryReference] = Field(default_factory=list, max_length=500)
    replayRefs: list[HarnessTrajectoryReference] = Field(default_factory=list, max_length=500)
    status: str = Field(min_length=1, max_length=120)
    reasonCode: str | None = Field(default=None, max_length=255)
    professionalSummary: str = Field(min_length=1, max_length=2000)
    limitations: list[str] = Field(default_factory=list, max_length=200)
    redactionStatus: Literal["backend_redacted", "not_required", "unavailable"]
    availability: Literal["available", "partial", "unavailable"]


class HarnessTrajectorySourceAvailability(_StrictTrajectoryModel):
    sourceType: str = Field(min_length=1, max_length=120)
    availability: Literal["available", "not_observed", "unavailable"]
    recordCount: int = Field(ge=0)
    reasonCode: str | None = Field(default=None, max_length=160)


class HarnessTrajectoryScope(_StrictTrajectoryModel):
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: UUID
    environmentId: UUID | None = None
    scopeDecisionRef: str = Field(min_length=1, max_length=1000)
    serverDerived: Literal[True] = True


class HarnessTrajectoryProjection(_StrictTrajectoryModel):
    schemaVersion: Literal["phase8.harness-trajectory.v1"] = (
        "phase8.harness-trajectory.v1"
    )
    generatedAt: datetime
    anchor: HarnessTrajectoryAnchor
    scope: HarnessTrajectoryScope
    authoritativeFactSource: Literal[False] = False
    sourceRecordsAuthoritative: Literal[True] = True
    readOnly: Literal[True] = True
    writesBusinessState: Literal[False] = False
    sortOrder: list[str]
    events: list[HarnessTrajectoryEvent]
    sourceAvailability: list[HarnessTrajectorySourceAvailability]
    limitations: list[str] = Field(default_factory=list)
    redactionStatus: Literal["backend_redacted"] = "backend_redacted"


__all__ = [
    "HarnessTrajectoryAnchor",
    "HarnessTrajectoryEvent",
    "HarnessTrajectoryEventType",
    "HarnessTrajectoryProjection",
    "HarnessTrajectoryReference",
    "HarnessTrajectoryScope",
    "HarnessTrajectorySourceAvailability",
]

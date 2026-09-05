# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.runtime.qa_harness.stop_reasons import HarnessRunStatus, StopReason


class _StrictHarnessModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class HarnessEvidenceRef(_StrictHarnessModel):
    type: str = Field(min_length=1, max_length=120)
    ref: str = Field(min_length=1, max_length=1000)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    metadata: dict[str, Any] = Field(default_factory=dict)


class BudgetSnapshot(_StrictHarnessModel):
    turnsUsed: int = Field(default=0, ge=0)
    modelCallsUsed: int = Field(default=0, ge=0)
    skillInvocationsUsed: int = Field(default=0, ge=0)
    toolCallsUsed: int = Field(default=0, ge=0)
    maxTurns: int = Field(ge=1)
    maxModelCalls: int = Field(ge=0)
    maxSkillInvocations: int = Field(ge=0)
    maxToolCalls: int = Field(ge=0)


class HarnessContextBlock(_StrictHarnessModel):
    sourceRef: str = Field(min_length=1, max_length=1000)
    sourceType: str = Field(min_length=1, max_length=120)
    sourceVersion: str | int | None = None
    revision: str | int | None = None
    scopeSnapshot: dict[str, Any] = Field(default_factory=dict)
    freshness: dict[str, Any] = Field(default_factory=dict)
    trustBoundary: Literal[
        "platform_authority",
        "service_authorized",
        "service_observation",
        "external_untrusted",
    ]
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redactionStatus: Literal["redacted", "not_required", "unavailable"]
    redactionPolicyVersion: str = Field(
        default="phase8.authorized-context.v1",
        min_length=1,
        max_length=120,
    )
    available: bool
    unavailableReason: str | None = Field(default=None, max_length=500)
    evidenceRefs: list[HarnessEvidenceRef] = Field(default_factory=list, max_length=500)
    limitations: list[str] = Field(default_factory=list, max_length=200)
    content: Any = None

    @model_validator(mode="after")
    def validate_availability(self) -> "HarnessContextBlock":
        if self.available and self.redactionStatus == "unavailable":
            raise ValueError("available context cannot have unavailable redaction status")
        if not self.available and not self.unavailableReason:
            raise ValueError("unavailable context requires unavailableReason")
        if not self.available and self.content is not None:
            raise ValueError("unavailable context cannot include content")
        return self


class SkillIntent(_StrictHarnessModel):
    intentId: str = Field(min_length=1, max_length=255)
    extensionPointId: str = Field(pattern=r"^[A-Z]+\.[a-z][a-z0-9_.-]*$", max_length=160)
    request: dict[str, Any]
    inputRefs: list[HarnessEvidenceRef] = Field(default_factory=list, max_length=200)
    expectedModelCalls: int = Field(default=1, ge=0, le=10)
    expectedSkillInvocations: int = Field(default=1, ge=1, le=10)
    expectedToolCalls: int = Field(default=0, ge=0, le=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentStepResult(_StrictHarnessModel):
    result: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[HarnessEvidenceRef] = Field(default_factory=list, max_length=500)
    limitations: list[str] = Field(default_factory=list, max_length=200)
    skillIntents: list[SkillIntent] = Field(default_factory=list, max_length=1)
    status: Literal["continue", "completed", "needs_review", "degraded", "blocked", "failed"]
    fallbackUsed: bool = False
    fallbackReason: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_step_shape(self) -> "AgentStepResult":
        if self.status == "continue" and len(self.skillIntents) != 1:
            raise ValueError("continue status requires exactly one Skill Intent")
        if self.status != "continue" and self.skillIntents:
            raise ValueError("terminal Agent step cannot include a Skill Intent")
        if self.fallbackUsed and not self.fallbackReason:
            raise ValueError("fallbackUsed requires fallbackReason")
        return self


class ObservationUsage(_StrictHarnessModel):
    modelCalls: int = Field(default=0, ge=0)
    skillInvocations: int = Field(default=0, ge=0)
    toolCalls: int = Field(default=0, ge=0)


class Observation(_StrictHarnessModel):
    observationId: str = Field(min_length=1, max_length=255)
    observationRef: str = Field(min_length=1, max_length=1000)
    intentId: str | None = Field(default=None, max_length=255)
    extensionPointId: str | None = Field(default=None, max_length=160)
    source: Literal["service"]
    kind: str = Field(min_length=1, max_length=120)
    status: Literal["completed", "degraded", "unavailable", "blocked", "failed"]
    available: bool
    result: dict[str, Any]
    evidenceRefs: list[HarnessEvidenceRef] = Field(default_factory=list, max_length=500)
    limitations: list[str] = Field(default_factory=list, max_length=200)
    reasonCode: StopReason | None = None
    usage: ObservationUsage = Field(default_factory=ObservationUsage)
    skillInvocationRef: str | None = Field(default=None, max_length=1000)
    modelInvocationRef: str | None = Field(default=None, max_length=1000)
    agentRunRef: str | None = Field(default=None, max_length=1000)
    traceRefs: list[str] = Field(default_factory=list, max_length=500)
    redactionStatus: Literal["redacted", "not_required"]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_status(self) -> "Observation":
        if self.available and self.status in {"unavailable", "blocked", "failed"}:
            raise ValueError("terminal unavailable Observation cannot be available")
        if not self.available and self.status in {"completed", "degraded"}:
            raise ValueError("completed or degraded Observation must be available")
        if not self.available and self.reasonCode is None:
            raise ValueError("unavailable Observation requires reasonCode")
        return self


class HarnessRunSpec(_StrictHarnessModel):
    runId: str = Field(min_length=1, max_length=255)
    workflow: str = Field(min_length=1, max_length=160)
    lifecycleStage: str = Field(min_length=1, max_length=50)
    objective: str = Field(min_length=1, max_length=4000)
    inputRefs: list[HarnessEvidenceRef] = Field(default_factory=list, max_length=500)
    allowedExtensionPoints: list[str] = Field(min_length=1, max_length=100)
    policySnapshot: dict[str, Any]
    profileSnapshot: dict[str, Any]
    maxTurns: int = Field(ge=1, le=100)
    maxModelCalls: int = Field(ge=0, le=100)
    maxSkillInvocations: int = Field(ge=0, le=100)
    maxToolCalls: int = Field(ge=0, le=1000)
    timeoutSeconds: float = Field(gt=0.0, le=3600.0)
    stopConditions: list[str] = Field(default_factory=list, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ensure_unique_extension_points(self) -> "HarnessRunSpec":
        if len(set(self.allowedExtensionPoints)) != len(self.allowedExtensionPoints):
            raise ValueError("allowedExtensionPoints must be unique")
        return self


class HarnessRunContext(_StrictHarnessModel):
    currentTurn: int = Field(default=0, ge=0)
    startedAt: datetime
    deadlineAt: datetime
    modelCallsUsed: int = Field(default=0, ge=0)
    skillInvocationsUsed: int = Field(default=0, ge=0)
    toolCallsUsed: int = Field(default=0, ge=0)
    observations: list[Observation] = Field(default_factory=list, max_length=1000)
    evidenceRefs: list[HarnessEvidenceRef] = Field(default_factory=list, max_length=2000)
    limitations: list[str] = Field(default_factory=list, max_length=1000)
    cancellationState: Literal["active", "cancelled"] = "active"


class HarnessRunResult(_StrictHarnessModel):
    status: HarnessRunStatus
    result: dict[str, Any]
    evidence: list[HarnessEvidenceRef] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    stopReason: StopReason
    turnsUsed: int = Field(ge=0)
    modelCallsUsed: int = Field(ge=0)
    skillInvocationsUsed: int = Field(ge=0)
    toolCallsUsed: int = Field(ge=0)
    trajectoryRefs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

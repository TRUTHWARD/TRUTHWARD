# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


GateMode = Literal["observe", "shadow", "enforce"]
SimulationStatus = Literal["queued", "running", "completed", "partial", "failed", "cancelled", "timed_out"]


class _StrictGatePolicySimulationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, hide_input_in_errors=True)


class SimulationRequest(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-simulation-request.v1"] = "phase8.gate-policy-simulation-request.v1"
    policyVersionId: UUID
    caseSnapshotIds: list[UUID] = Field(default_factory=list, max_length=500)
    maxCases: int = Field(default=100, ge=1, le=500)
    timeoutSeconds: int = Field(default=300, ge=1, le=3600)
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_requested_case_limit(self) -> "SimulationRequest":
        if self.caseSnapshotIds and len(self.caseSnapshotIds) > self.maxCases:
            raise ValueError("caseSnapshotIds cannot exceed maxCases")
        return self


class SimulationCaseDiff(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-simulation-case-diff.v1"] = "phase8.gate-policy-simulation-case-diff.v1"
    caseId: UUID
    caseIndex: int = Field(ge=0)
    gateDecisionId: UUID | None = None
    executionId: UUID | None = None
    gateInputSnapshotRef: str = Field(min_length=1, max_length=500)
    gateInputSnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    inputFingerprint: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    status: Literal["completed", "unavailable", "failed"]
    oldDecision: Literal["pass", "warn", "fail", "blocked"] | None = None
    newDecision: Literal["pass", "warn", "fail", "blocked"] | None = None
    addedReasonCodes: list[str] = Field(default_factory=list)
    removedReasonCodes: list[str] = Field(default_factory=list)
    falsePassRisk: bool = False
    newBlock: bool = False
    errorCode: str | None = Field(default=None, max_length=120)
    authoritative: Literal[False] = False


class SimulationSummary(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-simulation-summary.v1"] = "phase8.gate-policy-simulation-summary.v1"
    totalCases: int = Field(ge=0)
    completedCases: int = Field(ge=0)
    changedCases: int = Field(ge=0)
    unchangedCases: int = Field(ge=0)
    falsePassRiskCount: int = Field(ge=0)
    newBlockCount: int = Field(ge=0)
    unavailableCases: int = Field(ge=0)
    failedCases: int = Field(ge=0)
    decisionTransitions: dict[str, int]
    complete: bool
    authoritative: Literal[False] = False


class SimulationRun(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-simulation-run.v1"] = "phase8.gate-policy-simulation-run.v1"
    simulationRunId: UUID
    projectId: UUID
    policyId: UUID
    sourcePolicyVersionId: UUID | None = None
    policyVersionId: UUID
    policyVersionHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    evaluatorVersion: str = Field(min_length=1, max_length=80)
    runType: Literal["historical", "shadow"]
    status: SimulationStatus
    datasetFingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    totalCases: int = Field(ge=0)
    completedCases: int = Field(ge=0)
    unavailableCases: int = Field(ge=0)
    failedCases: int = Field(ge=0)
    summary: SimulationSummary | None = None
    cases: list[SimulationCaseDiff] = Field(default_factory=list)
    jobId: UUID | None = None
    traceRef: str | None = None
    errorCode: str | None = None
    retentionUntil: datetime
    createdAt: datetime
    startedAt: datetime | None = None
    completedAt: datetime | None = None
    authoritative: Literal[False] = False
    writesGateDecision: Literal[False] = False


class GateModeRequest(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-mode-request.v1"] = "phase8.gate-policy-mode-request.v1"
    mode: Literal["observe", "shadow"]
    expectedCurrentBindingId: UUID | None = None
    idempotencyKey: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class GateModeProjection(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-mode-projection.v1"] = "phase8.gate-policy-mode-projection.v1"
    projectId: UUID
    mode: GateMode
    bindingId: UUID | None = None
    policyVersionId: UUID | None = None
    policyVersionHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    active: bool
    authoritative: bool
    blocksGate: bool
    effectiveFrom: datetime | None = None
    historyRef: str | None = None


class ActivationRequest(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-activation-request.v1"] = "phase8.gate-policy-activation-request.v1"
    simulationRunId: UUID
    expectedCurrentBindingId: UUID | None = None
    expectedCurrentPolicyVersionId: UUID | None = None
    maxFalsePassRiskCount: int = Field(default=0, ge=0)
    maxNewBlockCount: int = Field(default=100, ge=0)
    idempotencyKey: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class ActivationResult(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-activation-result.v1"] = "phase8.gate-policy-activation-result.v1"
    activationRequestId: UUID
    status: Literal["approval_pending", "applied"]
    projectId: UUID
    policyId: UUID
    policyVersionId: UUID
    policyVersionHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    simulationRunId: UUID
    approvalId: UUID
    bindingId: UUID | None = None
    previousBindingId: UUID | None = None
    traceRef: str
    authoritative: bool
    effectiveFrom: datetime | None = None


class RollbackRequest(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-rollback-request.v1"] = "phase8.gate-policy-rollback-request.v1"
    targetPolicyVersionId: UUID
    expectedCurrentBindingId: UUID
    expectedCurrentPolicyVersionId: UUID
    idempotencyKey: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class RollbackResult(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-rollback-result.v1"] = "phase8.gate-policy-rollback-result.v1"
    rollbackRequestId: UUID
    status: Literal["approval_pending", "applied"]
    projectId: UUID
    targetPolicyVersionId: UUID
    approvalId: UUID
    bindingId: UUID | None = None
    replacedBindingId: UUID | None = None
    traceRef: str
    authoritative: bool
    effectiveFrom: datetime | None = None


class RollbackTargetProjection(_StrictGatePolicySimulationModel):
    schemaVersion: Literal["phase8.gate-policy-rollback-target.v1"] = "phase8.gate-policy-rollback-target.v1"
    policyId: UUID
    policyVersionId: UUID
    policyVersionHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    previousBindingId: UUID
    lastEnforcedAt: datetime
    available: bool
    unavailableReason: Literal["current", "archived", "unavailable", "corrupted"] | None = None


class CancelSimulationRequest(_StrictGatePolicySimulationModel):
    expectedStatus: Literal["queued", "running"]
    reason: str = Field(min_length=1, max_length=1000)


class SimulationListProjection(_StrictGatePolicySimulationModel):
    items: list[SimulationRun]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    pageSize: int = Field(ge=1, le=100)

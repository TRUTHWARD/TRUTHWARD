# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_qa.domain.enums import (
    ExecutionStage,
    FindingCategory,
    FindingSource,
    FindingSeverity,
    FindingStatus,
    GateResult,
    GuardrailDecisionType,
    RiskLevel,
    TaskStatus,
    TestDomain,
    TriageCategory,
)


class ExecutionOptions(BaseModel):
    runFunctional: bool = True
    runPerformance: bool = True
    runSecurity: bool = True
    enableTriage: bool = True
    enableHealing: bool = False
    parallelism: int = 5


class CreateExecutionRequest(BaseModel):
    planId: UUID
    executionPlanId: UUID | None = None
    environment: str
    triggeredBy: str | None = None
    options: ExecutionOptions = Field(default_factory=ExecutionOptions)


class ExecutionSummary(BaseModel):
    functional: str = "queued"
    performance: str = "queued"
    security: str = "queued"


class ExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    planId: UUID = Field(alias="plan_id")
    status: TaskStatus
    stage: ExecutionStage
    environment: str
    startedAt: datetime | None = Field(default=None, alias="started_at")
    endedAt: datetime | None = Field(default=None, alias="ended_at")
    summary: dict[str, Any]


class RetryExecutionRequest(BaseModel):
    scope: str = "failed_only"


class HealExecutionRequest(BaseModel):
    mode: str = "suggest_only"


class ExecutionProgressResponse(BaseModel):
    executionId: UUID
    status: TaskStatus
    stage: ExecutionStage
    progress: int
    currentTask: str | None = None
    completedTasks: int
    totalTasks: int


class TaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    executionId: UUID = Field(alias="execution_id")
    parentTaskId: UUID | None = Field(default=None, alias="parent_task_id")
    domain: TestDomain
    taskType: str = Field(alias="task_type")
    runner: str
    status: TaskStatus
    stage: ExecutionStage | None = None
    retryCount: int = Field(alias="retry_count")
    resultPayload: dict[str, Any] = Field(alias="result_payload")
    errorMessage: str | None = Field(default=None, alias="error_message")
    startedAt: datetime | None = Field(default=None, alias="started_at")
    endedAt: datetime | None = Field(default=None, alias="ended_at")


class ArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    taskId: UUID | None = Field(default=None, alias="task_id")
    artifactType: str = Field(alias="artifact_type")
    uri: str
    summary: str | None = None
    redactionStatus: str | None = None
    redactedUri: str | None = None
    expiresAt: datetime | None = None
    metadata: dict[str, Any]
    createdAt: datetime = Field(alias="created_at")


class LogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    taskId: UUID | None = Field(default=None, alias="task_id")
    level: str
    message: str
    context: dict[str, Any]
    createdAt: datetime = Field(alias="created_at")


class MetricResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    taskId: UUID | None = Field(default=None, alias="task_id")
    metricName: str = Field(alias="metric_name")
    metricValue: Decimal = Field(alias="metric_value")
    metricUnit: str | None = Field(default=None, alias="metric_unit")
    thresholdValue: Decimal | None = Field(default=None, alias="threshold_value")
    baselineValue: Decimal | None = Field(default=None, alias="baseline_value")
    metadata: dict[str, Any]


class GateResponse(BaseModel):
    executionId: UUID
    functional: GateResult
    performance: GateResult
    security: GateResult
    overall: GateResult
    reasons: list[str]


class TriageResultResponse(BaseModel):
    taskId: UUID | None
    category: TriageCategory
    confidence: float
    evidence: list[str]
    challenged: bool
    finalDecisionBy: str | None


class HealingSuggestionResponse(BaseModel):
    taskId: UUID | None
    type: str
    summary: str
    patch: str | None


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    executionId: UUID = Field(alias="execution_id")
    taskId: UUID | None = Field(default=None, alias="task_id")
    domain: TestDomain
    source: FindingSource
    severity: FindingSeverity
    status: FindingStatus
    category: FindingCategory
    title: str
    summary: str
    description: str | None = None
    evidenceRef: UUID | None = Field(default=None, alias="evidence_ref")
    confidence: float | None = None
    dedupeKey: str | None = None
    rawRef: str | None = None
    location: dict[str, Any] | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    comment: str | None = None
    metadata: dict[str, Any]


class UpdateFindingRequest(BaseModel):
    status: FindingStatus
    comment: str | None = None


class VisualInputRef(BaseModel):
    artifactId: UUID
    artifactType: str


class SemanticAction(BaseModel):
    schemaVersion: str = "phase7.v1"
    actionId: str
    actionType: str
    semanticTarget: dict[str, Any] = Field(default_factory=dict)
    targetHints: dict[str, Any] = Field(default_factory=dict)
    locatorStrategy: dict[str, Any] = Field(default_factory=dict)
    fallbackPolicy: dict[str, Any] = Field(default_factory=dict)
    assertionIntent: dict[str, Any] = Field(default_factory=dict)
    riskLevel: RiskLevel = RiskLevel.MEDIUM
    policyRefs: list[str] = Field(default_factory=list)


class VisualGroundingAttemptResponse(BaseModel):
    id: UUID
    executionId: UUID
    taskId: UUID | None
    actionId: str
    actionType: str
    semanticAction: dict[str, Any]
    locatorStrategy: dict[str, Any]
    fallbackPolicy: dict[str, Any]
    candidateLocators: list[dict[str, Any]]
    chosenLocator: dict[str, Any]
    confidence: float | None
    threshold: float | None
    coordinateClickAllowed: bool
    riskLevel: RiskLevel
    guardrailDecision: GuardrailDecisionType | None
    verificationStatus: str | None
    verificationResult: dict[str, Any]
    artifactRefs: list[dict[str, Any]]
    redactionStatus: str
    status: str
    errorMessage: str | None = None
    createdAt: datetime


class VerificationResultResponse(BaseModel):
    id: UUID
    executionId: UUID
    taskId: UUID | None
    visualAttemptId: UUID | None
    verificationType: str
    status: str
    confidence: float | None
    evidence: list[dict[str, Any]]
    artifactRefs: list[dict[str, Any]]
    resultPayload: dict[str, Any]
    normalizedFindingId: UUID | None
    createdAt: datetime

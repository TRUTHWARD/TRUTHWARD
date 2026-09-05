# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from pydantic import BaseModel

from agentic_qa.domain.enums import GateResult


class PullRequestTriggerRequest(BaseModel):
    repository: str
    pullRequestId: str
    branch: str
    commitSha: str


class PullRequestTriggerResponse(BaseModel):
    orchestrationId: UUID
    planId: UUID
    executionId: UUID
    status: str
    gateOverall: str
    retryOfRunId: UUID | None = None


class GateQueryResponse(BaseModel):
    executionId: UUID
    overall: GateResult
    functional: GateResult
    performance: GateResult
    security: GateResult
    reasons: list[str] = []
    traceRefs: list[dict[str, object]] = []
    pipeline: dict[str, object] | None = None
    approvalSummary: dict[str, int] = {}
    findingSummary: dict[str, int] = {}
    ci: dict[str, object] = {}
    resultRefs: dict[str, str | None] = {}


class OrchestrationRunResponse(BaseModel):
    id: UUID
    source: str
    triggerType: str
    status: str
    currentStep: str
    traceId: UUID | None = None
    requestId: str | None = None
    planId: UUID | None = None
    executionId: UUID | None = None
    retryOfRunId: UUID | None = None
    retryOfExecutionId: UUID | None = None
    checkpointCount: int
    result: dict
    errorMessage: str | None = None


class OrchestrationReplayResponse(OrchestrationRunResponse):
    integrationEvent: dict | None = None
    finalEnvelope: dict
    checkpoints: list[dict]

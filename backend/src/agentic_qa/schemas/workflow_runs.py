# SPDX-License-Identifier: Apache-2.0
from typing import Any, Literal

from pydantic import BaseModel, Field


class WorkflowRunAction(BaseModel):
    actionId: str
    label: str
    targetRoute: str
    targetResourceType: str
    targetResourceId: str
    mutation: bool = False


class WorkflowRunBlocker(BaseModel):
    category: str
    blocked: bool
    reason: str | None = None
    sourceStep: str
    approvalId: str | None = None


class WorkflowRunStageSummary(BaseModel):
    stageKey: Literal["requirement", "plan", "approval", "execution", "exploratory", "regression", "gate", "replay"]
    label: str
    status: str
    statusReason: str | None = None
    refs: dict[str, Any] = Field(default_factory=dict)
    checkpointRefs: list[dict[str, Any]] = Field(default_factory=list)
    governanceRefs: dict[str, Any] = Field(default_factory=dict)


class WorkflowRunProjection(BaseModel):
    schemaVersion: Literal["phase8.workflow-run-projection.v1"]
    generatedAt: str
    runId: str
    source: str
    triggerType: str
    status: str
    currentStep: str
    currentState: str
    blocked: bool
    blockedReason: str | None = None
    currentBlocker: WorkflowRunBlocker
    requestId: str | None = None
    traceId: str | None = None
    linkedResources: dict[str, Any]
    testDomains: list[dict[str, Any]] = Field(default_factory=list)
    executionStrategies: list[dict[str, Any]] = Field(default_factory=list)
    governanceStatus: dict[str, Any] = Field(default_factory=dict)
    stageSummaries: list[WorkflowRunStageSummary]
    nextActions: list[WorkflowRunAction]
    checkpointCount: int
    resultSummary: dict[str, Any] = Field(default_factory=dict)
    errorMessage: str | None = None
    startedAt: str | None = None
    endedAt: str | None = None
    createdAt: str
    updatedAt: str
    checkpoints: list[dict[str, Any]] | None = None


class WorkflowRunProjectionList(BaseModel):
    items: list[WorkflowRunProjection]
    total: int
    page: int
    pageSize: int

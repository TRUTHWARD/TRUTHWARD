# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


WorkItemStatus = Literal["open", "assigned", "in_progress", "completed", "cancelled"]
WorkItemPriority = Literal["low", "medium", "high", "urgent"]


class WorkItemCreateRequest(BaseModel):
    projectId: UUID
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    priority: WorkItemPriority = "medium"
    assigneeId: UUID | None = None
    requirementVersionId: UUID | None = None
    requirementItemId: str | None = None
    executionId: UUID | None = None
    findingId: UUID | None = None
    evidenceArtifactId: UUID | None = None
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkItemAssignRequest(BaseModel):
    assigneeId: UUID | None = None


class WorkItemTransitionRequest(BaseModel):
    status: WorkItemStatus
    comment: str | None = None


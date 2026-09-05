# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


RequirementLibraryItemType = Literal[
    "requirement_version",
    "requirement_intake_draft",
    "requirement_intake_preview",
    "requirement_item",
]


class RequirementLibraryFilters(BaseModel):
    projectId: UUID | None = None
    environmentId: UUID | None = None
    requirementVersionId: UUID | None = None
    sourceType: str | None = None
    status: str | None = None
    keyword: str | None = None


class RequirementLibrarySummary(BaseModel):
    requirementVersionCount: int = 0
    intakeDraftCount: int = 0
    intakePreviewCount: int = 0
    requirementItemCount: int = 0
    returnedCount: int = 0


class RequirementLibraryItem(BaseModel):
    itemId: str
    itemType: RequirementLibraryItemType
    sourceType: str
    status: str
    title: str
    summary: str | None = None
    projectId: UUID | None = None
    environmentId: UUID | None = None
    environment: str | None = None
    sourceRef: str | None = None
    sourceUri: str | None = None
    requirementVersionId: UUID | None = None
    linkedRequirementVersionId: UUID | None = None
    requirementItemId: str | None = None
    requirementItemIndex: int | None = None
    intakeDraftId: UUID | None = None
    intakePreviewId: UUID | None = None
    linkedPipelineId: UUID | None = None
    contentHash: str | None = None
    requirementCount: int = 0
    acceptanceCriteriaCount: int = 0
    artifactRefs: list[dict[str, Any]] = Field(default_factory=list)
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    traceId: UUID | None = None
    createdAt: datetime
    updatedAt: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequirementLibraryResponse(BaseModel):
    schemaVersion: Literal["phase8.requirement-library.v1"] = "phase8.requirement-library.v1"
    generatedAt: datetime
    filters: RequirementLibraryFilters
    items: list[RequirementLibraryItem]
    total: int
    page: int
    pageSize: int
    summary: RequirementLibrarySummary
    capability: dict[str, Any] = Field(default_factory=dict)

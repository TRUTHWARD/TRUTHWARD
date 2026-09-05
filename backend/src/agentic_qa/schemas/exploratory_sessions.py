# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


EvidenceType = Literal["screenshot", "log", "link", "execution_artifact", "console", "network", "har", "other"]
RedactionStatus = Literal["not_required", "redacted", "pending"]
SessionStatus = Literal["active", "completed", "cancelled"]
NoteType = Literal["note", "observation", "risk", "question"]


class ExploratoryEvidenceRefInput(BaseModel):
    evidenceType: EvidenceType = "other"
    ref: str = Field(min_length=1)
    summary: str | None = None
    redactionStatus: RedactionStatus | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CreateExploratorySessionRequest(BaseModel):
    projectId: UUID
    environmentId: UUID
    charter: str = Field(min_length=1)
    scope: list[dict[str, Any]] = Field(default_factory=list)
    timeboxMinutes: int = Field(gt=0)
    tester: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AddExploratoryNoteRequest(BaseModel):
    noteType: NoteType
    content: str = Field(min_length=1)
    evidenceRefs: list[ExploratoryEvidenceRefInput] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AddExploratoryEvidenceRequest(ExploratoryEvidenceRefInput):
    pass


class CreateBugCandidateRequest(BaseModel):
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    category: str = "functional_ui"
    confidence: float = Field(default=0.8, ge=0, le=1)
    location: dict[str, Any] = Field(default_factory=dict)
    evidenceRefIds: list[UUID] = Field(default_factory=list)
    evidenceRefs: list[ExploratoryEvidenceRefInput] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EndExploratorySessionRequest(BaseModel):
    debrief: str = Field(min_length=1)
    outcomeSummary: str | None = None
    risks: list[str] = Field(default_factory=list)
    questions: list[str] = Field(default_factory=list)
    followUps: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExploratorySessionQuery(BaseModel):
    projectId: UUID | None = None
    environmentId: UUID | None = None
    status: SessionStatus | None = None


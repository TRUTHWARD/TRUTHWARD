# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class IssueSyncRequest(BaseModel):
    connectorBindingId: UUID
    projectKey: str | None = None
    issueType: str = "Bug"
    forceUpdate: bool = False
    labels: list[str] = Field(default_factory=list)
    extraFields: dict[str, Any] = Field(default_factory=dict)


class IssueWebhookRequest(BaseModel):
    eventId: str
    connectorBindingId: UUID | None = None
    findingId: UUID | None = None
    externalIssueId: str | None = None
    externalIssueKey: str | None = None
    externalStatus: str
    externalIssueUrl: str | None = None
    updatedAt: datetime | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class ExternalIssueLinkResponse(BaseModel):
    id: UUID
    findingId: UUID
    executionId: UUID
    connectorBindingId: UUID | None = None
    connectorName: str
    externalIssueId: str | None = None
    externalIssueKey: str | None = None
    externalIssueUrl: str | None = None
    externalStatus: str | None = None
    syncStatus: str
    idempotencyKey: str
    lastSyncedAt: datetime | None = None
    lastStatusSyncedAt: datetime | None = None
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    replayRefs: list[dict[str, Any]] = Field(default_factory=list)
    traceRefs: list[str] = Field(default_factory=list)
    auditRefs: list[dict[str, Any]] = Field(default_factory=list)
    connectorCallRefs: list[dict[str, Any]] = Field(default_factory=list)
    createdAt: datetime
    updatedAt: datetime


class IssueWebhookResponse(BaseModel):
    status: str
    duplicate: bool = False
    eventId: str
    externalIssueKey: str | None = None
    link: ExternalIssueLinkResponse | None = None


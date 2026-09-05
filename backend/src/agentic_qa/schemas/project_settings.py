# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ProjectRequest(BaseModel):
    key: str
    name: str
    description: str | None = None
    status: str = "active"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProjectUpdateRequest(BaseModel):
    key: str | None = None
    name: str | None = None
    description: str | None = None
    status: str | None = None
    metadata: dict[str, Any] | None = None


class ProjectResponse(BaseModel):
    id: UUID
    key: str
    name: str
    description: str | None = None
    status: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    planCount: int = 0
    executionCount: int = 0
    environmentCount: int = 0
    memberCount: int = 0
    createdBy: UUID | None = None
    createdAt: datetime
    updatedAt: datetime


class EnvironmentRequest(BaseModel):
    key: str
    name: str
    description: str | None = None
    baseUrl: str | None = None
    status: str = "active"
    variables: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EnvironmentUpdateRequest(BaseModel):
    key: str | None = None
    name: str | None = None
    description: str | None = None
    baseUrl: str | None = None
    status: str | None = None
    variables: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


class EnvironmentResponse(BaseModel):
    id: UUID
    projectId: UUID
    key: str
    name: str
    description: str | None = None
    baseUrl: str | None = None
    status: str
    variables: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    createdBy: UUID | None = None
    createdAt: datetime
    updatedAt: datetime


class ProjectMemberRequest(BaseModel):
    userId: UUID
    role: str = "viewer"
    status: str = "active"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProjectMemberUpdateRequest(BaseModel):
    role: str | None = None
    status: str | None = None
    metadata: dict[str, Any] | None = None


class ProjectMemberResponse(BaseModel):
    id: UUID
    projectId: UUID
    userId: UUID | None = None
    userName: str | None = None
    userEmail: str | None = None
    role: str
    status: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    createdBy: UUID | None = None
    createdAt: datetime
    updatedAt: datetime

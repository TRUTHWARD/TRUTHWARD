# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_qa.domain.enums import MemoryScope, MemoryType


class CreateMemoryRequest(BaseModel):
    type: MemoryType
    scope: MemoryScope
    namespace: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    type: MemoryType
    scope: MemoryScope
    namespace: str
    content: str
    metadata: dict[str, Any]
    createdAt: datetime = Field(alias="created_at")
    updatedAt: datetime = Field(alias="updated_at")


class MemoryJobRequest(BaseModel):
    scope: MemoryScope
    namespace: str | None = None


class MemoryJobResponse(BaseModel):
    jobId: UUID
    status: str

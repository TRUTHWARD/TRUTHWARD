# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field


T = TypeVar("T")


class RequestContext(BaseModel):
    request_id: str
    trace_id: str


class Pagination(BaseModel):
    total: int
    page: int = 1
    page_size: int = 20


class PaginatedPayload(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int = 1
    page_size: int = 20


class ApiEnvelope(BaseModel, Generic[T]):
    success: bool = True
    message: str = "ok"
    data: T | dict[str, Any]
    request_id: str = Field(alias="requestId")


class ErrorEnvelope(BaseModel):
    success: bool = False
    message: str
    error_code: str = Field(alias="errorCode")
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str = Field(alias="requestId")


class AuditRecord(BaseModel):
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any] = Field(default_factory=dict)


class HealthItem(BaseModel):
    name: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class TimestampedModel(BaseModel):
    id: UUID
    created_at: datetime
    updated_at: datetime | None = None

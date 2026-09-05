# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


UserEdition = Literal["basic", "community", "pro", "enterprise"]
UserStatusValue = Literal["active", "inactive", "disabled"]
UserRoleValue = Literal["admin", "user", "system", "agent"]
AccessControlEffect = Literal["allow", "deny"]


class AccessControlUserAccessChangeRequest(BaseModel):
    edition: UserEdition | None = None
    roles: list[UserRoleValue] | None = None
    status: UserStatusValue | None = None
    reason: str = Field(min_length=1)
    idempotencyKey: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AccessControlRoleCapabilityRequest(BaseModel):
    roleName: str = Field(min_length=1, max_length=80)
    capabilityKey: str = Field(min_length=1, max_length=120)
    effect: AccessControlEffect
    reason: str = Field(min_length=1)
    idempotencyKey: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AccessControlUserEntitlementRequest(BaseModel):
    userId: UUID
    capabilityKey: str = Field(min_length=1, max_length=120)
    effect: AccessControlEffect
    expiresAt: datetime | None = None
    reason: str = Field(min_length=1)
    idempotencyKey: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AuditRetentionActionRequest(BaseModel):
    auditLogId: UUID
    action: Literal["archive", "purge", "set_legal_hold", "clear_legal_hold"]
    dryRun: bool = True
    retentionUntil: datetime | None = None
    reason: str | None = None
    idempotencyKey: str | None = Field(default=None, min_length=1)

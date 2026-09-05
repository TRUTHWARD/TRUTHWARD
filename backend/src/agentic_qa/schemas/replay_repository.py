# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class ReplayRepositoryFreezeRequest(BaseModel):
    executionId: UUID
    idempotencyKey: str | None = None


class ReplayRepositoryRetentionActionRequest(BaseModel):
    action: Literal["archive", "purge", "set_legal_hold", "clear_legal_hold"]
    dryRun: bool = True
    retentionUntil: datetime | None = None
    reason: str | None = None


class ReplayGovernancePolicyUpdateRequest(BaseModel):
    approvalMode: Literal["always", "policy_only", "threshold"]
    thresholdLevel: Literal["low", "medium", "high"] = "high"
    policyRules: dict[str, object] = Field(default_factory=dict)
    reason: str | None = None

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict


class CommunityAnalysisMaterializeRequest(BaseModel):
    """Optional server-owned anchors for a Community analysis refresh."""

    model_config = ConfigDict(extra="forbid")

    requirementVersionId: UUID | None = None
    executionId: UUID | None = None

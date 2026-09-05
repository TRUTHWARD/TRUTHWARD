# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IntegrationSkillStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class IntegrationEvidenceRef(BaseModel):
    type: str
    ref: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationSkillInput(BaseModel):
    skill: str
    operation: str
    provider: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationSkillResult(BaseModel):
    skill: str
    operation: str
    status: IntegrationSkillStatus
    data: dict[str, Any] = Field(default_factory=dict)
    evidence: list[IntegrationEvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.status == IntegrationSkillStatus.COMPLETED


def completed_result(
    *,
    skill: str,
    operation: str,
    data: dict[str, Any],
    evidence: list[IntegrationEvidenceRef] | None = None,
    metadata: dict[str, Any] | None = None,
) -> IntegrationSkillResult:
    return IntegrationSkillResult(
        skill=skill,
        operation=operation,
        status=IntegrationSkillStatus.COMPLETED,
        data=data,
        evidence=evidence or [],
        metadata=metadata or {},
    )


def failed_result(
    *,
    skill: str,
    operation: str,
    error: str,
    data: dict[str, Any] | None = None,
    evidence: list[IntegrationEvidenceRef] | None = None,
    metadata: dict[str, Any] | None = None,
) -> IntegrationSkillResult:
    return IntegrationSkillResult(
        skill=skill,
        operation=operation,
        status=IntegrationSkillStatus.FAILED,
        data=data or {},
        evidence=evidence or [],
        metadata=metadata or {},
        errors=[error],
    )


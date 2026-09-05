# SPDX-License-Identifier: Apache-2.0
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from agentic_qa.domain.enums import RiskLevel, TestDomain
from agentic_qa.schemas.requirement_scope import RequirementItemRef, RequirementScope


class RequirementPipelineRequest(BaseModel):
    name: str
    sourceRef: str
    document: str = Field(min_length=1)
    requirements: list[str] = Field(default_factory=list)
    acceptanceCriteria: list[str] = Field(default_factory=list)
    environment: str = "local"
    projectId: UUID | None = None
    environmentId: UUID | None = None
    domains: list[TestDomain] = Field(
        default_factory=lambda: [TestDomain.FUNCTIONAL, TestDomain.PERFORMANCE, TestDomain.SECURITY]
    )
    riskLevel: RiskLevel = RiskLevel.MEDIUM
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequirementLibraryPipelineRequest(BaseModel):
    selectionMode: Literal["requirement_version", "requirement_items", "requirement_scope"] = "requirement_version"
    requirementVersionId: UUID | None = None
    requirementVersionIds: list[UUID] = Field(default_factory=list)
    requirementItemIds: list[str] = Field(default_factory=list)
    requirementItemRefs: list[RequirementItemRef] = Field(default_factory=list)
    requirementScope: RequirementScope | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ClarificationAnswerRequest(BaseModel):
    answer: str = Field(min_length=1)


class CorrectionApplyRequest(BaseModel):
    targetType: str
    targetId: str
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    affectedAssetRefs: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

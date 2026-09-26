# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.domain.enums import PlanStatus, RiskLevel, SourceType, TestDomain
from agentic_qa.schemas.requirement_scope import RequirementScope


class CreateTestPlanRequest(BaseModel):
    name: str
    sourceType: SourceType
    sourceRef: str | None = None
    environment: str
    projectId: UUID | None = None
    environmentId: UUID | None = None
    domains: list[TestDomain]
    domainConfig: dict[str, dict[str, Any]] = Field(default_factory=dict)
    riskLevel: RiskLevel = RiskLevel.MEDIUM
    requirementVersionId: UUID | None = None
    requirementScope: RequirementScope | None = None
    input: dict[str, Any] = Field(default_factory=dict)


class UpdateTestPlanRequest(BaseModel):
    name: str | None = None
    environment: str | None = None
    projectId: UUID | None = None
    environmentId: UUID | None = None
    domains: list[TestDomain] | None = None
    domainConfig: dict[str, dict[str, Any]] | None = None
    riskLevel: RiskLevel | None = None
    requirementVersionId: UUID | None = None
    requirementScope: RequirementScope | None = None
    input: dict[str, Any] | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_client_managed_status(cls, value: Any) -> Any:
        if isinstance(value, dict) and "status" in value:
            raise ValueError("PLAN_STATUS_BACKEND_MANAGED: test plan status is managed by the backend lifecycle")
        return value


class TestPlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    status: PlanStatus
    domains: list[TestDomain]
    domainConfig: dict[str, dict[str, Any]] = Field(default_factory=dict)
    riskLevel: RiskLevel = Field(alias="risk_level")
    environment: str
    projectId: UUID | None = None
    environmentId: UUID | None = None
    sourceType: SourceType = Field(alias="source_type")
    sourceRef: str | None = Field(default=None, alias="source_ref")
    requirementVersionId: UUID | None = None
    requirementScope: dict[str, Any] = Field(default_factory=dict, alias="requirement_scope")
    input: dict[str, Any] = Field(alias="input_payload")
    generatedPlan: dict[str, Any] = Field(alias="generated_plan")
    createdAt: datetime = Field(alias="created_at")
    updatedAt: datetime = Field(alias="updated_at")


class GeneratePlanResponse(BaseModel):
    jobId: UUID
    planId: UUID
    status: str

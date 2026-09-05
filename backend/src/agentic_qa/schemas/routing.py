# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_qa.domain.enums import RiskLevel


class CreateRoutingPolicyRequest(BaseModel):
    name: str
    taskType: str
    riskLevel: RiskLevel
    requiresTools: bool = False
    requiresVision: bool = False
    requiresJson: bool = False
    dataSensitivity: str = "internal"
    preferLocal: bool = False
    challengerRequired: bool = False
    fallbackRequired: bool = False
    humanApprovalRequired: bool = False
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateRoutingPolicyRequest(BaseModel):
    name: str | None = None
    taskType: str | None = None
    riskLevel: RiskLevel | None = None
    requiresTools: bool | None = None
    requiresVision: bool | None = None
    requiresJson: bool | None = None
    dataSensitivity: str | None = None
    preferLocal: bool | None = None
    challengerRequired: bool | None = None
    fallbackRequired: bool | None = None
    humanApprovalRequired: bool | None = None
    enabled: bool | None = None
    metadata: dict[str, Any] | None = None


RoutingPolicyGovernanceAction = Literal["create", "update", "delete"]


class RoutingPolicyGovernanceActionRequest(BaseModel):
    action: RoutingPolicyGovernanceAction
    policyId: UUID | None = None
    policyPayload: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    idempotencyKey: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RoutingPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    taskType: str = Field(alias="task_type")
    riskLevel: RiskLevel = Field(alias="risk_level")
    requiresTools: bool = Field(alias="requires_tools")
    requiresVision: bool = Field(alias="requires_vision")
    requiresJson: bool = Field(alias="requires_json")
    dataSensitivity: str = Field(alias="data_sensitivity")
    preferLocal: bool = Field(alias="prefer_local")
    challengerRequired: bool = Field(alias="challenger_required")
    fallbackRequired: bool = Field(alias="fallback_required")
    humanApprovalRequired: bool = Field(alias="human_approval_required")
    enabled: bool
    metadata: dict[str, Any]
    createdAt: datetime = Field(alias="created_at")
    updatedAt: datetime = Field(alias="updated_at")


class RoutingPreviewRequest(BaseModel):
    taskType: str
    riskLevel: RiskLevel
    requiresTools: bool = False
    requiresVision: bool = False
    requiresJson: bool = False
    preferLocal: bool = False


class RoutingPreviewResponse(BaseModel):
    policyId: UUID | None = None
    selectedRoles: list[str]
    selectedModels: list[dict[str, Any]] = Field(default_factory=list)
    rationale: list[str]

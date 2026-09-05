# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


GatePolicyValidationStatusValue = Literal["not_validated", "valid", "invalid"]
GatePolicyGovernanceStatusValue = Literal[
    "draft",
    "review_pending",
    "review_approved",
    "review_rejected",
    "review_cancelled",
    "review_expired",
    "transition_pending",
    "transition_applied",
    "transition_rejected",
    "transition_cancelled",
    "transition_expired",
]
GatePolicyLifecycleTargetValue = Literal["disabled", "deprecated", "archived"]
GatePolicyImportFormatValue = Literal["json", "yaml"]


class _StrictGovernanceModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


class CreateGatePolicyDraftRequest(_StrictGovernanceModel):
    document: dict[str, Any]
    idempotencyKey: str = Field(min_length=1, max_length=255)
    expectedContentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")


class UpdateGatePolicyDraftRequest(_StrictGovernanceModel):
    document: dict[str, Any]
    expectedVersion: int = Field(ge=1)
    expectedContentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")


class ValidateGatePolicyDraftRequest(_StrictGovernanceModel):
    expectedVersion: int = Field(ge=1)


class SubmitGatePolicyReviewRequest(_StrictGovernanceModel):
    expectedVersion: int = Field(ge=1)
    idempotencyKey: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=1000)


class GatePolicyReviewDecisionRequest(_StrictGovernanceModel):
    approvalId: UUID
    decision: Literal["approve", "reject"]
    expectedVersion: int = Field(ge=1)
    comment: str | None = Field(default=None, max_length=2000)


class GatePolicyLifecycleRequest(_StrictGovernanceModel):
    targetStatus: GatePolicyLifecycleTargetValue
    expectedVersion: int = Field(ge=1)
    idempotencyKey: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=1000)


class GatePolicyValidationIssueProjection(_StrictGovernanceModel):
    errorCode: str = Field(min_length=1, max_length=128)
    field: str | None = Field(default=None, max_length=500)
    issueType: str | None = Field(default=None, max_length=128)


class GatePolicyValidationProjection(_StrictGovernanceModel):
    schemaVersion: Literal["phase8.gate-policy-validation.v1"]
    status: GatePolicyValidationStatusValue
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    validatedAt: datetime | None
    validatedBy: UUID | None
    errors: list[GatePolicyValidationIssueProjection]
    warnings: list[GatePolicyValidationIssueProjection]
    writesGateDecision: Literal[False]


class GatePolicyApprovalProjection(_StrictGovernanceModel):
    approvalId: UUID
    resourceType: Literal["gate_policy_version_review", "gate_policy_version_lifecycle"]
    action: Literal["gate_policy.review", "gate_policy.lifecycle"]
    status: Literal["pending", "approved", "rejected", "cancelled", "expired"]
    targetStatus: GatePolicyLifecycleTargetValue | None = None
    requestedBy: UUID | None = None
    decidedBy: UUID | None = None
    createdAt: datetime
    decidedAt: datetime | None = None


class GatePolicyVersionProjection(_StrictGovernanceModel):
    versionId: UUID
    versionRef: str
    versionNumber: int = Field(ge=1)
    schemaVersion: Literal["gate-policy.v1"]
    status: Literal["draft", "active", "disabled", "deprecated", "archived"]
    governanceStatus: GatePolicyGovernanceStatusValue
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    lockVersion: int = Field(ge=1)
    validation: GatePolicyValidationProjection
    currentApproval: GatePolicyApprovalProjection | None
    approvalRefs: list[dict[str, Any]]
    guardrailRefs: list[dict[str, Any]]
    auditRefs: list[dict[str, Any]]
    traceRefs: list[str]
    document: dict[str, Any] | None = None
    createdAt: datetime
    updatedAt: datetime


class GatePolicyProjection(_StrictGovernanceModel):
    policyId: UUID
    policyRef: str
    projectId: UUID
    tenantId: str
    workspaceId: str
    policyKey: str
    name: str
    description: str | None
    status: Literal["draft", "active", "disabled", "deprecated", "archived"]
    lockVersion: int = Field(ge=1)
    versions: list[GatePolicyVersionProjection]
    createdAt: datetime
    updatedAt: datetime
    executesGate: Literal[False]
    activatesProduction: Literal[False]


class GatePolicyListProjection(_StrictGovernanceModel):
    items: list[GatePolicyProjection]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    pageSize: int = Field(ge=1)
    readOnly: bool
    executesGate: Literal[False]


class GatePolicyGovernanceErrorProjection(_StrictGovernanceModel):
    errorCode: str = Field(min_length=1, max_length=128)
    field: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class GatePolicyValidationIssue(_StrictGovernanceModel):
    path: str = Field(min_length=1, max_length=500)
    code: str = Field(min_length=1, max_length=128)
    severity: Literal["error", "warning"]
    messageKey: str = Field(min_length=1, max_length=255)
    parameters: dict[str, Any]


class GatePolicyDiffChange(_StrictGovernanceModel):
    operation: Literal["add", "remove", "change"]
    path: str = Field(min_length=1, max_length=500)
    before: Any
    after: Any


class GatePolicyStructuredDiff(_StrictGovernanceModel):
    schemaVersion: Literal["phase8.gate-policy-structured-diff.v1"]
    changes: list[GatePolicyDiffChange]
    summary: dict[Literal["add", "remove", "change"], int]
    redacted: Literal[True]
    computedBy: Literal["backend"]


class GatePolicyImportPreview(_StrictGovernanceModel):
    schemaVersion: Literal["phase8.gate-policy-import-preview.v1"]
    format: GatePolicyImportFormatValue
    valid: bool
    contentHash: str | None = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    validationIssues: list[GatePolicyValidationIssue]
    canonicalPolicy: dict[str, Any] | None
    diff: GatePolicyStructuredDiff
    limits: dict[str, int]
    activatesProduction: Literal[False]
    executesGate: Literal[False]


class GatePolicyImportDraftSaveRequest(_StrictGovernanceModel):
    document: dict[str, Any]
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    idempotencyKey: str = Field(min_length=1, max_length=255)
    expectedVersion: int | None = Field(default=None, ge=1)


class GatePolicyImportRequest(_StrictGovernanceModel):
    format: GatePolicyImportFormatValue
    content: str = Field(max_length=65536)
    policyId: UUID | None = None
    versionId: UUID | None = None

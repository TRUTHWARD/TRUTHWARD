# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from agentic_qa.domain.enums import RiskLevel
from agentic_qa.schemas.contracts import CorrectionValidationResultContract, TestKnowledgeEntryContract


ProposalType = Literal[
    "locator_update",
    "assertion_update",
    "test_case_update",
    "test_step_update",
    "requirement_mapping_update",
    "execution_config_update",
    "generate_patch_suggestion",
    "graph_correction",
]


class CreateCorrectionProposalRequest(BaseModel):
    proposalType: ProposalType
    proposedChange: dict[str, Any]
    requirementVersionId: UUID | None = None
    executionId: UUID | None = None
    findingId: UUID | None = None
    attributionId: str | None = None
    riskLevel: RiskLevel
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    traceRefs: list[str] = Field(default_factory=list)
    idempotencyKey: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrectionGovernanceProjectionFilters(BaseModel):
    executionId: UUID | None = None
    requirementVersionId: UUID | None = None
    status: str | None = None
    page: int = Field(default=1, ge=1)
    pageSize: int = Field(default=50, ge=1, le=100)


class SubmitCorrectionApprovalRequest(BaseModel):
    summary: str | None = None
    expiresAt: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApplyCorrectionProposalRequest(BaseModel):
    idempotencyKey: str = Field(min_length=1)
    requestId: str = Field(min_length=1)
    status: Literal["applied", "failed_to_apply"] = "applied"
    appliedChangeRefs: list[dict[str, Any]] = Field(default_factory=list)
    sideEffectRefs: list[dict[str, Any]] = Field(default_factory=list)
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    traceRefs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidateCorrectionProposalRequest(BaseModel):
    idempotencyKey: str = Field(min_length=1)
    requestId: str = Field(min_length=1)
    correctionApplicationId: UUID | None = None
    result: CorrectionValidationResultContract
    traceRefs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RollbackCorrectionProposalRequest(BaseModel):
    idempotencyKey: str = Field(min_length=1)
    requestId: str = Field(min_length=1)
    rollbackReason: str = Field(min_length=1)
    status: Literal["rolled_back", "rollback_failed"] | None = None
    rollbackRefs: list[dict[str, Any]] = Field(default_factory=list)
    evidenceRefs: list[dict[str, Any]] = Field(default_factory=list)
    traceRefs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgePromotionStatus(StrEnum):
    PENDING = "pending"
    PROMOTED = "promoted"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"
    SUPERSEDED = "superseded"


class KnowledgePromotionSource(StrEnum):
    VALIDATED_CORRECTION = "validated_correction"
    REPLAY_VALIDATED_CORRECTION = "replay_validated_correction"


class PromoteCorrectionProposalRequest(BaseModel):
    knowledgeEntry: TestKnowledgeEntryContract
    coverageProofRef: dict[str, Any]
    source: KnowledgePromotionSource = KnowledgePromotionSource.VALIDATED_CORRECTION
    replayValidationId: str | None = None
    approvalRefs: list[dict[str, Any]] = Field(default_factory=list)
    idempotencyKey: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CreateKnowledgePromotionRequest(PromoteCorrectionProposalRequest):
    correctionProposalId: UUID


class RollbackKnowledgePromotionRequest(BaseModel):
    idempotencyKey: str = Field(min_length=1)
    requestId: str = Field(min_length=1)
    rollbackReason: str = Field(min_length=1)
    rollbackRef: dict[str, Any] = Field(default_factory=dict)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    traceRefs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SupersedeKnowledgePromotionRequest(BaseModel):
    idempotencyKey: str = Field(min_length=1)
    requestId: str = Field(min_length=1)
    supersedeReason: str = Field(min_length=1)
    supersedeRef: dict[str, Any] = Field(default_factory=dict)
    replacementKnowledgePromotionId: UUID | None = None
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    traceRefs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

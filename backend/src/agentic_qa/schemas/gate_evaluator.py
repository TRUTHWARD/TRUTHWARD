# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


GateDecisionValue = Literal["pass", "warn", "fail", "blocked"]
DomainApplicabilityValue = Literal["applicable", "not_applicable", "unknown"]
DomainAvailabilityValue = Literal["available", "missing", "invalid", "unavailable"]
GateDomainValue = Literal["functional", "performance", "security"]
GateInputTypeValue = Literal[
    "normalizedFindings",
    "metrics",
    "approvalState",
    "evidence",
    "normalization",
    "policySnapshot",
]


class _StrictGateEvaluatorModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


class GateAuthorityRefContract(_StrictGateEvaluatorModel):
    type: str = Field(min_length=1, max_length=80)
    id: str = Field(min_length=1, max_length=500)
    source: str = Field(min_length=1, max_length=120)


class GateEvaluationContextContract(_StrictGateEvaluatorModel):
    evaluationId: str = Field(min_length=1, max_length=255)
    evaluationTime: datetime
    traceId: str = Field(min_length=1, max_length=255)
    requestId: str = Field(min_length=1, max_length=255)

    @field_validator("evaluationTime")
    @classmethod
    def normalize_evaluation_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluationTime must include an explicit timezone")
        return value.astimezone(timezone.utc)


class GateExecutionContextContract(_StrictGateEvaluatorModel):
    executionId: str = Field(min_length=1, max_length=255)
    planId: str = Field(min_length=1, max_length=255)
    executionPlanId: str | None = Field(default=None, max_length=255)
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: str | None = Field(default=None, max_length=255)
    environmentId: str | None = Field(default=None, max_length=255)
    stage: Literal["GATE"]
    status: str = Field(min_length=1, max_length=80)
    riskLevel: Literal["low", "medium", "high"]
    approvalRequired: bool
    authorityRefs: list[GateAuthorityRefContract] = Field(min_length=1, max_length=64)


class DomainInputStateContract(_StrictGateEvaluatorModel):
    domain: GateDomainValue
    applicability: DomainApplicabilityValue
    availability: DomainAvailabilityValue
    required: bool
    requiredInputTypes: list[GateInputTypeValue] = Field(min_length=1, max_length=8)
    authorityRefs: list[GateAuthorityRefContract] = Field(min_length=1, max_length=64)
    inputRefs: list[GateAuthorityRefContract] = Field(max_length=10_000)
    missingInputs: list[GateInputTypeValue] = Field(max_length=8)
    invalidInputs: list[GateInputTypeValue] = Field(max_length=8)
    unavailableInputs: list[GateInputTypeValue] = Field(max_length=8)

    @model_validator(mode="after")
    def validate_state_evidence(self) -> "DomainInputStateContract":
        if self.applicability == "not_applicable":
            if not self.authorityRefs:
                raise ValueError("not_applicable requires an authoritative scope reference")
            if self.required:
                raise ValueError("not_applicable domain must not be required")
        if self.availability == "available" and (
            self.missingInputs or self.invalidInputs or self.unavailableInputs
        ):
            raise ValueError("available domain must not report missing/invalid/unavailable inputs")
        if self.applicability == "applicable":
            expected = {
                "missing": self.missingInputs,
                "invalid": self.invalidInputs,
                "unavailable": self.unavailableInputs,
            }
            if self.availability != "available" and not expected[self.availability]:
                raise ValueError(f"{self.availability} domain must name the affected input")
        return self


class GateNormalizedFindingContract(_StrictGateEvaluatorModel):
    id: str = Field(min_length=1, max_length=255)
    executionId: str = Field(min_length=1, max_length=255)
    taskId: str | None = Field(default=None, max_length=255)
    domain: GateDomainValue
    source: str = Field(min_length=1, max_length=120)
    category: str = Field(min_length=1, max_length=120)
    severity: Literal["critical", "high", "medium", "low", "info"]
    status: str = Field(min_length=1, max_length=80)
    confidence: float = Field(ge=0.0, le=1.0)
    dedupeKey: str = Field(min_length=1, max_length=500)
    rawRef: str = Field(min_length=1, max_length=1000)
    evidenceRefs: list[GateAuthorityRefContract] = Field(max_length=1000)


class GateMetricContract(_StrictGateEvaluatorModel):
    id: str = Field(min_length=1, max_length=255)
    executionId: str = Field(min_length=1, max_length=255)
    taskId: str | None = Field(default=None, max_length=255)
    name: str = Field(min_length=1, max_length=160)
    value: float
    unit: str | None = Field(default=None, max_length=80)
    threshold: float | None = None
    baseline: float | None = None
    domain: GateDomainValue
    source: str = Field(min_length=1, max_length=120)
    evidenceRefs: list[GateAuthorityRefContract] = Field(max_length=1000)


class GateApprovalStateContract(_StrictGateEvaluatorModel):
    id: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=120)
    status: Literal["pending", "approved", "rejected", "cancelled", "expired"]
    resourceType: str = Field(min_length=1, max_length=120)
    resourceId: str = Field(min_length=1, max_length=500)
    decidedAt: datetime | None = None

    @field_validator("decidedAt")
    @classmethod
    def normalize_decided_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("decidedAt must include an explicit timezone")
        return value.astimezone(timezone.utc)


class GateNormalizationStateContract(_StrictGateEvaluatorModel):
    status: Literal["not_started", "in_progress", "completed", "failed", "unknown"]
    rawFindingCount: int = Field(ge=0)
    normalizedFindingCount: int = Field(ge=0)
    unresolvedRawFindingCount: int = Field(ge=0)
    authorityRefs: list[GateAuthorityRefContract] = Field(max_length=64)


class GateEvidenceIntegrityContract(_StrictGateEvaluatorModel):
    status: Literal["valid", "missing", "invalid", "unknown"]
    checkedRefCount: int = Field(ge=0)
    missingRefs: list[GateAuthorityRefContract] = Field(max_length=10_000)
    invalidRefs: list[GateAuthorityRefContract] = Field(max_length=10_000)
    authorityRefs: list[GateAuthorityRefContract] = Field(max_length=64)


class GateInputContract(_StrictGateEvaluatorModel):
    schemaVersion: Literal["phase8.gate-input.v1"]
    evaluationContext: GateEvaluationContextContract
    executionContext: GateExecutionContextContract
    domainInputStates: list[DomainInputStateContract] = Field(min_length=3, max_length=3)
    normalizedFindings: list[GateNormalizedFindingContract] = Field(max_length=100_000)
    metrics: list[GateMetricContract] = Field(max_length=100_000)
    approvalState: list[GateApprovalStateContract] = Field(max_length=10_000)
    normalizationState: GateNormalizationStateContract
    evidenceIntegrity: GateEvidenceIntegrityContract
    policySnapshot: dict[str, Any] | None
    policySnapshotHash: str | None = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    inputFingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    metadata: dict[str, Any] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_domains_and_execution_refs(self) -> "GateInputContract":
        domains = [item.domain for item in self.domainInputStates]
        if set(domains) != {"functional", "performance", "security"} or len(set(domains)) != 3:
            raise ValueError("domainInputStates must contain functional/performance/security exactly once")
        execution_id = self.executionContext.executionId
        if any(item.executionId != execution_id for item in self.normalizedFindings):
            raise ValueError("normalized finding executionId must match Gate execution context")
        if any(item.executionId != execution_id for item in self.metrics):
            raise ValueError("metric executionId must match Gate execution context")
        return self


class GateMetricEvaluationContract(_StrictGateEvaluatorModel):
    metricRef: str = Field(min_length=1, max_length=500)
    domain: GateDomainValue
    ruleId: str | None = Field(default=None, max_length=128)
    value: float
    threshold: float | None = None
    comparisonValue: float | None = None
    outcome: Literal["matched", "not_matched", "ignored", "invalid"]
    decision: GateDecisionValue
    reasonCode: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{2,127}$")


class GateDomainResultContract(_StrictGateEvaluatorModel):
    domain: GateDomainValue
    applicability: DomainApplicabilityValue
    availability: DomainAvailabilityValue
    decision: GateDecisionValue
    reasonCodes: list[str]
    matchedRules: list[str]
    blockingRefs: list[GateAuthorityRefContract]
    warningRefs: list[GateAuthorityRefContract]
    metricEvaluations: list[GateMetricEvaluationContract]
    completeness: Literal["complete", "partial", "incomplete", "not_applicable", "unknown"]
    confidence: float = Field(ge=0.0, le=1.0)
    authorityRefs: list[GateAuthorityRefContract]


class GateCompletenessSummaryContract(_StrictGateEvaluatorModel):
    status: Literal["complete", "partial", "incomplete", "unknown"]
    applicableDomainCount: int = Field(ge=0)
    evaluatedDomainCount: int = Field(ge=0)
    excludedDomainCount: int = Field(ge=0)
    requiredMissingCount: int = Field(ge=0)
    optionalMissingCount: int = Field(ge=0)


class GatePolicyEvaluationSummaryContract(_StrictGateEvaluatorModel):
    policyId: str | None = Field(default=None, max_length=255)
    policyVersionId: str | None = Field(default=None, max_length=255)
    policyVersionHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    bindingRef: str | None = Field(default=None, max_length=500)
    resolvedScope: dict[str, Any]
    snapshotHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")


class GateInputEvaluationSummaryContract(_StrictGateEvaluatorModel):
    fingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    snapshotRef: str | None = Field(default=None, max_length=500)
    normalizedFindingRefs: list[str]
    metricRefs: list[str]
    approvalRefs: list[str]


class GateResultContract(_StrictGateEvaluatorModel):
    schemaVersion: Literal["phase8.gate-result.v1"]
    evaluatorVersion: str = Field(min_length=1, max_length=80)
    evaluationId: str = Field(min_length=1, max_length=255)
    executionId: str = Field(min_length=1, max_length=255)
    decision: GateDecisionValue
    domainResults: list[GateDomainResultContract] = Field(min_length=3, max_length=3)
    reasonCodes: list[str]
    reasons: list[str]
    matchedRules: list[str]
    blockingRefs: list[GateAuthorityRefContract]
    warningRefs: list[GateAuthorityRefContract]
    metricEvaluations: list[GateMetricEvaluationContract]
    completeness: GateCompletenessSummaryContract
    confidence: float = Field(ge=0.0, le=1.0)
    policy: GatePolicyEvaluationSummaryContract
    input: GateInputEvaluationSummaryContract
    decisionSnapshot: dict[str, Any]
    decisionSnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    writesGateDecision: Literal[False]

    @model_validator(mode="after")
    def validate_domain_results(self) -> "GateResultContract":
        domains = [item.domain for item in self.domainResults]
        if set(domains) != {"functional", "performance", "security"} or len(set(domains)) != 3:
            raise ValueError("domainResults must contain functional/performance/security exactly once")
        return self

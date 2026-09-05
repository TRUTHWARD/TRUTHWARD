# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_qa.infra.redaction import contains_unsafe_control_characters, redact_sensitive_text


class _StrictCIModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


CIStatus = Literal[
    "pending",
    "in_progress",
    "success",
    "failure",
    "neutral",
    "cancelled",
    "stale",
]
AdmissionMode = Literal["observe", "shadow", "enforce"]


class CIEvidenceLink(_StrictCIModel):
    label: str = Field(min_length=1, max_length=160)
    href: str = Field(min_length=1, max_length=1200)

    @field_validator("href")
    @classmethod
    def safe_href(cls, value: str) -> str:
        if contains_unsafe_control_characters(value) or redact_sensitive_text(value) != value:
            raise ValueError("CI evidence links must not contain sensitive material")
        if not value.startswith(("/", "https://", "http://")):
            raise ValueError("CI evidence links must be platform paths or HTTP(S) URLs")
        return value


class CIConclusion(_StrictCIModel):
    schemaVersion: Literal["phase8.ci-conclusion.v1"] = "phase8.ci-conclusion.v1"
    status: CIStatus
    admissionMode: AdmissionMode
    gateResult: Literal["pass", "warn", "fail", "blocked"] | None
    authoritative: bool
    blocking: bool
    summary: str = Field(min_length=1, max_length=1000)
    reasonCodes: list[str] = Field(default_factory=list, max_length=1000)
    evidenceLinks: list[CIEvidenceLink] = Field(default_factory=list, max_length=100)
    platformRunLink: str = Field(min_length=1, max_length=1200)

    @model_validator(mode="after")
    def enforce_is_the_only_blocking_mode(self) -> "CIConclusion":
        if self.blocking and (self.admissionMode != "enforce" or self.status != "failure"):
            raise ValueError("only an Enforce failure may be blocking")
        if self.admissionMode != "enforce" and self.status == "failure":
            raise ValueError("Observe and Shadow must not emit a blocking CI failure")
        if self.authoritative != (self.admissionMode == "enforce"):
            raise ValueError("only Enforce CI conclusions are authoritative")
        return self


class EnforcementDecision(_StrictCIModel):
    schemaVersion: Literal["phase8.enforcement-decision.v1"] = "phase8.enforcement-decision.v1"
    mode: AdmissionMode
    authoritative: bool
    nonAuthoritative: bool
    blocksMerge: bool
    gateDecisionRef: str | None = Field(default=None, max_length=1200)
    approvalRef: str | None = Field(default=None, max_length=1200)
    policyHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    branchProtectionConfigured: bool
    branchProtectionExternallyManaged: Literal[True] = True
    reasonCodes: list[str] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_mode_authority(self) -> "EnforcementDecision":
        if self.mode == "enforce":
            if not self.authoritative or self.nonAuthoritative or not self.approvalRef:
                raise ValueError("Enforce requires authoritative Service state and an Approval ref")
        elif self.authoritative or not self.nonAuthoritative or self.blocksMerge:
            raise ValueError("Observe and Shadow enforcement projections are non-authoritative")
        if self.blocksMerge and self.mode != "enforce":
            raise ValueError("only Enforce may block merge")
        return self


class StaleRevisionResult(_StrictCIModel):
    schemaVersion: Literal["phase8.stale-revision-result.v1"] = "phase8.stale-revision-result.v1"
    status: Literal["current", "stale", "unavailable"]
    expectedHeadSha: str = Field(pattern=r"^[a-f0-9]{7,64}$")
    currentHeadSha: str | None = Field(default=None, pattern=r"^[a-f0-9]{7,64}$")
    checkedAt: str = Field(min_length=1, max_length=80)
    writeSuppressed: bool
    reasonCode: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    connectorCallRef: str | None = Field(default=None, max_length=1200)

    @model_validator(mode="after")
    def validate_suppression(self) -> "StaleRevisionResult":
        if self.status == "current" and (self.writeSuppressed or self.currentHeadSha != self.expectedHeadSha):
            raise ValueError("a current revision must match and permit writeback")
        if self.status != "current" and (not self.writeSuppressed or not self.reasonCode):
            raise ValueError("stale or unavailable revision checks must suppress writeback with a ReasonCode")
        return self


class ExternalActionRef(_StrictCIModel):
    schemaVersion: Literal["phase8.external-action-ref.v1"] = "phase8.external-action-ref.v1"
    provider: Literal["github", "gitlab", "mock-scm"]
    operation: Literal["write_check"] = "write_check"
    externalId: str | None = Field(default=None, max_length=500)
    url: str | None = Field(default=None, max_length=1200)
    connectorCallRef: str = Field(min_length=1, max_length=1200)
    responseHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class LegacySkillDecisionFieldNotice(_StrictCIModel):
    schemaVersion: Literal["phase8.legacy-skill-decision-field-notice.v1"] = (
        "phase8.legacy-skill-decision-field-notice.v1"
    )
    fieldsPresent: list[Literal["shouldMerge", "exitCode"]] = Field(min_length=1, max_length=2)
    ignored: Literal[True] = True
    reasonCode: Literal["DEPRECATED_SKILL_DECISION_FIELD_IGNORED"] = (
        "DEPRECATED_SKILL_DECISION_FIELD_IGNORED"
    )
    skillVersion: str | None = Field(default=None, max_length=64)
    manifestHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")


class CIWritebackRequest(_StrictCIModel):
    schemaVersion: Literal["phase8.ci-writeback-request.v1"] = "phase8.ci-writeback-request.v1"
    admissionRunId: UUID
    checkName: str = Field(default="Agentic QA / PR Admission", min_length=1, max_length=120)
    idempotencyKey: str = Field(min_length=8, max_length=255)


class CIWritebackRetryRequest(_StrictCIModel):
    schemaVersion: Literal["phase8.ci-writeback-retry-request.v1"] = (
        "phase8.ci-writeback-retry-request.v1"
    )
    reason: str = Field(min_length=3, max_length=500)
    idempotencyKey: str = Field(min_length=8, max_length=255)


class CIWritebackResult(_StrictCIModel):
    schemaVersion: Literal["phase8.ci-writeback-result.v1"] = "phase8.ci-writeback-result.v1"
    writebackAttemptId: UUID
    admissionRunId: UUID
    status: CIStatus
    writeStatus: Literal["completed", "failed", "suppressed", "unknown"]
    checkName: str = Field(min_length=1, max_length=120)
    headSha: str = Field(pattern=r"^[a-f0-9]{7,64}$")
    conclusion: CIConclusion
    enforcement: EnforcementDecision
    staleRevision: StaleRevisionResult
    externalAction: ExternalActionRef | None
    legacyFieldNotice: LegacySkillDecisionFieldNotice | None
    reasonCodes: list[str] = Field(default_factory=list, max_length=1000)
    attemptCount: int = Field(ge=1)
    idempotentReplay: bool = False


class CIEnforcementChangeRequest(_StrictCIModel):
    schemaVersion: Literal["phase8.ci-enforcement-change-request.v1"] = (
        "phase8.ci-enforcement-change-request.v1"
    )
    repositoryRef: str = Field(min_length=1, max_length=1000)
    checkName: str = Field(default="Agentic QA / PR Admission", min_length=1, max_length=120)
    targetMode: AdmissionMode
    branchProtectionConfigured: bool = False
    reason: str = Field(min_length=3, max_length=500)
    idempotencyKey: str = Field(min_length=8, max_length=255)


class CIEnforcementPolicyProjection(_StrictCIModel):
    schemaVersion: Literal["phase8.ci-enforcement-policy.v1"] = "phase8.ci-enforcement-policy.v1"
    projectId: UUID
    repositoryRef: str
    checkName: str
    mode: AdmissionMode
    status: Literal["active", "approval_pending", "disabled"]
    policyHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    branchProtectionConfigured: bool
    branchProtectionExternallyManaged: Literal[True] = True
    approvalRef: str | None = None
    ready: bool
    unavailableReason: str | None = None
    requiredCapabilities: list[Literal["ci.write", "enforce.manage", "ci.retry"]]


__all__ = [
    "CIConclusion",
    "CIEnforcementChangeRequest",
    "CIEnforcementPolicyProjection",
    "CIStatus",
    "CIWritebackRequest",
    "CIWritebackRetryRequest",
    "CIWritebackResult",
    "EnforcementDecision",
    "ExternalActionRef",
    "LegacySkillDecisionFieldNotice",
    "StaleRevisionResult",
]

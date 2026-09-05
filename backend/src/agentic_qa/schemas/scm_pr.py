# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_qa.infra.redaction import contains_unsafe_control_characters, redact_sensitive_text


SCM_WEBHOOK_SCHEMA_VERSION = "phase8.scm-webhook-envelope.v1"
PR_REVISION_SCHEMA_VERSION = "phase8.pr-revision.v1"
PR_CONTEXT_SCHEMA_VERSION = "phase8.pr-context.v1"
REQUIREMENT_MATCH_SCHEMA_VERSION = "phase8.requirement-match.v1"
REQUIREMENT_MATCH_SNAPSHOT_SCHEMA_VERSION = "phase8.requirement-match-snapshot.v1"
REQUIREMENT_MATCH_ALGORITHM_VERSION = "p20.requirement-match.v1"

ScmProvider = Literal["github", "gitlab", "mock-scm"]
MatchSource = Literal[
    "explicit_reference",
    "manual_mapping",
    "verified_traceability",
    "rule",
    "history",
    "ai_suggestion",
]
MatchStatus = Literal["confirmed", "candidate", "rejected", "unknown"]


class _StrictScmModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


class ScmRef(_StrictScmModel):
    type: str = Field(min_length=1, max_length=80)
    ref: str = Field(min_length=1, max_length=1000)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("ref")
    @classmethod
    def safe_ref(cls, value: str) -> str:
        if contains_unsafe_control_characters(value) or redact_sensitive_text(value) != value:
            raise ValueError("SCM refs must not contain sensitive values")
        return value


class WebhookRepository(_StrictScmModel):
    nativeId: str = Field(min_length=1, max_length=255)
    fullName: str = Field(min_length=1, max_length=500)
    webUrl: str | None = Field(default=None, max_length=2000)


class WebhookEnvelope(_StrictScmModel):
    schemaVersion: Literal["phase8.scm-webhook-envelope.v1"]
    provider: ScmProvider
    deliveryId: str = Field(min_length=1, max_length=255)
    eventType: Literal["pull_request", "merge_request"]
    action: str = Field(min_length=1, max_length=80)
    installationRef: str = Field(min_length=1, max_length=500)
    repository: WebhookRepository
    pullRequestNumber: int = Field(ge=1)
    providerEventAt: datetime
    receivedAt: datetime
    payloadHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    payloadSnapshot: dict[str, Any]


class PRRevision(_StrictScmModel):
    schemaVersion: Literal["phase8.pr-revision.v1"]
    baseRef: str = Field(min_length=1, max_length=500)
    baseSha: str = Field(pattern=r"^[a-fA-F0-9]{40,64}$")
    headRef: str = Field(min_length=1, max_length=500)
    headSha: str = Field(pattern=r"^[a-fA-F0-9]{40,64}$")
    previousHeadSha: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{40,64}$")
    forcePush: bool = False


class ChangedFile(_StrictScmModel):
    path: str = Field(min_length=1, max_length=2000)
    changeType: Literal["added", "modified", "deleted", "renamed", "copied", "unknown"] = "unknown"
    previousPath: str | None = Field(default=None, max_length=2000)

    @field_validator("path", "previousPath")
    @classmethod
    def safe_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.replace("\\", "/").lstrip("./")
        if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
            raise ValueError("changed file path must be repository-relative")
        if contains_unsafe_control_characters(normalized) or redact_sensitive_text(normalized) != normalized:
            raise ValueError("changed file path contains unsafe data")
        return normalized


class PRBindingSnapshot(_StrictScmModel):
    schemaVersion: Literal["phase8.connector-binding-safe-projection.v1"]
    redactionPolicyVersion: Literal["p27.connector-binding-safe-projection.v1"]
    connectorBindingId: UUID
    connectorType: ScmProvider
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: UUID
    scopeType: Literal["project_repository"]
    repositoryRef: str = Field(min_length=1, max_length=1000)
    repositoryNativeId: str = Field(min_length=1, max_length=255)
    installationRef: str = Field(min_length=1, max_length=500)
    bindingRevision: int = Field(ge=0)
    configurationHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class PRContext(_StrictScmModel):
    schemaVersion: Literal["phase8.pr-context.v1"]
    contextId: UUID
    versionId: UUID
    version: int = Field(ge=1)
    provider: ScmProvider
    projectId: UUID
    repositoryRef: str = Field(min_length=1, max_length=1000)
    repositoryNativeId: str = Field(min_length=1, max_length=255)
    pullRequestNumber: int = Field(ge=1)
    revision: PRRevision
    authorRef: str = Field(min_length=1, max_length=500)
    draft: bool
    state: Literal["open", "closed", "merged", "unknown"]
    action: str = Field(min_length=1, max_length=80)
    fork: bool = False
    labels: list[str] = Field(default_factory=list, max_length=200)
    changedFiles: list[ChangedFile] = Field(default_factory=list, max_length=50_000)
    changeSetRef: ScmRef | None
    explicitRequirementRefs: list[str] = Field(default_factory=list, max_length=500)
    receivedAt: datetime
    providerEventAt: datetime
    bindingSnapshot: PRBindingSnapshot
    webhookReceiptRef: ScmRef
    skillInvocationRef: ScmRef | None
    evidenceRefs: list[ScmRef] = Field(default_factory=list, max_length=500)
    contextHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    readOnly: Literal[True]
    gateDecision: Literal[None] = None
    executionCreated: Literal[False]


class RequirementMatchReason(_StrictScmModel):
    code: str = Field(min_length=1, max_length=160)
    layer: Literal["explicit", "mapping", "traceability", "rule_history", "ai"]
    explanationKey: str = Field(min_length=1, max_length=160)
    evidenceRefs: list[ScmRef] = Field(default_factory=list, max_length=256)


class RequirementMatchCandidate(_StrictScmModel):
    requirementId: str = Field(min_length=1, max_length=255)
    requirementVersionId: UUID | None
    requirementVersion: int | None = Field(default=None, ge=1)
    source: MatchSource
    confidence: float = Field(ge=0.0, le=1.0)
    status: MatchStatus
    reasons: list[RequirementMatchReason] = Field(min_length=1, max_length=32)
    evidenceRefs: list[ScmRef] = Field(default_factory=list, max_length=256)
    modelInvocationRef: ScmRef | None = None
    reviewRequired: bool

    @model_validator(mode="after")
    def enforce_confirmation_boundary(self) -> "RequirementMatchCandidate":
        if self.source in {"rule", "history", "ai_suggestion"} and self.status == "confirmed":
            raise ValueError("rule, history, and AI matches cannot be auto-confirmed")
        if self.status == "confirmed" and self.confidence < 0.8:
            raise ValueError("confirmed matches require confidence >= 0.8")
        if self.source == "ai_suggestion" and not self.reviewRequired:
            raise ValueError("AI matches always require review")
        if self.status == "unknown" and self.requirementVersionId is not None:
            raise ValueError("unknown matches cannot claim a requirement version")
        return self


class RequirementMatch(_StrictScmModel):
    schemaVersion: Literal["phase8.requirement-match.v1"]
    matchId: UUID
    prContextVersionId: UUID
    candidate: RequirementMatchCandidate
    matchHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    createdAt: datetime


class RequirementMatchSnapshot(_StrictScmModel):
    schemaVersion: Literal["phase8.requirement-match-snapshot.v1"]
    snapshotId: UUID
    prContextVersionId: UUID
    algorithmVersion: Literal["p20.requirement-match.v1"]
    status: Literal["confirmed", "candidate", "conflict", "unknown"]
    matches: list[RequirementMatch] = Field(default_factory=list, max_length=2000)
    explicitUnknownRefs: list[str] = Field(default_factory=list, max_length=500)
    modelInvocationRefs: list[ScmRef] = Field(default_factory=list, max_length=100)
    guardrailEventRefs: list[ScmRef] = Field(default_factory=list, max_length=100)
    auditRefs: list[ScmRef] = Field(default_factory=list, max_length=100)
    snapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    createdAt: datetime
    reviewRequired: bool
    readOnly: Literal[True]
    gateDecision: Literal[None] = None
    executionCreated: Literal[False]


class PRContextList(_StrictScmModel):
    items: list[dict[str, Any]]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    pageSize: int = Field(ge=1, le=200)
    readOnly: Literal[True]


__all__ = [
    "ChangedFile",
    "PRBindingSnapshot",
    "PRContext",
    "PRContextList",
    "PRRevision",
    "RequirementMatch",
    "RequirementMatchCandidate",
    "RequirementMatchReason",
    "RequirementMatchSnapshot",
    "ScmRef",
    "WebhookEnvelope",
]

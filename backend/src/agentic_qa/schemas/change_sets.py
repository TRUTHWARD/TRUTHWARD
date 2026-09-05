# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_qa.infra.redaction import contains_unsafe_control_characters, redact_sensitive_text


CHANGE_SET_SCHEMA_VERSION = "phase8.change-set.v1"
REQUIREMENT_CHANGE_SET_SCHEMA_VERSION = "phase8.requirement-change-set.v1"
CODE_CHANGE_SET_SCHEMA_VERSION = "phase8.code-change-set.v1"
NORMALIZATION_ISSUE_SCHEMA_VERSION = "phase8.normalization-issue.v1"
MAX_CODE_DIFF_INPUT_BYTES = 8 * 1024 * 1024


class _StrictChangeModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChangeSourceRef(_StrictChangeModel):
    type: str = Field(min_length=1, max_length=80)
    ref: str = Field(min_length=1, max_length=1000)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("ref")
    @classmethod
    def validate_safe_ref(cls, value: str) -> str:
        return _reject_sensitive_identifier(value, field_name="ref")


class RequirementChangeHint(_StrictChangeModel):
    requirementId: str = Field(min_length=1, max_length=255)
    changeType: Literal["add", "update", "remove", "rename", "split", "merge", "unknown"]
    beforeRequirementIds: list[str] = Field(default_factory=list, max_length=100)
    afterRequirementIds: list[str] = Field(default_factory=list, max_length=100)
    changedFields: list[str] = Field(default_factory=list, max_length=100)
    explicitCapabilityRefs: list[ChangeSourceRef] = Field(default_factory=list, max_length=100)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[ChangeSourceRef] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_shape(self) -> "RequirementChangeHint":
        if self.changeType == "split" and len(self.afterRequirementIds) < 2:
            raise ValueError("split requires at least two afterRequirementIds")
        if self.changeType == "merge" and len(self.beforeRequirementIds) < 2:
            raise ValueError("merge requires at least two beforeRequirementIds")
        return self


class RequirementChangeSetIngestRequest(_StrictChangeModel):
    schemaVersion: Literal["phase8.requirement-change-set-ingest.v1"] = (
        "phase8.requirement-change-set-ingest.v1"
    )
    sourceType: Literal["requirement_version"] = "requirement_version"
    sourceId: str = Field(min_length=1, max_length=500)
    revision: str = Field(min_length=1, max_length=255)
    baseRequirementVersionId: UUID | None = None
    headRequirementVersionId: UUID
    changeHints: list[RequirementChangeHint] = Field(default_factory=list, max_length=5000)
    sourceRefs: list[ChangeSourceRef] = Field(default_factory=list, max_length=200)

    @field_validator("sourceId", "revision")
    @classmethod
    def validate_source_identity(cls, value: str) -> str:
        return _reject_sensitive_identifier(value, field_name="source identity")

    @model_validator(mode="after")
    def validate_versions(self) -> "RequirementChangeSetIngestRequest":
        if self.baseRequirementVersionId == self.headRequirementVersionId:
            raise ValueError("baseRequirementVersionId and headRequirementVersionId must differ")
        return self


class CodeChangeSetIngestRequest(_StrictChangeModel):
    schemaVersion: Literal["phase8.code-change-set-ingest.v1"] = (
        "phase8.code-change-set-ingest.v1"
    )
    sourceType: Literal[
        "github_pull_request", "git_compare", "scm_webhook", "manual_scm_diff"
    ]
    sourceId: str = Field(min_length=1, max_length=500)
    revision: str = Field(min_length=1, max_length=255)
    repositoryRef: str = Field(min_length=1, max_length=1000)
    baseSha: str = Field(pattern=r"^[a-fA-F0-9]{40,64}$")
    headSha: str = Field(pattern=r"^[a-fA-F0-9]{40,64}$")
    diff: str = Field(max_length=MAX_CODE_DIFF_INPUT_BYTES)
    sourceRefs: list[ChangeSourceRef] = Field(default_factory=list, max_length=200)
    shallowClone: bool = False
    baseReachable: bool = True
    forcePush: bool = False
    sourceDeleted: bool = False
    encoding: str = Field(default="utf-8", min_length=1, max_length=80)

    @field_validator("repositoryRef")
    @classmethod
    def validate_repository_ref(cls, value: str) -> str:
        if "://" not in value or any(char in value for char in ("\x00", "\r", "\n")):
            raise ValueError("repositoryRef must be a stable URI-style repository reference")
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("repositoryRef must not contain credentials, query, or fragment")
        _reject_sensitive_identifier(value, field_name="repositoryRef")
        return value

    @field_validator("sourceId", "revision")
    @classmethod
    def validate_source_identity(cls, value: str) -> str:
        return _reject_sensitive_identifier(value, field_name="source identity")

    @field_validator("diff")
    @classmethod
    def validate_diff_byte_size(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_CODE_DIFF_INPUT_BYTES:
            raise ValueError(f"diff exceeds {MAX_CODE_DIFF_INPUT_BYTES} UTF-8 bytes")
        return value

    @model_validator(mode="after")
    def validate_revisions(self) -> "CodeChangeSetIngestRequest":
        self.baseSha = self.baseSha.lower()
        self.headSha = self.headSha.lower()
        if self.baseSha == self.headSha and self.diff.strip():
            raise ValueError("non-empty diff requires distinct baseSha and headSha")
        if re.search(r"[\ud800-\udfff]", self.diff):
            raise ValueError("diff contains invalid Unicode surrogate data")
        return self


class NormalizationIssueContract(_StrictChangeModel):
    schemaVersion: Literal["phase8.normalization-issue.v1"]
    issueId: str = Field(min_length=1)
    category: Literal["incomplete", "ambiguous", "unsupported", "sensitive"]
    code: str = Field(min_length=1, max_length=120)
    message: str = Field(min_length=1, max_length=1000)
    field: str | None = Field(max_length=255)
    recoverable: bool
    evidence: list[dict[str, Any]]


class RequirementChangeItemContract(_StrictChangeModel):
    itemId: str
    requirementId: str
    beforeRequirementVersionId: str | None
    afterRequirementVersionId: str | None
    changeType: Literal["add", "update", "remove", "rename", "split", "merge", "unknown"]
    beforeRefs: list[dict[str, Any]]
    afterRefs: list[dict[str, Any]]
    changedFields: list[str]
    explicitCapabilityRefs: list[dict[str, Any]]
    relatedRequirementIds: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]]


class CodeSymbolContract(_StrictChangeModel):
    symbolId: str
    name: str
    kind: str
    changeType: Literal["add", "update", "remove", "unknown"]
    oldLineStart: int | None
    oldLineEnd: int | None
    newLineStart: int | None
    newLineEnd: int | None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]]


class CodeHunkContract(_StrictChangeModel):
    hunkId: str
    header: str
    oldLineStart: int | None
    oldLineCount: int | None
    newLineStart: int | None
    newLineCount: int | None
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    diffArtifactRefs: list[dict[str, Any]]
    sensitive: bool
    redactionCount: int = Field(ge=0)
    symbols: list[CodeSymbolContract]


class CodeFileContract(_StrictChangeModel):
    fileId: str
    path: str
    oldPath: str | None
    changeType: Literal["add", "update", "remove", "rename", "copy", "unknown"]
    language: str | None
    binary: bool
    generated: bool
    vendor: bool
    submodule: bool
    riskHints: list[str]
    diffArtifactRefs: list[dict[str, Any]]
    hunks: list[CodeHunkContract]


class ChangeSetBaseContract(_StrictChangeModel):
    schemaVersion: str = CHANGE_SET_SCHEMA_VERSION
    changeSetId: str
    changeSetType: Literal["requirement", "code"]
    projectId: str
    environmentId: str | None
    sourceSnapshotId: str
    sourceType: str
    sourceId: str
    sourceRevision: str
    sourceContentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    fingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    normalizerVersion: str
    status: Literal["completed", "partial", "unknown"]
    itemCount: int = Field(ge=0)
    issueCount: int = Field(ge=0)
    sensitive: bool
    sourceRefs: list[dict[str, Any]]
    artifactRefs: list[dict[str, Any]]
    replayRefs: list[dict[str, Any]]
    traceId: str
    issues: list[NormalizationIssueContract]
    deduplicated: bool
    createdAt: datetime


class RequirementChangeSetContract(ChangeSetBaseContract):
    schemaVersion: Literal["phase8.requirement-change-set.v1"]
    changeSetType: Literal["requirement"]
    baseRequirementVersionId: str | None
    headRequirementVersionId: str
    items: list[RequirementChangeItemContract]
    impactAnalysisPerformed: Literal[False]


class CodeChangeSetContract(ChangeSetBaseContract):
    schemaVersion: Literal["phase8.code-change-set.v1"]
    changeSetType: Literal["code"]
    repositoryRef: str
    baseSha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    headSha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    files: list[CodeFileContract]
    fullDiffStoredInDatabase: Literal[False]
    impactAnalysisPerformed: Literal[False]


def _reject_sensitive_identifier(value: str, *, field_name: str) -> str:
    if contains_unsafe_control_characters(value):
        raise ValueError(f"{field_name} contains unsafe control characters")
    if redact_sensitive_text(value) != value:
        raise ValueError(f"{field_name} must not contain Secret or PII material")
    return value


__all__ = [
    "CHANGE_SET_SCHEMA_VERSION",
    "CODE_CHANGE_SET_SCHEMA_VERSION",
    "CodeChangeSetContract",
    "CodeChangeSetIngestRequest",
    "MAX_CODE_DIFF_INPUT_BYTES",
    "NORMALIZATION_ISSUE_SCHEMA_VERSION",
    "NormalizationIssueContract",
    "REQUIREMENT_CHANGE_SET_SCHEMA_VERSION",
    "RequirementChangeSetContract",
    "RequirementChangeSetIngestRequest",
]

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


EvidenceSourceType = Literal[
    "execution",
    "finding",
    "gate",
    "policy",
    "trace",
    "replay",
    "graph",
    "artifact",
]
EvidenceClassification = Literal["public", "internal", "confidential", "restricted"]
EvidenceRetentionState = Literal[
    "active",
    "archived",
    "purge_eligible",
    "purged",
    "legal_hold",
]


class EvidenceIndexEntryContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.evidence-index-entry.v1"]
    entryId: UUID
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: UUID
    sourceType: EvidenceSourceType
    sourceId: str = Field(min_length=1, max_length=255)
    sourceVersion: str = Field(min_length=1, max_length=255)
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    title: str = Field(min_length=1, max_length=500)
    summary: str = Field(max_length=4000)
    facets: dict[str, object]
    evidenceRefs: list[dict[str, object]]
    artifactRefs: list[dict[str, object]]
    classification: EvidenceClassification
    redactionVersion: str = Field(min_length=1, max_length=80)
    indexedAt: datetime
    sourceUpdatedAt: datetime | None
    stale: bool
    retentionState: EvidenceRetentionState
    unavailableReasonCode: str | None


class EvidenceIndexJobContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.evidence-index-job.v1"]
    jobId: UUID
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: UUID
    jobType: Literal["incremental", "rebuild", "redaction_reindex"]
    status: Literal["queued", "running", "completed", "failed"]
    idempotencyKey: str = Field(min_length=1, max_length=255)
    sourceTypes: list[EvidenceSourceType]
    scannedCount: int = Field(ge=0)
    upsertedCount: int = Field(ge=0)
    unchangedCount: int = Field(ge=0)
    staleCount: int = Field(ge=0)
    redactionVersion: str = Field(min_length=1, max_length=80)
    traceId: UUID
    startedAt: datetime | None
    finishedAt: datetime | None
    errorCode: str | None


class EvidenceQueryFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sourceTypes: list[EvidenceSourceType] = Field(default_factory=list, max_length=8)
    classifications: list[EvidenceClassification] = Field(default_factory=list, max_length=4)
    executionIds: list[UUID] = Field(default_factory=list, max_length=50)
    lifecycleStages: list[
        Literal["PREPARE", "EXECUTE", "OBSERVE", "ANALYZE", "NORMALIZE", "GATE"]
    ] = Field(default_factory=list, max_length=6)
    indexedAfter: datetime | None = None
    indexedBefore: datetime | None = None
    includeStale: bool = False

    @model_validator(mode="after")
    def validate_time_window(self) -> "EvidenceQueryFilters":
        if (
            self.indexedAfter is not None
            and self.indexedBefore is not None
            and self.indexedAfter > self.indexedBefore
        ):
            raise ValueError("indexedAfter must not be after indexedBefore")
        return self


_EXECUTABLE_QUERY_PATTERN = re.compile(
    r"(?is)(?:\bselect\b.+\bfrom\b|\b(?:insert|update|delete|drop|alter|create)\b\s+"
    r"(?:table|database|index|into|from)?|<\s*script\b|#!\s*/|\$\(|\b(?:powershell|cmd\.exe)\b)"
)


class EvidenceQueryRequestContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.evidence-query-request.v1"] = (
        "phase8.evidence-query-request.v1"
    )
    projectId: UUID
    question: str = Field(min_length=1, max_length=2000)
    queryMode: Literal["keyword", "semantic", "hybrid"] = "hybrid"
    filters: EvidenceQueryFilters = Field(default_factory=EvidenceQueryFilters)
    limit: int = Field(default=20, ge=1, le=50)
    cursor: str | None = Field(default=None, max_length=4096)
    includeAnswer: bool = True

    @field_validator("question")
    @classmethod
    def reject_executable_query_language(cls, value: str) -> str:
        normalized = value.strip()
        if _EXECUTABLE_QUERY_PATTERN.search(normalized):
            raise ValueError("question must be natural language, not SQL or executable script")
        return normalized


class EvidenceCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    citationId: str
    entryId: UUID
    sourceType: EvidenceSourceType
    sourceId: str
    sourceVersion: str
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    title: str
    snippet: str
    evidenceRefs: list[dict[str, object]]
    artifactRefs: list[dict[str, object]]
    classification: EvidenceClassification
    available: bool
    unavailableReasonCode: str | None
    href: str | None


class EvidenceMatchedEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry: EvidenceIndexEntryContract
    score: float = Field(ge=0.0, le=1.0)
    matchedTerms: list[str]


class EvidenceQueryResultContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.evidence-query-result.v1"]
    queryHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    projectId: UUID
    answer: str | None
    citations: list[EvidenceCitation]
    matchedEntries: list[EvidenceMatchedEntry]
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str]
    unavailableReasons: list[dict[str, object]]
    traceId: UUID
    modelInvocationRef: dict[str, object] | None
    guardrailEventRefs: list[dict[str, object]]
    nextCursor: str | None
    snapshotAt: datetime
    readOnly: Literal[True]
    writesCanonicalDecision: Literal[False]

    @model_validator(mode="after")
    def require_citations_for_answer(self) -> "EvidenceQueryResultContract":
        if self.answer and not self.citations:
            raise ValueError("a factual answer requires at least one citation")
        return self


__all__ = [
    "EvidenceCitation",
    "EvidenceClassification",
    "EvidenceIndexEntryContract",
    "EvidenceIndexJobContract",
    "EvidenceMatchedEntry",
    "EvidenceQueryFilters",
    "EvidenceQueryRequestContract",
    "EvidenceQueryResultContract",
    "EvidenceRetentionState",
    "EvidenceSourceType",
]

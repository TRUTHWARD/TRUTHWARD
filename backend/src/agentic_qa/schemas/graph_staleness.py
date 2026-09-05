# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


GraphStalenessStatus = Literal["fresh", "suspect", "stale", "invalid", "unknown"]
_HASH = r"^sha256:[0-9a-f]{64}$"
_SECRET_MARKERS = re.compile(
    r"(?i)(password|passwd|authorization|bearer\s|api[_-]?key|private[_-]?key|client[_-]?secret|cookie)"
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


def _redacted(value: Any, label: str) -> Any:
    if _SECRET_MARKERS.search(json.dumps(value, sort_keys=True, default=str)):
        raise ValueError(f"{label} must not contain secret material")
    return value


class RequirementVersionRange(_StrictModel):
    sourceRef: str | None = Field(default=None, max_length=500)
    fromVersionId: UUID | None = None
    toVersionId: UUID | None = None
    minVersionNo: int | None = Field(default=None, ge=1)
    maxVersionNo: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_range(self) -> "RequirementVersionRange":
        if not any((self.fromVersionId, self.toVersionId, self.minVersionNo, self.maxVersionNo)):
            raise ValueError("requirement version range requires a stable version boundary")
        if self.minVersionNo and self.maxVersionNo and self.minVersionNo > self.maxVersionNo:
            raise ValueError("requirement version range is empty")
        return self


class CodeRevisionRange(_StrictModel):
    repositoryRef: str | None = Field(default=None, max_length=500)
    fromFingerprint: str | None = Field(default=None, pattern=_HASH)
    toFingerprint: str | None = Field(default=None, pattern=_HASH)
    acceptedFingerprints: list[str] = Field(default_factory=list, max_length=256)

    @field_validator("acceptedFingerprints")
    @classmethod
    def validate_fingerprints(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(_HASH, item) for item in value):
            raise ValueError("code revision fingerprints must be canonical sha256 refs")
        return sorted(set(value))

    @model_validator(mode="after")
    def validate_range(self) -> "CodeRevisionRange":
        if not any((self.fromFingerprint, self.toFingerprint, self.acceptedFingerprints)):
            raise ValueError("code revision range requires a stable fingerprint boundary")
        return self


class ApplicabilityRange(_StrictModel):
    schemaVersion: Literal["phase8.graph-applicability-range.v1"] = (
        "phase8.graph-applicability-range.v1"
    )
    requirementVersionRange: RequirementVersionRange | None = None
    codeRevisionRange: CodeRevisionRange | None = None
    environmentIds: list[UUID] = Field(default_factory=list, max_length=128)
    stages: list[str] = Field(default_factory=list, max_length=32)
    domains: list[str] = Field(default_factory=list, max_length=64)
    apiSchemaFingerprints: list[str] = Field(default_factory=list, max_length=128)
    uiAssetFingerprints: list[str] = Field(default_factory=list, max_length=128)

    @field_validator("apiSchemaFingerprints", "uiAssetFingerprints")
    @classmethod
    def validate_asset_fingerprints(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(_HASH, item) for item in value):
            raise ValueError("asset fingerprints must be canonical sha256 refs")
        return sorted(set(value))

    @field_validator("stages", "domains")
    @classmethod
    def normalize_names(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,79}", item) for item in value):
            raise ValueError("stage/domain contains an invalid identifier")
        return sorted(set(value))

    @model_validator(mode="after")
    def require_version_identity(self) -> "ApplicabilityRange":
        if not any(
            (
                self.requirementVersionRange,
                self.codeRevisionRange,
                self.apiSchemaFingerprints,
                self.uiAssetFingerprints,
            )
        ):
            raise ValueError("applicability requires at least one stable version or asset fingerprint")
        _redacted(self.model_dump(mode="json"), "Graph applicability")
        return self


class StalenessSignal(_StrictModel):
    signalId: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    source: Literal[
        "requirement", "scm", "environment", "api_schema", "ui_asset", "retention", "manual", "system"
    ]
    type: Literal["match", "changed", "missing", "unavailable", "conflict", "retention_deleted"]
    ref: str = Field(min_length=1, max_length=500)
    oldFingerprint: str | None = Field(default=None, pattern=_HASH)
    newFingerprint: str | None = Field(default=None, pattern=_HASH)
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]] = Field(min_length=1, max_length=256)

    @field_validator("ref")
    @classmethod
    def validate_signal_ref(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", value):
            raise ValueError("staleness signal ref must be a stable URI")
        return value

    @field_validator("evidence")
    @classmethod
    def validate_signal_evidence(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in value:
            if not isinstance(item.get("type"), str) or not item["type"].strip():
                raise ValueError("staleness evidence requires a type")
            ref = item.get("ref")
            if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", ref):
                raise ValueError("staleness evidence requires a stable URI ref")
        return value

    @model_validator(mode="after")
    def validate_signal(self) -> "StalenessSignal":
        if self.type == "match" and self.severity != "info":
            raise ValueError("matching signal severity must be info")
        if self.type == "changed" and (not self.oldFingerprint or not self.newFingerprint):
            raise ValueError("changed signal requires old and new fingerprints")
        _redacted(self.model_dump(mode="json"), "Staleness signal")
        return self


class AssessGraphStalenessRequest(_StrictModel):
    applicabilityRange: ApplicabilityRange
    signals: list[StalenessSignal] = Field(min_length=1, max_length=1_000)
    ruleVersion: Literal["graph-staleness-rules.v1"] = "graph-staleness-rules.v1"
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def unique_signals(self) -> "AssessGraphStalenessRequest":
        ids = [item.signalId for item in self.signals]
        if len(ids) != len(set(ids)):
            raise ValueError("staleness signalId values must be unique")
        return self


class RequestGraphStalenessReview(_StrictModel):
    action: Literal["confirm", "override", "deprecate"]
    requestedStatus: GraphStalenessStatus | None = None
    reasonCode: str = Field(pattern=r"^GRAPH_STALENESS_[A-Z0-9_]+$", max_length=120)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1, max_length=256)
    expiresAt: datetime | None = None
    expectedAssessmentHash: str = Field(pattern=_HASH)
    idempotencyKey: str = Field(min_length=1, max_length=255)

    @field_validator("evidenceRefs")
    @classmethod
    def validate_review_evidence(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in value:
            if not isinstance(item.get("type"), str) or not item["type"].strip():
                raise ValueError("review evidence requires a type")
            ref = item.get("ref")
            if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", ref):
                raise ValueError("review evidence requires a stable URI ref")
        return value

    @model_validator(mode="after")
    def validate_review(self) -> "RequestGraphStalenessReview":
        if self.action == "override" and (self.requestedStatus is None or self.expiresAt is None):
            raise ValueError("override requires requestedStatus and expiry")
        if self.action != "override" and self.requestedStatus is not None:
            raise ValueError("requestedStatus is only valid for override")
        if self.action == "deprecate" and self.expiresAt is not None:
            raise ValueError("deprecation does not expire")
        _redacted(self.evidenceRefs, "Staleness review evidence")
        return self


class ApplyGraphStalenessReview(_StrictModel):
    approvalId: UUID
    expectedLockVersion: int = Field(ge=1)


class GraphSelectionContext(_StrictModel):
    requirementVersionId: UUID | None = None
    requirementVersionNo: int | None = Field(default=None, ge=1)
    codeRevisionFingerprint: str | None = Field(default=None, pattern=_HASH)
    environmentId: UUID | None = None
    stage: str | None = Field(default=None, max_length=80)
    domain: str | None = Field(default=None, max_length=80)
    apiSchemaFingerprint: str | None = Field(default=None, pattern=_HASH)
    uiAssetFingerprint: str | None = Field(default=None, pattern=_HASH)


class SelectCanonicalGraphRequest(_StrictModel):
    mode: Literal["live", "replay"] = "live"
    graphId: UUID | None = None
    exactVersionId: UUID | None = None
    context: GraphSelectionContext = Field(default_factory=GraphSelectionContext)
    stalePolicy: Literal["reject", "allow_reviewed"] = "reject"

    @model_validator(mode="after")
    def validate_mode(self) -> "SelectCanonicalGraphRequest":
        if self.mode == "replay" and self.exactVersionId is None:
            raise ValueError("Replay selection requires the historically frozen exactVersionId")
        if self.mode == "live" and self.exactVersionId is not None:
            raise ValueError("live selection cannot force an exact historical version")
        return self


class GraphStalenessAssessmentContract(_StrictModel):
    schemaVersion: Literal["phase8.graph-staleness-assessment.v1"]
    assessmentId: UUID
    graphId: UUID
    graphVersionId: UUID
    status: GraphStalenessStatus
    applicabilityRange: dict[str, Any]
    signals: list[dict[str, Any]] = Field(min_length=1)
    sourceFingerprint: str = Field(pattern=_HASH)
    ruleVersion: Literal["graph-staleness-rules.v1"]
    reasonCodes: list[str] = Field(min_length=1)
    impact: dict[str, Any]
    automaticPromotionEligible: bool
    assessmentHash: str = Field(pattern=_HASH)
    assessedAt: datetime

    @model_validator(mode="after")
    def enforce_fresh_only_autonomy(self) -> "GraphStalenessAssessmentContract":
        if self.automaticPromotionEligible != (self.status == "fresh"):
            raise ValueError("only a base fresh assessment can qualify controlled autonomy")
        return self

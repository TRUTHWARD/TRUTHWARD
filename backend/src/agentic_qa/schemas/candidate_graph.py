# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CANDIDATE_TRANSFORMER_VERSION = "trace-to-candidate.v1"
MAX_CANDIDATE_ACTIONS = 2_000


class _StrictCandidateModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


class CandidateSourceRef(_StrictCandidateModel):
    type: Literal[
        "execution",
        "trace",
        "trace_span",
        "execution_task",
        "visual_attempt",
        "verification",
        "tool_call",
        "connector_call",
        "artifact",
        "evidence",
        "replay",
        "audit",
        "guardrail",
        "model_invocation",
        "candidate_build",
    ]
    ref: str = Field(min_length=4, max_length=500, pattern=r"^[a-z][a-z0-9+.-]*://[^\s]+$")
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    available: bool = True
    unavailableReason: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def validate_reference(self) -> "CandidateSourceRef":
        expected_scheme = {
            "execution": "execution://",
            "trace": "trace://",
            "trace_span": "trace-span://",
            "execution_task": "execution-task://",
            "visual_attempt": "visual-attempt://",
            "verification": "verification://",
            "tool_call": "tool-call://",
            "connector_call": "connector-call://",
            "artifact": "artifact://",
            "evidence": "evidence://",
            "replay": "replay://",
            "audit": "audit://",
            "guardrail": "guardrail://",
            "model_invocation": "model-invocation://",
            "candidate_build": "candidate-build://",
        }[self.type]
        if not self.ref.startswith(expected_scheme):
            raise ValueError(f"{self.type} Candidate ref must use {expected_scheme}")
        if any(marker in self.ref for marker in ("@", "?", "#", "=")):
            raise ValueError("Candidate refs must not contain credentials or query material")
        if self.available and self.unavailableReason is not None:
            raise ValueError("available Candidate ref must not carry unavailableReason")
        if not self.available and self.unavailableReason is None:
            raise ValueError("unavailable Candidate ref requires unavailableReason")
        return self


class ObservedTraceRef(_StrictCandidateModel):
    executionId: UUID
    traceRefs: list[CandidateSourceRef] = Field(max_length=128)
    sourceEventRefs: list[CandidateSourceRef] = Field(min_length=1, max_length=20_000)
    toolCallRefs: list[CandidateSourceRef] = Field(max_length=2_000)
    connectorCallRefs: list[CandidateSourceRef] = Field(max_length=2_000)
    replayRefs: list[CandidateSourceRef] = Field(max_length=256)
    authoritative: Literal[True] = True
    observed: Literal[True] = True
    immutable: Literal[True] = True


class CandidateAmbiguity(_StrictCandidateModel):
    code: str = Field(pattern=r"^CANDIDATE_[A-Z0-9_]+$", max_length=120)
    severity: Literal["info", "warning", "error"]
    entityRef: str | None = Field(default=None, max_length=500)
    detailKey: str = Field(pattern=r"^candidate\.ambiguity\.[a-z0-9_.-]+$", max_length=180)
    sourceEventRefs: list[CandidateSourceRef] = Field(max_length=256)
    parameters: dict[str, Any] = Field(default_factory=dict, max_length=32)

    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        serialized = str(value).lower()
        if any(marker in serialized for marker in ("password", "bearer ", "private key")):
            raise ValueError("Candidate ambiguity parameters must be redacted")
        return value


class CandidateProvenance(_StrictCandidateModel):
    sourceEventRefs: list[CandidateSourceRef] = Field(min_length=1, max_length=2_000)
    evidenceRefs: list[CandidateSourceRef] = Field(max_length=2_000)
    transformerVersion: str = Field(min_length=1, max_length=80)
    confidence: float = Field(ge=0.0, le=1.0)
    ambiguities: list[CandidateAmbiguity] = Field(max_length=2_000)


class CandidateNode(_StrictCandidateModel):
    nodeId: UUID
    nodeRef: str = Field(pattern=r"^ceg-node://[^\s]+$", max_length=500)
    semanticKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    nodeType: Literal["action", "assertion"]
    actionType: str = Field(min_length=1, max_length=80)
    intentKey: str = Field(min_length=1, max_length=128)
    provenance: CandidateProvenance


class CandidateEdge(_StrictCandidateModel):
    edgeId: UUID
    edgeRef: str = Field(pattern=r"^ceg-edge://[^\s]+$", max_length=500)
    edgeType: Literal["precedes", "transitions_to"]
    sourceNodeId: UUID
    targetNodeId: UUID
    reviewStatus: Literal["not_required", "pending_review"]
    provenance: CandidateProvenance


class CandidatePathStep(_StrictCandidateModel):
    stepId: UUID
    stepRef: str = Field(pattern=r"^ceg-step://[^\s]+$", max_length=500)
    order: int = Field(ge=1, le=MAX_CANDIDATE_ACTIONS)
    nodeId: UUID
    viaEdgeId: UUID | None
    outcome: Literal["success", "failure", "partial", "unknown"]
    retryCount: int = Field(ge=0)
    fallbackTypes: list[str] = Field(max_length=32)
    verificationStatus: str | None = Field(default=None, max_length=80)
    provenance: CandidateProvenance


class CandidatePath(_StrictCandidateModel):
    pathId: UUID
    pathRef: str = Field(pattern=r"^ceg-path://[^\s]+$", max_length=500)
    pathKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    versionId: UUID
    status: Literal["candidate"] = "candidate"
    source: Literal["candidate"] = "candidate"
    confidence: float = Field(ge=0.0, le=1.0)
    nodes: list[CandidateNode] = Field(min_length=1, max_length=MAX_CANDIDATE_ACTIONS)
    edges: list[CandidateEdge] = Field(max_length=MAX_CANDIDATE_ACTIONS)
    steps: list[CandidatePathStep] = Field(min_length=1, max_length=MAX_CANDIDATE_ACTIONS)
    provenance: CandidateProvenance
    activeCanonical: Literal[False] = False
    promotionEligible: Literal[False] = False

    @model_validator(mode="after")
    def validate_path(self) -> "CandidatePath":
        orders = [item.order for item in self.steps]
        if orders != list(range(1, len(self.steps) + 1)):
            raise ValueError("Candidate Path steps must be contiguous and ordered")
        node_ids = {item.nodeId for item in self.nodes}
        edge_ids = {item.edgeId for item in self.edges}
        if any(item.nodeId not in node_ids for item in self.steps):
            raise ValueError("Candidate Path step must reference a Candidate Node")
        if any(item.viaEdgeId not in edge_ids for item in self.steps if item.viaEdgeId):
            raise ValueError("Candidate Path step must reference a Candidate Edge")
        return self


class CandidateEvidenceSummary(_StrictCandidateModel):
    independentRunCount: int = Field(ge=0)
    successCount: int = Field(ge=0)
    failureCount: int = Field(ge=0)
    distinctRevisionCount: int = Field(ge=0)
    distinctEnvironmentCount: int = Field(ge=0)
    verificationCoverage: float = Field(ge=0.0, le=1.0)
    retryCount: int = Field(ge=0)
    fallbackTypes: list[str] = Field(max_length=32)
    coordinateClickCount: int = Field(ge=0)
    conflictRefs: list[CandidateSourceRef] = Field(max_length=2_000)
    flakySignals: list[str] = Field(max_length=128)
    lastObservedAt: datetime

    @model_validator(mode="after")
    def validate_run_counts(self) -> "CandidateEvidenceSummary":
        if self.successCount + self.failureCount > self.independentRunCount:
            raise ValueError("Candidate outcome counts cannot exceed independentRunCount")
        return self


class CandidateBuildConfig(_StrictCandidateModel):
    includeModelSuggestions: bool = False
    maxActions: int = Field(default=1_000, ge=1, le=MAX_CANDIDATE_ACTIONS)
    confidenceFloor: float = Field(default=0.05, ge=0.0, le=1.0)


class CandidateBuildRequest(_StrictCandidateModel):
    schemaVersion: Literal["phase8.candidate-build-request.v1"] = (
        "phase8.candidate-build-request.v1"
    )
    graphId: UUID
    executionId: UUID
    transformerVersion: str = Field(default=CANDIDATE_TRANSFORMER_VERSION, min_length=1, max_length=80)
    config: CandidateBuildConfig = Field(default_factory=CandidateBuildConfig)

    @field_validator("transformerVersion")
    @classmethod
    def validate_transformer_version(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,79}", value):
            raise ValueError("transformerVersion must be a stable version identifier")
        return value


class CandidateSuggestionItem(_StrictCandidateModel):
    suggestionType: Literal["ambiguity", "confidence_review", "semantic_label"]
    targetSemanticKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    reasonCode: str = Field(pattern=r"^CANDIDATE_MODEL_[A-Z0-9_]+$", max_length=120)
    confidence: float = Field(ge=0.0, le=1.0)


class CandidateModelSuggestion(_StrictCandidateModel):
    status: Literal["not_requested", "unavailable", "suggested", "rejected"]
    suggestions: list[CandidateSuggestionItem] = Field(max_length=128)
    modelInvocationRef: CandidateSourceRef | None = None
    applied: Literal[False] = False


class CandidateBuildResult(_StrictCandidateModel):
    schemaVersion: Literal["phase8.candidate-build-result.v1"] = (
        "phase8.candidate-build-result.v1"
    )
    buildId: UUID
    buildRef: str = Field(pattern=r"^candidate-build://[^\s]+$", max_length=500)
    projectId: UUID
    graphId: UUID
    candidateVersionId: UUID
    status: Literal["completed"]
    transformerVersion: str = Field(min_length=1, max_length=80)
    configHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    observedTrace: ObservedTraceRef
    candidatePath: CandidatePath
    evidenceSummary: CandidateEvidenceSummary
    ambiguities: list[CandidateAmbiguity] = Field(max_length=5_000)
    modelSuggestion: CandidateModelSuggestion
    traceId: UUID
    guardrailEventRefs: list[CandidateSourceRef] = Field(max_length=128)
    auditRefs: list[CandidateSourceRef] = Field(max_length=128)
    canonical: Literal[False] = False
    active: Literal[False] = False
    promotionPerformed: Literal[False] = False
    writesGate: Literal[False] = False
    writesMemory: Literal[False] = False
    executesActions: Literal[False] = False
    readOnly: Literal[True] = True


__all__ = [
    "CANDIDATE_TRANSFORMER_VERSION",
    "CandidateAmbiguity",
    "CandidateBuildConfig",
    "CandidateBuildRequest",
    "CandidateBuildResult",
    "CandidateEdge",
    "CandidateEvidenceSummary",
    "CandidateModelSuggestion",
    "CandidateNode",
    "CandidatePath",
    "CandidatePathStep",
    "CandidateProvenance",
    "CandidateSourceRef",
    "CandidateSuggestionItem",
    "ObservedTraceRef",
]

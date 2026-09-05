# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.schemas.candidate_graph import CandidateSuggestionItem


class _StrictModelOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ModelEvidenceRef(_StrictModelOutput):
    type: str = Field(min_length=1, max_length=120)
    ref: str | None = Field(default=None, min_length=1, max_length=1000)
    id: str | None = Field(default=None, min_length=1, max_length=500)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def require_stable_reference(self) -> "ModelEvidenceRef":
        if not self.ref and not self.id:
            raise ValueError("model evidence must include ref or id")
        return self


class PlannerDomainScenarios(_StrictModelOutput):
    scenarios: list[str] = Field(max_length=200)


class PlannerDomainTargets(_StrictModelOutput):
    targets: list[str] = Field(max_length=200)


class PlannerDomainChecks(_StrictModelOutput):
    checks: list[str] = Field(max_length=200)


class PlannerResultOutput(_StrictModelOutput):
    functional: PlannerDomainScenarios
    performance: PlannerDomainTargets
    security: PlannerDomainChecks


class PlannerModelOutput(_StrictModelOutput):
    result: PlannerResultOutput
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[ModelEvidenceRef] = Field(max_length=200)
    limitations: list[str] = Field(max_length=100)
    metadata: dict[str, Any]


class GeneratedCasesOutput(_StrictModelOutput):
    functional: list[dict[str, Any]] = Field(max_length=500)
    performance: list[dict[str, Any]] = Field(max_length=500)
    security: list[dict[str, Any]] = Field(max_length=500)


class GeneratorResultOutput(_StrictModelOutput):
    generatedCases: GeneratedCasesOutput
    summary: str = Field(max_length=4000)


class GeneratorModelOutput(_StrictModelOutput):
    result: GeneratorResultOutput
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[ModelEvidenceRef] = Field(max_length=200)
    limitations: list[str] = Field(max_length=100)
    metadata: dict[str, Any]


class CandidateSuggestionModelOutput(_StrictModelOutput):
    suggestions: list[CandidateSuggestionItem] = Field(max_length=128)


class EvidenceAnswerModelOutput(_StrictModelOutput):
    answer: str | None = Field(max_length=20_000)
    citationEntryIds: list[str] = Field(max_length=200)
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(max_length=100)


class RequirementMatchCandidateOutput(_StrictModelOutput):
    requirementId: str = Field(min_length=1, max_length=255)
    confidence: float = Field(ge=0.0, le=1.0)


class RequirementMatchModelOutput(_StrictModelOutput):
    candidates: list[RequirementMatchCandidateOutput] = Field(max_length=50)


__all__ = [
    "CandidateSuggestionModelOutput",
    "EvidenceAnswerModelOutput",
    "GeneratorModelOutput",
    "ModelEvidenceRef",
    "PlannerModelOutput",
    "RequirementMatchModelOutput",
]

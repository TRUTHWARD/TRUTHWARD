# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ScenarioAcceptanceContract(BaseModel):
    """A review record; it does not certify business correctness."""

    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["community.scenario-acceptance.v1"]
    expectedOutcome: str = Field(max_length=4000)
    sourceCriterionRef: str = Field(max_length=1000)
    sourceText: str = Field(max_length=4000)
    basis: Literal["requirement", "inferred", "manual"]
    openQuestions: list[str] = Field(max_length=50)
    reviewed: bool

    @model_validator(mode="after")
    def validate_review(self) -> "ScenarioAcceptanceContract":
        if self.reviewed and (not self.expectedOutcome.strip() or self.openQuestions):
            raise ValueError("A reviewed expectation needs an outcome and no open questions")
        if any(len(question) > 4000 for question in self.openQuestions):
            raise ValueError("Business question exceeds the size limit")
        if self.basis == "requirement" and (not self.sourceCriterionRef or not self.sourceText):
            raise ValueError("A requirement basis needs a source reference and quotation")
        if self.basis != "requirement" and (self.sourceCriterionRef or self.sourceText):
            raise ValueError("An unlinked expectation cannot carry a requirement quotation")
        return self

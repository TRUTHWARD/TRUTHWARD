# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from agentic_qa.domain.enums import ModelRole


@dataclass(slots=True)
class AgentResult:
    result: dict[str, Any]
    confidence: float
    evidence: list[str | dict[str, Any]]
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def payload(self) -> dict[str, Any]:
        """Compatibility view for legacy call sites while result is canonical."""

        return self.result if isinstance(self.result, dict) else {}

    def to_contract(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "limitations": self.limitations,
            "metadata": self.metadata,
        }


class BaseAgent(ABC):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = {}
    output_schema: dict[str, Any] = {}
    allowed_tools: list[str] = []
    allowed_skills: list[str] = []
    preferred_model_role: ModelRole = ModelRole.PRIMARY

    @abstractmethod
    def run(self, input_payload: dict[str, Any]) -> AgentResult:
        raise NotImplementedError

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "allowedTools": self.allowed_tools,
            "allowedSkills": self.allowed_skills,
            "preferredModelRole": self.preferred_model_role.value,
        }

# SPDX-License-Identifier: Apache-2.0
from typing import Any

from pydantic import BaseModel, Field, field_validator

from agentic_qa.guardrails.result import GuardrailDecision


class UpdateGuardrailPolicyRequest(BaseModel):
    enabled: bool | None = None
    decisionOverrides: dict[str, str] | None = Field(default=None)
    metadata: dict[str, Any] | None = Field(default=None)

    @field_validator("decisionOverrides")
    @classmethod
    def validate_decision_overrides(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is None:
            return value
        allowed_decisions = {decision.value for decision in GuardrailDecision}
        for source, target in value.items():
            if source not in allowed_decisions:
                raise ValueError(f"unsupported source decision: {source}")
            if target not in allowed_decisions:
                raise ValueError(f"unsupported target decision: {target}")
        return value

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class GuardrailDecision(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(slots=True)
class GuardrailResult:
    """
    Structured result emitted by runtime guardrails.

    Args:
        rule_id: Stable rule identifier for audit and analytics.
        decision: Allow, warn, or block outcome.
        reason: Human-readable rule outcome summary.
        evidence: Supporting evidence used to explain the outcome.
        metadata: Additional machine-readable context for auditing.
    """

    rule_id: str
    decision: GuardrailDecision
    reason: str
    evidence: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        """Return whether the current rule outcome should stop execution."""

        return self.decision == GuardrailDecision.BLOCK


class GuardrailViolationError(ValueError):
    """Raised when a runtime guardrail blocks the current operation."""

    def __init__(self, result: GuardrailResult) -> None:
        super().__init__(result.reason)
        self.result = result

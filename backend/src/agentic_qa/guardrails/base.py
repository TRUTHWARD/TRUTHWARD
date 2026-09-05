# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from agentic_qa.guardrails.result import GuardrailResult


@dataclass(slots=True)
class GuardrailContext:
    """
    Common evaluation context shared by runtime guardrails.

    Args:
        trace_id: Current trace identifier used for audit correlation.
        request_id: Current request identifier used for audit correlation.
        actor_id: Optional user or system actor identifier.
        actor_roles: Roles available to the current actor.
        resource_type: Business resource being protected.
        resource_id: Optional protected resource identifier.
        execution_id: Optional execution identifier for execution-scoped rules.
        skill_invocation_id: Optional service-managed skill invocation identifier.
        connector_binding_id: Optional connector credential binding identifier.
        tool_call_id: Optional managed tool call identifier.
        payload: Rule-specific structured input.
        metadata: Additional evaluation hints that are not part of payload.
    """

    trace_id: str | UUID | None
    request_id: str | None
    actor_id: str | UUID | None = None
    actor_roles: list[str] = field(default_factory=list)
    resource_type: str = "guardrail"
    resource_id: str | None = None
    execution_id: str | UUID | None = None
    skill_invocation_id: str | UUID | None = None
    connector_binding_id: str | UUID | None = None
    tool_call_id: str | UUID | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class RuntimeGuardrail(ABC):
    """Base contract for synchronous runtime guardrail evaluation."""

    rule_id: str

    @abstractmethod
    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        """
        Evaluate a runtime guardrail.

        Args:
            context: Structured runtime context for the current operation.

        Returns:
            GuardrailResult: Evaluation outcome for the rule.
        """

        raise NotImplementedError

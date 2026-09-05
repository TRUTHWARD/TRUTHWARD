# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult


class MemoryWriteGuard(RuntimeGuardrail):
    """Protect long-term memory from unverified or speculative writes."""

    rule_id = "memory_write.confirmed_fact_only"

    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        scope = str(context.payload.get("scope", "")).lower()
        metadata = context.payload.get("metadata", {})
        source = str(metadata.get("source", "unknown")).lower()

        if scope not in {"project", "org"}:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.ALLOW,
                reason="session-scoped memory is allowed without long-term verification",
                evidence=[f"scope={scope or 'session'}"],
            )

        if metadata.get("verified") is False or metadata.get("confirmedFact") is False:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="unverified data cannot be written into long-term memory",
                evidence=["metadata marks the memory as unverified"],
                metadata={"scope": scope, "source": source},
            )

        if source in {"triage", "healer", "agent"} and not metadata.get("confirmedFact"):
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.WARN,
                reason="agent-derived long-term memory should carry confirmedFact=true",
                evidence=[f"source={source}", "confirmedFact flag missing"],
                metadata={"scope": scope, "source": source},
            )

        return GuardrailResult(
            rule_id=self.rule_id,
            decision=GuardrailDecision.ALLOW,
            reason="memory write satisfied long-term verification policy",
            evidence=[f"scope={scope}", f"source={source}"],
            metadata={"scope": scope, "source": source},
        )

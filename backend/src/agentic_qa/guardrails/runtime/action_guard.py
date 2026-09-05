# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult


class ActionGuard(RuntimeGuardrail):
    """Protect high-impact actions that need role checks or approvals."""

    rule_id = "action.high_risk_operations_controlled"

    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        action = str(context.metadata.get("action", "unknown"))
        mode = str(context.payload.get("mode", ""))
        actor_roles = set(context.actor_roles)

        if action == "execution.heal" and mode == "generate_patch":
            if "admin" not in actor_roles:
                return GuardrailResult(
                    rule_id=self.rule_id,
                    decision=GuardrailDecision.BLOCK,
                    reason="generate_patch requires admin privileges",
                    evidence=["current actor does not have admin role"],
                    metadata={"action": action, "mode": mode},
                )
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.WARN,
                reason="generate_patch is high risk and should stay approval-backed",
                evidence=["patch generation can modify executable test assets"],
                metadata={"action": action, "mode": mode},
            )

        return GuardrailResult(
            rule_id=self.rule_id,
            decision=GuardrailDecision.ALLOW,
            reason=f"{action} satisfied action guard",
            evidence=["no restricted action detected"],
            metadata={"action": action, "mode": mode},
        )

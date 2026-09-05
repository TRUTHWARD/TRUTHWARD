# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.policies import HIGH_RISK_LEVELS
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult


class ModelRoutingGuard(RuntimeGuardrail):
    """Validate that selected model roles satisfy high-risk routing policy."""

    rule_id = "model_routing.required_roles_resolved"

    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        risk_level = context.payload.get("riskLevel")
        required_roles = set(context.payload.get("selectedRoles", []))
        selected_models = context.payload.get("selectedModels", [])
        prefer_local = bool(context.payload.get("preferLocal", False))

        missing_roles = [
            item["role"]
            for item in selected_models
            if item["role"] in required_roles and not item.get("roleSatisfied", False)
        ]

        if missing_roles:
            decision = GuardrailDecision.BLOCK if risk_level in HIGH_RISK_LEVELS else GuardrailDecision.WARN
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=decision,
                reason="routing policy could not resolve all required model roles",
                evidence=[f"missing role binding for {role}" for role in missing_roles],
                metadata={"missingRoles": missing_roles},
            )

        if prefer_local and not any(item.get("provider") in {"ollama", "vllm"} for item in selected_models):
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="preferLocal policy requested a local model but none was selected",
                evidence=["no selected provider is marked as local"],
            )

        return GuardrailResult(
            rule_id=self.rule_id,
            decision=GuardrailDecision.ALLOW,
            reason="routing policy satisfied guardrail checks",
            evidence=[f"roles={sorted(required_roles)}"],
        )

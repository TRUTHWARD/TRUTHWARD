# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult


class GatePolicyMutationGuard(RuntimeGuardrail):
    """Reassess Gate Policy mutation risk inside the backend boundary."""

    rule_id = "gate_policy.mutation_preflight"

    _KNOWN_ACTIONS = {
        "create_draft",
        "preview_import",
        "update_draft",
        "validate",
        "submit_review",
        "review_decision",
        "lifecycle_transition",
        "simulation_create",
        "simulation_cancel",
        "shadow_evaluate",
        "mode_change",
        "activation_request",
        "activation_apply",
        "rollback_request",
        "rollback_apply",
    }
    _HIGH_RISK_ACTIONS = {
        "submit_review",
        "review_decision",
        "lifecycle_transition",
        "activation_request",
        "activation_apply",
        "rollback_request",
        "rollback_apply",
    }

    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        action = str(context.metadata.get("action") or "")
        target_status = context.payload.get("targetStatus")
        document_status = context.payload.get("documentStatus")

        if action not in self._KNOWN_ACTIONS:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="unknown Gate Policy mutation is blocked",
                evidence=["service mutation allowlist"],
                metadata={"action": action, "riskLevel": "high"},
            )
        if target_status == "active" and action not in {"activation_request", "activation_apply"}:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="production Gate Policy activation must use the P06 approval-backed activation flow",
                evidence=["P06 activation boundary"],
                metadata={"action": action, "riskLevel": "high"},
            )
        if context.payload.get("mode") == "enforce" and action not in {"activation_request", "activation_apply", "rollback_request", "rollback_apply"}:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="Enforce mode must use approval-backed activation or rollback",
                evidence=["system hard rule: Enforce requires approval"],
                metadata={"action": action, "riskLevel": "high"},
            )
        if action in {"create_draft", "update_draft"} and document_status != "draft":
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="draft mutation cannot publish or activate a Gate Policy version",
                evidence=["draft-only management contract"],
                metadata={"action": action, "riskLevel": "high"},
            )

        risk_level = "high" if action in self._HIGH_RISK_ACTIONS else "medium"
        decision = GuardrailDecision.WARN if risk_level == "high" else GuardrailDecision.ALLOW
        return GuardrailResult(
            rule_id=self.rule_id,
            decision=decision,
            reason=f"Gate Policy {action} passed backend mutation preflight",
            evidence=["capability checked", "project scope checked", "P06 mode boundary checked"],
            metadata={
                "action": action,
                "riskLevel": risk_level,
                "approvalRequired": action in self._HIGH_RISK_ACTIONS,
            },
        )

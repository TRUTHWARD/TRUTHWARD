# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult


class CIWritebackGuard(RuntimeGuardrail):
    """Fail closed around CI Connector writes and Enforce policy changes."""

    rule_id = "ci.writeback_controlled"
    _ACTIONS = {
        "ci.writeback",
        "ci.writeback.retry",
        "ci.enforcement.change",
        "ci.enforcement.apply",
    }

    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        action = str(context.metadata.get("action") or "")
        mode = str(context.payload.get("mode") or "")
        if action not in self._ACTIONS:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="unknown CI writeback action is blocked",
                evidence=["CI action allowlist"],
                metadata={"action": action},
            )
        if any(context.payload.get(flag) for flag in ("closePullRequest", "merge", "deleteBranch", "modifyCode")):
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="CI writeback cannot close, merge, delete a branch, or modify code",
                evidence=["P23 dangerous action prohibition"],
                metadata={"action": action, "mode": mode},
            )
        if action in {"ci.writeback", "ci.writeback.retry"} and context.payload.get("headCurrent") is not True:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="CI writeback requires a current SCM head check",
                evidence=["SCM current head verification"],
                metadata={"action": action, "mode": mode},
            )
        if (mode == "enforce" or action == "ci.writeback.retry") and not context.payload.get("approvalRef"):
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="Enforce requires an approval-backed active policy",
                evidence=["P23 Enforce approval hard rule"],
                metadata={"action": action, "mode": mode},
            )
        decision = GuardrailDecision.WARN if mode == "enforce" or action.endswith("retry") else GuardrailDecision.ALLOW
        return GuardrailResult(
            rule_id=self.rule_id,
            decision=decision,
            reason="CI writeback action passed controlled preflight",
            evidence=["Service-owned conclusion", "SCM head check", "Connector capability check"],
            metadata={"action": action, "mode": mode, "approvalRequired": mode == "enforce" or action.endswith("retry")},
        )

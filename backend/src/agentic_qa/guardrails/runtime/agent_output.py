# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.agents.base import AgentResult
from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.schemas.contracts import ContractValidationError, validate_contract


class AgentOutputGuard(RuntimeGuardrail):
    """Ensure agent results remain structured and evidence-backed."""

    rule_id = "agent_output.structured_result_required"

    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        agent_name = str(context.payload.get("agentName", "agent"))
        agent_result = context.payload.get("agentResult")
        evidence: list[str] = []
        issues: list[str] = []

        if not isinstance(agent_result, AgentResult):
            issues.append("agent result is not an AgentResult instance")
        else:
            try:
                validate_contract("agent-output", agent_result.to_contract())
            except ContractValidationError as exc:
                issues.extend(exc.issues)
            if isinstance(agent_result.evidence, list):
                evidence.extend(str(item) for item in agent_result.evidence)

        if issues:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason=f"{agent_name} returned an invalid structured payload",
                evidence=issues,
                metadata={"agentName": agent_name},
            )

        return GuardrailResult(
            rule_id=self.rule_id,
            decision=GuardrailDecision.ALLOW,
            reason=f"{agent_name} output satisfied structured contract",
            evidence=evidence,
            metadata={"agentName": agent_name},
        )

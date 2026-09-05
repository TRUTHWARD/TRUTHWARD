# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent


class GeneratorAgent(BaseAgent):
    name = "GeneratorAgent"
    description = "Expand a high-level plan into concrete executable scenarios for each enabled domain."
    input_schema = {
        "planName": "str",
        "generatedPlan": "dict",
    }
    output_schema = {
        "generatedCases": "dict[str, list[dict[str, str]]]",
        "summary": "str",
    }
    allowed_tools = []
    allowed_skills = ["test-case-generation"]

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        generated_plan = input_payload.get("generatedPlan", {})
        functional_plan = generated_plan.get("functional", {}) if isinstance(generated_plan, dict) else {}
        performance_plan = generated_plan.get("performance", {}) if isinstance(generated_plan, dict) else {}
        security_plan = generated_plan.get("security", {}) if isinstance(generated_plan, dict) else {}

        functional_cases = [
            {"name": f"functional::{scenario}", "goal": str(scenario)}
            for scenario in functional_plan.get("scenarios", [])[:5]
        ]
        performance_cases = [
            {"name": f"performance::{target}", "goal": str(target)}
            for target in performance_plan.get("targets", [])[:3]
        ]
        security_cases = [
            {"name": f"security::{check}", "goal": str(check)}
            for check in security_plan.get("checks", [])[:4]
        ]

        payload = {
            "generatedCases": {
                "functional": functional_cases,
                "performance": performance_cases,
                "security": security_cases,
            },
            "summary": f"generated {len(functional_cases) + len(performance_cases) + len(security_cases)} cases",
        }
        return AgentResult(
            result=payload,
            confidence=0.86,
            evidence=["generatedPlan"],
            metadata={"status": "generated"},
        )

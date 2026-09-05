# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent


class PlannerAgent(BaseAgent):
    name = "PlannerAgent"
    description = "Generate a high-level cross-domain test plan from requirements and code change context."
    input_schema = {
        "requirements": "list[str]",
        "diffSummary": "str",
    }
    output_schema = {
        "functional": {"scenarios": "list[str]"},
        "performance": {"targets": "list[str]"},
        "security": {"checks": "list[str]"},
    }
    allowed_tools = []
    allowed_skills = ["test-plan-generation"]

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        requirements = input_payload.get("requirements", [])
        diff_summary = str(input_payload.get("diffSummary", ""))

        functional_scenarios = [
            "core journey regression",
            "boundary input validation",
        ]
        if requirements:
            functional_scenarios.extend(str(item) for item in requirements[:3])
        if "checkout" in diff_summary.lower():
            functional_scenarios.append("checkout smoke verification")

        payload = {
            "functional": {
                "scenarios": functional_scenarios,
            },
            "performance": {
                "targets": [
                    "critical API p95 < 800ms",
                ],
            },
            "security": {
                "checks": [
                    "authorization validation",
                    "input validation",
                ],
            },
        }
        return AgentResult(
            result=payload,
            confidence=0.88,
            evidence=["requirements", "diffSummary"],
            metadata={"status": "generated"},
        )

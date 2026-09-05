# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent


class PlannerAgent(BaseAgent):
    name = "PlannerAgent"

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        requirements = input_payload.get("requirements", [])
        diff_summary = str(input_payload.get("diffSummary", ""))

        functional_scenarios = [
            "核心主流程回归",
            "边界输入校验",
        ]
        if requirements:
            functional_scenarios.extend(str(item) for item in requirements[:3])
        if "checkout" in diff_summary.lower():
            functional_scenarios.append("结算链路冒烟验证")

        payload = {
            "functional": {
                "scenarios": functional_scenarios,
            },
            "performance": {
                "targets": [
                    "关键 API p95 < 800ms",
                ],
            },
            "security": {
                "checks": [
                    "鉴权校验",
                    "输入校验",
                ],
            },
        }
        return AgentResult(
            result=payload,
            confidence=0.88,
            evidence=["requirements", "diffSummary"],
            metadata={"status": "generated"},
        )

# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent
from agentic_qa.domain.enums import ModelRole


class JudgeAgent(BaseAgent):
    name = "JudgeAgent"
    description = "Render the final decision for challenged or high-risk analysis results."
    input_schema = {
        "domain": "str",
        "primaryResult": "dict",
        "taskStatus": "str",
    }
    output_schema = {
        "category": "str",
        "challenged": "bool",
        "summary": "str",
    }
    allowed_tools = []
    allowed_skills = ["risk-judgement"]
    preferred_model_role = ModelRole.JUDGE

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        domain = str(input_payload.get("domain", "functional"))
        primary_result = input_payload.get("primaryResult", {})
        task_status = str(input_payload.get("taskStatus", "completed"))
        category = str(primary_result.get("category", "unknown")) if isinstance(primary_result, dict) else "unknown"
        summary = f"judge reviewed {domain} analysis"
        if domain == "security" and task_status == "failed":
            category = "security_issue"
            summary = "judge kept blocking security classification"
        elif domain == "performance" and task_status == "failed":
            category = "performance_issue"
            summary = "judge confirmed performance regression"

        payload = {
            "category": category,
            "challenged": domain in {"performance", "security"},
            "summary": summary,
        }
        return AgentResult(
            result=payload,
            confidence=0.93 if payload["challenged"] else 0.78,
            evidence=["primaryResult", "taskStatus"],
            metadata={"status": category},
        )

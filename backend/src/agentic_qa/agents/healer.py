# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent


class HealerAgent(BaseAgent):
    name = "HealerAgent"
    description = "Produce a safe patch suggestion or remediation draft for a failed task."
    input_schema = {
        "taskType": "str",
        "errorMessage": "str",
    }
    output_schema = {
        "type": "str",
        "summary": "str",
        "patch": "str",
    }
    allowed_tools = []
    allowed_skills = ["patch-suggestion"]

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        task_name = str(input_payload.get("taskType", "task"))
        summary = f"Provide patch suggestion for {task_name}"
        patch = (
            "--- a/tests/example.spec.ts\n"
            "+++ b/tests/example.spec.ts\n"
            "@@\n"
            "- await page.locator('text=Submit').click()\n"
            "+ await page.getByRole('button', { name: 'Submit' }).click()\n"
        )
        return AgentResult(
            result={
                "type": "locator_fix",
                "summary": summary,
                "patch": patch,
            },
            confidence=0.79,
            evidence=["taskType", "errorMessage"],
            metadata={"status": "suggested"},
        )

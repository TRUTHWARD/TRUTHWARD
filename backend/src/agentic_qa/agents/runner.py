# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent


class RunnerAgent(BaseAgent):
    name = "RunnerAgent"
    description = "Prepare execution intent and skill request constraints for one execution task."
    input_schema = {
        "domain": "str",
        "taskType": "str",
        "runner": "str",
        "config": "dict",
        "parallelism": "int",
    }
    output_schema = {
        "skillRequest": "dict",
        "executionIntent": "dict",
        "semanticActionIntent": "dict",
        "executionConstraints": "dict",
        "timeoutSeconds": "int",
        "parallelism": "int",
    }
    allowed_tools = []
    allowed_skills = ["execution-runner"]

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        config = input_payload.get("config", {})
        domain = str(input_payload.get("domain", "functional"))
        runner = str(input_payload.get("runner", "playwright"))
        timeout_seconds = int(config.get("timeoutSeconds", 60)) if isinstance(config, dict) else 60
        parallelism = int(input_payload.get("parallelism", 1))

        payload = {
            "skillRequest": {
                "skillId": "execution-runner",
                "operation": "execute_task",
                "input": {
                    "domain": domain,
                    "taskType": str(input_payload.get("taskType", "")),
                    "runnerRef": runner,
                    "configRef": "task.config",
                },
            },
            "executionIntent": {
                "domain": domain,
                "runnerRef": runner,
                "taskType": str(input_payload.get("taskType", "")),
            },
            "semanticActionIntent": input_payload.get("semanticAction", {}) if isinstance(input_payload.get("semanticAction"), dict) else {},
            "executionConstraints": {
                "timeoutSeconds": timeout_seconds,
                "parallelism": parallelism,
            },
            "timeoutSeconds": timeout_seconds,
            "parallelism": parallelism,
            "intentNotes": [
                f"domain={domain}",
                f"runnerRef={runner}",
                "preserve normalized finding contract",
            ],
        }
        return AgentResult(
            result=payload,
            confidence=0.82,
            evidence=["taskType", "runner", "config"],
            metadata={"status": "skill_request_ready"},
        )

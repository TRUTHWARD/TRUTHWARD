# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent


class TriageAgent(BaseAgent):
    name = "TriageAgent"
    description = "Classify functional failures and summarize the most likely root cause."
    input_schema = {
        "domain": "str",
        "errorMessage": "str",
    }
    output_schema = {
        "category": "str",
        "confidence": "float",
        "evidence": "list[str]",
    }
    allowed_tools = []
    allowed_skills = ["finding-triage"]

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        error_message = str(input_payload.get("errorMessage", "")).lower()
        domain = str(input_payload.get("domain", "functional"))

        category = "unknown"
        evidence = []
        if "timeout" in error_message or "locator" in error_message:
            category = "test_issue"
            evidence.append("error message indicates unstable UI interaction")
        elif domain == "performance":
            category = "performance_issue"
            evidence.append("performance domain task exceeded threshold")
        elif domain == "security":
            category = "security_issue"
            evidence.append("security domain task produced blocking evidence")
        elif error_message:
            category = "bug"
            evidence.append("execution task returned application error")

        confidence = 0.84 if category != "unknown" else 0.55
        result = {
            "category": category,
            "confidence": confidence,
            "evidence": evidence or ["insufficient explicit evidence"],
        }
        return AgentResult(
            result=result,
            confidence=confidence,
            evidence=result["evidence"],
            metadata={"status": category},
        )

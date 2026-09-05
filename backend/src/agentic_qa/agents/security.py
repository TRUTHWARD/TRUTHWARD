# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent


class SecurityAgent(BaseAgent):
    name = "SecurityAgent"
    description = "Analyze normalized security findings and summarize the likely security risk."
    input_schema = {
        "findings": "list[dict]",
        "errorMessage": "str | None",
    }
    output_schema = {
        "category": "str",
        "confidence": "float",
        "evidence": "list[str]",
        "severity": "str",
    }
    allowed_tools = []
    allowed_skills = ["security-analysis"]

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        findings = input_payload.get("findings", [])
        error_message = str(input_payload.get("errorMessage", "") or "")
        evidence: list[str] = []
        highest_severity = "low"
        if isinstance(findings, list):
            finding_items = [item for item in findings if isinstance(item, dict)]
            severities = [str(item.get("severity", "low")) for item in finding_items]
            if "critical" in severities:
                highest_severity = "critical"
            elif "high" in severities:
                highest_severity = "high"
            elif "medium" in severities:
                highest_severity = "medium"
            if finding_items:
                evidence.append(f"{len(finding_items)} security findings analyzed")
                evidence.extend(
                    (
                        f"{item.get('source', 'security')} raw finding "
                        f"{item.get('id') or item.get('rawRef')}"
                    )
                    for item in finding_items
                    if item.get("id") or item.get("rawRef")
                )
        if error_message:
            evidence.append(error_message)

        confidence = 0.91 if findings else 0.7
        payload = {
            "category": "security_issue" if findings or error_message else "unknown",
            "confidence": confidence,
            "evidence": evidence or ["security domain task evaluated"],
            "severity": highest_severity,
        }
        return AgentResult(
            result=payload,
            confidence=confidence,
            evidence=payload["evidence"],
            metadata={"status": payload["category"]},
        )

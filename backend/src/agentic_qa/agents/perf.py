# SPDX-License-Identifier: Apache-2.0
from agentic_qa.agents.base import AgentResult, BaseAgent


class PerfAgent(BaseAgent):
    name = "PerfAgent"
    description = "Analyze performance metrics and classify latency or capacity regressions."
    input_schema = {
        "metrics": "list[dict]",
        "errorMessage": "str | None",
    }
    output_schema = {
        "category": "str",
        "confidence": "float",
        "evidence": "list[str]",
        "summary": "str",
        "baselineComparisons": "list[dict]",
    }
    allowed_tools = []
    allowed_skills = ["performance-analysis"]

    def run(self, input_payload: dict[str, object]) -> AgentResult:
        metrics = input_payload.get("metrics", [])
        error_message = str(input_payload.get("errorMessage", "") or "")
        evidence: list[str] = []
        baseline_comparisons: list[dict[str, object]] = []
        category = "performance_issue"
        summary = "performance regression requires follow-up"

        if isinstance(metrics, list):
            structured_metrics = [item for item in metrics if isinstance(item, dict)]
            threshold_breaches = [
                item
                for item in structured_metrics
                if item.get("thresholdValue") is not None
                and item.get("metricValue") is not None
                and item["metricValue"] > item["thresholdValue"]
            ]
            for item in structured_metrics:
                metric_value = item.get("metricValue")
                baseline_value = item.get("baselineValue")
                if metric_value is None or baseline_value is None:
                    continue
                delta = float(metric_value) - float(baseline_value)
                delta_percent = (
                    (delta / float(baseline_value)) * 100.0
                    if float(baseline_value) != 0.0
                    else None
                )
                metric_ref = (
                    f"execution_metric:{item['id']}"
                    if item.get("id")
                    else f"metric:{item.get('metricName', 'unknown')}"
                )
                comparison = {
                    "metricRef": metric_ref,
                    "metricName": item.get("metricName"),
                    "metricValue": metric_value,
                    "baselineValue": baseline_value,
                    "delta": delta,
                    "deltaPercent": delta_percent,
                    "regression": delta > 0,
                }
                baseline_comparisons.append(comparison)
                evidence.append(
                    f"{metric_ref} baseline comparison "
                    f"value={metric_value} baseline={baseline_value} delta={delta}"
                )
            if threshold_breaches:
                for item in threshold_breaches:
                    metric_ref = (
                        f"execution_metric:{item['id']}"
                        if item.get("id")
                        else f"metric:{item.get('metricName', 'unknown')}"
                    )
                    evidence.append(
                        f"{metric_ref} threshold exceeded "
                        f"value={item['metricValue']} threshold={item['thresholdValue']}"
                    )
                summary = "threshold breach detected"
            elif structured_metrics:
                evidence.append("performance metrics captured without threshold breach")
                category = "unknown"
                summary = "metrics captured but no explicit breach"

        if error_message:
            evidence.append(error_message)

        confidence = 0.88 if category == "performance_issue" else 0.62
        payload = {
            "category": category,
            "confidence": confidence,
            "evidence": evidence or ["performance domain task evaluated"],
            "summary": summary,
            "baselineComparisons": baseline_comparisons,
        }
        return AgentResult(
            result=payload,
            confidence=confidence,
            evidence=payload["evidence"],
            metadata={"status": category},
        )

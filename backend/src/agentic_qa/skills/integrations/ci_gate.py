# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.domain.enums import ApprovalStatus, FindingSeverity, FindingStatus, GateResult
from agentic_qa.skills.integrations.contracts import (
    IntegrationEvidenceRef,
    IntegrationSkillInput,
    IntegrationSkillResult,
    completed_result,
    failed_result,
)


class CiGateSkill:
    """Frozen ci-gate 1.0.0 behavior for historical Replay compatibility only."""

    skill_name = "ci-gate"

    def run(self, request: IntegrationSkillInput) -> IntegrationSkillResult:
        if request.operation != "build_ci_gate_response":
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error=f"unsupported operation: {request.operation}",
            )
        payload = dict(request.payload)
        required = ["executionId", "decision"]
        missing = [field for field in required if field not in payload]
        if missing:
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error=f"missing required CI gate fields: {', '.join(missing)}",
                data={"missing": missing},
            )

        decision = dict(payload["decision"])
        execution_id = str(payload["executionId"])
        approvals = list(payload.get("approvals", [])) if isinstance(payload.get("approvals", []), list) else []
        findings = list(payload.get("findings", [])) if isinstance(payload.get("findings", []), list) else []
        pipeline = payload.get("pipeline") if isinstance(payload.get("pipeline"), dict) else None
        trace_refs = list(payload.get("traceRefs", [])) if isinstance(payload.get("traceRefs", []), list) else []
        blocking_findings = [
            finding
            for finding in findings
            if finding.get("status") == FindingStatus.OPEN.value
            and finding.get("severity") in {FindingSeverity.HIGH.value, FindingSeverity.CRITICAL.value}
        ]
        overall = str(decision["overall"])
        data = {
            "executionId": execution_id,
            "overall": overall,
            "functional": str(decision["functional"]),
            "performance": str(decision["performance"]),
            "security": str(decision["security"]),
            "reasons": list(decision.get("reasons", [])) if isinstance(decision.get("reasons", []), list) else [],
            "reasonCodes": list(decision.get("reasonCodes", [])) if isinstance(decision.get("reasonCodes", []), list) else [],
            "matchedRules": list(decision.get("matchedRules", [])) if isinstance(decision.get("matchedRules", []), list) else [],
            "completeness": dict(decision.get("completeness", {})) if isinstance(decision.get("completeness", {}), dict) else {},
            "confidence": decision.get("confidence"),
            "policyVersionId": decision.get("policyVersionId"),
            "policyVersionHash": decision.get("policyVersionHash"),
            "policyBindingRef": decision.get("policyBindingRef"),
            "inputFingerprint": decision.get("inputFingerprint"),
            "decisionSnapshotHash": decision.get("decisionSnapshotHash"),
            "evaluatorVersion": decision.get("evaluatorVersion"),
            "traceRefs": trace_refs,
            "pipeline": pipeline,
            "approvalSummary": {
                "pending": sum(1 for approval in approvals if approval.get("status") == ApprovalStatus.PENDING.value),
                "approved": sum(1 for approval in approvals if approval.get("status") == ApprovalStatus.APPROVED.value),
                "rejected": sum(1 for approval in approvals if approval.get("status") == ApprovalStatus.REJECTED.value),
            },
            "findingSummary": {
                "openCount": sum(1 for finding in findings if finding.get("status") == FindingStatus.OPEN.value),
                "blockingCount": len(blocking_findings),
            },
            "ci": {
                "exitCode": 0 if overall == GateResult.PASS.value else 1,
                "shouldMerge": overall == GateResult.PASS.value,
            },
            "resultRefs": {
                "executionReplay": f"/api/v1/executions/{execution_id}/replay",
                "pipelineReplay": f"/api/v1/integrations/pipelines/{pipeline['id']}/replay" if pipeline else None,
            },
        }
        return completed_result(
            skill=self.skill_name,
            operation=request.operation,
            data=data,
            evidence=[
                IntegrationEvidenceRef(
                    type="gate_decision",
                    ref=f"execution:{execution_id}",
                    metadata={"overall": overall},
                )
            ],
            metadata={"provider": request.provider or "ci"},
        )


class CiGateEvidenceSkill:
    """ci-gate 2.0.0 evidence adapter with no merge or process-exit decision."""

    skill_name = "ci-gate"

    def run(self, request: IntegrationSkillInput) -> IntegrationSkillResult:
        if request.operation != "build_ci_evidence":
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error=f"unsupported operation: {request.operation}",
            )
        payload = dict(request.payload)
        if "executionId" not in payload or "decision" not in payload:
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error="missing required CI evidence fields: executionId, decision",
            )
        decision = dict(payload["decision"])
        execution_id = str(payload["executionId"])
        evidence = {
            "executionId": execution_id,
            "gateResult": str(decision.get("overall") or "blocked"),
            "domainResults": {
                "functional": str(decision.get("functional") or "blocked"),
                "performance": str(decision.get("performance") or "blocked"),
                "security": str(decision.get("security") or "blocked"),
            },
            "reasonCodes": list(decision.get("reasonCodes") or []),
            "matchedRules": list(decision.get("matchedRules") or []),
            "policyVersionId": decision.get("policyVersionId"),
            "policyVersionHash": decision.get("policyVersionHash"),
            "inputFingerprint": decision.get("inputFingerprint"),
            "decisionSnapshotHash": decision.get("decisionSnapshotHash"),
            "evaluatorVersion": decision.get("evaluatorVersion"),
            "traceRefs": list(payload.get("traceRefs") or []),
        }
        return completed_result(
            skill=self.skill_name,
            operation=request.operation,
            data={"ciEvidence": evidence},
            evidence=[
                IntegrationEvidenceRef(
                    type="gate_decision",
                    ref=f"execution:{execution_id}",
                    metadata={"overall": evidence["gateResult"]},
                )
            ],
            metadata={
                "providerNeutral": True,
                "decisionOwner": "domain-service",
                "deprecatedDecisionFieldsProduced": False,
            },
        )

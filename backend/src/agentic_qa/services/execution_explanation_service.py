# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any

from agentic_qa.infra.redaction import redact_sensitive_data


PLAIN_VIEW_CAPABILITY = "replay.read"
PROFESSIONAL_VIEW_CAPABILITY = "audit.logs.read"
RAW_VIEW_CAPABILITY = "replay.export.read"


EVENT_REASON_CODES: dict[str, str] = {
    "execution.created": "EXECUTION_CREATED",
    "execution.started": "EXECUTION_STARTED",
    "execution.ended": "EXECUTION_ENDED",
    "orchestration.checkpoint": "ORCHESTRATION_CHECKPOINT_RECORDED",
    "execution.task.created": "EXECUTION_TASK_CREATED",
    "execution.task.started": "EXECUTION_TASK_STARTED",
    "execution.task.ended": "EXECUTION_TASK_ENDED",
    "evidence.artifact.recorded": "EVIDENCE_ARTIFACT_RECORDED",
    "evidence.metric.recorded": "EXECUTION_METRIC_RECORDED",
    "finding.raw.observed": "RAW_FINDING_OBSERVED",
    "execution.visual_grounding.recorded": "VISUAL_GROUNDING_EVIDENCE_RECORDED",
    "execution.verification.recorded": "EXECUTION_VERIFICATION_RECORDED",
    "analysis.triage.recorded": "FINDING_TRIAGE_RECORDED",
    "agent.run.recorded": "AGENT_RUN_RECORDED",
    "model.invocation.recorded": "MODEL_INVOCATION_RECORDED",
    "finding.normalized": "CANONICAL_FINDING_NORMALIZED",
    "trace.span.recorded": "TRACE_SPAN_RECORDED",
    "skill.invocation.recorded": "SKILL_INVOCATION_RECORDED",
    "tool.call.recorded": "TOOL_CALL_RECORDED",
    "connector.call.recorded": "CONNECTOR_CALL_RECORDED",
    "guardrail.decision.recorded": "GUARDRAIL_DECISION_RECORDED",
    "gate.input_snapshot.frozen": "GATE_INPUT_SNAPSHOT_FROZEN",
    "gate.decision.recorded": "GATE_DECISION_RECORDED",
    "approval.requested": "APPROVAL_REQUESTED",
    "approval.decided": "APPROVAL_DECIDED",
    "replay.export.recorded": "REPLAY_EXPORT_RECORDED",
    "replay.repository.frozen": "REPLAY_REPOSITORY_FROZEN",
    "audit.recorded": "AUDIT_RECORD_RECORDED",
}

EVIDENCE_REFERENCE_TYPES = {
    "evidence",
    "execution_artifact",
    "artifact",
    "raw_finding",
    "finding",
    "execution_metric",
    "metric",
    "verification_result",
    "visual_grounding_attempt",
}


def reason_code_for_event(event: dict[str, Any]) -> str:
    """Map persisted timeline facts to stable explanation reason codes."""

    ceg_kind = str(event.get("cegEventKind") or "").lower()
    promotion_type = str(event.get("promotionType") or "").lower()
    approval_refs = event.get("approvalRefs") or []
    if ceg_kind == "observed":
        return "CEG_PATH_OBSERVED_ONLY"
    if ceg_kind == "candidate":
        return "CEG_PATH_REVIEW_CANDIDATE"
    if approval_refs and promotion_type not in {
        "automatic",
        "policy_auto",
        "policy_automatic",
        "system_auto",
        "system_automatic",
    }:
        return "CEG_PATH_HUMAN_APPROVED_STANDARD"
    if ceg_kind == "promotion" and promotion_type in {
        "automatic",
        "policy_auto",
        "policy_automatic",
        "system_auto",
        "system_automatic",
    }:
        return "CEG_PATH_LOW_RISK_AUTO_VALIDATED_STANDARD"
    if ceg_kind:
        return f"CEG_PATH_{ceg_kind.upper()}"

    event_type = str(event.get("eventType") or "")
    if event_type.startswith("gate.policy."):
        return "GATE_POLICY_LIFECYCLE_RECORDED"
    if event_type.startswith("skill."):
        return "SKILL_INVOCATION_EVENT_RECORDED"
    return EVENT_REASON_CODES.get(event_type, "UNKNOWN_TIMELINE_REASON")


def build_explain_view_projection(
    event: dict[str, Any],
    *,
    professional_allowed: bool,
    raw_allowed: bool,
    projected_at: datetime,
    professional_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build three expression layers from one already-scoped timeline event."""

    fields = professional_fields or {}
    event_id = str(event["eventId"])
    source_refs = list(event.get("refs") or [])
    available_refs = [ref for ref in source_refs if ref.get("available", True)]
    evidence_refs = [
        ref
        for ref in available_refs
        if str(ref.get("referenceType")) in EVIDENCE_REFERENCE_TYPES
        or str(ref.get("relationship")) in {"evidence", "artifact", "finding", "metric"}
    ]
    reason_code = reason_code_for_event(event)
    parameters: dict[str, str | int | float | bool | None] = {
        "eventType": str(event.get("eventType") or "unknown"),
        "stage": str(event.get("lifecycleStage") or "unknown"),
        "status": str(event.get("status") or "unknown"),
        "actorType": str(event.get("actorType") or "unknown"),
        "evidenceCount": len(evidence_refs),
        "reasonCode": reason_code,
    }
    message_keys = _message_keys(reason_code)
    plain = {
        "schemaVersion": "phase8.execution-explanation-plain.v1",
        "eventId": event_id,
        "sourceRefs": source_refs,
        "available": True,
        "requiredCapability": PLAIN_VIEW_CAPABILITY,
        "unavailableReasonCode": None,
        "reasonCode": reason_code,
        "sourceMessageKey": str(event.get("plainSummaryKey") or ""),
        "whatHappened": _message(message_keys["what"], parameters),
        "why": _message(message_keys["why"], parameters),
        "impact": _message(message_keys["impact"], parameters),
        "nextAction": _message(message_keys["next"], parameters),
        "evidenceCount": len(evidence_refs),
        "cegPathMeaning": (
            _message(message_keys["meaning"], parameters)
            if message_keys.get("meaning")
            else None
        ),
    }

    integrity_status = _integrity_status(event, source_refs)
    reason_codes = _string_list(fields.get("reasonCodes"))
    if reason_code not in reason_codes:
        reason_codes.insert(0, reason_code)
    professional = {
        "schemaVersion": "phase8.execution-explanation-professional.v1",
        "eventId": event_id,
        "sourceRefs": source_refs,
        "available": professional_allowed,
        "requiredCapability": PROFESSIONAL_VIEW_CAPABILITY,
        "unavailableReasonCode": None if professional_allowed else "PERMISSION_RESTRICTED",
        "reasonCode": reason_code if professional_allowed else None,
        "reasonCodes": reason_codes if professional_allowed else [],
        "ruleIds": _string_list(fields.get("ruleIds")) if professional_allowed else [],
        "policy": (
            {
                "policyId": _optional_string(fields.get("policyId")),
                "versionId": _optional_string(fields.get("policyVersionId")),
                "versionHash": _optional_string(fields.get("policyVersionHash")),
            }
            if professional_allowed
            and any(
                fields.get(key) is not None
                for key in ("policyId", "policyVersionId", "policyVersionHash")
            )
            else None
        ),
        "promotionType": event.get("promotionType") if professional_allowed else None,
        "graphLearningMode": event.get("graphLearningMode") if professional_allowed else None,
        "policyDecisionRefs": list(event.get("policyDecisionRefs") or []) if professional_allowed else [],
        "approvalState": _optional_string(fields.get("approvalState")) if professional_allowed else None,
        "humanApproved": bool(
            professional_allowed
            and event.get("approvalRefs")
            and reason_code == "CEG_PATH_HUMAN_APPROVED_STANDARD"
        ),
        "approvalRefs": list(event.get("approvalRefs") or []) if professional_allowed else [],
        "findingRefs": _refs_by_type(source_refs, {"finding", "raw_finding"}) if professional_allowed else [],
        "metricRefs": _refs_by_type(source_refs, {"execution_metric", "metric"}) if professional_allowed else [],
        "evidenceRefs": evidence_refs if professional_allowed else [],
        "integrityStatus": integrity_status if professional_allowed else None,
    }

    first_source = source_refs[0] if source_refs else None
    raw_projection = {
        "eventId": event_id,
        "eventType": event.get("eventType"),
        "lifecycleStage": event.get("lifecycleStage"),
        "sequence": event.get("sequence"),
        "sourceSequence": event.get("sourceSequence"),
        "sortKey": event.get("sortKey"),
        "occurredAt": event.get("occurredAt"),
        "status": event.get("status"),
        "actorType": event.get("actorType"),
        "actorRef": event.get("actorRef"),
        "visibility": event.get("visibility"),
        "unavailableReason": event.get("unavailableReason"),
        "linkedIds": {
            key: event.get(key)
            for key in (
                "traceId",
                "executionId",
                "skillInvocationId",
                "toolCallId",
                "connectorCallId",
                "agentRunId",
                "modelInvocationId",
                "gateDecisionId",
                "approvalId",
                "replayId",
            )
        },
        "ceg": {
            "eventKind": event.get("cegEventKind"),
            "graphLearningMode": event.get("graphLearningMode"),
            "promotionType": event.get("promotionType"),
        },
    }
    raw = {
        "schemaVersion": "phase8.execution-explanation-raw.v1",
        "eventId": event_id,
        "sourceRefs": source_refs,
        "available": raw_allowed,
        "requiredCapability": RAW_VIEW_CAPABILITY,
        "unavailableReasonCode": None if raw_allowed else "PERMISSION_RESTRICTED",
        "redactionStatus": "backend_redacted",
        "labelKey": "executionExplanation.authorizedRedactedRaw",
        "source": (
            {
                "sourceType": str(first_source.get("referenceType")) if first_source else "timeline_event",
                "sourceTimestamp": event["occurredAt"],
                "projectedAt": projected_at.isoformat(),
                "integrityStatus": integrity_status,
                "retentionStatus": _retention_status(event, source_refs),
            }
            if raw_allowed
            else None
        ),
        "projection": redact_sensitive_data(raw_projection) if raw_allowed else None,
        "truncated": False,
    }
    available_views = ["plain"]
    if professional_allowed:
        available_views.append("professional")
    if raw_allowed:
        available_views.append("raw")
    projection = {
        "schemaVersion": "phase8.execution-explanation-views.v1",
        "eventId": event_id,
        "sourceRefs": source_refs,
        "availableViews": available_views,
        "plain": plain,
        "professional": professional,
        "raw": raw,
    }
    return redact_sensitive_data(projection)


def _message_keys(reason_code: str) -> dict[str, str]:
    ceg_profiles = {
        "CEG_PATH_OBSERVED_ONLY": "Observed",
        "CEG_PATH_REVIEW_CANDIDATE": "Candidate",
        "CEG_PATH_HUMAN_APPROVED_STANDARD": "HumanApproved",
        "CEG_PATH_LOW_RISK_AUTO_VALIDATED_STANDARD": "AutoValidated",
    }
    suffix = ceg_profiles.get(reason_code)
    if suffix:
        prefix = f"executionExplanation.ceg{suffix}"
        return {
            "what": f"{prefix}.what",
            "why": f"{prefix}.why",
            "impact": f"{prefix}.impact",
            "next": f"{prefix}.next",
            "meaning": f"{prefix}.meaning",
        }
    if reason_code == "UNKNOWN_TIMELINE_REASON" or reason_code.startswith("CEG_PATH_"):
        return {
            "what": "executionExplanation.unknown.what",
            "why": "executionExplanation.generic.why",
            "impact": "executionExplanation.generic.impact",
            "next": "executionExplanation.generic.next",
        }
    return {
        "what": "executionExplanation.generic.what",
        "why": "executionExplanation.generic.why",
        "impact": "executionExplanation.generic.impact",
        "next": "executionExplanation.generic.next",
    }


def _message(
    key: str,
    parameters: dict[str, str | int | float | bool | None],
) -> dict[str, Any]:
    return {"messageKey": key, "parameters": dict(parameters)}


def _refs_by_type(
    refs: list[dict[str, Any]],
    reference_types: set[str],
) -> list[dict[str, Any]]:
    return [
        ref
        for ref in refs
        if ref.get("available", True)
        and str(ref.get("referenceType")) in reference_types
    ]


def _integrity_status(
    event: dict[str, Any],
    refs: list[dict[str, Any]],
) -> str:
    if event.get("unavailableReason") is not None and not refs:
        return "unavailable"
    if event.get("unavailableReason") is not None or any(
        not ref.get("available", True) for ref in refs
    ):
        return "partial"
    return "complete"


def _retention_status(
    event: dict[str, Any],
    refs: list[dict[str, Any]],
) -> str:
    unavailable_codes = {
        str(ref.get("unavailableReasonCode") or "") for ref in refs
    }
    if event.get("unavailableReason") and not refs:
        return "unavailable"
    if unavailable_codes & {
        "REFERENCE_RETAINED_OR_PURGED",
        "SOURCE_NOT_RECORDED_OR_RETAINED",
    }:
        return "partial"
    return "retained"


def _string_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return [str(item) for item in value if item is not None and str(item)]


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


__all__ = [
    "EVENT_REASON_CODES",
    "PLAIN_VIEW_CAPABILITY",
    "PROFESSIONAL_VIEW_CAPABILITY",
    "RAW_VIEW_CAPABILITY",
    "build_explain_view_projection",
    "reason_code_for_event",
]

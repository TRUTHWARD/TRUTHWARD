# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from collections.abc import Sequence
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from uuid import UUID
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.guardrails.catalog import get_guardrail_definition
from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult, GuardrailViolationError
from agentic_qa.domain.enums import GuardrailDecisionType
from agentic_qa.domain.models import Execution, GuardrailEvent, GuardrailPolicy
from agentic_qa.services.guardrail_service import GuardrailService
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.infra.trace import record_span


class RuntimeGuardrailEngine:
    """Evaluate runtime guardrails and emit a consistent audit trail."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.policy_service = GuardrailService(db)

    def enforce(self, context: GuardrailContext, guardrails: Sequence[RuntimeGuardrail]) -> list[GuardrailResult]:
        """
        Evaluate and persist runtime guardrail results.

        Args:
            context: Structured evaluation context.
            guardrails: Guardrails to run in order.

        Returns:
            list[GuardrailResult]: All emitted rule results.

        Raises:
            GuardrailViolationError: Raised when any rule blocks the operation.
        """

        results: list[GuardrailResult] = []
        for guardrail in guardrails:
            result = self._apply_policy(guardrail.evaluate(context))
            self.record_result(context, result)
            results.append(result)
            if result.is_blocking:
                # Guardrail blocks are part of the audit trail, so persist them
                # before the exception unwinds the request transaction.
                self.db.commit()
                raise GuardrailViolationError(result)
        return results

    def record_result(self, context: GuardrailContext, result: GuardrailResult) -> GuardrailResult:
        """
        Persist a guardrail result into trace and audit records.

        Args:
            context: Structured evaluation context.
            result: Guardrail outcome to persist.

        Returns:
            GuardrailResult: The same result for fluent call sites.
        """

        normalized_trace_id = self._normalize_uuid(context.trace_id) or uuid4()
        request_id = context.request_id or f"req_guardrail_{uuid4().hex}"
        resource_id = context.resource_id or result.rule_id
        requested_execution_id = self._normalize_uuid(context.execution_id)
        normalized_execution_id = (
            requested_execution_id
            if requested_execution_id is not None
            and self.db.get(Execution, requested_execution_id) is not None
            else None
        )
        normalized_skill_invocation_id = self._normalize_uuid(context.skill_invocation_id)
        normalized_connector_binding_id = self._normalize_uuid(context.connector_binding_id)
        normalized_tool_call_id = self._normalize_uuid(context.tool_call_id)
        sanitized_metadata = redact_sensitive_data(self._json_safe(result.metadata))
        details = redact_sensitive_data(
            self._json_safe(
                {
                    "ruleId": result.rule_id,
                    "decision": result.decision.value,
                    "reason": result.reason,
                    "evidence": result.evidence,
                    "metadata": sanitized_metadata,
                    "executionId": str(context.execution_id) if context.execution_id else None,
                    "skillInvocationId": (
                        str(context.skill_invocation_id)
                        if context.skill_invocation_id
                        else None
                    ),
                    "connectorBindingId": (
                        str(context.connector_binding_id)
                        if context.connector_binding_id
                        else None
                    ),
                    "toolCallId": (
                        str(context.tool_call_id)
                        if context.tool_call_id
                        else None
                    ),
                }
            )
        )
        write_audit_log(
            self.db,
            context.actor_id,
            f"guardrail.{result.decision.value}",
            context.resource_type,
            resource_id,
            request_id,
            normalized_trace_id,
            execution_id=normalized_execution_id,
            details=details,
        )
        policy = self.db.scalar(select(GuardrailPolicy).where(GuardrailPolicy.rule_id == result.rule_id))
        policy_version = self.policy_service.current_policy_version(policy) if policy is not None else None
        sanitized_payload = redact_sensitive_data(
            self._json_safe(
                {
                    "resourceType": context.resource_type,
                    "resourceId": resource_id,
                    **context.payload,
                }
            )
        )
        sanitized_evidence = redact_sensitive_data(
            [{"type": "guardrail_evidence", "ref": entry} for entry in result.evidence]
        )
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                policy_id=policy.id if policy else None,
                policy_version_id=policy_version.id if policy_version else None,
                rule_id=result.rule_id,
                decision=GuardrailDecisionType(result.decision.value),
                execution_id=normalized_execution_id,
                trace_id=normalized_trace_id,
                agent_run_id=None,
                skill_invocation_id=normalized_skill_invocation_id,
                connector_binding_id=normalized_connector_binding_id,
                tool_call_id=normalized_tool_call_id,
                request_id=request_id,
                severity=result.decision.value,
                message=str(redact_sensitive_data(result.reason)),
                evidence=sanitized_evidence,
                payload=sanitized_payload,
                metadata_json=sanitized_metadata,
            )
        )
        record_span(
            self.db,
            trace_id=normalized_trace_id,
            span_name=f"guardrail.{result.rule_id}",
            service_name="guardrails",
            status=result.decision.value,
            attributes=details,
        )
        return result

    def _apply_policy(self, result: GuardrailResult) -> GuardrailResult:
        definition = get_guardrail_definition(result.rule_id)
        if definition is None:
            return result
        policy = self.policy_service.get_effective_policy(result.rule_id)
        decision_overrides = policy["decisionOverrides"]
        original_decision = result.decision.value
        if not policy["enabled"]:
            effective_decision = GuardrailDecision.ALLOW.value
            policy_reason = "guardrail disabled by policy"
        else:
            effective_decision = decision_overrides.get(original_decision, original_decision)
            policy_reason = "guardrail evaluated under configured policy"
        if effective_decision == original_decision:
            result.metadata = {
                **result.metadata,
                "policy": {
                    "enabled": policy["enabled"],
                    "effectiveDecision": effective_decision,
                    "originalDecision": original_decision,
                    "decisionOverrides": decision_overrides,
                },
            }
            return result
        return GuardrailResult(
            rule_id=result.rule_id,
            decision=GuardrailDecision(effective_decision),
            reason=policy_reason,
            evidence=result.evidence,
            metadata={
                **result.metadata,
                "policy": {
                    "enabled": policy["enabled"],
                    "effectiveDecision": effective_decision,
                    "originalDecision": original_decision,
                    "decisionOverrides": decision_overrides,
                },
            },
        )

    def _normalize_uuid(self, value: str | UUID | None) -> UUID | None:
        if value is None:
            return None
        if isinstance(value, UUID):
            return value
        return UUID(str(value))

    def _json_safe(self, value):
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, Decimal):
            return float(value)
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, Enum):
            return value.value
        if is_dataclass(value):
            return self._json_safe(asdict(value))
        if hasattr(value, "model_dump"):
            return self._json_safe(value.model_dump(mode="json"))
        if isinstance(value, dict):
            return {str(key): self._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._json_safe(item) for item in value]
        if hasattr(value, "__dict__"):
            return self._json_safe(vars(value))
        return str(value)

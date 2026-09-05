# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import GuardrailPolicyStatus, GuardrailScope
from agentic_qa.domain.models import GuardrailEvent, GuardrailPolicy, GuardrailPolicyVersion
from agentic_qa.guardrails.catalog import get_guardrail_definition, list_guardrail_definitions
from agentic_qa.guardrails.result import GuardrailDecision
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.services.common import ServiceContext, paginate_result


GUARDRAIL_DECISIONS = tuple(decision.value for decision in GuardrailDecision)


class GuardrailService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_policies(self, page: int, page_size: int) -> dict[str, object]:
        persisted = self._policy_lookup()
        items = [
            self.serialize_policy(definition.rule_id, persisted.get(definition.rule_id))
            for definition in list_guardrail_definitions()
        ]
        start = (page - 1) * page_size
        end = start + page_size
        return paginate_result(items[start:end], len(items), page, page_size)

    def get_effective_policy(self, rule_id: str) -> dict[str, object]:
        policy = self.db.scalar(select(GuardrailPolicy).where(GuardrailPolicy.rule_id == rule_id))
        return self.serialize_policy(rule_id, policy)

    def update_policy(self, rule_id: str, payload, context: ServiceContext) -> dict[str, object]:
        definition = get_guardrail_definition(rule_id)
        if definition is None:
            raise ValueError("guardrail policy not found")
        policy = self.db.scalar(select(GuardrailPolicy).where(GuardrailPolicy.rule_id == rule_id))
        if policy is None:
            policy = GuardrailPolicy(
                id=uuid4(),
                rule_id=rule_id,
                name=definition.name,
                scope=self._scope_for_rule(rule_id),
                status=GuardrailPolicyStatus.ACTIVE,
                enabled=definition.default_enabled,
                config={"decisionOverrides": dict(definition.default_decision_overrides)},
                metadata_json={},
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(policy)
            self.db.flush()

        if payload.enabled is not None:
            policy.enabled = payload.enabled
            policy.status = GuardrailPolicyStatus.ACTIVE if payload.enabled else GuardrailPolicyStatus.DISABLED
        if payload.decisionOverrides is not None:
            policy.config = {
                **policy.config,
                "decisionOverrides": dict(payload.decisionOverrides),
            }
        if payload.metadata is not None:
            policy.metadata_json = redact_sensitive_data(payload.metadata)
        policy.updated_by = context.user.id
        version = self.create_policy_version(policy, context, change_reason="guardrail_policy.update")

        write_audit_log(
            self.db,
            str(context.user.id),
            "guardrail_policy.update",
            "guardrail_policy",
            rule_id,
            context.request_id,
            context.trace_id,
            details={
                "ruleId": rule_id,
                "enabled": policy.enabled,
                "decisionOverrides": policy.config.get("decisionOverrides", {}),
                "metadata": policy.metadata_json,
                "policyVersionId": str(version.id),
                "versionNo": version.version_no,
            },
        )
        self.db.commit()
        self.db.refresh(policy)
        return self.serialize_policy(rule_id, policy)

    def list_policy_versions(self, rule_id: str, page: int, page_size: int) -> dict[str, object]:
        policy = self.db.scalar(select(GuardrailPolicy).where(GuardrailPolicy.rule_id == rule_id))
        if policy is None:
            raise ValueError("guardrail policy not found")
        self.current_policy_version(policy)
        statement = (
            select(GuardrailPolicyVersion)
            .where(GuardrailPolicyVersion.policy_id == policy.id)
            .order_by(GuardrailPolicyVersion.version_no.desc())
        )
        total = self.db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0
        rows = list(self.db.scalars(statement.offset((page - 1) * page_size).limit(page_size)))
        return paginate_result([self.serialize_policy_version(row) for row in rows], total, page, page_size)

    def list_events(
        self,
        page: int,
        page_size: int,
        decision: str | None = None,
        rule_id: str | None = None,
        execution_id: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, object]:
        statement = select(GuardrailEvent).order_by(GuardrailEvent.created_at.desc())
        if decision:
            statement = statement.where(GuardrailEvent.decision == decision)
        if execution_id:
            statement = statement.where(GuardrailEvent.execution_id == UUID(str(execution_id)))
        if trace_id:
            statement = statement.where(GuardrailEvent.trace_id == UUID(str(trace_id)))
        if rule_id:
            statement = statement.where(GuardrailEvent.rule_id == rule_id)

        total = self.db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0
        offset = (page - 1) * page_size
        rows = list(self.db.scalars(statement.offset(offset).limit(page_size)))

        base_statement = select(GuardrailEvent)
        if decision:
            base_statement = base_statement.where(GuardrailEvent.decision == decision)
        if execution_id:
            base_statement = base_statement.where(GuardrailEvent.execution_id == UUID(str(execution_id)))
        if trace_id:
            base_statement = base_statement.where(GuardrailEvent.trace_id == UUID(str(trace_id)))
        if rule_id:
            base_statement = base_statement.where(GuardrailEvent.rule_id == rule_id)

        summary = self._decision_summary(base_statement)
        items = [self.serialize_event(row) for row in rows]
        payload = paginate_result(items, total, page, page_size)
        payload["summary"] = summary
        return payload

    def serialize_policy(self, rule_id: str, policy: GuardrailPolicy | None) -> dict[str, object]:
        definition = get_guardrail_definition(rule_id)
        if definition is None:
            raise ValueError("guardrail policy not found")
        decision_overrides = dict(definition.default_decision_overrides)
        enabled = definition.default_enabled
        metadata: dict[str, object] = {}
        updated_at = None
        scope = self._scope_for_rule(rule_id).value
        status = GuardrailPolicyStatus.ACTIVE.value
        if policy is not None:
            current_version = self.current_policy_version(policy)
            enabled = policy.enabled
            decision_overrides = dict(policy.config.get("decisionOverrides", {}))
            metadata = policy.metadata_json
            updated_at = policy.updated_at.isoformat()
            scope = policy.scope.value
            status = policy.status.value
        else:
            current_version = None

        effective_decisions = {
            decision.value: decision_overrides.get(decision.value, decision.value)
            for decision in GuardrailDecision
        }
        return {
            "ruleId": definition.rule_id,
            "name": definition.name,
            "description": definition.description,
            "owner": definition.owner,
            "scope": scope,
            "status": status,
            "enabled": enabled,
            "defaultEnabled": definition.default_enabled,
            "decisionOverrides": decision_overrides,
            "defaultDecisionOverrides": definition.default_decision_overrides,
            "effectiveDecisions": effective_decisions,
            "metadata": metadata,
            "updatedAt": updated_at,
            "currentVersion": current_version.version_no if current_version else None,
            "currentVersionId": str(current_version.id) if current_version else None,
        }

    def serialize_policy_version(self, version: GuardrailPolicyVersion) -> dict[str, object]:
        return {
            "id": str(version.id),
            "policyId": str(version.policy_id),
            "ruleId": version.rule_id,
            "versionNo": version.version_no,
            "enabled": version.enabled,
            "status": version.status.value,
            "decisionOverrides": dict(version.config.get("decisionOverrides", {})),
            "metadata": version.metadata_json,
            "changeReason": version.change_reason,
            "createdBy": str(version.created_by) if version.created_by else None,
            "createdAt": version.created_at.isoformat(),
        }

    def serialize_event(self, event: GuardrailEvent) -> dict[str, object]:
        return {
            "id": str(event.id),
            "policyVersionId": str(event.policy_version_id) if event.policy_version_id else None,
            "traceId": str(event.trace_id) if event.trace_id else None,
            "executionId": str(event.execution_id) if event.execution_id else None,
            "agentRunId": str(event.agent_run_id) if event.agent_run_id else None,
            "skillInvocationId": str(event.skill_invocation_id) if event.skill_invocation_id else None,
            "connectorBindingId": str(event.connector_binding_id) if event.connector_binding_id else None,
            "toolCallId": str(event.tool_call_id) if event.tool_call_id else None,
            "requestId": event.request_id,
            "resourceType": event.payload.get("resourceType"),
            "resourceId": event.payload.get("resourceId"),
            "ruleId": event.rule_id,
            "decision": event.decision.value,
            "message": redact_sensitive_data(event.message),
            "reason": redact_sensitive_data(event.message),
            "evidence": redact_sensitive_data(event.evidence),
            "payload": redact_sensitive_data(event.payload),
            "metadata": redact_sensitive_data(event.metadata_json),
            "createdAt": event.created_at.isoformat(),
        }

    def _policy_lookup(self) -> dict[str, GuardrailPolicy]:
        rows = self.db.scalars(select(GuardrailPolicy))
        return {row.rule_id: row for row in rows}

    def current_policy_version(self, policy: GuardrailPolicy) -> GuardrailPolicyVersion:
        version = self.db.scalar(
            select(GuardrailPolicyVersion)
            .where(GuardrailPolicyVersion.policy_id == policy.id)
            .order_by(GuardrailPolicyVersion.version_no.desc())
        )
        if version is not None:
            return version
        return self.create_policy_version(policy, None, change_reason="guardrail_policy.initial")

    def create_policy_version(
        self,
        policy: GuardrailPolicy,
        context: ServiceContext | None,
        *,
        change_reason: str,
    ) -> GuardrailPolicyVersion:
        current_no = (
            self.db.scalar(
                select(func.max(GuardrailPolicyVersion.version_no)).where(GuardrailPolicyVersion.policy_id == policy.id)
            )
            or 0
        )
        version = GuardrailPolicyVersion(
            id=uuid4(),
            policy_id=policy.id,
            rule_id=policy.rule_id,
            version_no=int(current_no) + 1,
            enabled=policy.enabled,
            status=policy.status,
            decision_override=policy.decision_override,
            config=dict(policy.config or {}),
            metadata_json=dict(policy.metadata_json or {}),
            change_reason=change_reason,
            created_by=context.user.id if context else policy.updated_by or policy.created_by,
        )
        self.db.add(version)
        self.db.flush()
        return version

    def _decision_summary(self, statement) -> dict[str, int]:
        summary = {decision: 0 for decision in GUARDRAIL_DECISIONS}
        subquery = statement.order_by(None).subquery()
        decision_column = subquery.c.decision
        rows = self.db.execute(select(decision_column, func.count()).group_by(decision_column))
        for decision, count in rows:
            if hasattr(decision, "value"):
                decision = decision.value
            if decision in summary:
                summary[decision] = count
        return summary

    def _scope_for_rule(self, rule_id: str) -> GuardrailScope:
        prefix = rule_id.split(".", 1)[0]
        mapping = {
            "prompt_safety": GuardrailScope.REQUEST,
            "requirement_intake": GuardrailScope.REQUEST,
            "model_routing": GuardrailScope.ROUTING,
            "agent_output": GuardrailScope.AGENT_OUTPUT,
            "memory_write": GuardrailScope.MEMORY_WRITE,
            "action": GuardrailScope.ACTION,
            "skill": GuardrailScope.SKILL,
            "connector": GuardrailScope.CONNECTOR,
        }
        return mapping.get(prefix, GuardrailScope.SYSTEM)

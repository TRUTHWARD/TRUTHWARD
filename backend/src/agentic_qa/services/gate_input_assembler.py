# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import TaskStatus
from agentic_qa.domain.models import (
    Approval,
    Execution,
    ExecutionMetric,
    ExecutionPlan,
    ExecutionTask,
    Finding,
    Project,
    RawFindingRecord,
    TestPlan,
    TestPlanDomain,
)
from agentic_qa.infra.redaction import redact_sensitive_text
from agentic_qa.schemas.gate_evaluator import GateInputContract
from agentic_qa.schemas.gate_policy import GatePolicyResolutionRequestContract
from agentic_qa.services.gate_evaluator import (
    DOMAIN_ORDER,
    DomainApplicabilityResolver,
    compute_gate_input_fingerprint,
)
from agentic_qa.services.gate_policy_repository import GatePolicyRepository
from agentic_qa.services.gate_policy_resolver import GatePolicyResolutionError, GatePolicyResolver


class GateInputAssemblyError(ValueError):
    pass


class GateInputAssembler:
    """Build the evaluator input from persisted, Service-owned authorities."""

    def __init__(
        self,
        db: Session,
        *,
        applicability_resolver: DomainApplicabilityResolver | None = None,
        policy_resolver: GatePolicyResolver | None = None,
    ) -> None:
        self.db = db
        self.applicability_resolver = applicability_resolver or DomainApplicabilityResolver()
        self.policy_resolver = policy_resolver or GatePolicyResolver(GatePolicyRepository(db))

    def assemble(
        self,
        execution_id: UUID,
        *,
        findings: Sequence[Finding],
        metrics: Sequence[ExecutionMetric],
        approvals: Sequence[Approval],
        integrity_issues: Sequence[dict[str, str]] = (),
        trace_id: str,
        request_id: str,
    ) -> GateInputContract:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise GateInputAssemblyError("Gate execution context is unavailable")
        plan = self.db.get(TestPlan, execution.plan_id)
        if plan is None:
            raise GateInputAssemblyError("Gate test plan context is unavailable")
        execution_plan = (
            self.db.get(ExecutionPlan, execution.execution_plan_id)
            if execution.execution_plan_id is not None
            else None
        )
        assembly_integrity_issues = [dict(item) for item in integrity_issues]
        if execution.execution_plan_id is not None and execution_plan is None:
            assembly_integrity_issues.append(
                {
                    "type": "execution_plan",
                    "id": str(execution.execution_plan_id),
                    "source": "execution_plan_missing",
                }
            )
        if execution_plan is not None and execution_plan.test_plan_id != plan.id:
            raise GateInputAssemblyError("Gate execution plan belongs to a different test plan")

        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution_id)
                .order_by(ExecutionTask.domain.asc(), ExecutionTask.id.asc())
            )
        )
        plan_domains = list(
            self.db.scalars(
                select(TestPlanDomain)
                .where(TestPlanDomain.plan_id == plan.id)
                .order_by(TestPlanDomain.domain.asc(), TestPlanDomain.id.asc())
            )
        )
        raw_findings = list(
            self.db.scalars(
                select(RawFindingRecord)
                .where(RawFindingRecord.execution_id == execution_id)
                .order_by(RawFindingRecord.created_at.asc(), RawFindingRecord.id.asc())
            )
        )
        # Raw findings are inspected only to prove NORMALIZE completeness. They
        # never become evaluator inputs; an unresolved row is represented as a
        # fail-closed normalization state and the Gate still persists a
        # traceable blocked decision.
        unresolved_raw = [item for item in raw_findings if item.normalized_finding_id is None]

        self._validate_owned_inputs(execution_id, tasks, findings, metrics, approvals)
        tenant_id, workspace_id, project = self._authoritative_ownership_context(plan)
        evaluation_time = self._evaluation_time(execution, tasks)
        policy_resolution_time = self._policy_resolution_time(execution)
        resolution_request = GatePolicyResolutionRequestContract(
            schemaVersion="phase8.gate-policy-resolution-request.v1",
            tenantId=tenant_id,
            workspaceId=workspace_id,
            projectId=str(plan.project_id) if plan.project_id else None,
            environment=(
                str(plan.environment_id)
                if plan.environment_id is not None
                else execution.environment
            ),
            stage="GATE",
            domain=None,
            # Enforce cutovers are keyed to the immutable execution creation
            # boundary. A Gate evaluation that finishes after an activation
            # must not retroactively apply that policy to an older execution.
            evaluationTime=policy_resolution_time,
        )
        try:
            resolution = self.policy_resolver.resolve(resolution_request)
        except GatePolicyResolutionError as exc:
            resolution = None
            policy = None
            policy_source = "unavailable"
            fallback_reason = exc.code
        else:
            assert resolution is not None
            policy = resolution.snapshot.policy
            policy_source = resolution.source
            fallback_reason = resolution.fallbackReason
        normalization_status = self._normalization_status(execution, unresolved_raw)
        task_groups: dict[str, list[ExecutionTask]] = {
            domain: [task for task in tasks if task.domain.value == domain]
            for domain in DOMAIN_ORDER
        }
        metric_groups: dict[str, list[ExecutionMetric]] = {
            domain: [metric for metric in metrics if self._metric_domain(metric) == domain]
            for domain in DOMAIN_ORDER
        }
        input_availability: dict[str, str] = {
            domain: self._availability(
                domain,
                task_groups[domain],
                metric_groups[domain],
                normalization_status,
            )
            for domain in DOMAIN_ORDER
        }
        execution_plan_domains = {
            str(item.get("domain"))
            for item in (execution_plan.tasks if execution_plan is not None else [])
            if isinstance(item, dict) and item.get("domain") in DOMAIN_ORDER
        }
        plan_domain_states = {item.domain.value: bool(item.enabled) for item in plan_domains}
        execution_scope_is_authoritative = bool(tasks) and execution.status in {
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
        task_domains: dict[str, dict[str, Any]] = {
            domain: {"taskIds": [str(item.id) for item in task_groups[domain]]}
            for domain in DOMAIN_ORDER
            if task_groups[domain]
        }
        authority_refs: dict[str, list[dict[str, str]]] = {
            domain: self._domain_authority_refs(
                execution,
                plan,
                execution_plan,
                domain,
                task_groups[domain],
                plan_domains,
            )
            for domain in DOMAIN_ORDER
        }
        required_domains = self._required_domains(policy)
        domain_states = self.applicability_resolver.resolve(
            task_domains=task_domains,
            plan_domain_states=plan_domain_states,
            execution_plan_domains=execution_plan_domains,
            execution_scope_is_authoritative=execution_scope_is_authoritative,
            input_availability=input_availability,
            required_domains=required_domains,
            authority_refs=authority_refs,
        )

        normalized_findings = [self._finding_input(item) for item in findings]
        metric_inputs = [self._metric_input(item) for item in metrics]
        approval_state = [self._approval_input(item) for item in approvals]
        input_refs_by_domain: dict[str, list[dict[str, object]]] = {
            domain: [
                *[
                    {"type": "normalized_finding", "id": item["id"], "source": "NORMALIZE"}
                    for item in normalized_findings
                    if item["domain"] == domain
                ],
                *[
                    {"type": "metric", "id": item["id"], "source": "execution_metric"}
                    for item in metric_inputs
                    if item["domain"] == domain
                ],
            ]
            for domain in DOMAIN_ORDER
        }
        for state in domain_states:
            state["inputRefs"] = input_refs_by_domain.get(str(state["domain"]), [])

        missing_evidence_refs: list[dict[str, str]] = [
            dict(item)
            for item in assembly_integrity_issues
            if item.get("source") == "NORMALIZE_evidence_missing"
        ]
        invalid_evidence_refs: list[dict[str, str]] = [
            dict(item)
            for item in assembly_integrity_issues
            if item.get("source") != "NORMALIZE_evidence_missing"
        ]
        for finding in findings:
            if not finding.evidence:
                missing_evidence_refs.append(
                    {"type": "normalized_finding", "id": str(finding.id), "source": "NORMALIZE"}
                )
            elif any(not isinstance(item, dict) or not item.get("type") or not item.get("ref") for item in finding.evidence):
                invalid_evidence_refs.append(
                    {"type": "normalized_finding", "id": str(finding.id), "source": "NORMALIZE"}
                )
        evidence_status = (
            "invalid"
            if invalid_evidence_refs
            else "missing"
            if missing_evidence_refs
            else "valid"
        )
        payload: dict[str, Any] = {
            "schemaVersion": "phase8.gate-input.v1",
            "evaluationContext": {
                "evaluationId": f"gate-evaluation:{execution.id}",
                "evaluationTime": evaluation_time.isoformat(),
                "traceId": trace_id,
                "requestId": request_id,
            },
            "executionContext": {
                "executionId": str(execution.id),
                "planId": str(plan.id),
                "executionPlanId": (
                    str(execution.execution_plan_id)
                    if execution.execution_plan_id is not None
                    else None
                ),
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
                "projectId": str(plan.project_id) if plan.project_id else None,
                "environmentId": (
                    str(plan.environment_id)
                    if plan.environment_id is not None
                    else execution.environment
                ),
                "stage": "GATE",
                "status": execution.status.value,
                "riskLevel": (execution_plan.risk_level.value if execution_plan else plan.risk_level.value),
                "approvalRequired": bool(execution_plan.approval_required) if execution_plan else False,
                "authorityRefs": [
                    {"type": "execution", "id": str(execution.id), "source": "execution_service"},
                    {"type": "test_plan", "id": str(plan.id), "source": "test_plan"},
                    *(
                        [{"type": "execution_plan", "id": str(execution_plan.id), "source": "execution_plan"}]
                        if execution_plan is not None
                        else []
                    ),
                    *(
                        [{"type": "project", "id": str(project.id), "source": "project_configuration"}]
                        if project is not None
                        else []
                    ),
                ],
            },
            "domainInputStates": domain_states,
            "normalizedFindings": normalized_findings,
            "metrics": metric_inputs,
            "approvalState": approval_state,
            "normalizationState": {
                "status": normalization_status,
                "rawFindingCount": len(raw_findings),
                "normalizedFindingCount": len(findings),
                "unresolvedRawFindingCount": len(unresolved_raw),
                "authorityRefs": [
                    {"type": "normalization", "id": str(execution.id), "source": "execution_service"}
                ],
            },
            "evidenceIntegrity": {
                "status": evidence_status,
                "checkedRefCount": sum(len(item.evidence or []) for item in findings) + len(metric_inputs),
                "missingRefs": missing_evidence_refs,
                "invalidRefs": invalid_evidence_refs,
                "authorityRefs": [
                    {"type": "execution", "id": str(execution.id), "source": "execution_service"}
                ],
            },
            "policySnapshot": (
                resolution.snapshot.model_dump(mode="json") if resolution is not None else None
            ),
            "policySnapshotHash": resolution.snapshotHash if resolution is not None else None,
            "inputFingerprint": "sha256:" + ("0" * 64),
            "metadata": {
                "assembledBy": "GateInputAssembler",
                "policySource": policy_source,
                "fallbackReason": fallback_reason,
            },
        }
        normalized = GateInputContract.model_validate(payload)
        payload = normalized.model_dump(mode="json")
        payload["inputFingerprint"] = compute_gate_input_fingerprint(payload)
        return GateInputContract.model_validate(payload)

    @staticmethod
    def _validate_owned_inputs(
        execution_id: UUID,
        tasks: Sequence[ExecutionTask],
        findings: Sequence[Finding],
        metrics: Sequence[ExecutionMetric],
        approvals: Sequence[Approval],
    ) -> None:
        task_ids = {item.id for item in tasks}
        for finding in findings:
            if finding.execution_id != execution_id:
                raise GateInputAssemblyError("canonical Finding belongs to another execution")
            if finding.task_id is not None and finding.task_id not in task_ids:
                raise GateInputAssemblyError("canonical Finding task belongs to another execution")
        for metric in metrics:
            if metric.execution_id != execution_id:
                raise GateInputAssemblyError("metric belongs to another execution")
            if metric.task_id is not None and metric.task_id not in task_ids:
                raise GateInputAssemblyError("metric task belongs to another execution")
        normalized_execution_id = str(execution_id).replace("-", "")
        for approval in approvals:
            if approval.resource_type == "execution" and approval.resource_id.replace("-", "") != normalized_execution_id:
                raise GateInputAssemblyError("approval state belongs to another execution")

    def _authoritative_ownership_context(self, plan: TestPlan) -> tuple[str, str, Project | None]:
        project = self.db.get(Project, plan.project_id) if plan.project_id is not None else None
        plan_context = plan.metadata_json.get("gateContext")
        project_context = project.metadata_json.get("gateContext") if project is not None else None
        plan_context = plan_context if isinstance(plan_context, dict) else {}
        project_context = project_context if isinstance(project_context, dict) else {}
        tenant_id = str(
            plan_context.get("tenantId")
            or project_context.get("tenantId")
            or "local-tenant"
        )
        workspace_id = str(
            plan_context.get("workspaceId")
            or project_context.get("workspaceId")
            or (f"project-{plan.project_id}" if plan.project_id else "local-workspace")
        )
        if not tenant_id.strip() or not workspace_id.strip():
            raise GateInputAssemblyError("Gate tenant/workspace ownership context is invalid")
        return tenant_id, workspace_id, project

    @staticmethod
    def _evaluation_time(execution: Execution, tasks: Sequence[ExecutionTask]) -> datetime:
        candidates = [execution.ended_at, execution.started_at, execution.created_at]
        candidates.extend(item.ended_at for item in tasks)
        value = next((item for item in candidates if item is not None), datetime.now(timezone.utc))
        if value.tzinfo is None or value.utcoffset() is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _policy_resolution_time(execution: Execution) -> datetime:
        value = execution.created_at
        if value.tzinfo is None or value.utcoffset() is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _normalization_status(execution: Execution, unresolved: Sequence[RawFindingRecord]) -> str:
        if unresolved:
            return "in_progress"
        if execution.stage.value in {"NORMALIZE", "ANALYZE", "GATE"} or execution.status in {
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }:
            return "completed"
        return "unknown"

    @staticmethod
    def _availability(
        domain: str,
        tasks: Sequence[ExecutionTask],
        metrics: Sequence[ExecutionMetric],
        normalization_status: str,
    ) -> str:
        if not tasks:
            return "missing"
        # Functional/security consume NORMALIZE output. A failed runner task
        # may be the authoritative source of a canonical finding, so task
        # failure alone does not make that already-normalized input
        # unavailable.
        if domain != "performance":
            return "available" if normalization_status == "completed" else "unavailable"
        if any(item.status in {TaskStatus.FAILED, TaskStatus.CANCELLED} for item in tasks):
            return "unavailable"
        if any(item.status in {TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.ANALYZING} for item in tasks):
            return "unavailable"
        if not metrics:
            return "missing"
        if any(
            not GateInputAssembler._finite(item.metric_value)
            or (item.threshold_value is not None and not GateInputAssembler._finite(item.threshold_value))
            or (item.baseline_value is not None and not GateInputAssembler._finite(item.baseline_value))
            for item in metrics
        ):
            return "invalid"
        return "available"

    @staticmethod
    def _required_domains(policy) -> dict[str, bool]:
        if policy is None:
            return {domain: True for domain in DOMAIN_ORDER}
        required = {
            "functional": True,
            "performance": bool(policy.completeness.requireAllInputs),
            "security": True,
        }
        compatibility = policy.metadata.get("compatibility")
        requirements = compatibility.get("domainInputRequirements") if isinstance(compatibility, dict) else None
        if isinstance(requirements, dict):
            for domain in DOMAIN_ORDER:
                item = requirements.get(domain)
                if isinstance(item, dict) and isinstance(item.get("required"), bool):
                    required[domain] = item["required"]
        if policy.completeness.requireAllInputs:
            required = {domain: True for domain in DOMAIN_ORDER}
        return required

    @staticmethod
    def _domain_authority_refs(
        execution: Execution,
        plan: TestPlan,
        execution_plan: ExecutionPlan | None,
        domain: str,
        tasks: Sequence[ExecutionTask],
        plan_domains: Sequence[TestPlanDomain],
    ) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = [
            {
                "type": "execution_domain_scope",
                "id": f"{execution.id}:{domain}",
                "source": "execution_service",
            }
        ]
        refs.extend(
            {"type": "execution_task", "id": str(item.id), "source": "execution_plan"}
            for item in tasks
        )
        refs.extend(
            {"type": "test_plan_domain", "id": str(item.id), "source": "test_plan"}
            for item in plan_domains
            if item.domain.value == domain
        )
        if execution_plan is not None:
            refs.append(
                {"type": "execution_plan", "id": str(execution_plan.id), "source": "execution_plan"}
            )
        else:
            refs.append({"type": "test_plan", "id": str(plan.id), "source": "test_plan"})
        return refs

    @staticmethod
    def _finding_input(finding: Finding) -> dict[str, object]:
        evidence_refs = [
            {
                "type": str(item.get("type") or "evidence"),
                "id": redact_sensitive_text(str(item.get("ref") or f"finding:{finding.id}:evidence")),
                "source": "canonical_finding_evidence",
            }
            for item in finding.evidence
            if isinstance(item, dict)
        ]
        return {
            "id": str(finding.id),
            "executionId": str(finding.execution_id),
            "taskId": str(finding.task_id) if finding.task_id else None,
            "domain": finding.domain.value,
            "source": finding.source.value,
            "category": finding.category.value,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "confidence": float(finding.confidence or Decimal("0")),
            "dedupeKey": redact_sensitive_text(finding.dedupe_key),
            "rawRef": redact_sensitive_text(finding.raw_ref),
            "evidenceRefs": evidence_refs,
        }

    @staticmethod
    def _metric_domain(metric: ExecutionMetric) -> str:
        domain = str(metric.metadata_json.get("domain") or "")
        if domain in DOMAIN_ORDER:
            return domain
        if str(metric.metadata_json.get("source") or "").lower() == "k6":
            return "performance"
        return "performance"

    @classmethod
    def _metric_input(cls, metric: ExecutionMetric) -> dict[str, object]:
        raw_ref = metric.metadata_json.get("rawMetricRef")
        evidence_refs = [
            {
                "type": "metric",
                "id": redact_sensitive_text(str(raw_ref or metric.id)),
                "source": "execution_metric",
            }
        ]
        return {
            "id": str(metric.id),
            "executionId": str(metric.execution_id),
            "taskId": str(metric.task_id) if metric.task_id else None,
            "name": metric.metric_name,
            "value": float(metric.metric_value),
            "unit": metric.metric_unit,
            "threshold": float(metric.threshold_value) if metric.threshold_value is not None else None,
            "baseline": float(metric.baseline_value) if metric.baseline_value is not None else None,
            "domain": cls._metric_domain(metric),
            "source": str(metric.metadata_json.get("source") or "execution_metric"),
            "evidenceRefs": evidence_refs,
        }

    @staticmethod
    def _approval_input(approval: Approval) -> dict[str, object]:
        decided_at = approval.decided_at
        if decided_at is not None and (decided_at.tzinfo is None or decided_at.utcoffset() is None):
            decided_at = decided_at.replace(tzinfo=timezone.utc)
        return {
            "id": str(approval.id),
            "type": approval.type.value,
            "status": approval.status.value,
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "decidedAt": decided_at.isoformat() if decided_at else None,
        }

    @staticmethod
    def _finite(value: Decimal) -> bool:
        return value.is_finite()

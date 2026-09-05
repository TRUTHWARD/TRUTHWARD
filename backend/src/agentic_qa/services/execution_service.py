# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import String, cast, delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentic_qa.agents.runner import RunnerAgent
from agentic_qa.domain.enums import (
    AgentRunStatus,
    ArtifactType,
    ExecutionStage,
    FindingCategory,
    FindingSource,
    FindingSeverity,
    FindingStatus,
    GateResult,
    GuardrailDecisionType,
    JobStatus,
    ModelRole,
    RiskLevel,
    TaskStatus,
    TestDomain,
)
from agentic_qa.domain.models import (
    AdmissionRunRecord,
    AgentRun,
    Approval,
    CanonicalExecutionGraphVersion,
    CanonicalGraphStalenessAssessment,
    ChangeSetRecord,
    CodeChangeSetRecord,
    Execution,
    ExecutionArtifact,
    ExecutionLog,
    ExecutionMetric,
    ExecutionPlan,
    ExecutionTask,
    ExternalIssueLink,
    Finding,
    GateDecision,
    GateInputSnapshot,
    GraphCoverageSnapshot,
    GuardrailEvent,
    HealingSuggestion,
    ImpactResultRecord,
    Job,
    RawFindingRecord,
    RequirementVersion,
    SelectiveReplayPlanRecord,
    TestAsset,
    TestPlan,
    TestPlanDomain,
    TriageResult,
    VerificationResult,
    VisualGroundingAttempt,
    SkillInvocation,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime import ActionGuard, AgentOutputGuard, RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.artifact_storage import (
    ArtifactStorageAdapter,
    artifact_storage_adapter,
)
from agentic_qa.infra.redaction import redact_sensitive_data, redact_sensitive_text
from agentic_qa.infra.settings import get_settings
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.contracts import ContractValidationError, validate_contract
from agentic_qa.schemas.gate_evaluator import GateInputContract, GateResultContract
from agentic_qa.schemas.models import VisualTargetResolveOutput
from agentic_qa.schemas.selective_replay import (
    SELECTIVE_REPLAY_ALGORITHM_VERSION,
    SelectiveReplayPlan,
    SelectiveReplayRequest,
)
from agentic_qa.services.analysis_service import AnalysisService
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
    canonical_json,
    paginate_query,
    paginate_result,
)
from agentic_qa.services.gate_evaluator import GATE_EVALUATOR_VERSION, GateEvaluator
from agentic_qa.services.gate_input_assembler import GateInputAssembler
from agentic_qa.services.impact_analysis_query_service import SelectiveReplayQueryService
from agentic_qa.services.skill_execution_policy import SkillInvocationExecutionError
from agentic_qa.services.skill_runtime import CapabilityGateway, ManagedSkillRuntimeRegistry
from agentic_qa.services.skill_service import ExtensionInvocationCompletion, SkillService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService
from agentic_qa.tools.model_gateway import ModelGatewayTool
from agentic_qa.tools.runner_protocols import (
    RunnerExecutionRequest,
    RunnerExecutionResult,
    runner_retry_safety,
)
from agentic_qa.tools.runner_registry import RunnerRegistry


@dataclass(frozen=True)
class _GateInputs:
    findings: tuple[Finding, ...]
    metrics: tuple[ExecutionMetric, ...]
    approvals: tuple[Approval, ...]
    policy_snapshot: dict[str, object]
    integrity_issues: tuple[dict[str, str], ...] = ()


class ExecutionService(SelectiveReplayQueryService):
    PUBLIC_RUNTIME_REF_LIMIT = 100
    GATE_INPUT_INLINE_MAX_BYTES = 64 * 1024 * 1024

    def __init__(
        self,
        db: Session,
        runner_registry: RunnerRegistry | None = None,
        *,
        artifact_storage: ArtifactStorageAdapter | None = None,
        runtime_registry: ManagedSkillRuntimeRegistry | None = None,
    ) -> None:
        super().__init__(db)
        self.runner_registry = runner_registry or RunnerRegistry()
        self.runner_agent = RunnerAgent()
        self.guardrail_engine = RuntimeGuardrailEngine(db)
        self.model_tool = ModelGatewayTool(db)
        self.settings = get_settings()
        self.skill_service = SkillService(db, runtime_registry=runtime_registry)
        self.gate_input_assembler = GateInputAssembler(db)
        self.gate_evaluator = GateEvaluator()
        self.capability_gateway = CapabilityGateway(self.runner_registry)
        self._artifact_storage = artifact_storage

    def create_execution(self, payload, context: ServiceContext) -> dict[str, object]:
        execution, job = self.prepare_execution_job(payload, context)
        self.db.commit()
        from agentic_qa.infra.queue import enqueue_task

        try:
            queue_task = enqueue_task(
                "execution.run",
                str(job.id),
                str(execution.id),
                str(context.user.id),
                context.user.roles,
                context.request_id,
                context.trace_id,
            )
        except Exception as exc:
            self._record_queue_dispatch_failure(
                execution.id,
                job.id,
                exc,
                context,
            )
            raise
        job.payload = {**job.payload, "queueTaskId": str(queue_task.id)}
        self.db.commit()
        self.db.expire_all()
        refreshed_execution = self._require_execution(execution.id)
        return {
            "id": str(refreshed_execution.id),
            "jobId": str(job.id),
            "queueTaskId": str(queue_task.id),
            "status": refreshed_execution.status.value,
            "stage": refreshed_execution.stage.value,
        }

    def prepare_execution_job(self, payload, context: ServiceContext) -> tuple[Execution, Job]:
        plan = self._require_plan(payload.planId)
        self._authorize_plan_scope(plan, context, write=True)
        execution_plan_id = getattr(payload, "executionPlanId", None)
        options = payload.options.model_dump(mode="json")
        execution = Execution(
            id=uuid4(),
            plan_id=plan.id,
            status=TaskStatus.QUEUED,
            stage=ExecutionStage.PREPARE,
            environment=payload.environment,
            triggered_by=context.user.id,
            trigger_source="manual",
            options=options,
            summary={
                "functional": "queued",
                "performance": "queued",
                "security": "queued",
            },
            execution_plan_id=execution_plan_id,
        )
        self.db.add(execution)
        self.db.flush()
        self._create_tasks_for_plan(execution.id, plan.id, options, execution_plan_id=execution_plan_id)
        job = Job(
            id=uuid4(),
            job_type="execution.run",
            status=JobStatus.QUEUED,
            payload={"executionId": str(execution.id)},
            progress=0,
        )
        self.db.add(job)
        write_audit_log(self.db, str(context.user.id), "execution.create", "execution", str(execution.id), context.request_id, context.trace_id)
        self.db.flush()
        return execution, job

    def list_executions(
        self,
        page: int,
        page_size: int,
        context: ServiceContext,
    ) -> dict[str, Any]:
        statement = select(Execution).order_by(Execution.created_at.desc())
        if not {"admin", "system"}.intersection(context.user.roles):
            project_ids = ScopeAuthorizationService(self.db).authorized_project_ids(context)
            statement = (
                statement.join(TestPlan, Execution.plan_id == TestPlan.id)
                .where(TestPlan.project_id.in_(project_ids))
            )
        rows, total = paginate_query(self.db, statement, page, page_size)
        plan_ids = {item.plan_id for item in rows}
        plans = {
            item.id: item
            for item in self.db.scalars(select(TestPlan).where(TestPlan.id.in_(plan_ids)))
        } if plan_ids else {}
        runtime_by_execution = self._runtime_summary_projections(rows)
        items = [
            self.serialize_execution(
                item,
                plan=plans.get(item.plan_id),
                runtime=runtime_by_execution[item.id],
            )
            for item in rows
        ]
        return paginate_result(items, total, page, page_size)

    def get_execution(self, execution_id: UUID, context: ServiceContext) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        self.authorize_execution_scope(execution.id, context)
        return self.serialize_execution(
            execution,
            runtime=self.runtime_projection(
                execution_id,
                ref_limit=self.PUBLIC_RUNTIME_REF_LIMIT,
            ),
        )

    def runtime_projection(
        self,
        execution_id: UUID,
        *,
        ref_limit: int | None = None,
    ) -> dict[str, Any]:
        execution = self._require_execution(execution_id)
        if ref_limit is not None and ref_limit < 0:
            raise ValueError("ref_limit must be >= 0")

        def ref_rows(model, order_by):
            statement = (
                select(model)
                .where(model.execution_id == execution.id)
                .order_by(*order_by)
            )
            if ref_limit is not None:
                statement = statement.limit(ref_limit)
            return list(self.db.scalars(statement))

        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution.id)
                .order_by(ExecutionTask.created_at.asc(), ExecutionTask.id.asc())
            )
        )
        artifacts = ref_rows(
            ExecutionArtifact,
            (ExecutionArtifact.created_at.asc(), ExecutionArtifact.id.asc()),
        )
        metrics = ref_rows(
            ExecutionMetric,
            (ExecutionMetric.created_at.asc(), ExecutionMetric.id.asc()),
        )
        raw_findings = ref_rows(
            RawFindingRecord,
            (RawFindingRecord.created_at.asc(), RawFindingRecord.id.asc()),
        )
        findings = ref_rows(
            Finding,
            (Finding.created_at.asc(), Finding.id.asc()),
        )
        gate = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id))
        latest_job = self.db.scalar(
            select(Job)
            .where(Job.result_ref == str(execution.id))
            .order_by(Job.created_at.desc())
        )
        if ref_limit is None:
            statistics = self._runtime_statistics_from_rows(
                tasks,
                artifacts,
                metrics,
                raw_findings,
                findings,
            )
        else:
            statistics = self._runtime_statistics([execution.id])[execution.id]
        return self._build_runtime_projection(
            execution,
            statistics,
            artifacts=artifacts,
            metrics=metrics,
            raw_findings=raw_findings,
            findings=findings,
            gate=gate,
            latest_job=latest_job,
            ref_limit=ref_limit,
        )

    def _runtime_summary_projections(
        self,
        executions: list[Execution],
    ) -> dict[UUID, dict[str, object]]:
        if not executions:
            return {}
        execution_ids = [item.id for item in executions]
        statistics = self._runtime_statistics(execution_ids)
        gates: dict[UUID, GateDecision] = {}
        for gate in self.db.scalars(
            select(GateDecision)
            .where(GateDecision.execution_id.in_(execution_ids))
            .order_by(GateDecision.created_at.desc(), GateDecision.id.desc())
        ):
            gates.setdefault(gate.execution_id, gate)
        jobs: dict[UUID, Job] = {}
        execution_id_by_ref = {str(item): item for item in execution_ids}
        for job in self.db.scalars(
            select(Job)
            .where(Job.result_ref.in_(execution_id_by_ref))
            .order_by(Job.created_at.desc(), Job.id.desc())
        ):
            execution_id = execution_id_by_ref.get(str(job.result_ref))
            if execution_id is not None:
                jobs.setdefault(execution_id, job)
        return {
            execution.id: self._build_runtime_projection(
                execution,
                statistics[execution.id],
                artifacts=[],
                metrics=[],
                raw_findings=[],
                findings=[],
                gate=gates.get(execution.id),
                latest_job=jobs.get(execution.id),
                ref_limit=0,
            )
            for execution in executions
        }

    def _runtime_statistics(
        self,
        execution_ids: list[UUID],
    ) -> dict[UUID, dict[str, int]]:
        statistics = {
            execution_id: {
                "taskCount": 0,
                "completedTaskCount": 0,
                "failedTaskCount": 0,
                "terminalTaskCount": 0,
                "artifactRefCount": 0,
                "rawMetricRefCount": 0,
                "rawFindingRefCount": 0,
                "normalizedRawFindingCount": 0,
                "normalizedFindingRefCount": 0,
            }
            for execution_id in execution_ids
        }
        if not execution_ids:
            return statistics
        for execution_id, status, count in self.db.execute(
            select(ExecutionTask.execution_id, ExecutionTask.status, func.count())
            .where(ExecutionTask.execution_id.in_(execution_ids))
            .group_by(ExecutionTask.execution_id, ExecutionTask.status)
        ):
            value = int(count)
            statistics[execution_id]["taskCount"] += value
            if status == TaskStatus.COMPLETED:
                statistics[execution_id]["completedTaskCount"] = value
            if status == TaskStatus.FAILED:
                statistics[execution_id]["failedTaskCount"] = value
            if status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
                statistics[execution_id]["terminalTaskCount"] += value
        for model, key in (
            (ExecutionArtifact, "artifactRefCount"),
            (ExecutionMetric, "rawMetricRefCount"),
            (Finding, "normalizedFindingRefCount"),
        ):
            for execution_id, count in self.db.execute(
                select(model.execution_id, func.count())
                .where(model.execution_id.in_(execution_ids))
                .group_by(model.execution_id)
            ):
                statistics[execution_id][key] = int(count)
        for execution_id, count, normalized_count in self.db.execute(
            select(
                RawFindingRecord.execution_id,
                func.count(RawFindingRecord.id),
                func.count(RawFindingRecord.normalized_finding_id),
            )
            .where(RawFindingRecord.execution_id.in_(execution_ids))
            .group_by(RawFindingRecord.execution_id)
        ):
            statistics[execution_id]["rawFindingRefCount"] = int(count)
            statistics[execution_id]["normalizedRawFindingCount"] = int(
                normalized_count
            )
        return statistics

    @staticmethod
    def _runtime_statistics_from_rows(
        tasks: list[ExecutionTask],
        artifacts: list[ExecutionArtifact],
        metrics: list[ExecutionMetric],
        raw_findings: list[RawFindingRecord],
        findings: list[Finding],
    ) -> dict[str, int]:
        terminal_statuses = {
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
        return {
            "taskCount": len(tasks),
            "completedTaskCount": sum(
                task.status == TaskStatus.COMPLETED for task in tasks
            ),
            "failedTaskCount": sum(task.status == TaskStatus.FAILED for task in tasks),
            "terminalTaskCount": sum(task.status in terminal_statuses for task in tasks),
            "artifactRefCount": len(artifacts),
            "rawMetricRefCount": len(metrics),
            "rawFindingRefCount": len(raw_findings),
            "normalizedRawFindingCount": sum(
                item.normalized_finding_id is not None for item in raw_findings
            ),
            "normalizedFindingRefCount": len(findings),
        }

    def _build_runtime_projection(
        self,
        execution: Execution,
        statistics: dict[str, int],
        *,
        artifacts: list[ExecutionArtifact],
        metrics: list[ExecutionMetric],
        raw_findings: list[RawFindingRecord],
        findings: list[Finding],
        gate: GateDecision | None,
        latest_job: Job | None,
        ref_limit: int | None,
    ) -> dict[str, object]:
        raw_count = statistics["rawFindingRefCount"]
        all_raw_findings_normalized = bool(raw_count) and (
            statistics["normalizedRawFindingCount"] == raw_count
        )
        normalize_completed = execution.stage in {
            ExecutionStage.NORMALIZE,
            ExecutionStage.GATE,
        } and (not raw_count or all_raw_findings_normalized)
        evidence_count = (
            statistics["artifactRefCount"]
            + statistics["rawMetricRefCount"]
            + raw_count
        )
        task_count = statistics["taskCount"]
        replay_consumable = (
            execution.status == TaskStatus.COMPLETED
            and bool(task_count)
            and normalize_completed
            and evidence_count > 0
        )
        return {
            "schemaVersion": "phase8.execution-runtime.v1",
            "queueMode": self.settings.queue_mode,
            "executionStatus": execution.status.value,
            "executionStage": execution.stage.value,
            "counts": {
                key: value
                for key, value in statistics.items()
                if key not in {"terminalTaskCount", "normalizedRawFindingCount"}
            } | {
                "gateDecisionCount": 1 if gate else 0,
            },
            "refs": {
                "artifactRefs": self._artifact_refs_from_rows(artifacts),
                "rawMetricRefs": self._raw_metric_refs_from_rows(metrics),
                "rawFindingRefs": self._raw_finding_refs_from_rows(raw_findings),
                "findingRefs": self._finding_refs_from_rows(findings),
                "gateDecisionRef": str(gate.id) if gate else None,
                "latestJobRef": (
                    {"id": str(latest_job.id), "jobType": latest_job.job_type, "status": latest_job.status.value}
                    if latest_job
                    else None
                ),
            },
            "refProjection": {
                "limit": ref_limit,
                "truncated": {
                    "artifactRefs": len(artifacts) < statistics["artifactRefCount"],
                    "rawMetricRefs": len(metrics) < statistics["rawMetricRefCount"],
                    "rawFindingRefs": len(raw_findings) < raw_count,
                    "findingRefs": len(findings)
                    < statistics["normalizedFindingRefCount"],
                },
            },
            "readiness": {
                "rawEvidencePersisted": evidence_count > 0,
                "allTasksTerminal": bool(task_count)
                and statistics["terminalTaskCount"] == task_count,
                "normalizeCompleted": normalize_completed,
                "allRawFindingsNormalized": all_raw_findings_normalized
                if raw_count
                else True,
                "gateReady": normalize_completed and bool(task_count),
                "gateCompleted": gate is not None,
                "replayConsumable": replay_consumable,
                "replayExportConsumable": replay_consumable,
            },
            "consumerContract": {
                "gateInputs": ["normalized_findings", "metrics", "approval_state", "policy_snapshot"],
                "frontendCalculatesGate": False,
                "frontendCalculatesReplayValidity": False,
                "frontendCalculatesCoverage": False,
                "frontendCalculatesProof": False,
            },
        }

    def build_orchestration_envelope(
        self,
        execution_id: UUID,
        context: ServiceContext,
        *,
        stage: str,
        policy_snapshot: dict[str, object] | None = None,
        memory_snapshot: dict[str, object] | None = None,
    ) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        plan = self.db.get(TestPlan, execution.plan_id)
        requirement_scope = dict(plan.requirement_scope) if plan and plan.requirement_scope else {}
        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution.id)
                .order_by(ExecutionTask.created_at.asc())
            )
        )
        return {
            "runContext": {
                "runId": str(execution.id),
                "requestId": context.request_id,
                "traceId": str(context.trace_id),
                "triggeredBy": str(execution.triggered_by) if execution.triggered_by else None,
                "triggerSource": execution.trigger_source,
                "queueMode": self.settings.queue_mode,
                "attempt": max((task.retry_count for task in tasks), default=0) + 1,
                "startedAt": execution.started_at.isoformat() if execution.started_at else None,
            },
            "executionContext": {
                "executionId": str(execution.id),
                "planId": str(execution.plan_id),
                "environment": execution.environment,
                "stage": stage,
                "domains": [task.domain.value for task in tasks],
                "options": execution.options,
                "requirementScope": requirement_scope,
            },
            "artifactRefs": self._artifact_refs_for_execution(execution.id),
            "findingRefs": self._finding_refs_for_execution(execution.id),
            "policySnapshot": policy_snapshot or self._policy_snapshot_from_tasks(tasks),
            "memorySnapshot": memory_snapshot or {"memoryIds": [], "namespaces": [], "summaryRef": None},
        }

    def progress(self, execution_id: UUID) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)))
        total = len(tasks)
        completed = len([task for task in tasks if task.status == TaskStatus.COMPLETED])
        current_task = next((task.task_type for task in tasks if task.status == TaskStatus.RUNNING), None)
        progress = int((completed / total) * 100) if total else 0
        return {
            "executionId": str(execution.id),
            "status": execution.status.value,
            "stage": execution.stage.value,
            "progress": progress,
            "currentTask": current_task,
            "completedTasks": completed,
            "totalTasks": total,
        }

    def plan_regression(
        self,
        execution_id: UUID,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution.id)
                .order_by(ExecutionTask.priority.asc(), ExecutionTask.created_at.asc())
            )
        )
        findings = list(self.db.scalars(select(Finding).where(Finding.execution_id == execution.id)))
        finding_by_task: dict[UUID, list[Finding]] = {}
        for finding in findings:
            if finding.task_id:
                finding_by_task.setdefault(finding.task_id, []).append(finding)

        affected_cases: list[dict[str, object]] = []
        affected_case_ids: set[str] = set()
        for task in tasks:
            task_findings = finding_by_task.get(task.id, [])
            if task.status == TaskStatus.FAILED or task_findings:
                severity = self._max_finding_severity(task_findings)
                affected_cases.append(
                    {
                        "caseId": str(task.id),
                        "taskType": task.task_type,
                        "domain": task.domain.value,
                        "runner": task.runner,
                        "reason": "failed task" if task.status == TaskStatus.FAILED else "open finding",
                        "severity": severity,
                    }
                )
                affected_case_ids.add(str(task.id))

        requirement_change = self._requirement_change_context(execution, tasks)
        changed_asset_ids = set(requirement_change["changedAssetIds"])
        for task in tasks:
            asset_id = str(task.config.get("assetId") or "")
            if not asset_id or asset_id not in changed_asset_ids or str(task.id) in affected_case_ids:
                continue
            affected_cases.append(
                {
                    "caseId": str(task.id),
                    "taskType": task.task_type,
                    "domain": task.domain.value,
                    "runner": task.runner,
                    "reason": "requirement version change",
                    "severity": "medium",
                }
            )
            affected_case_ids.add(str(task.id))

        if not affected_cases:
            affected_cases = [
                {
                    "caseId": str(task.id),
                    "taskType": task.task_type,
                    "domain": task.domain.value,
                    "runner": task.runner,
                    "reason": "baseline smoke coverage",
                    "severity": "info",
                }
                for task in tasks[: min(3, len(tasks))]
            ]

        recommended_suite = [
            {
                **case,
                "priority": self._regression_priority(str(case["severity"]), str(case["reason"])),
            }
            for case in affected_cases
        ]
        risk_priority = sorted(
            [
                {
                    "caseId": case["caseId"],
                    "risk": self._regression_priority(str(case["severity"]), str(case["reason"])),
                    "reason": case["reason"],
                }
                for case in affected_cases
            ],
            key=lambda item: {"high": 0, "medium": 1, "low": 2}.get(str(item["risk"]), 3),
        )
        baseline_plan = validate_contract(
            "regression-plan",
            {
                "schemaVersion": "phase8.regression-plan.v1",
                "baseRef": {
                    "executionId": str(execution.id),
                    "planId": str(execution.plan_id),
                    "stage": execution.stage.value,
                    "status": execution.status.value,
                },
                "affectedCases": affected_cases,
                "recommendedRegressionSuite": recommended_suite,
                "riskBasedPriority": risk_priority,
                "evidenceRefs": [
                    {"type": "finding", "id": str(finding.id), "taskId": str(finding.task_id) if finding.task_id else None}
                    for finding in findings
                ]
                + requirement_change["evidenceRefs"],
                "replayRefs": [{"type": "execution", "id": str(execution.id)}],
                "metadata": {
                    "taskCount": len(tasks),
                    "findingCount": len(findings),
                    "strategy": "risk_based_delta",
                    "requirementChange": requirement_change["metadata"],
                },
            },
        )
        if context is None:
            return baseline_plan
        return self._run_regression_scope_skill(execution, baseline_plan, context)

    def _run_regression_scope_skill(
        self,
        execution: Execution,
        baseline_plan: dict[str, object],
        context: ServiceContext,
    ) -> dict[str, object]:
        request = {
            "operation": "recommend_regression_scope",
            "payload": {
                "executionId": str(execution.id),
                "planId": str(execution.plan_id),
                "baselinePlan": baseline_plan,
            },
        }
        validated_plan: dict[str, object] | None = None

        def validate_regression_scope(
            runtime_result: object,
            invocation: SkillInvocation,
        ) -> None:
            nonlocal validated_plan
            if not isinstance(runtime_result, dict):
                raise ValueError("regression scope Skill runtime returned an incompatible result")
            result_payload = runtime_result.get("result")
            if not isinstance(result_payload, dict):
                raise ValueError("regression scope Skill runtime did not return a result object")
            proposed_plan = result_payload.get("regressionPlan")
            if not isinstance(proposed_plan, dict):
                raise ValueError("regression scope Skill runtime did not return regressionPlan")
            from agentic_qa.services.community_skill_policy import (
                COMMUNITY_REGRESSION_ADAPTER,
                verify_presentation_preserves_plan,
            )

            if invocation.resolution_snapshot.get("runtimeAdapter") == COMMUNITY_REGRESSION_ADAPTER:
                verify_presentation_preserves_plan(baseline_plan, proposed_plan)
            validated = validate_contract("regression-plan", proposed_plan)
            validated["metadata"] = {
                **dict(validated.get("metadata") or {}),
                "skillInvocationId": str(invocation.id),
                "resolvedSkillId": invocation.resolution_snapshot.get("skillId"),
                "manifestHash": invocation.resolution_snapshot.get("manifestHash"),
            }
            runtime_result["result"] = {**dict(result_payload), "regressionPlan": validated}
            validated_plan = validated

        self.skill_service.invoke_extension(
            extension_point_id="PREPARE.regression_scope",
            source_workflow="execution.regression_plan",
            context=context,
            execution_id=execution.id,
            request=request,
            scope={
                **self._skill_scope_for_execution(execution),
                "stage": "PREPARE",
                "domain": "regression",
            },
            policy_snapshot={
                "workflow": "execution.regression_plan",
                "stage": "PREPARE",
                "recommendationOnly": True,
                "serviceOwnsExecution": True,
            },
            capabilities={"execute": self._default_regression_scope_runtime},
            result_validator=validate_regression_scope,
        )
        if validated_plan is None:
            raise ValueError("regression scope Skill runtime validation did not produce a plan")
        return validated_plan

    @staticmethod
    def _default_regression_scope_runtime(
        runtime_context,
        request: dict[str, object],
    ) -> dict[str, object]:
        payload = dict(request.get("payload") or {})
        baseline_plan = dict(payload.get("baselinePlan") or {})
        return {
            "result": {
                "regressionPlan": baseline_plan,
                "recommendationOnly": True,
            },
            "confidence": 0.85,
            "evidence": list(baseline_plan.get("evidenceRefs") or []),
            "artifactRefs": [],
            "rawFindingRefs": [],
            "findingCandidates": [],
            "metadata": {
                "runtime": "managed-skill-runtime",
                "skillInvocationId": str(runtime_context.skill_invocation_id),
                "resolvedSkillId": runtime_context.skill_id,
                "serviceOwnsExecution": True,
            },
        }

    def create_selective_replay_plan(
        self,
        project_id: UUID,
        payload: SelectiveReplayRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        """Freeze a graph-aware plan without creating an Execution, task, retry, or Tool call."""

        scope = self._selective_replay_scope(project_id, context, "replay.plan.create")
        impact = self.db.scalar(
            select(ImpactResultRecord).where(
                ImpactResultRecord.id == payload.impactResultId,
                ImpactResultRecord.tenant_id == scope.tenant_id,
                ImpactResultRecord.workspace_id == scope.workspace_id,
                ImpactResultRecord.project_id == project_id,
            )
        )
        if impact is None:
            raise ValueError("SELECTIVE_REPLAY_IMPACT_RESULT_NOT_FOUND")
        base_execution = self._require_execution(payload.baseExecutionId)
        base_plan = self.db.get(TestPlan, base_execution.plan_id)
        if base_plan is None or base_plan.project_id != project_id:
            raise ValueError("SELECTIVE_REPLAY_BASE_EXECUTION_NOT_FOUND")
        if payload.environmentId is not None:
            if base_plan.environment_id != payload.environmentId:
                raise ValueError("SELECTIVE_REPLAY_ENVIRONMENT_SCOPE_MISMATCH")
        elif base_plan.environment_id is not None:
            payload = payload.model_copy(update={"environmentId": base_plan.environment_id})
        base_tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == base_execution.id)
                .order_by(
                    ExecutionTask.priority.asc(),
                    ExecutionTask.created_at.asc(),
                    ExecutionTask.id.asc(),
                )
            )
        )
        if not base_tasks:
            raise ValueError("SELECTIVE_REPLAY_CONSERVATIVE_BASELINE_UNAVAILABLE")
        conservative_plan = self.plan_regression(base_execution.id)
        base_execution_fingerprint = self._base_execution_fingerprint(
            base_execution, base_tasks
        )

        coverage = self.db.scalar(
            select(GraphCoverageSnapshot).where(
                GraphCoverageSnapshot.id == payload.coverageSnapshotId,
                GraphCoverageSnapshot.tenant_id == scope.tenant_id,
                GraphCoverageSnapshot.workspace_id == scope.workspace_id,
                GraphCoverageSnapshot.project_id == project_id,
                GraphCoverageSnapshot.graph_version_id == impact.graph_version_id,
                GraphCoverageSnapshot.execution_id == base_execution.id,
            )
        )
        if coverage is None:
            raise ValueError("SELECTIVE_REPLAY_COVERAGE_SNAPSHOT_NOT_FOUND")
        if (
            base_plan.requirement_version_id is not None
            and coverage.requirement_version_id != base_plan.requirement_version_id
        ):
            raise ValueError("SELECTIVE_REPLAY_COVERAGE_REQUIREMENT_SCOPE_MISMATCH")
        assessment = (
            self.db.get(CanonicalGraphStalenessAssessment, impact.graph_assessment_id)
            if impact.graph_assessment_id
            else None
        )
        graph_version = self.db.get(CanonicalExecutionGraphVersion, impact.graph_version_id)
        if graph_version is None:
            raise ValueError("SELECTIVE_REPLAY_GRAPH_VERSION_NOT_FOUND")
        change_sets = list(
            self.db.scalars(
                select(ChangeSetRecord)
                .where(
                    ChangeSetRecord.id.in_([UUID(item) for item in impact.change_set_ids]),
                    ChangeSetRecord.tenant_id == scope.tenant_id,
                    ChangeSetRecord.workspace_id == scope.workspace_id,
                    ChangeSetRecord.project_id == project_id,
                )
                .order_by(ChangeSetRecord.id.asc())
            )
        )
        if len(change_sets) != len(impact.change_set_ids):
            raise ValueError("SELECTIVE_REPLAY_CHANGE_SET_SNAPSHOT_INVALID")
        self._validate_head_revision(change_sets, payload.expectedHeadRevision)

        policy_refs = self._replay_policy_refs(payload)
        input_material = {
            "projectId": str(project_id),
            "impactResultId": str(impact.id),
            "impactInputFingerprint": impact.input_fingerprint,
            "changeSets": [
                {"id": str(item.id), "fingerprint": item.fingerprint}
                for item in change_sets
            ],
            "graph": {
                "versionId": str(graph_version.id),
                "contentHash": graph_version.content_hash,
                "assessmentId": str(assessment.id) if assessment else None,
                "assessmentHash": assessment.assessment_hash if assessment else None,
                "staleness": impact.graph_staleness,
            },
            "coverage": {
                "snapshotId": str(coverage.id),
                "snapshotHash": coverage.snapshot_hash,
                "status": coverage.status,
            },
            "baseExecution": {
                "executionId": str(base_execution.id),
                "contentHash": base_execution_fingerprint,
                "regressionPlanHash": canonical_hash(conservative_plan),
            },
            "environmentId": str(payload.environmentId) if payload.environmentId else None,
            "policyRefs": [item.model_dump(mode="json") for item in policy_refs],
            "budget": payload.budget.model_dump(mode="json"),
            "confidenceThreshold": payload.confidenceThreshold,
            "ttlMinutes": payload.ttlMinutes,
            "expectedHeadRevision": payload.expectedHeadRevision,
            "algorithmVersion": SELECTIVE_REPLAY_ALGORITHM_VERSION,
        }
        input_fingerprint = canonical_hash(input_material)
        request_hash = canonical_hash(
            {
                "schemaVersion": payload.schemaVersion,
                **input_material,
                "idempotencyKey": payload.idempotencyKey,
            }
        )
        lock_scope = f"{scope.tenant_id}:{scope.workspace_id}:{project_id}:{input_fingerprint}"
        acquire_transaction_advisory_lock(self.db, "p19-selective-replay", lock_scope)
        same_key = self.db.scalar(
            select(SelectiveReplayPlanRecord).where(
                SelectiveReplayPlanRecord.tenant_id == scope.tenant_id,
                SelectiveReplayPlanRecord.workspace_id == scope.workspace_id,
                SelectiveReplayPlanRecord.project_id == project_id,
                SelectiveReplayPlanRecord.idempotency_key == payload.idempotencyKey,
            )
        )
        if same_key is not None:
            if same_key.request_hash != request_hash:
                raise ValueError("SELECTIVE_REPLAY_IDEMPOTENCY_CONFLICT")
            return self._selective_replay_projection(same_key, deduplicated=True)
        existing = self.db.scalar(
            select(SelectiveReplayPlanRecord).where(
                SelectiveReplayPlanRecord.tenant_id == scope.tenant_id,
                SelectiveReplayPlanRecord.workspace_id == scope.workspace_id,
                SelectiveReplayPlanRecord.project_id == project_id,
                SelectiveReplayPlanRecord.input_fingerprint == input_fingerprint,
            )
        )
        if existing is not None:
            return self._selective_replay_projection(existing, deduplicated=True)

        plan_id = uuid4()
        created_at = datetime.now(timezone.utc)
        fallback_reasons = self._selective_fallback_reasons(
            impact,
            assessment,
            coverage,
            payload.confidenceThreshold,
        )
        fallback_reasons.extend(
            self._applicability_fallback_reasons(
                graph_version,
                assessment,
                base_plan,
                payload.environmentId,
            )
        )
        fallback_reasons = list(dict.fromkeys(fallback_reasons))
        guardrail_refs = self._record_selective_replay_guardrail(
            project_id,
            plan_id,
            input_fingerprint,
            fallback_reasons,
            context,
        )
        with traced_operation(
            self.db,
            context.trace_id,
            None,
            "selective-replay.plan",
            "selective-replay.selection",
            "execution-service",
            attributes={
                "projectId": str(project_id),
                "impactResultId": str(impact.id),
                "baseExecutionId": str(base_execution.id),
                "coverageSnapshotId": str(coverage.id),
                "graphVersionId": str(graph_version.id),
                "algorithmVersion": SELECTIVE_REPLAY_ALGORITHM_VERSION,
                "fallbackReasons": fallback_reasons,
                "createsExecution": False,
            },
            parent_span_id=context.parent_span_id,
        ):
            build_kwargs: dict[str, Any] = {
                "plan_id": plan_id,
                "project_id": project_id,
                "impact": impact,
                "change_sets": change_sets,
                "graph_version": graph_version,
                "assessment": assessment,
                "coverage": coverage,
                "base_execution": base_execution,
                "base_tasks": base_tasks,
                "conservative_plan": conservative_plan,
                "base_execution_fingerprint": base_execution_fingerprint,
                "payload": payload,
                "policy_refs": policy_refs,
                "input_fingerprint": input_fingerprint,
                "fallback_reasons": fallback_reasons,
                "created_at": created_at,
                "created_by": context.user.id,
                "guardrail_refs": guardrail_refs,
            }
            try:
                plan_data = self._build_selective_replay_plan(**build_kwargs)
            except Exception as exc:
                terminal_codes = {
                    "SELECTIVE_REPLAY_CONSERVATIVE_BASELINE_UNAVAILABLE",
                    "SELECTIVE_REPLAY_HIGH_RISK_BUDGET_OMISSION",
                }
                if isinstance(exc, ValueError) and str(exc) in terminal_codes:
                    raise
                fallback_reasons.append("SELECTIVE_REPLAY_ALGORITHM_ERROR")
                fallback_reasons[:] = list(dict.fromkeys(fallback_reasons))
                guardrail_refs[:] = self._record_selective_replay_guardrail(
                    project_id,
                    plan_id,
                    input_fingerprint,
                    fallback_reasons,
                    context,
                )
                plan_data = self._build_selective_replay_plan(
                    **build_kwargs,
                    skip_graph_selection=True,
                )
            audit = write_audit_log(
                self.db,
                context.user.id,
                "selective_replay.plan.create",
                "selective_replay_plan",
                str(plan_id),
                context.request_id,
                context.trace_id,
                {
                    "projectId": str(project_id),
                    "impactResultId": str(impact.id),
                    "baseExecutionId": str(base_execution.id),
                    "inputFingerprint": input_fingerprint,
                    "planHash": plan_data["planHash"],
                    "algorithmVersion": SELECTIVE_REPLAY_ALGORITHM_VERSION,
                    "selectedPathCount": len(plan_data["selectedPaths"]),
                    "selectedTestCount": len(plan_data["selectedTests"]),
                    "fallbackUsed": plan_data["fallback"]["used"],
                    "fallbackReasonCodes": plan_data["fallback"]["reasonCodes"],
                    "estimatedCost": plan_data["estimatedCost"],
                    "executionCreated": False,
                },
            )
            audit_refs = [
                {
                    "type": "audit_log",
                    "ref": f"audit://logs/{audit.id}",
                    "contentHash": None,
                }
            ]
            plan_data["auditRefs"] = audit_refs
            plan_data["replaySnapshot"]["auditRefs"] = audit_refs
            validated = SelectiveReplayPlan.model_validate(plan_data).model_dump(mode="json")
            record = SelectiveReplayPlanRecord(
                id=plan_id,
                tenant_id=scope.tenant_id,
                workspace_id=scope.workspace_id,
                project_id=project_id,
                impact_result_id=impact.id,
                base_execution_id=base_execution.id,
                coverage_snapshot_id=coverage.id,
                environment_id=payload.environmentId,
                graph_version_id=graph_version.id,
                graph_assessment_id=assessment.id if assessment else None,
                algorithm_version=SELECTIVE_REPLAY_ALGORITHM_VERSION,
                input_fingerprint=input_fingerprint,
                idempotency_key=payload.idempotencyKey,
                request_hash=request_hash,
                plan_hash=validated["planHash"],
                status=validated["status"],
                risk_level=validated["riskSummary"]["overallRisk"],
                fallback_used=validated["fallback"]["used"],
                selected_test_count=len(validated["selectedTests"]),
                estimated_seconds=validated["estimatedCost"]["estimatedSeconds"],
                expires_at=created_at + timedelta(minutes=payload.ttlMinutes),
                plan_snapshot=validated,
                replay_snapshot=validated["replaySnapshot"],
                guardrail_event_refs=guardrail_refs,
                audit_refs=audit_refs,
                trace_id=UUID(context.trace_id),
                created_by=context.user.id,
                created_at=created_at,
            )
            self.db.add(record)
            self.db.flush()
        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            recovered = self.db.scalar(
                select(SelectiveReplayPlanRecord).where(
                    SelectiveReplayPlanRecord.tenant_id == scope.tenant_id,
                    SelectiveReplayPlanRecord.workspace_id == scope.workspace_id,
                    SelectiveReplayPlanRecord.project_id == project_id,
                    SelectiveReplayPlanRecord.input_fingerprint == input_fingerprint,
                )
            )
            if recovered is not None:
                return self._selective_replay_projection(recovered, deduplicated=True)
            raise ValueError("SELECTIVE_REPLAY_PLAN_CONFLICT") from exc
        self.db.refresh(record)
        return self._selective_replay_projection(record, deduplicated=False)

    def _build_selective_replay_plan(
        self,
        *,
        plan_id: UUID,
        project_id: UUID,
        impact: ImpactResultRecord,
        change_sets: list[ChangeSetRecord],
        graph_version: CanonicalExecutionGraphVersion,
        assessment: CanonicalGraphStalenessAssessment | None,
        coverage: GraphCoverageSnapshot,
        base_execution: Execution,
        base_tasks: list[ExecutionTask],
        conservative_plan: dict[str, object],
        base_execution_fingerprint: str,
        payload: SelectiveReplayRequest,
        policy_refs: list,
        input_fingerprint: str,
        fallback_reasons: list[str],
        created_at: datetime,
        created_by: UUID | None,
        guardrail_refs: list[dict[str, object]],
        skip_graph_selection: bool = False,
    ) -> dict[str, Any]:
        result = dict(impact.result_snapshot)
        if skip_graph_selection:
            result = {
                **result,
                "impactedPaths": [],
                "impactedTests": [],
                "unknownAreas": [],
            }
        tasks = base_tasks
        if not tasks:
            raise ValueError("SELECTIVE_REPLAY_CONSERVATIVE_BASELINE_UNAVAILABLE")
        task_by_id = {str(task.id): task for task in tasks}
        task_by_asset = {
            str(task.config.get("assetId")): task
            for task in tasks
            if task.config.get("assetId")
        }
        task_by_path: dict[str, ExecutionTask] = {}
        for task in tasks:
            for key in ("pathId", "pathRef", "cegPathId", "cegPathRef"):
                if task.config.get(key):
                    task_by_path[str(task.config[key])] = task

        selected_paths: dict[str, dict[str, Any]] = {}
        candidates: dict[str, dict[str, Any]] = {}
        excluded: dict[str, dict[str, Any]] = {}
        unknown = [
            {
                "code": str(item.get("code") or "SELECTIVE_REPLAY_IMPACT_UNKNOWN"),
                "areaRef": item.get("areaRef"),
                "riskLevel": self._replay_risk(str(item.get("riskLevel") or "high")),
                "sourceRefs": self._normalize_replay_refs(item.get("evidenceRefs") or []),
            }
            for item in result.get("unknownAreas", [])
        ]
        reason_refs: dict[str, list[dict[str, Any]]] = {}

        for path in result.get("impactedPaths", []):
            path_key = str(path.get("pathId") or path.get("pathRef"))
            risk = self._replay_risk(str(path.get("riskLevel") or "medium"))
            confidence = float(path.get("confidence") or 0)
            reasons = ["DIRECT_IMPACT"]
            if len(path.get("propagationPath") or []) > 1:
                reasons.append("DEPENDENCY_PROPAGATION")
            if risk == "high":
                reasons.append("HIGH_RISK_NEIGHBORHOOD")
            refs = self._normalize_replay_refs(path.get("evidenceRefs") or [])
            selected_paths[path_key] = {
                "pathId": path_key,
                "pathRef": str(path.get("pathRef") or f"ceg-path://{path_key}"),
                "name": str(path.get("name") or path_key),
                "riskLevel": risk,
                "confidence": confidence,
                "selectionReasonCodes": reasons,
                "evidenceRefs": refs,
            }
            for reason in reasons:
                reason_refs.setdefault(reason, []).extend(refs)
            mapped_task = task_by_path.get(path_key) or task_by_path.get(str(path.get("pathRef")))
            if mapped_task is not None:
                self._keep_replay_candidate(
                    candidates,
                    self._task_replay_candidate(
                        mapped_task,
                        risk=risk,
                        confidence=confidence,
                        reasons=reasons,
                        evidence_refs=refs,
                    ),
                )

        for test in result.get("impactedTests", []):
            test_ref = str(test.get("testRef") or "")
            risk = self._replay_risk(str(test.get("riskLevel") or "medium"))
            confidence = float(test.get("confidence") or 0)
            refs = self._normalize_replay_refs(test.get("evidenceRefs") or [])
            reasons = ["DIRECT_IMPACT"]
            if len(test.get("propagationPath") or []) > 1:
                reasons.append("DEPENDENCY_PROPAGATION")
            if risk == "high":
                reasons.append("HIGH_RISK_NEIGHBORHOOD")
            asset_id = self._asset_id_from_test_ref(test_ref)
            asset = self.db.get(TestAsset, asset_id) if asset_id else None
            if asset is None or asset.asset_type != "test_case" or asset.status in {
                "invalidated", "disabled", "archived",
            }:
                code = "SELECTIVE_REPLAY_TEST_NOT_FOUND" if asset is None else "SELECTIVE_REPLAY_TEST_DISABLED"
                excluded[test_ref] = {
                    "testRef": test_ref,
                    "riskLevel": risk,
                    "reasonCode": code,
                    "evidenceRefs": refs,
                }
                unknown.append(
                    {"code": code, "areaRef": test_ref, "riskLevel": risk, "sourceRefs": refs}
                )
                if risk == "high" and code not in fallback_reasons:
                    fallback_reasons.append(code)
                continue
            asset_task = task_by_asset.get(str(asset.id))
            if asset_task is None:
                code = "SELECTIVE_REPLAY_TEST_TASK_UNMAPPED"
                excluded[test_ref] = {
                    "testRef": test_ref,
                    "riskLevel": risk,
                    "reasonCode": code,
                    "evidenceRefs": refs,
                }
                unknown.append(
                    {"code": code, "areaRef": test_ref, "riskLevel": risk, "sourceRefs": refs}
                )
                if risk == "high" and code not in fallback_reasons:
                    fallback_reasons.append(code)
                continue
            candidate = self._task_replay_candidate(
                asset_task,
                risk=risk,
                confidence=confidence,
                reasons=reasons,
                evidence_refs=refs,
                test_ref=test_ref,
                asset_id=str(asset.id),
                domain=str(test.get("testKind") or asset.domain or asset_task.domain.value),
            )
            self._keep_replay_candidate(candidates, candidate)
            for reason in reasons:
                reason_refs.setdefault(reason, []).extend(refs)

        conservative = conservative_plan
        for case in conservative.get("recommendedRegressionSuite", []):
            conservative_task = task_by_id.get(str(case.get("caseId")))
            if conservative_task is None:
                continue
            legacy_reason = str(case.get("reason") or "conservative fallback")
            reason = {
                "failed task": "HISTORICAL_FAILURE",
                "open finding": "OPEN_FINDING",
                "requirement version change": "REQUIREMENT_CHANGE",
                "baseline smoke coverage": "SMOKE_BASELINE",
            }.get(legacy_reason, "CONSERVATIVE_FALLBACK")
            candidate = self._task_replay_candidate(
                conservative_task,
                risk=self._risk_from_regression_priority(str(case.get("priority") or "medium")),
                confidence=1.0,
                reasons=[reason],
                evidence_refs=self._legacy_regression_refs(conservative, conservative_task.id),
            )
            self._keep_replay_candidate(candidates, candidate)
            reason_refs.setdefault(reason, []).extend(candidate["evidenceRefs"])

        baseline_task = next(
            (task for task in tasks if "smoke" in task.task_type.lower()),
            tasks[0],
        )
        baseline = self._task_replay_candidate(
            baseline_task,
            risk="low",
            confidence=1.0,
            reasons=["SMOKE_BASELINE"],
            evidence_refs=[
                {
                    "type": "execution_task",
                    "ref": f"execution-task://{baseline_task.id}",
                    "contentHash": None,
                }
            ],
        )
        self._keep_replay_candidate(candidates, baseline)
        reason_refs.setdefault("SMOKE_BASELINE", []).extend(baseline["evidenceRefs"])

        projected_seconds = sum(int(item["estimatedSeconds"]) for item in candidates.values())
        if (
            payload.budget.overflowBehavior == "conservative_fallback"
            and (
                len(candidates) > payload.budget.maxTests
                or projected_seconds > payload.budget.maxEstimatedSeconds
            )
            and "SELECTIVE_REPLAY_BUDGET_INSUFFICIENT" not in fallback_reasons
        ):
            fallback_reasons.append("SELECTIVE_REPLAY_BUDGET_INSUFFICIENT")

        if fallback_reasons:
            fallback_candidates: dict[str, dict[str, Any]] = {}
            for case in conservative.get("recommendedRegressionSuite", []):
                conservative_task = task_by_id.get(str(case.get("caseId")))
                if conservative_task is None:
                    continue
                self._keep_replay_candidate(
                    fallback_candidates,
                    self._task_replay_candidate(
                        conservative_task,
                        risk=self._risk_from_regression_priority(str(case.get("priority") or "medium")),
                        confidence=1.0,
                        reasons=["CONSERVATIVE_FALLBACK"],
                        evidence_refs=self._legacy_regression_refs(
                            conservative, conservative_task.id
                        ),
                    ),
                )
            if not fallback_candidates:
                for task in tasks:
                    self._keep_replay_candidate(
                        fallback_candidates,
                        self._task_replay_candidate(
                            task,
                            risk="medium",
                            confidence=1.0,
                            reasons=["CONSERVATIVE_FALLBACK"],
                            evidence_refs=[
                                {
                                    "type": "execution_task",
                                    "ref": f"execution-task://{task.id}",
                                    "contentHash": None,
                                }
                            ],
                            ),
                        )
            for candidate in candidates.values():
                if candidate["riskLevel"] != "high":
                    continue
                preserved = {
                    **candidate,
                    "selectionReasonCodes": sorted(
                        set(candidate["selectionReasonCodes"])
                        | {"CONSERVATIVE_FALLBACK"},
                        key=self._reason_priority,
                    ),
                }
                self._keep_replay_candidate(fallback_candidates, preserved)
            candidates = fallback_candidates
            reason_refs["CONSERVATIVE_FALLBACK"] = self._normalize_replay_refs(
                conservative.get("evidenceRefs") or []
            )

        selected_tests, budget_excluded = self._apply_replay_budget(
            list(candidates.values()), payload
        )
        excluded.update({str(item["testRef"]): item for item in budget_excluded})
        if not selected_tests:
            raise ValueError("SELECTIVE_REPLAY_CONSERVATIVE_BASELINE_UNAVAILABLE")
        if any(item["riskLevel"] == "high" for item in budget_excluded):
            raise ValueError("SELECTIVE_REPLAY_HIGH_RISK_BUDGET_OMISSION")

        selected_tests.sort(key=self._replay_test_sort_key)
        selected_path_values = sorted(
            selected_paths.values(), key=lambda item: (-self._risk_score(str(item["riskLevel"])), str(item["pathRef"]))
        )
        estimated_seconds = sum(int(item["estimatedSeconds"]) for item in selected_tests)
        over_tests = max(0, len(selected_tests) - payload.budget.maxTests)
        over_seconds = max(0, estimated_seconds - payload.budget.maxEstimatedSeconds)
        overall_risk = max(
            (str(item["riskLevel"]) for item in selected_tests),
            key=self._risk_score,
        )
        reason_codes = sorted(
            {code for item in selected_tests for code in item["selectionReasonCodes"]},
            key=self._reason_priority,
        )
        selection_reasons = [
            {
                "code": code,
                "category": self._reason_category(code),
                "priority": 1000 - self._reason_priority(code),
                "explanationKey": f"selectiveReplay.reason.{code.lower()}",
                "sourceRefs": self._dedupe_replay_refs(reason_refs.get(code, [])),
            }
            for code in reason_codes
        ]
        coverage_summary = self._coverage_summary(coverage)
        fallback_used = bool(fallback_reasons)
        source_plan_ref = (
            {
                "type": "regression_plan",
                "ref": f"regression-plan://executions/{base_execution.id}",
                "contentHash": canonical_hash(conservative),
            }
            if fallback_used
            else None
        )
        expires_at = created_at + timedelta(minutes=payload.ttlMinutes)
        replay_snapshot = {
            "schemaVersion": "phase8.selective-replay-snapshot.v1",
            "inputFingerprint": input_fingerprint,
            "impactResultId": str(impact.id),
            "impactInputFingerprint": impact.input_fingerprint,
            "changeSets": [
                {"id": str(item.id), "fingerprint": item.fingerprint}
                for item in change_sets
            ],
            "graph": {
                "versionId": str(graph_version.id),
                "contentHash": graph_version.content_hash,
                "staleness": impact.graph_staleness,
                "assessmentId": str(assessment.id) if assessment else None,
                "assessmentHash": assessment.assessment_hash if assessment else None,
            },
            "coverage": {
                "snapshotId": str(coverage.id),
                "snapshotHash": coverage.snapshot_hash,
                "status": coverage.status,
            },
            "baseExecution": {
                "executionId": str(base_execution.id),
                "contentHash": base_execution_fingerprint,
                "regressionPlanHash": canonical_hash(conservative),
            },
            "policyRefs": [item.model_dump(mode="json") for item in policy_refs],
            "algorithmVersion": SELECTIVE_REPLAY_ALGORITHM_VERSION,
            "selectedPathRefs": [item["pathRef"] for item in selected_path_values],
            "selectedTestRefs": [item["testRef"] for item in selected_tests],
            "fallbackReasonCodes": sorted(set(fallback_reasons)),
            "guardrailEventRefs": guardrail_refs,
            "auditRefs": [],
            "expectedHeadRevision": payload.expectedHeadRevision,
            "redaction": {
                "sourceSnippetsIncluded": False,
                "diffContentIncluded": False,
                "requirementTextIncluded": False,
            },
            "executionCreated": False,
        }
        hash_material = {
            "inputFingerprint": input_fingerprint,
            "algorithmVersion": SELECTIVE_REPLAY_ALGORITHM_VERSION,
            "selectedPaths": selected_path_values,
            "selectedTests": selected_tests,
            "excludedTests": sorted(excluded.values(), key=lambda item: str(item["testRef"])),
            "unknownAreas": self._dedupe_replay_unknown(unknown),
            "fallbackReasonCodes": sorted(set(fallback_reasons)),
            "budget": payload.budget.model_dump(mode="json"),
            "expiresAt": expires_at.isoformat(),
        }
        plan_hash = canonical_hash(hash_material)
        return {
            "schemaVersion": "phase8.selective-replay-plan.v1",
            "planId": plan_id,
            "projectId": project_id,
            "status": "fallback" if fallback_used else "ready",
            "impactResultRef": {
                "type": "impact_result",
                "ref": f"impact-result://{impact.id}",
                "contentHash": impact.input_fingerprint,
            },
            "changeSetRefs": [
                {"type": "change_set", "ref": f"change-set://{item.id}", "contentHash": item.fingerprint}
                for item in change_sets
            ],
            "graphRef": dict(result["graphRef"]),
            "graphVersionRef": dict(result["graphVersionRef"]),
            "graphAssessmentRef": dict(result["graphAssessmentRef"]) if result.get("graphAssessmentRef") else None,
            "coverageSnapshotRef": {
                "type": "graph_coverage_snapshot",
                "ref": coverage.snapshot_ref,
                "contentHash": coverage.snapshot_hash,
            },
            "policyRefs": [item.model_dump(mode="json") for item in policy_refs],
            "baseExecutionRef": {
                "type": "execution",
                "ref": f"execution://{base_execution.id}",
                "contentHash": base_execution_fingerprint,
            },
            "environmentRef": (
                {
                    "type": "environment",
                    "ref": f"environment://{payload.environmentId}",
                    "contentHash": None,
                }
                if payload.environmentId else None
            ),
            "algorithmVersion": SELECTIVE_REPLAY_ALGORITHM_VERSION,
            "inputFingerprint": input_fingerprint,
            "selectedPaths": selected_path_values,
            "selectedTests": selected_tests,
            "selectionReasons": selection_reasons,
            "riskSummary": {
                "overallRisk": overall_risk,
                "selectedByRisk": {
                    risk: sum(1 for item in selected_tests if item["riskLevel"] == risk)
                    for risk in ("low", "medium", "high")
                },
                "highRiskOmitted": False,
                "approvalRequiredForExecution": overall_risk == "high" or over_tests > 0 or over_seconds > 0,
            },
            "coverageSummary": coverage_summary,
            "excludedTests": sorted(excluded.values(), key=lambda item: str(item["testRef"])),
            "unknownAreas": self._dedupe_replay_unknown(unknown),
            "budget": payload.budget.model_dump(mode="json"),
            "estimatedCost": {
                "selectedTestCount": len(selected_tests),
                "estimatedSeconds": estimated_seconds,
                "withinBudget": over_tests == 0 and over_seconds == 0,
                "overBudgetByTests": over_tests,
                "overBudgetBySeconds": over_seconds,
            },
            "fallback": {
                "used": fallback_used,
                "reasonCodes": sorted(set(fallback_reasons)),
                "strategy": "existing_regression_plan" if fallback_used else "none",
                "sourcePlanRef": source_plan_ref,
                "conservativeSelectionPreserved": fallback_used,
            },
            "planHash": plan_hash,
            "expiresAt": expires_at,
            "validity": {"state": "active", "reasonCodes": [], "requiresRegeneration": False},
            "createdAt": created_at,
            "createdBy": created_by,
            "guardrailEventRefs": guardrail_refs,
            "auditRefs": [],
            "replaySnapshot": replay_snapshot,
            "deduplicated": False,
            "readOnly": True,
            "executionCreated": False,
            "frontendAuthoritative": False,
        }

    def _selective_fallback_reasons(
        self,
        impact: ImpactResultRecord,
        assessment: CanonicalGraphStalenessAssessment | None,
        coverage: GraphCoverageSnapshot,
        confidence_threshold: float,
    ) -> list[str]:
        result = dict(impact.result_snapshot)
        reasons: list[str] = []
        if impact.status == "unknown":
            reasons.append("SELECTIVE_REPLAY_IMPACT_UNKNOWN")
        if impact.graph_staleness != "fresh" or assessment is None or assessment.status != "fresh":
            reasons.append(f"SELECTIVE_REPLAY_GRAPH_{impact.graph_staleness.upper()}")
        if float(impact.confidence) < confidence_threshold:
            reasons.append("SELECTIVE_REPLAY_LOW_CONFIDENCE")
        if not result.get("impactedPaths") and not result.get("impactedTests"):
            reasons.append("SELECTIVE_REPLAY_NO_MAPPING")
        if impact.truncated:
            reasons.append("SELECTIVE_REPLAY_IMPACT_TRUNCATED")
        if result.get("unknownAreas"):
            reasons.append("SELECTIVE_REPLAY_UNKNOWN_AREA")
        if impact.review_required:
            approval = self.db.get(Approval, impact.approval_id) if impact.approval_id else None
            if approval is None or approval.status.value != "approved":
                reasons.append("SELECTIVE_REPLAY_REVIEW_INCOMPLETE")
        if coverage.status in {"unknown", "uncovered"}:
            reasons.append(f"SELECTIVE_REPLAY_COVERAGE_{coverage.status.upper()}")
        latest = self.db.scalar(
            select(CanonicalGraphStalenessAssessment)
            .where(
                CanonicalGraphStalenessAssessment.graph_version_id == impact.graph_version_id,
                CanonicalGraphStalenessAssessment.tenant_id == impact.tenant_id,
                CanonicalGraphStalenessAssessment.workspace_id == impact.workspace_id,
                CanonicalGraphStalenessAssessment.project_id == impact.project_id,
            )
            .order_by(
                CanonicalGraphStalenessAssessment.assessed_at.desc(),
                CanonicalGraphStalenessAssessment.id.desc(),
            )
        )
        if latest is not None and latest.id != impact.graph_assessment_id:
            reasons.append("SELECTIVE_REPLAY_GRAPH_ASSESSMENT_ADVANCED")
        return list(dict.fromkeys(reasons))

    def _record_selective_replay_guardrail(
        self,
        project_id: UUID,
        plan_id: UUID,
        input_fingerprint: str,
        fallback_reasons: list[str],
        context: ServiceContext,
    ) -> list[dict[str, object]]:
        result = GuardrailResult(
            rule_id="replay.selective_plan_minimized_context",
            decision=GuardrailDecision.WARN if fallback_reasons else GuardrailDecision.ALLOW,
            reason=(
                "Selective Replay inputs require conservative fallback; the existing regression planner remains authoritative for fallback selection."
                if fallback_reasons
                else "Selective Replay planning uses frozen refs and minimized source context."
            ),
            evidence=[
                "full diff and requirement text excluded",
                f"inputFingerprint={input_fingerprint}",
            ],
            metadata={
                "action": "selective_replay.plan",
                "projectId": str(project_id),
                "fallbackReasonCodes": fallback_reasons,
                "executionCreated": False,
            },
        )
        self.guardrail_engine.record_result(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="selective_replay_plan",
                resource_id=str(plan_id),
                payload={"projectId": str(project_id), "inputFingerprint": input_fingerprint},
                metadata={"action": "selective_replay.plan"},
            ),
            result,
        )
        self.db.flush()
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(
                    GuardrailEvent.trace_id == UUID(context.trace_id),
                    GuardrailEvent.rule_id == result.rule_id,
                )
                .order_by(GuardrailEvent.created_at.asc())
            )
        )
        return [
            {
                "type": "guardrail_event",
                "ref": f"guardrail-event://{item.id}",
                "contentHash": None,
            }
            for item in events
        ]

    @staticmethod
    def _applicability_fallback_reasons(
        graph_version: CanonicalExecutionGraphVersion,
        assessment: CanonicalGraphStalenessAssessment | None,
        base_plan: TestPlan,
        environment_id: UUID | None,
    ) -> list[str]:
        applicability = (
            dict(assessment.applicability_range)
            if assessment is not None
            else dict(graph_version.applicability or {})
        )
        reasons: list[str] = []
        environments = {str(item) for item in applicability.get("environmentIds") or []}
        if environments and (environment_id is None or str(environment_id) not in environments):
            reasons.append("SELECTIVE_REPLAY_GRAPH_NOT_APPLICABLE_ENVIRONMENT")
        requirement_range = applicability.get("requirementVersionRange") or {}
        if requirement_range and base_plan.requirement_version_id is not None:
            accepted_ids = {str(item) for item in requirement_range.get("acceptedVersionIds") or []}
            if accepted_ids and str(base_plan.requirement_version_id) not in accepted_ids:
                reasons.append("SELECTIVE_REPLAY_GRAPH_NOT_APPLICABLE_REQUIREMENT")
        stages = {str(item).upper() for item in applicability.get("stages") or []}
        if stages and "EXECUTE" not in stages:
            reasons.append("SELECTIVE_REPLAY_GRAPH_NOT_APPLICABLE_STAGE")
        return reasons

    def _replay_policy_refs(self, payload: SelectiveReplayRequest) -> list:
        refs = list(payload.policyRefs)
        if not refs:
            from agentic_qa.schemas.selective_replay import ReplayPlanRef

            refs.append(
                ReplayPlanRef(
                    type="replay_selection_policy",
                    ref="policy://selective-replay/default-v1",
                    contentHash=canonical_hash(
                        {
                            "algorithmVersion": SELECTIVE_REPLAY_ALGORITHM_VERSION,
                            "confidenceThreshold": payload.confidenceThreshold,
                            "budget": payload.budget.model_dump(mode="json"),
                        }
                    ),
                )
            )
        return refs

    def _validate_head_revision(
        self,
        change_sets: list[ChangeSetRecord],
        expected_head_revision: str | None,
    ) -> None:
        if expected_head_revision is None:
            return
        code_sets = [
            self.db.get(CodeChangeSetRecord, item.id)
            for item in change_sets
            if item.change_set_type == "code"
        ]
        heads = {item.head_sha for item in code_sets if item is not None}
        if len(heads) != 1 or expected_head_revision not in heads:
            raise ValueError("SELECTIVE_REPLAY_HEAD_REVISION_MISMATCH")

    @staticmethod
    def _asset_id_from_test_ref(test_ref: str) -> UUID | None:
        prefix = "test://assets/"
        if not test_ref.startswith(prefix):
            return None
        try:
            return UUID(test_ref.removeprefix(prefix).split("/", 1)[0])
        except ValueError:
            return None

    @staticmethod
    def _replay_risk(value: str) -> str:
        return value if value in {"low", "medium", "high"} else "high"

    @staticmethod
    def _risk_from_regression_priority(value: str) -> str:
        if value == "high":
            return "high"
        if value == "medium":
            return "medium"
        return "low"

    @staticmethod
    def _risk_score(value: str) -> int:
        return {"low": 0, "medium": 1, "high": 2}.get(value, 2)

    @staticmethod
    def _reason_priority(value: str) -> int:
        return {
            "CONSERVATIVE_FALLBACK": 0,
            "HIGH_RISK_NEIGHBORHOOD": 1,
            "HISTORICAL_FAILURE": 2,
            "OPEN_FINDING": 3,
            "DIRECT_IMPACT": 4,
            "DEPENDENCY_PROPAGATION": 5,
            "REQUIREMENT_CHANGE": 6,
            "SMOKE_BASELINE": 7,
        }.get(value, 99)

    @staticmethod
    def _reason_category(value: str) -> str:
        if value in {"DIRECT_IMPACT", "DEPENDENCY_PROPAGATION"}:
            return "impact"
        if value == "HIGH_RISK_NEIGHBORHOOD":
            return "risk"
        if value in {"HISTORICAL_FAILURE", "OPEN_FINDING", "REQUIREMENT_CHANGE"}:
            return "history"
        if value == "SMOKE_BASELINE":
            return "baseline"
        return "fallback"

    def _task_replay_candidate(
        self,
        task: ExecutionTask,
        *,
        risk: str,
        confidence: float,
        reasons: list[str],
        evidence_refs: list[dict[str, object]],
        test_ref: str | None = None,
        asset_id: str | None = None,
        domain: str | None = None,
    ) -> dict[str, Any]:
        duration = int(task.config.get("estimatedDurationSeconds") or 60)
        duration = max(1, min(duration, 86_400))
        normalized_asset_id = asset_id or (
            str(task.config.get("assetId")) if task.config.get("assetId") else None
        )
        return {
            "testRef": test_ref or (
                f"test://assets/{normalized_asset_id}"
                if normalized_asset_id
                else f"execution-task://{task.id}"
            ),
            "assetId": normalized_asset_id,
            "taskRef": f"execution-task://{task.id}",
            "domain": domain or task.domain.value,
            "riskLevel": risk,
            "confidence": max(0.0, min(confidence, 1.0)),
            "selectionReasonCodes": sorted(set(reasons), key=self._reason_priority),
            "estimatedSeconds": duration,
            "evidenceRefs": self._dedupe_replay_refs(
                [
                    *evidence_refs,
                    {
                        "type": "execution_task",
                        "ref": f"execution-task://{task.id}",
                        "contentHash": None,
                    },
                ]
            ),
        }

    def _keep_replay_candidate(
        self, candidates: dict[str, dict[str, Any]], candidate: dict[str, Any]
    ) -> None:
        key = str(candidate["testRef"])
        current = candidates.get(key)
        if current is None:
            candidates[key] = candidate
            return
        current_risk = self._risk_score(str(current["riskLevel"]))
        incoming_risk = self._risk_score(str(candidate["riskLevel"]))
        current["riskLevel"] = candidate["riskLevel"] if incoming_risk > current_risk else current["riskLevel"]
        current["confidence"] = max(float(current["confidence"]), float(candidate["confidence"]))
        current["selectionReasonCodes"] = sorted(
            set(current["selectionReasonCodes"]) | set(candidate["selectionReasonCodes"]),
            key=self._reason_priority,
        )
        current["evidenceRefs"] = self._dedupe_replay_refs(
            [*current["evidenceRefs"], *candidate["evidenceRefs"]]
        )

    def _apply_replay_budget(
        self,
        candidates: list[dict[str, Any]],
        payload: SelectiveReplayRequest,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        ordered = sorted(candidates, key=self._replay_test_sort_key)
        selected: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        seconds = 0
        for candidate in ordered:
            cost = int(candidate["estimatedSeconds"])
            required = candidate["riskLevel"] == "high" or "SMOKE_BASELINE" in candidate["selectionReasonCodes"]
            fits = len(selected) < payload.budget.maxTests and seconds + cost <= payload.budget.maxEstimatedSeconds
            if fits or required:
                selected.append(candidate)
                seconds += cost
                continue
            excluded.append(
                {
                    "testRef": candidate["testRef"],
                    "riskLevel": candidate["riskLevel"],
                    "reasonCode": "SELECTIVE_REPLAY_BUDGET_EXCLUDED",
                    "evidenceRefs": candidate["evidenceRefs"],
                }
            )
        return selected, excluded

    def _replay_test_sort_key(self, item: dict[str, Any]) -> tuple[int, int, str]:
        reason_rank = min(
            (self._reason_priority(str(code)) for code in item["selectionReasonCodes"]),
            default=99,
        )
        return (-self._risk_score(str(item["riskLevel"])), reason_rank, str(item["testRef"]))

    @staticmethod
    def _normalize_replay_refs(refs: object) -> list[dict[str, object]]:
        output: list[dict[str, object]] = []
        for item in refs if isinstance(refs, list) else []:
            if not isinstance(item, dict):
                continue
            ref = item.get("ref") or item.get("id")
            if not ref:
                continue
            ref_text = str(ref)
            if "://" not in ref_text:
                ref_text = f"{item.get('type', 'evidence')}://{ref_text}"
            output.append(
                {
                    "type": str(item.get("type") or "evidence"),
                    "ref": ref_text,
                    "contentHash": item.get("contentHash"),
                }
            )
        return ExecutionService._dedupe_replay_refs(output)

    @staticmethod
    def _dedupe_replay_refs(refs: list[dict[str, object]]) -> list[dict[str, object]]:
        deduped: dict[tuple[str, str], dict[str, object]] = {}
        for item in refs:
            key = (str(item.get("type") or "evidence"), str(item.get("ref") or ""))
            if key[1]:
                deduped[key] = item
        return [deduped[key] for key in sorted(deduped)]

    @staticmethod
    def _dedupe_replay_unknown(items: list[dict[str, object]]) -> list[dict[str, object]]:
        deduped: dict[tuple[str, str], dict[str, object]] = {}
        for item in items:
            key = (str(item["code"]), str(item.get("areaRef") or ""))
            deduped[key] = item
        return [deduped[key] for key in sorted(deduped)]

    def _legacy_regression_refs(
        self, regression: dict[str, object], task_id: UUID
    ) -> list[dict[str, object]]:
        refs = [
            item
            for item in regression.get("evidenceRefs", [])
            if item.get("taskId") in {None, str(task_id)}
        ]
        return self._normalize_replay_refs(refs)

    @staticmethod
    def _coverage_summary(coverage: GraphCoverageSnapshot) -> dict[str, object]:
        metrics = {str(item.get("dimension")): item for item in coverage.metric_snapshot}
        path = metrics.get("canonical_path") or {}
        impact = metrics.get("change_impact") or {}
        return {
            "status": coverage.status,
            "pathCoverageRatio": path.get("coverageRatio"),
            "changeImpactCoverageRatio": impact.get("coverageRatio"),
            "gapCount": len(coverage.gap_snapshot),
            "sourceRef": {
                "type": "graph_coverage_snapshot",
                "ref": coverage.snapshot_ref,
                "contentHash": coverage.snapshot_hash,
            },
        }

    @staticmethod
    def _base_execution_fingerprint(
        execution: Execution, tasks: list[ExecutionTask]
    ) -> str:
        return canonical_hash(
            {
                "executionId": str(execution.id),
                "planId": str(execution.plan_id),
                "environment": execution.environment,
                "tasks": [
                    {
                        "id": str(item.id),
                        "status": item.status.value,
                        "priority": item.priority,
                        "assetId": item.config.get("assetId"),
                    }
                    for item in tasks
                ],
            }
        )

    def _requirement_change_context(
        self,
        execution: Execution,
        tasks: list[ExecutionTask],
    ) -> dict[str, object]:
        plan = self.db.get(TestPlan, execution.plan_id)
        if plan is None or plan.requirement_version_id is None:
            return {"changedAssetIds": [], "evidenceRefs": [], "metadata": {"status": "not_applicable"}}
        current = self.db.get(RequirementVersion, plan.requirement_version_id)
        if current is None:
            return {"changedAssetIds": [], "evidenceRefs": [], "metadata": {"status": "pending"}}
        previous = self.db.scalar(
            select(RequirementVersion)
            .where(
                RequirementVersion.source_ref == current.source_ref,
                RequirementVersion.version_no < current.version_no,
            )
            .order_by(RequirementVersion.version_no.desc())
        )
        if previous is None:
            return {
                "changedAssetIds": [],
                "evidenceRefs": [{"type": "requirement_version", "id": str(current.id)}],
                "metadata": {
                    "status": "available",
                    "requirementVersionId": str(current.id),
                    "previousRequirementVersionId": None,
                    "changedRequirementRefs": [],
                },
            }

        current_requirements = list(current.requirements)
        previous_requirements = list(previous.requirements)
        changed_refs = {
            str(index + 1)
            for index in range(max(len(current_requirements), len(previous_requirements)))
            if (current_requirements[index] if index < len(current_requirements) else None)
            != (previous_requirements[index] if index < len(previous_requirements) else None)
        }
        asset_ids = {
            str(task.config.get("assetId"))
            for task in tasks
            if task.config.get("assetId")
        }
        changed_asset_ids: list[str] = []
        if changed_refs and asset_ids:
            assets = self.db.scalars(select(TestAsset).where(TestAsset.id.in_([UUID(item) for item in asset_ids])))
            changed_asset_ids = [
                str(asset.id)
                for asset in assets
                if changed_refs.intersection(str(ref) for ref in asset.requirement_refs)
            ]
        return {
            "changedAssetIds": changed_asset_ids,
            "evidenceRefs": [
                {"type": "requirement_version", "id": str(current.id)},
                {"type": "requirement_version", "id": str(previous.id)},
            ],
            "metadata": {
                "status": "available",
                "requirementVersionId": str(current.id),
                "previousRequirementVersionId": str(previous.id),
                "changedRequirementRefs": sorted(changed_refs, key=int),
                "changedAssetIds": changed_asset_ids,
            },
        }

    def cancel(self, execution_id: UUID, context: ServiceContext) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        self.authorize_execution_scope(execution.id, context, write=True)
        if execution.status == TaskStatus.CANCELLED:
            return {"id": str(execution.id), "status": execution.status.value}
        if execution.status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
            raise ValueError("terminal execution cannot be cancelled")
        execution.status = TaskStatus.CANCELLED
        execution.ended_at = datetime.now(timezone.utc)
        tasks = list(
            self.db.scalars(
                select(ExecutionTask).where(ExecutionTask.execution_id == execution.id)
            )
        )
        for task in tasks:
            if task.status in {TaskStatus.QUEUED, TaskStatus.RUNNING}:
                task.status = TaskStatus.CANCELLED
                task.error_message = "execution cancelled"
                task.ended_at = execution.ended_at
        write_audit_log(self.db, str(context.user.id), "execution.cancel", "execution", str(execution.id), context.request_id, context.trace_id)
        self.db.commit()
        return {"id": str(execution.id), "status": execution.status.value}

    def retry(self, execution_id: UUID, scope: str, context: ServiceContext) -> dict[str, object]:
        self.authorize_execution_scope(execution_id, context, write=True)
        if self._retry_requires_approval(scope):
            from agentic_qa.services.approval_service import ApprovalService

            return ApprovalService(self.db).request_execution_retry(execution_id, scope, context)
        return self.execute_approved_retry(execution_id, scope, context, approval_id=None)

    def heal(self, execution_id: UUID, mode: str, context: ServiceContext) -> dict[str, object]:
        self.authorize_execution_scope(execution_id, context, write=True)
        self.guardrail_engine.enforce(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="execution",
                resource_id=str(execution_id),
                execution_id=execution_id,
                payload={"mode": mode},
                metadata={"action": "execution.heal"},
            ),
            [ActionGuard()],
        )
        if self._heal_requires_approval(mode):
            from agentic_qa.services.approval_service import ApprovalService

            return ApprovalService(self.db).request_execution_heal(execution_id, mode, context)
        return self.execute_approved_heal(execution_id, mode, context, approval_id=None)

    def gate(self, execution_id: UUID, context: ServiceContext) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        self.authorize_execution_scope(execution.id, context, write=True)
        decision = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id))
        if decision is not None:
            gate_inputs = self._collect_gate_inputs(execution.id)
            self._persist_gate_input_snapshot(decision, gate_inputs, context)
            write_audit_log(self.db, str(context.user.id), "execution.gate", "execution", str(execution.id), context.request_id, context.trace_id)
            self.db.commit()
            return {
                **self._serialize_gate_decision(execution.id, decision),
                "status": JobStatus.COMPLETED.value,
            }

        job = self.prepare_gate_job(execution_id, context)
        self.db.commit()
        from agentic_qa.infra.queue import enqueue_task

        try:
            queue_task = enqueue_task(
                "execution.gate",
                str(job.id),
                str(execution.id),
                str(context.user.id),
                context.user.roles,
                context.request_id,
                context.trace_id,
            )
        except Exception as exc:
            self._record_queue_dispatch_failure(
                execution.id,
                job.id,
                exc,
                context,
            )
            raise
        job.payload = {**job.payload, "queueTaskId": str(queue_task.id)}
        self.db.commit()
        self.db.expire_all()
        decision = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id))
        if decision is not None:
            return {
                **self._serialize_gate_decision(execution.id, decision),
                "jobId": str(job.id),
                "queueTaskId": str(queue_task.id),
                "status": self._require_job(job.id).status.value,
            }
        return {
            "executionId": str(execution.id),
            "jobId": str(job.id),
            "queueTaskId": str(queue_task.id),
            "status": JobStatus.QUEUED.value,
        }

    def prepare_gate_job(self, execution_id: UUID, context: ServiceContext) -> Job:
        execution = self._require_execution(execution_id)
        acquire_transaction_advisory_lock(self.db, "gate-job", str(execution.id))
        idempotency_key = f"execution.gate:{execution.id}"
        existing = self.db.scalar(select(Job).where(Job.idempotency_key == idempotency_key))
        if existing is not None:
            return existing
        job = Job(
            id=uuid4(),
            job_type="execution.gate",
            status=JobStatus.QUEUED,
            payload={"executionId": str(execution.id)},
            progress=0,
            idempotency_key=idempotency_key,
        )
        self.db.add(job)
        write_audit_log(self.db, str(context.user.id), "execution.gate", "execution", str(execution.id), context.request_id, context.trace_id)
        self.db.flush()
        return job

    def run_execution_job(
        self,
        job_id: UUID,
        execution_id: UUID,
        context: ServiceContext,
        *,
        defer_normalize: bool = False,
    ) -> dict[str, object]:
        job = self._require_job(job_id)
        execution = self._require_execution(execution_id)
        if job.status == JobStatus.COMPLETED:
            return {
                "jobId": str(job.id),
                "executionId": str(execution.id),
                "status": job.status.value,
                "deduplicated": True,
            }
        if execution.status == TaskStatus.CANCELLED:
            job.status = JobStatus.CANCELLED
            job.progress = 100
            job.result_ref = str(execution.id)
            job.result_payload = {
                "executionId": str(execution.id),
                "status": execution.status.value,
                "stage": execution.stage.value,
                "summary": execution.summary,
            }
            job.ended_at = execution.ended_at or datetime.now(timezone.utc)
            self.db.commit()
            return {
                "jobId": str(job.id),
                "executionId": str(execution.id),
                "status": job.status.value,
            }
        try:
            job.status = JobStatus.RUNNING
            job.progress = 10
            job.started_at = datetime.now(timezone.utc)
            execution.status = TaskStatus.RUNNING
            execution.stage = ExecutionStage.PREPARE
            execution.started_at = execution.started_at or job.started_at
            execution.ended_at = None
            self.db.flush()

            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="execution.run",
                span_name="execution.prepare",
                service_name="execution-service",
                attributes={"executionId": str(execution.id)},
            ):
                self._prepare_tasks_for_run(execution.id)

            execution.stage = ExecutionStage.EXECUTE
            job.progress = 45
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="execution.run",
                span_name="execution.execute",
                service_name="execution-service",
                attributes={"executionId": str(execution.id)},
            ):
                self._run_tasks(execution.id, context=context)

            execution.stage = ExecutionStage.OBSERVE
            job.progress = 70
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="execution.run",
                span_name="execution.observe",
                service_name="execution-service",
                attributes={"executionId": str(execution.id)},
            ):
                self._record_execution_observations(execution.id)

            if not defer_normalize:
                execution.stage = ExecutionStage.ANALYZE
                job.progress = 80
                with traced_operation(
                    self.db,
                    trace_id=context.trace_id,
                    execution_id=execution.id,
                    root_span_name="execution.run",
                    span_name="execution.analyze",
                    service_name="agent-service",
                    attributes={"executionId": str(execution.id)},
                ):
                    AnalysisService(self.db).analyze_execution(execution.id, context, reset=True)
                self.normalize_execution(execution.id, context)
            else:
                execution.summary = self._build_execution_summary(execution.id)

            execution.status = self._execution_terminal_status(execution.id)
            execution.ended_at = datetime.now(timezone.utc)
            job.status = self._job_status_for_execution(execution.status)
            job.progress = 100
            job.result_ref = str(execution.id)
            job.result_payload = {
                "executionId": str(execution.id),
                "status": execution.status.value,
                "stage": execution.stage.value,
                "summary": execution.summary,
                "runtime": self.runtime_projection(execution.id),
            }
            if execution.status != TaskStatus.COMPLETED:
                job.error_message = self._execution_terminal_error(execution.id)
            job.ended_at = execution.ended_at
            write_audit_log(self.db, str(context.user.id), "execution.run", "execution", str(execution.id), context.request_id, context.trace_id)
            self.db.commit()
            return {"jobId": str(job.id), "executionId": str(execution.id), "status": job.status.value}
        except Exception as exc:
            self.db.rollback()
            recovered = self._recover_committed_job(job_id, execution_id)
            if recovered is not None:
                return recovered
            execution = self._require_execution(execution_id)
            job = self._require_job(job_id)
            execution.status = TaskStatus.FAILED
            execution.ended_at = datetime.now(timezone.utc)
            job.status = JobStatus.FAILED
            job.progress = 100
            job.error_message = str(exc)
            job.ended_at = execution.ended_at
            self._fail_nonterminal_tasks(execution.id, str(exc), ended_at=execution.ended_at)
            self.db.commit()
            raise

    def normalize_execution(
        self,
        execution_id: UUID,
        context: ServiceContext,
        *,
        task_ids: list[UUID] | None = None,
    ) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        execution.stage = ExecutionStage.NORMALIZE
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=execution.id,
            root_span_name="execution.run",
            span_name="execution.normalize",
            service_name="execution-service",
            attributes={"executionId": str(execution.id)},
        ):
            # P15 coverage gaps are Service-owned raw candidates. If an
            # execution froze a CEG version, materialize the authoritative
            # snapshot before NORMALIZE so no gap can bypass canonical Finding.
            from agentic_qa.services.graph_coverage_service import GraphCoverageService

            GraphCoverageService(self.db).materialize_for_execution(execution.id, context)
            self._normalize_raw_findings(execution.id, task_ids=task_ids)
            execution.summary = self._build_execution_summary(execution.id)
        self.db.flush()
        return {
            "executionId": str(execution.id),
            "stage": execution.stage.value,
            "summary": execution.summary,
            "runtime": self.runtime_projection(execution.id),
        }

    def run_retry_job(self, job_id: UUID, execution_id: UUID, scope: str, context: ServiceContext) -> dict[str, object]:
        job = self._require_job(job_id)
        execution = self._require_execution(execution_id)
        if job.status == JobStatus.COMPLETED:
            return {
                "jobId": str(job.id),
                "executionId": str(execution.id),
                "status": job.status.value,
                "deduplicated": True,
            }
        target_tasks = self._tasks_for_retry_scope(execution.id, scope)
        if not target_tasks:
            raise ValueError("no tasks matched retry scope")
        try:
            job.status = JobStatus.RUNNING
            job.progress = 10
            job.started_at = datetime.now(timezone.utc)
            execution.status = TaskStatus.RUNNING
            execution.stage = ExecutionStage.PREPARE
            execution.ended_at = None
            self.db.flush()

            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="execution.retry",
                span_name="execution.prepare",
                service_name="execution-service",
                attributes={"executionId": str(execution.id), "scope": scope},
            ):
                self._reset_retry_outputs(execution.id, [task.id for task in target_tasks])
                self._prepare_tasks_for_retry(target_tasks)

            execution.stage = ExecutionStage.EXECUTE
            job.progress = 45
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="execution.retry",
                span_name="execution.execute",
                service_name="execution-service",
                attributes={"executionId": str(execution.id), "scope": scope},
            ):
                self._run_tasks(execution.id, context=context, task_ids=[task.id for task in target_tasks])

            execution.stage = ExecutionStage.OBSERVE
            job.progress = 70
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="execution.retry",
                span_name="execution.observe",
                service_name="execution-service",
                attributes={"executionId": str(execution.id), "scope": scope},
            ):
                self._record_execution_observations(execution.id, task_ids=[task.id for task in target_tasks])

            execution.stage = ExecutionStage.ANALYZE
            job.progress = 80
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="execution.retry",
                span_name="execution.analyze",
                service_name="agent-service",
                attributes={"executionId": str(execution.id), "scope": scope},
            ):
                AnalysisService(self.db).analyze_execution(execution.id, context, reset=True)
            job.progress = 85
            self.normalize_execution(
                execution.id,
                context,
                task_ids=[task.id for task in target_tasks],
            )

            execution.status = self._execution_terminal_status(execution.id)
            execution.ended_at = datetime.now(timezone.utc)
            job.status = self._job_status_for_execution(execution.status)
            job.progress = 100
            job.result_ref = str(execution.id)
            job.result_payload = {
                "executionId": str(execution.id),
                "scope": scope,
                "retriedTaskCount": len(target_tasks),
                "summary": execution.summary,
                "runtime": self.runtime_projection(execution.id),
            }
            if execution.trigger_source == "pr_admission":
                from agentic_qa.services.admission_service import AdmissionService

                AdmissionService(self.db).refresh_after_execution_retry(
                    execution.id,
                    dict(job.result_payload["runtime"]),
                    context,
                )
            if execution.status != TaskStatus.COMPLETED:
                job.error_message = self._execution_terminal_error(execution.id)
            job.ended_at = execution.ended_at
            write_audit_log(
                self.db,
                str(context.user.id),
                "execution.retry.run",
                "execution",
                str(execution.id),
                context.request_id,
                context.trace_id,
                {"scope": scope, "retriedTaskCount": len(target_tasks)},
            )
            self.db.commit()
            return {"jobId": str(job.id), "executionId": str(execution.id), "status": job.status.value}
        except Exception as exc:
            self.db.rollback()
            recovered = self._recover_committed_job(job_id, execution_id)
            if recovered is not None:
                return recovered
            execution = self._require_execution(execution_id)
            job = self._require_job(job_id)
            execution.status = TaskStatus.FAILED
            execution.ended_at = datetime.now(timezone.utc)
            job.status = JobStatus.FAILED
            job.progress = 100
            job.error_message = str(exc)
            job.ended_at = execution.ended_at
            self._fail_nonterminal_tasks(execution.id, str(exc), ended_at=execution.ended_at)
            self.db.commit()
            raise

    def run_heal_job(self, job_id: UUID, execution_id: UUID, mode: str, context: ServiceContext) -> dict[str, object]:
        job = self._require_job(job_id)
        execution = self._require_execution(execution_id)
        if job.status == JobStatus.COMPLETED:
            return {
                "jobId": str(job.id),
                "executionId": str(execution.id),
                "status": job.status.value,
                "deduplicated": True,
            }
        analysis_service = AnalysisService(self.db)
        original_stage = execution.stage
        try:
            job.status = JobStatus.RUNNING
            job.progress = 20
            job.started_at = datetime.now(timezone.utc)
            execution.stage = ExecutionStage.ANALYZE
            self.db.flush()

            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution.id,
                root_span_name="execution.heal",
                span_name="healing.generate",
                service_name="agent-service",
                attributes={"executionId": str(execution.id), "mode": mode},
            ):
                suggestion_count = analysis_service.generate_healing(execution.id, context=context, reset=True)

            execution.stage = original_stage
            job.status = JobStatus.COMPLETED
            job.progress = 100
            job.result_ref = str(execution.id)
            job.result_payload = {
                "executionId": str(execution.id),
                "mode": mode,
                "suggestionCount": suggestion_count,
            }
            job.ended_at = datetime.now(timezone.utc)
            write_audit_log(
                self.db,
                str(context.user.id),
                "execution.heal.run",
                "execution",
                str(execution.id),
                context.request_id,
                context.trace_id,
                {"mode": mode, "suggestionCount": suggestion_count},
            )
            self.db.commit()
            return {"jobId": str(job.id), "executionId": str(execution.id), "status": job.status.value}
        except Exception as exc:
            self.db.rollback()
            recovered = self._recover_committed_job(job_id, execution_id)
            if recovered is not None:
                return recovered
            execution = self._require_execution(execution_id)
            job = self._require_job(job_id)
            execution.stage = original_stage
            job.status = JobStatus.FAILED
            job.progress = 100
            job.error_message = str(exc)
            job.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            raise

    def run_gate_job(self, job_id: UUID, execution_id: UUID, context: ServiceContext) -> dict[str, object]:
        job = self._require_job(job_id)
        execution = self._require_execution(execution_id)
        if job.status == JobStatus.COMPLETED:
            decision = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id))
            if decision is not None:
                gate_inputs = self._collect_gate_inputs(execution.id)
                self._persist_gate_input_snapshot(decision, gate_inputs, context)
                self.db.commit()
            return {
                "jobId": str(job.id),
                "executionId": str(execution.id),
                "status": job.status.value,
                "deduplicated": True,
            }
        try:
            acquire_transaction_advisory_lock(self.db, "gate-evaluation", str(execution.id))
            decision = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id))
            job.status = JobStatus.RUNNING
            job.progress = 20
            job.started_at = datetime.now(timezone.utc)
            self.db.flush()

            if decision is None:
                gate_inputs = self._collect_gate_inputs(execution.id)
                execution.stage = ExecutionStage.GATE
                with traced_operation(
                    self.db,
                    trace_id=context.trace_id,
                    execution_id=execution.id,
                    root_span_name="execution.gate",
                    span_name="gate.evaluate",
                    service_name="execution-service",
                    attributes={
                        "executionId": str(execution.id),
                        "gateEvaluatorVersion": GATE_EVALUATOR_VERSION,
                        "gateAuthority": "execution-service",
                    },
                ):
                    decision = self._evaluate_gate_from_inputs(
                        execution.id,
                        gate_inputs,
                        context=context,
                    )
                    self.db.add(decision)
                    self.db.flush()
                    self._persist_gate_input_snapshot(decision, gate_inputs, context)
                execution.status = TaskStatus.COMPLETED
                execution.ended_at = execution.ended_at or datetime.now(timezone.utc)
            elif (
                self.db.scalar(
                    select(GateInputSnapshot).where(GateInputSnapshot.gate_decision_id == decision.id)
                )
                is None
            ):
                gate_inputs = self._collect_gate_inputs(execution.id)
                self._persist_gate_input_snapshot(decision, gate_inputs, context)

            job.status = JobStatus.COMPLETED
            job.progress = 100
            job.result_ref = str(execution.id)
            job.result_payload = self._serialize_gate_decision(execution.id, decision)
            job.ended_at = datetime.now(timezone.utc)
            audit = write_audit_log(
                self.db,
                str(context.user.id),
                "execution.gate.run",
                "execution",
                str(execution.id),
                context.request_id,
                context.trace_id,
                {
                    "gateDecisionId": str(decision.id),
                    "decision": decision.overall.value,
                    "reasonCodes": list(decision.reason_codes or []),
                    "matchedRules": list(decision.matched_rules or []),
                    "inputFingerprint": decision.input_fingerprint,
                    "decisionSnapshotHash": decision.decision_snapshot_hash,
                    "policyVersionId": decision.policy_version_id,
                    "policyVersionHash": decision.policy_version_hash,
                    "evaluatorVersion": decision.evaluator_version,
                },
                execution_id=execution.id,
            )
            gate_snapshot = self.db.scalar(
                select(GateInputSnapshot).where(GateInputSnapshot.gate_decision_id == decision.id)
            )
            if gate_snapshot is not None:
                gate_snapshot.audit_refs = [
                    {"type": "audit_log", "id": str(audit.id), "action": audit.action}
                ]
            self.db.commit()
            # Shadow is deliberately evaluated only after the authoritative Gate
            # transaction commits. A Shadow failure can never roll back or block
            # the canonical Gate decision.
            try:
                from agentic_qa.services.gate_policy_simulation_service import (
                    GatePolicySimulationService,
                )

                GatePolicySimulationService(self.db).run_shadow_for_execution(
                    execution_id=execution.id,
                    gate_decision_id=decision.id,
                    context=context,
                )
            except Exception:
                self.db.rollback()
                write_audit_log(
                    self.db,
                    str(context.user.id),
                    "gate_policy.shadow.unavailable",
                    "gate_decision",
                    str(decision.id),
                    context.request_id,
                    context.trace_id,
                    {
                        "errorCode": "GATE_POLICY_SHADOW_EVALUATION_UNAVAILABLE",
                        "authoritativeGatePreserved": True,
                        "blocksGate": False,
                    },
                    execution_id=execution.id,
                )
                self.db.commit()
            return {"jobId": str(job.id), "executionId": str(execution.id), "status": job.status.value}
        except Exception as exc:
            self.db.rollback()
            recovered = self._recover_committed_job(job_id, execution_id)
            if recovered is not None:
                return recovered
            job = self._require_job(job_id)
            job.status = JobStatus.FAILED
            job.progress = 100
            job.error_message = str(exc)
            job.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            raise

    def list_tasks(self, execution_id: UUID) -> dict[str, object]:
        rows = [self.serialize_task(row) for row in self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution_id))]
        return {"items": rows, "total": len(rows)}

    def get_task(self, task_id: UUID) -> dict[str, object]:
        return self.serialize_task(self._require_task(task_id))

    def list_artifacts(self, task_id: UUID) -> dict[str, object]:
        rows = [self.serialize_artifact(row) for row in self.db.scalars(select(ExecutionArtifact).where(ExecutionArtifact.task_id == task_id))]
        return {"items": rows, "total": len(rows)}

    def list_logs(self, task_id: UUID) -> dict[str, object]:
        rows = [self.serialize_log(row) for row in self.db.scalars(select(ExecutionLog).where(ExecutionLog.task_id == task_id))]
        return {"items": rows, "total": len(rows)}

    def list_metrics(self, task_id: UUID) -> dict[str, object]:
        rows = [self.serialize_metric(row) for row in self.db.scalars(select(ExecutionMetric).where(ExecutionMetric.task_id == task_id))]
        return {"items": rows, "total": len(rows)}

    def list_findings(
        self,
        execution_id: UUID,
        domain: str | None = None,
        severity: str | None = None,
        *,
        page: int = 1,
        page_size: int = 100,
    ) -> dict[str, object]:
        statement = select(Finding).where(Finding.execution_id == execution_id)
        if domain is not None:
            try:
                statement = statement.where(Finding.domain == TestDomain(domain))
            except ValueError:
                return paginate_result([], 0, page, page_size)
        if severity is not None:
            try:
                statement = statement.where(
                    Finding.severity == FindingSeverity(severity)
                )
            except ValueError:
                return paginate_result([], 0, page, page_size)
        statement = statement.order_by(
            Finding.created_at.desc(),
            Finding.id.desc(),
        )
        rows, total = paginate_query(self.db, statement, page, page_size)
        links_by_finding = self._latest_external_issue_links(
            [finding.id for finding in rows]
        )
        items = [
            self._serialize_finding(
                finding,
                links_by_finding.get(finding.id),
            )
            for finding in rows
        ]
        return paginate_result(items, total, page, page_size)

    def list_visual_grounding_attempts(self, execution_id: UUID) -> dict[str, object]:
        rows = list(
            self.db.scalars(
                select(VisualGroundingAttempt)
                .where(VisualGroundingAttempt.execution_id == execution_id)
                .order_by(VisualGroundingAttempt.created_at.asc())
            )
        )
        return {"items": [self.serialize_visual_grounding_attempt(row) for row in rows], "total": len(rows)}

    def list_verification_results(self, execution_id: UUID) -> dict[str, object]:
        rows = list(
            self.db.scalars(
                select(VerificationResult)
                .where(VerificationResult.execution_id == execution_id)
                .order_by(VerificationResult.created_at.asc())
            )
        )
        return {"items": [self.serialize_verification_result(row) for row in rows], "total": len(rows)}

    def get_finding(self, finding_id: UUID) -> dict[str, object]:
        return self.serialize_finding(self._require_finding(finding_id))

    def update_finding(self, finding_id: UUID, status, comment: str | None, context: ServiceContext) -> dict[str, object]:
        if status == FindingStatus.ACCEPTED_RISK:
            from agentic_qa.services.approval_service import ApprovalService

            return ApprovalService(self.db).request_accepted_risk(finding_id, comment, context)
        return self.execute_approved_finding_update(finding_id, status.value if isinstance(status, FindingStatus) else str(status), comment, context, approval_id=None)

    def execute_approved_retry(self, execution_id: UUID, scope: str, context: ServiceContext, approval_id: UUID | None) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        self.authorize_execution_scope(execution.id, context, write=True)
        admission_run = (
            self.db.scalar(
                select(AdmissionRunRecord).where(AdmissionRunRecord.execution_id == execution.id)
            )
            if execution.trigger_source == "pr_admission"
            else None
        )
        queue_trace_id = str(admission_run.trace_id) if admission_run is not None else context.trace_id
        job = Job(
            id=uuid4(),
            job_type="execution.retry",
            status=JobStatus.QUEUED,
            payload={
                "executionId": str(execution.id),
                "scope": scope,
                "approvalId": str(approval_id) if approval_id else None,
                "rootTraceId": queue_trace_id,
            },
            progress=0,
        )
        execution.status = TaskStatus.QUEUED
        execution.stage = ExecutionStage.PREPARE
        execution.ended_at = None
        self.db.add(job)
        write_audit_log(
            self.db,
            str(context.user.id),
            "execution.retry",
            "execution",
            str(execution.id),
            context.request_id,
            queue_trace_id,
            {"scope": scope, "approvalId": str(approval_id) if approval_id else None},
        )
        self.db.commit()
        from agentic_qa.infra.queue import enqueue_task

        try:
            queue_task = enqueue_task(
                "execution.retry",
                str(job.id),
                str(execution.id),
                scope,
                str(context.user.id),
                context.user.roles,
                context.request_id,
                queue_trace_id,
            )
        except Exception as exc:
            self._record_queue_dispatch_failure(
                execution.id,
                job.id,
                exc,
                context,
            )
            raise
        job.payload = {**job.payload, "queueTaskId": str(queue_task.id)}
        self.db.commit()
        self.db.expire_all()
        refreshed_execution = self._require_execution(execution.id)
        return {
            "approvalRequired": False,
            "approvalId": str(approval_id) if approval_id else None,
            "jobId": str(job.id),
            "queueTaskId": str(queue_task.id),
            "executionId": str(execution.id),
            "status": refreshed_execution.status.value,
            "stage": refreshed_execution.stage.value,
        }

    def execute_approved_heal(self, execution_id: UUID, mode: str, context: ServiceContext, approval_id: UUID | None) -> dict[str, object]:
        execution = self._require_execution(execution_id)
        self.authorize_execution_scope(execution.id, context, write=True)
        job = Job(
            id=uuid4(),
            job_type="execution.heal",
            status=JobStatus.QUEUED,
            payload={
                "executionId": str(execution_id),
                "mode": mode,
                "approvalId": str(approval_id) if approval_id else None,
            },
            progress=0,
        )
        self.db.add(job)
        write_audit_log(
            self.db,
            str(context.user.id),
            "execution.heal",
            "execution",
            str(execution_id),
            context.request_id,
            context.trace_id,
            {"mode": mode, "approvalId": str(approval_id) if approval_id else None},
        )
        self.db.commit()
        from agentic_qa.infra.queue import enqueue_task

        try:
            queue_task = enqueue_task(
                "execution.heal",
                str(job.id),
                str(execution.id),
                mode,
                str(context.user.id),
                context.user.roles,
                context.request_id,
                context.trace_id,
            )
        except Exception as exc:
            self._record_queue_dispatch_failure(
                execution.id,
                job.id,
                exc,
                context,
            )
            raise
        job.payload = {**job.payload, "queueTaskId": str(queue_task.id)}
        self.db.commit()
        self.db.expire_all()
        return {
            "approvalRequired": False,
            "approvalId": str(approval_id) if approval_id else None,
            "jobId": str(job.id),
            "queueTaskId": str(queue_task.id),
            "executionId": str(execution.id),
            "status": self._require_job(job.id).status.value,
        }

    def execute_approved_finding_update(
        self,
        finding_id: UUID,
        status_value: str,
        comment: str | None,
        context: ServiceContext,
        approval_id: UUID | None,
    ) -> dict[str, object]:
        finding = self._require_finding(finding_id)
        self.authorize_execution_scope(finding.execution_id, context, write=True)
        finding.status = FindingStatus(status_value)
        if comment:
            finding.comment = comment
        self._invalidate_gate_decision(finding.execution_id)
        write_audit_log(
            self.db,
            str(context.user.id),
            "finding.update",
            "finding",
            str(finding.id),
            context.request_id,
            context.trace_id,
            {"status": finding.status.value, "approvalId": str(approval_id) if approval_id else None},
        )
        self.db.commit()
        return {
            **self.serialize_finding(finding),
            "approvalRequired": False,
            "approvalId": str(approval_id) if approval_id else None,
        }

    def execute_approved_visual_action_review(
        self,
        execution_id: UUID,
        attempt_id: UUID,
        context: ServiceContext,
        approval_id: UUID | None,
    ) -> dict[str, object]:
        attempt = self.db.get(VisualGroundingAttempt, attempt_id)
        if attempt is None or attempt.execution_id != execution_id:
            raise ValueError("visual grounding attempt not found")
        attempt.status = "approved_review"
        attempt.verification_status = "approved_review"
        attempt.verification_result = {
            **attempt.verification_result,
            "approvalId": str(approval_id) if approval_id else None,
            "approvedBy": str(context.user.id),
            "approvedAt": datetime.now(timezone.utc).isoformat(),
        }
        verification_results = list(
            self.db.scalars(
                select(VerificationResult)
                .where(VerificationResult.visual_attempt_id == attempt.id)
                .order_by(VerificationResult.created_at.asc())
            )
        )
        for result in verification_results:
            result.status = "approved_review"
            result.result_payload = {
                **result.result_payload,
                "approvalId": str(approval_id) if approval_id else None,
                "approvedBy": str(context.user.id),
            }
        write_audit_log(
            self.db,
            str(context.user.id),
            "visual_grounding.review.approve",
            "execution",
            str(execution_id),
            context.request_id,
            context.trace_id,
            {
                "attemptId": str(attempt.id),
                "actionId": attempt.action_id,
                "approvalId": str(approval_id) if approval_id else None,
            },
        )
        self.db.commit()
        return {
            "approvalRequired": False,
            "approvalId": str(approval_id) if approval_id else None,
            "executionId": str(execution_id),
            "attemptId": str(attempt.id),
            "status": attempt.status,
            "verificationStatus": attempt.verification_status,
        }

    def serialize_execution(
        self,
        execution: Execution,
        *,
        plan: TestPlan | None = None,
        runtime: dict[str, object] | None = None,
    ) -> dict[str, object]:
        plan = plan or self.db.get(TestPlan, execution.plan_id)
        return {
            "id": str(execution.id),
            "planId": str(execution.plan_id),
            "status": execution.status.value,
            "stage": execution.stage.value,
            "environment": execution.environment,
            "startedAt": execution.started_at.isoformat() if execution.started_at else None,
            "endedAt": execution.ended_at.isoformat() if execution.ended_at else None,
            "summary": execution.summary,
            "requirementScope": dict(plan.requirement_scope) if plan and plan.requirement_scope else {},
            "runtime": runtime or self.runtime_projection(execution.id),
        }

    def serialize_task(self, task: ExecutionTask) -> dict[str, object]:
        return {
            "id": str(task.id),
            "executionId": str(task.execution_id),
            "parentTaskId": str(task.parent_task_id) if task.parent_task_id else None,
            "domain": task.domain.value,
            "taskType": task.task_type,
            "runner": task.runner,
            "status": task.status.value,
            "stage": task.stage.value if task.stage else None,
            "retryCount": task.retry_count,
            "resultPayload": task.result_payload,
            "errorMessage": task.error_message,
            "startedAt": task.started_at.isoformat() if task.started_at else None,
            "endedAt": task.ended_at.isoformat() if task.ended_at else None,
        }

    def serialize_artifact(self, artifact: ExecutionArtifact) -> dict[str, object]:
        return {
            "id": str(artifact.id),
            "taskId": str(artifact.task_id) if artifact.task_id else None,
            "artifactType": artifact.artifact_type.value,
            "uri": artifact.uri,
            "summary": artifact.summary,
            "redactionStatus": artifact.redaction_status,
            "redactedUri": artifact.redacted_uri,
            "expiresAt": artifact.expires_at.isoformat() if artifact.expires_at else None,
            "metadata": artifact.metadata_json,
            "createdAt": artifact.created_at.isoformat(),
        }

    def serialize_log(self, log: ExecutionLog) -> dict[str, object]:
        return {
            "id": str(log.id),
            "taskId": str(log.task_id) if log.task_id else None,
            "level": log.level,
            "message": log.message,
            "context": log.context,
            "createdAt": log.created_at.isoformat(),
        }

    def serialize_metric(self, metric: ExecutionMetric) -> dict[str, object]:
        return {
            "id": str(metric.id),
            "taskId": str(metric.task_id) if metric.task_id else None,
            "metricName": metric.metric_name,
            "metricValue": float(metric.metric_value),
            "metricUnit": metric.metric_unit,
            "thresholdValue": float(metric.threshold_value) if metric.threshold_value is not None else None,
            "baselineValue": float(metric.baseline_value) if metric.baseline_value is not None else None,
            "metadata": metric.metadata_json,
        }

    def serialize_finding(self, finding: Finding) -> dict[str, object]:
        return self._serialize_finding(
            finding,
            self._external_issue_link_for_finding(finding.id),
        )

    def _serialize_finding(
        self,
        finding: Finding,
        external_issue_link: ExternalIssueLink | None,
    ) -> dict[str, object]:
        self._validate_finding_contract(finding)
        return {
            "id": str(finding.id),
            "executionId": str(finding.execution_id),
            "taskId": str(finding.task_id) if finding.task_id else None,
            "domain": finding.domain.value,
            "source": finding.source.value,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "category": finding.category.value,
            "title": finding.title,
            "summary": finding.summary,
            "description": finding.description,
            "evidenceRef": str(finding.evidence_ref) if finding.evidence_ref else None,
            "confidence": float(finding.confidence) if finding.confidence is not None else None,
            "dedupeKey": finding.dedupe_key,
            "rawRef": finding.raw_ref,
            "location": finding.location,
            "evidence": finding.evidence,
            "comment": finding.comment,
            "metadata": finding.metadata_json,
            "externalIssueLink": self._serialize_external_issue_link(
                external_issue_link
            ),
        }

    def _external_issue_link_for_finding(
        self,
        finding_id: UUID,
    ) -> ExternalIssueLink | None:
        return self.db.scalar(
            select(ExternalIssueLink)
            .where(ExternalIssueLink.finding_id == finding_id)
            .order_by(
                ExternalIssueLink.updated_at.desc(),
                ExternalIssueLink.created_at.desc(),
            )
        )

    def _latest_external_issue_links(
        self,
        finding_ids: list[UUID],
    ) -> dict[UUID, ExternalIssueLink]:
        if not finding_ids:
            return {}
        rows = list(
            self.db.scalars(
                select(ExternalIssueLink)
                .where(ExternalIssueLink.finding_id.in_(finding_ids))
                .order_by(
                    ExternalIssueLink.updated_at.desc(),
                    ExternalIssueLink.created_at.desc(),
                )
            )
        )
        latest: dict[UUID, ExternalIssueLink] = {}
        for row in rows:
            latest.setdefault(row.finding_id, row)
        return latest

    def _serialize_external_issue_link_for_finding(
        self,
        finding_id: UUID,
    ) -> dict[str, object] | None:
        return self._serialize_external_issue_link(
            self._external_issue_link_for_finding(finding_id)
        )

    def _serialize_external_issue_link(
        self,
        link: ExternalIssueLink | None,
    ) -> dict[str, object] | None:
        if link is None:
            return None
        return {
            "id": str(link.id),
            "connectorName": link.connector_name,
            "externalIssueId": link.external_issue_id,
            "externalIssueKey": link.external_issue_key,
            "externalIssueUrl": link.external_issue_url,
            "externalStatus": link.external_status,
            "syncStatus": link.sync_status,
            "lastSyncedAt": link.last_synced_at.isoformat() if link.last_synced_at else None,
            "lastStatusSyncedAt": link.last_status_synced_at.isoformat() if link.last_status_synced_at else None,
            "evidenceRefs": link.evidence_refs,
            "replayRefs": link.replay_refs,
            "traceRefs": link.trace_refs,
            "auditRefs": link.audit_refs,
        }

    def _validate_finding_contract(self, finding: Finding) -> None:
        validate_contract(
            "finding",
            {
                "id": str(finding.id),
                "source": finding.source.value,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "title": finding.title,
                "summary": finding.summary,
                "evidence": finding.evidence,
                "location": finding.location,
                "confidence": float(finding.confidence) if finding.confidence is not None else None,
                "dedupeKey": finding.dedupe_key,
                "rawRef": finding.raw_ref,
            },
        )

    def serialize_visual_grounding_attempt(self, attempt: VisualGroundingAttempt) -> dict[str, object]:
        return {
            "id": str(attempt.id),
            "executionId": str(attempt.execution_id),
            "taskId": str(attempt.task_id) if attempt.task_id else None,
            "actionId": attempt.action_id,
            "actionType": attempt.action_type,
            "semanticAction": attempt.semantic_action,
            "locatorStrategy": attempt.locator_strategy,
            "fallbackPolicy": attempt.fallback_policy,
            "candidateLocators": attempt.candidate_locators,
            "chosenLocator": attempt.chosen_locator,
            "confidence": float(attempt.confidence) if attempt.confidence is not None else None,
            "threshold": float(attempt.threshold) if attempt.threshold is not None else None,
            "coordinateClickAllowed": attempt.coordinate_click_allowed,
            "riskLevel": attempt.risk_level.value,
            "guardrailDecision": attempt.guardrail_decision.value if attempt.guardrail_decision else None,
            "verificationStatus": attempt.verification_status,
            "verificationResult": attempt.verification_result,
            "artifactRefs": attempt.artifact_refs,
            "redactionStatus": attempt.redaction_status,
            "status": attempt.status,
            "errorMessage": attempt.error_message,
            "createdAt": attempt.created_at.isoformat(),
        }

    def serialize_verification_result(self, result: VerificationResult) -> dict[str, object]:
        return {
            "id": str(result.id),
            "executionId": str(result.execution_id),
            "taskId": str(result.task_id) if result.task_id else None,
            "visualAttemptId": str(result.visual_attempt_id) if result.visual_attempt_id else None,
            "verificationType": result.verification_type,
            "status": result.status,
            "confidence": float(result.confidence) if result.confidence is not None else None,
            "evidence": result.evidence,
            "artifactRefs": result.artifact_refs,
            "resultPayload": result.result_payload,
            "normalizedFindingId": str(result.normalized_finding_id) if result.normalized_finding_id else None,
            "createdAt": result.created_at.isoformat(),
        }

    def _create_tasks_for_plan(
        self,
        execution_id: UUID,
        plan_id: UUID,
        options: dict[str, object],
        *,
        execution_plan_id: UUID | None = None,
    ) -> None:
        if execution_plan_id is not None:
            execution_plan = self.db.get(ExecutionPlan, execution_plan_id)
            if execution_plan is None or execution_plan.test_plan_id != plan_id:
                raise ValueError("approved execution plan not found for test plan")
            if execution_plan.status != "approved":
                raise ValueError("execution plan is not approved")
            for index, task_spec in enumerate(execution_plan.tasks):
                domain = TestDomain(str(task_spec["domain"]))
                should_run = options.get(f"run{domain.value.capitalize()}", True)
                if not should_run:
                    continue
                self.db.add(
                    ExecutionTask(
                        id=uuid4(),
                        execution_id=execution_id,
                        domain=domain,
                        task_type=str(task_spec.get("taskType") or f"{domain.value}.generated"),
                        runner=str(task_spec["runner"]),
                        status=TaskStatus.QUEUED,
                        stage=ExecutionStage.PREPARE,
                        priority=index + 1,
                        config={
                            "assetId": task_spec.get("assetId"),
                            "objective": task_spec.get("objective"),
                            "executionPlanId": str(execution_plan_id),
                            "requirementRefs": task_spec.get("requirementRefs", []),
                            "requirementScope": task_spec.get("requirementScope", execution_plan.requirement_scope),
                        },
                        result_payload={"enabled": True},
                    )
                )
            return
        domains = list(self.db.scalars(select(TestPlanDomain).where(TestPlanDomain.plan_id == plan_id)))
        for domain in domains:
            should_run = options.get(f"run{domain.domain.value.capitalize()}", True)
            if not should_run:
                continue
            runner = self.runner_registry.default_runner_for_domain(domain.domain, domain.config)
            self.db.add(
                ExecutionTask(
                    id=uuid4(),
                    execution_id=execution_id,
                    domain=domain.domain,
                    task_type=f"{domain.domain.value}.regression",
                    runner=runner,
                    status=TaskStatus.QUEUED,
                    stage=ExecutionStage.PREPARE,
                    config=domain.config,
                    result_payload={"enabled": domain.enabled},
                )
            )

    def _prepare_tasks_for_run(self, execution_id: UUID) -> None:
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)))
        for task in tasks:
            task.status = TaskStatus.QUEUED
            task.stage = ExecutionStage.PREPARE
            task.error_message = None
            task.started_at = None
            task.ended_at = None

    def _prepare_tasks_for_retry(self, tasks: list[ExecutionTask]) -> None:
        for task in tasks:
            task.status = TaskStatus.QUEUED
            task.stage = ExecutionStage.PREPARE
            task.error_message = None
            task.started_at = None
            task.ended_at = None
            task.retry_count += 1

    def _run_tasks(self, execution_id: UUID, context: ServiceContext, task_ids: list[UUID] | None = None) -> None:
        execution = self._require_execution(execution_id)
        statement = select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)
        if task_ids:
            statement = statement.where(ExecutionTask.id.in_(task_ids))
        tasks = list(self.db.scalars(statement.order_by(ExecutionTask.created_at.asc())))
        for task in tasks:
            dispatch_input = {
                "domain": task.domain.value,
                "taskType": task.task_type,
                "runner": task.runner,
                "config": task.config,
                "parallelism": execution.options.get("parallelism", 1),
            }
            runner_model_response = self.model_tool.invoke_structured(
                trace_id=UUID(context.trace_id),
                execution_id=execution.id,
                role=ModelRole.PRIMARY,
                prompt=f"Prepare runner dispatch for {task.task_type}",
                payload={"agent": self.runner_agent.name, **dispatch_input},
                request_id=context.request_id,
            )
            runner_agent_result = self.runner_agent.run(dispatch_input)
            self.guardrail_engine.enforce(
                GuardrailContext(
                    trace_id=context.trace_id,
                    request_id=context.request_id,
                    actor_id=context.user.id,
                    actor_roles=context.user.roles,
                    resource_type="execution_task",
                    resource_id=str(task.id),
                    execution_id=execution.id,
                    payload={"agentName": self.runner_agent.name, "agentResult": runner_agent_result},
                ),
                [AgentOutputGuard()],
            )
            task.config = {
                **task.config,
                "timeoutSeconds": runner_agent_result.payload["timeoutSeconds"],
                "parallelism": runner_agent_result.payload["parallelism"],
                "dispatchPlan": runner_agent_result.payload,
            }
            self.db.add(
                AgentRun(
                    id=uuid4(),
                    execution_id=execution.id,
                    task_id=task.id,
                    trace_id=UUID(context.trace_id),
                    agent_name=self.runner_agent.name,
                    status=AgentRunStatus.COMPLETED,
                    input_payload=dispatch_input,
                    output_payload=runner_agent_result.to_contract(),
                    model_id=self._parse_model_id(runner_model_response),
                )
            )
            task.status = TaskStatus.RUNNING
            task.stage = ExecutionStage.EXECUTE
            task.started_at = datetime.now(timezone.utc)
            task.ended_at = None
            task.error_message = None
            self.db.flush()

            extension_point_id = "EXECUTE.manual_simulation" if task.config.get("manualSimulation") else "EXECUTE.automated_execution"
            extension_request = {
                "operation": "execute_task" if extension_point_id == "EXECUTE.automated_execution" else "propose_semantic_actions",
                "payload": {
                    "executionId": str(execution.id),
                    "taskId": str(task.id),
                    "runnerRef": task.runner,
                    "taskType": task.task_type,
                    "dispatchPlan": runner_agent_result.payload,
                },
            }
            extension_scope = {
                **self._skill_scope_for_execution(execution),
                "stage": "EXECUTE",
                "domain": task.domain.value,
                "requirementScope": task.config.get("requirementScope", {}),
            }
            extension_policy = {
                "workflow": "execution.run",
                "stage": "EXECUTE",
                "dispatchPlan": runner_agent_result.payload,
                "requirementScope": task.config.get("requirementScope", {}),
            }
            if extension_point_id == "EXECUTE.manual_simulation":
                def accept_manual_result(
                    runtime_result: object,
                    invocation: SkillInvocation,
                ) -> ExtensionInvocationCompletion:
                    if not isinstance(runtime_result, dict):
                        raise ValueError("manual simulation Skill runtime returned an incompatible result")
                    task.status = TaskStatus.COMPLETED
                    task.result_payload = {
                        **task.result_payload,
                        "skillInvocationId": str(invocation.id),
                        "manualSimulation": runtime_result["result"],
                    }
                    task.ended_at = datetime.now(timezone.utc)
                    return ExtensionInvocationCompletion(output_snapshot=runtime_result)

                try:
                    self.skill_service.invoke_extension(
                        extension_point_id=extension_point_id,
                        source_workflow="execution.run",
                        context=context,
                        execution_id=execution.id,
                        request=extension_request,
                        scope=extension_scope,
                        policy_snapshot=extension_policy,
                        capabilities={
                            "execute": lambda selected_context, _runtime_request: self.capability_gateway.propose_manual_simulation(
                                selected_context,
                                task,
                                runner_agent_result.payload,
                            ),
                        },
                        deadline_at=self._runner_deadline_at(task),
                        timeout_seconds=float(
                            task.config.get(
                                "timeoutSeconds",
                                self.capability_gateway.default_timeout_seconds(task.runner),
                            )
                        ),
                        cancellation_probe=lambda: (
                            execution.status == TaskStatus.CANCELLED
                            or task.status == TaskStatus.CANCELLED
                        ),
                        execution_mode="managed_task",
                        result_acceptor=accept_manual_result,
                    )
                except SkillInvocationExecutionError as exc:
                    if not self._apply_skill_invocation_terminal_to_task(task, exc):
                        raise
                self.db.flush()
                continue

            visual_grounding_blocked = False

            def execute_automated_task(selected_context, _runtime_request):
                nonlocal visual_grounding_blocked
                if self._task_requires_visual_grounding(task):
                    with traced_operation(
                        self.db,
                        trace_id=context.trace_id,
                        execution_id=execution.id,
                        root_span_name="execution.visual_grounding",
                        span_name="visual_grounding.resolve_dom",
                        service_name="execution-service",
                        attributes={"executionId": str(execution.id), "taskId": str(task.id)},
                    ) as span:
                        can_execute_runner = self._run_visual_grounding_for_task(
                            execution,
                            task,
                            context,
                            runner=self.capability_gateway.runner_for_visual_capture(task.runner),
                            trace_span_id=span.id,
                        )
                    if not can_execute_runner:
                        visual_grounding_blocked = True
                        task.status = TaskStatus.FAILED
                        task.error_message = "visual grounding blocked execution or requires approval-backed review"
                        task.ended_at = datetime.now(timezone.utc)
                        raise ValueError(task.error_message)
                request = self._build_runner_request(execution, task, context)
                return self.capability_gateway.run_execution_task(
                    selected_context,
                    request,
                )

            def accept_runner_result(
                runtime_result: object,
                invocation: SkillInvocation,
            ) -> ExtensionInvocationCompletion:
                if not isinstance(runtime_result, RunnerExecutionResult):
                    raise ValueError("automated execution Skill runtime returned an incompatible runner result")
                persisted_refs = self._persist_runner_result(task, runtime_result)
                task.result_payload = {
                    **task.result_payload,
                    "skillInvocationId": str(invocation.id),
                }
                task.ended_at = runtime_result.ended_at
                return ExtensionInvocationCompletion(
                    output_snapshot=self._runner_skill_result(
                        task,
                        runtime_result,
                        persisted_refs=persisted_refs,
                    ),
                    artifact_refs=persisted_refs["artifactRefs"],
                    tool_call_refs=[
                        {
                            "tool": runtime_result.runner_id,
                            "taskId": str(task.id),
                            "status": runtime_result.tool_status,
                        }
                    ],
                    status=(
                        "completed"
                        if runtime_result.status == "completed"
                        else "cancelled"
                        if runtime_result.status == "cancelled"
                        else "timed_out"
                        if runtime_result.timed_out
                        or runtime_result.tool_status == "timeout"
                        else "failed"
                    ),
                    error_message=runtime_result.error,
                )

            try:
                self.skill_service.invoke_extension(
                    extension_point_id=extension_point_id,
                    source_workflow="execution.run",
                    context=context,
                    execution_id=execution.id,
                    request=extension_request,
                    scope=extension_scope,
                    policy_snapshot=extension_policy,
                    capabilities={"execute": execute_automated_task},
                    deadline_at=self._runner_deadline_at(task),
                    timeout_seconds=float(
                        task.config.get(
                            "timeoutSeconds",
                            self.capability_gateway.default_timeout_seconds(task.runner),
                        )
                    ),
                    cancellation_probe=lambda: (
                        execution.status == TaskStatus.CANCELLED
                        or task.status == TaskStatus.CANCELLED
                    ),
                    execution_mode="managed_task",
                    result_acceptor=accept_runner_result,
                )
            except SkillInvocationExecutionError as exc:
                if self._apply_skill_invocation_terminal_to_task(task, exc):
                    self.db.flush()
                    continue
                raise
            except Exception:
                if visual_grounding_blocked:
                    self.db.flush()
                    continue
                raise

    def _apply_skill_invocation_terminal_to_task(
        self,
        task: ExecutionTask,
        error: SkillInvocationExecutionError,
    ) -> bool:
        if error.status not in {"cancelled", "timed_out"}:
            return False
        tool_status = "cancelled" if error.status == "cancelled" else "timeout"
        runner_status = "cancelled" if error.status == "cancelled" else "failed"
        task.status = (
            TaskStatus.CANCELLED
            if error.status == "cancelled"
            else TaskStatus.FAILED
        )
        task.error_message = redact_sensitive_text(str(error))
        task.ended_at = datetime.now(timezone.utc)
        existing_payload = dict(task.result_payload or {})
        task.result_payload = redact_sensitive_data(
            {
                **existing_payload,
                "runner": task.runner,
                "runnerStatus": runner_status,
                "toolStatus": tool_status,
                "retrySafety": runner_retry_safety(tool_status),
                "skillInvocationStatus": error.status,
                "reasonCode": error.reason_code,
                "executionMode": "managed_policy_pre_dispatch",
                "actualExecution": False,
            }
        )
        self._add_execution_log(
            task=task,
            level="warn",
            message="managed Skill policy stopped task result acceptance",
            context={
                "runner": task.runner,
                "toolStatus": tool_status,
                "reasonCode": error.reason_code,
                "actualExecution": False,
            },
        )
        return True

    def run_managed_admission_execution(
        self,
        execution_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        """Execute a P21 admission run through EXECUTE→OBSERVE→ANALYZE→NORMALIZE only."""

        execution = self._require_execution(execution_id)
        if execution.trigger_source != "pr_admission":
            raise ValueError("managed admission execution requires trigger_source=pr_admission")
        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution.id)
                .order_by(ExecutionTask.priority.asc(), ExecutionTask.id.asc())
            )
        )
        allowed_runners = {"sandbox-semgrep", "sandbox-python-unittest"}
        if not tasks or any(task.runner not in allowed_runners for task in tasks):
            raise ValueError("managed admission execution contains an unapproved runner recipe")
        forbidden_config = {"command", "args", "workdir", "env", "scriptPath", "binaryPath"}
        if any(forbidden_config.intersection(task.config) for task in tasks):
            raise ValueError("managed admission execution rejects arbitrary command configuration")

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=execution.id,
            root_span_name="admission.run",
            span_name="admission.prepare",
            service_name="orchestrator-service",
            attributes={"executionId": str(execution.id), "nonAuthoritative": True},
        ):
            execution.status = TaskStatus.RUNNING
            execution.stage = ExecutionStage.PREPARE
            execution.started_at = execution.started_at or datetime.now(timezone.utc)
            execution.ended_at = None
            self._prepare_tasks_for_run(execution.id)
            self.db.flush()

        execution.stage = ExecutionStage.EXECUTE
        self._admission_stage_preflight(execution, "EXECUTE", context)
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=execution.id,
            root_span_name="admission.execute",
            span_name="admission.execute.sandbox",
            service_name="execution-service",
            attributes={"executionId": str(execution.id), "gateDecisionCreated": False, "nonAuthoritative": True},
        ):
            self._run_tasks(execution.id, context=context)

        execution.stage = ExecutionStage.OBSERVE
        self._admission_stage_preflight(execution, "OBSERVE", context)
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=execution.id,
            root_span_name="admission.run",
            span_name="admission.observe",
            service_name="execution-service",
            attributes={"executionId": str(execution.id), "nonAuthoritative": True},
        ):
            self._record_execution_observations(execution.id)
        execution.stage = ExecutionStage.ANALYZE
        self._admission_stage_preflight(execution, "ANALYZE", context)
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=execution.id,
            root_span_name="admission.run",
            span_name="admission.analyze",
            service_name="agent-service",
            attributes={"executionId": str(execution.id), "nonAuthoritative": True},
        ):
            AnalysisService(self.db).analyze_execution(execution.id, context, reset=True)
        self._admission_stage_preflight(execution, "NORMALIZE", context)
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=execution.id,
            root_span_name="admission.run",
            span_name="admission.normalize",
            service_name="execution-service",
            attributes={"executionId": str(execution.id), "nonAuthoritative": True},
        ):
            self.normalize_execution(execution.id, context)
        execution.status = self._execution_terminal_status(execution.id)
        execution.ended_at = datetime.now(timezone.utc)
        execution.summary = self._build_execution_summary(execution.id)
        self.db.flush()
        return self.runtime_projection(execution.id)

    def evaluate_admission_shadow_gate(
        self,
        execution_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        """Evaluate Gate inputs without persisting a GateDecision or writing external CI state."""

        execution = self._require_execution(execution_id)
        if execution.trigger_source != "pr_admission":
            raise ValueError("Admission shadow Gate requires trigger_source=pr_admission")
        if self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id)) is not None:
            raise ValueError("Admission shadow Gate refuses an execution with an authoritative GateDecision")
        runtime = self.runtime_projection(execution.id)
        readiness = dict(runtime.get("readiness") or {})
        if not readiness.get("normalizeCompleted"):
            raise ValueError("ADMISSION_NORMALIZE_NOT_COMPLETED")
        gate_inputs = self._collect_gate_inputs(execution.id)
        assembled = self.gate_input_assembler.assemble(
            execution.id,
            findings=gate_inputs.findings,
            metrics=gate_inputs.metrics,
            approvals=gate_inputs.approvals,
            integrity_issues=gate_inputs.integrity_issues,
            trace_id=context.trace_id,
            request_id=context.request_id,
        )
        result = self._run_gate_evaluator(assembled)
        if result.writesGateDecision is not False:
            raise ValueError("Admission shadow Gate evaluator attempted an authoritative write")
        execution.stage = ExecutionStage.GATE
        self.db.flush()
        policy_hash = result.policy.snapshotHash or result.policy.policyVersionHash
        policy_identity = result.policy.policyVersionId or "builtin-default"
        return {
            "schemaVersion": "phase8.admission-shadow-gate.v1",
            "status": "completed",
            "decision": result.decision,
            "domainResults": [
                {
                    "domain": item.domain,
                    "applicability": item.applicability,
                    "availability": item.availability,
                    "decision": item.decision,
                    "reasonCodes": item.reasonCodes,
                    "completeness": item.completeness,
                    "confidence": item.confidence,
                }
                for item in result.domainResults
            ],
            "reasonCodes": result.reasonCodes,
            "completeness": result.completeness.model_dump(mode="json"),
            "confidence": result.confidence,
            "policyRef": {
                "type": "gate_policy_snapshot",
                "ref": f"gate-policy-snapshot://{policy_identity}",
                "contentHash": policy_hash,
                "redactionStatus": "redacted",
            },
            "inputFingerprint": result.input.fingerprint,
            "decisionSnapshotHash": result.decisionSnapshotHash,
            "evaluatorVersion": result.evaluatorVersion,
            "evaluatedAt": datetime.now(timezone.utc).isoformat(),
            "reasonCode": None,
            "nonAuthoritative": True,
            "gateDecisionCreated": False,
            "ciWriteback": False,
            "mergeBlocking": False,
        }

    def evaluate_admission_enforce_gate(
        self,
        execution_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        """Persist the one authoritative GateDecision for an approved P23 Enforce run."""

        execution = self._require_execution(execution_id)
        if execution.trigger_source != "pr_admission":
            raise ValueError("Admission Enforce Gate requires trigger_source=pr_admission")
        existing = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id))
        if existing is not None:
            return {
                "schemaVersion": "phase8.admission-enforce-gate.v1",
                "status": "completed",
                "decision": existing.overall.value,
                "reasonCodes": list(existing.reason_codes or []),
                "gateDecisionId": str(existing.id),
                "gateDecisionRef": f"gate-decision://{existing.id}",
                "inputFingerprint": existing.input_fingerprint,
                "decisionSnapshotHash": existing.decision_snapshot_hash,
                "evaluatorVersion": existing.evaluator_version,
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "nonAuthoritative": False,
                "gateDecisionCreated": True,
            }
        runtime = self.runtime_projection(execution.id)
        if not dict(runtime.get("readiness") or {}).get("normalizeCompleted"):
            raise ValueError("ADMISSION_NORMALIZE_NOT_COMPLETED")
        gate_inputs = self._collect_gate_inputs(execution.id)
        decision = self._evaluate_gate_from_inputs(execution.id, gate_inputs, context=context)
        self.db.add(decision)
        self.db.flush()
        gate_snapshot = self._persist_gate_input_snapshot(decision, gate_inputs, context)
        execution.stage = ExecutionStage.GATE
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            "admission.enforce.gate",
            "admission_execution",
            str(execution.id),
            context.request_id,
            context.trace_id,
            {
                "gateDecisionId": str(decision.id),
                "decision": decision.overall.value,
                "reasonCodes": list(decision.reason_codes or []),
                "inputFingerprint": decision.input_fingerprint,
                "decisionSnapshotHash": decision.decision_snapshot_hash,
                "evaluatorVersion": decision.evaluator_version,
                "authority": "execution-service",
                "ciConclusionMappedBy": "domain-service",
            },
            execution_id=execution.id,
        )
        gate_snapshot.audit_refs = [{"type": "audit_log", "id": str(audit.id), "action": audit.action}]
        self.db.flush()
        return {
            "schemaVersion": "phase8.admission-enforce-gate.v1",
            "status": "completed",
            "decision": decision.overall.value,
            "reasonCodes": list(decision.reason_codes or []),
            "gateDecisionId": str(decision.id),
            "gateDecisionRef": f"gate-decision://{decision.id}",
            "inputFingerprint": decision.input_fingerprint,
            "decisionSnapshotHash": decision.decision_snapshot_hash,
            "evaluatorVersion": decision.evaluator_version,
            "evaluatedAt": datetime.now(timezone.utc).isoformat(),
            "nonAuthoritative": False,
            "gateDecisionCreated": True,
        }

    def _admission_stage_preflight(
        self,
        execution: Execution,
        stage: str,
        context: ServiceContext,
    ) -> None:
        self.guardrail_engine.enforce(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="admission_run",
                resource_id=str(execution.options.get("admissionRunId") or execution.id),
                execution_id=execution.id,
                payload={
                    "stage": stage,
                    "mode": execution.options.get("admissionMode", "observe"),
                    "nonAuthoritative": bool(execution.options.get("nonAuthoritative", True)),
                },
                metadata={"action": f"admission.stage.{stage.lower()}"},
            ),
            [ActionGuard()],
        )

    def _task_requires_visual_grounding(self, task: ExecutionTask) -> bool:
        return bool(task.config.get("requiresVision") or task.config.get("requires_vision") or task.config.get("semanticAction"))

    def _run_visual_grounding_for_task(
        self,
        execution: Execution,
        task: ExecutionTask,
        context: ServiceContext,
        *,
        runner: object,
        trace_span_id: UUID | None,
    ) -> bool:
        semantic_action = self._semantic_action_from_task(task)
        policy = self._visual_policy_snapshot(task)
        risk_level = self._visual_risk_level(semantic_action, execution.environment)
        threshold = Decimal(str(policy["visionFallbackThreshold"]))
        review_threshold = Decimal(str(policy["reviewThreshold"]))
        redaction_result = self._visual_redaction_result(task, semantic_action, execution, context)

        if redaction_result.decision == GuardrailDecision.BLOCK:
            raw_finding = self._create_visual_grounding_raw_finding(
                task,
                semantic_action,
                [],
                confidence=Decimal("0"),
                severity=FindingSeverity.HIGH,
                summary="Visual artifact persistence was blocked because redaction/data guardrail did not pass.",
            )
            attempt = VisualGroundingAttempt(
                id=uuid4(),
                execution_id=execution.id,
                task_id=task.id,
                trace_id=UUID(context.trace_id),
                trace_span_id=trace_span_id,
                action_id=str(semantic_action["actionId"]),
                action_type=str(semantic_action["actionType"]),
                semantic_action=semantic_action,
                locator_strategy=dict(semantic_action.get("locatorStrategy", {})),
                fallback_policy=dict(semantic_action.get("fallbackPolicy", {})),
                candidate_locators=[],
                chosen_locator={},
                confidence=Decimal("0"),
                threshold=threshold,
                coordinate_click_allowed=False,
                risk_level=risk_level,
                guardrail_decision=GuardrailDecisionType.BLOCK,
                verification_status="blocked_by_guardrail",
                verification_result={
                    "verified": False,
                    "reviewRequired": False,
                    "confidence": 0,
                    "threshold": float(threshold),
                    "guardrailDecision": GuardrailDecision.BLOCK.value,
                    "reason": redaction_result.reason,
                },
                artifact_refs=[],
                redaction_status="blocked",
                status="blocked",
                error_message=redaction_result.reason,
            )
            self.db.add(attempt)
            self.db.flush()
            verification = self._record_visual_verification_result(
                execution,
                task,
                attempt,
                context,
                status="blocked_by_guardrail",
                confidence=Decimal("0"),
                evidence=[{"type": "semantic_target", "ref": str(semantic_action["actionId"])}],
                artifact_refs=[],
                payload=attempt.verification_result,
                finding_id=None,
            )
            self._link_visual_raw_to_verification(raw_finding, verification)
            self._attach_visual_result_to_task(task, semantic_action, attempt, approval_id=None)
            return False

        capture_artifacts = self._capture_visual_artifacts_for_task(execution, task, runner, context)
        artifact_refs = self._visual_artifact_refs(capture_artifacts)
        missing_types = self._missing_visual_artifact_types(capture_artifacts)
        if missing_types:
            raw_finding = self._create_visual_grounding_raw_finding(
                task,
                semantic_action,
                artifact_refs,
                confidence=Decimal("0"),
                severity=FindingSeverity.HIGH,
                summary=f"Visual grounding could not capture required artifacts: {', '.join(sorted(missing_types))}.",
            )
            attempt = VisualGroundingAttempt(
                id=uuid4(),
                execution_id=execution.id,
                task_id=task.id,
                trace_id=UUID(context.trace_id),
                trace_span_id=trace_span_id,
                action_id=str(semantic_action["actionId"]),
                action_type=str(semantic_action["actionType"]),
                semantic_action=semantic_action,
                locator_strategy=dict(semantic_action.get("locatorStrategy", {})),
                fallback_policy=dict(semantic_action.get("fallbackPolicy", {})),
                candidate_locators=[],
                chosen_locator={},
                confidence=Decimal("0"),
                threshold=threshold,
                coordinate_click_allowed=False,
                risk_level=risk_level,
                guardrail_decision=GuardrailDecisionType.BLOCK,
                verification_status="artifact_capture_failed",
                verification_result={
                    "verified": False,
                    "reviewRequired": False,
                    "confidence": 0,
                    "threshold": float(threshold),
                    "missingArtifactTypes": sorted(missing_types),
                },
                artifact_refs=artifact_refs,
                redaction_status="redacted",
                status="failed",
                error_message="visual artifact capture failed",
            )
            self.db.add(attempt)
            self.db.flush()
            verification = self._record_visual_verification_result(
                execution,
                task,
                attempt,
                context,
                status="artifact_capture_failed",
                confidence=Decimal("0"),
                evidence=[{"type": "semantic_target", "ref": str(semantic_action["actionId"])}],
                artifact_refs=artifact_refs,
                payload=attempt.verification_result,
                finding_id=None,
            )
            self._link_visual_raw_to_verification(raw_finding, verification)
            self._attach_visual_result_to_task(task, semantic_action, attempt, approval_id=None)
            return False
        vision_output = self._invoke_visual_resolver_if_needed(execution, task, context, semantic_action, artifact_refs)
        visual_result_artifacts = self._create_visual_result_artifacts(execution, task, semantic_action, vision_output)
        artifact_refs.extend(self._visual_artifact_refs(visual_result_artifacts))
        candidate_locators = self._visual_candidate_locators(semantic_action, vision_output=vision_output, artifact_refs=artifact_refs)
        chosen_locator, confidence, fusion_reason = self._fuse_locator_candidates(candidate_locators)
        coordinate_click_allowed, coordinate_click_denials = self._coordinate_click_evaluation(
            semantic_action,
            confidence=confidence,
            threshold=Decimal(str(policy["coordinateClickThreshold"])),
            has_verifiable_target=self._locator_has_verifiable_area(chosen_locator),
            has_evidence=bool(artifact_refs),
            risk_level=risk_level,
            guardrail_blocked=False,
        )
        verified = confidence >= threshold and bool(chosen_locator) and risk_level != RiskLevel.HIGH
        review_required = not verified and (confidence < review_threshold or risk_level == RiskLevel.HIGH)
        guardrail_result = self._record_visual_action_guardrail(
            execution,
            task,
            context,
            semantic_action,
            confidence=confidence,
            risk_level=risk_level,
            review_required=review_required,
            coordinate_click_allowed=coordinate_click_allowed,
            coordinate_click_denials=coordinate_click_denials,
        )
        guardrail_decision = GuardrailDecisionType(guardrail_result.decision.value)
        if guardrail_decision == GuardrailDecisionType.BLOCK:
            coordinate_click_allowed = False
            if "guardrail blocked visual action" not in coordinate_click_denials:
                coordinate_click_denials = [*coordinate_click_denials, "guardrail blocked visual action"]
        verified = verified and guardrail_decision != GuardrailDecisionType.BLOCK
        review_required = guardrail_decision != GuardrailDecisionType.BLOCK and (
            review_required or guardrail_decision == GuardrailDecisionType.WARN
        )
        if verified:
            verification_status = "passed"
        elif review_required:
            verification_status = "not_executed_review_required"
        elif guardrail_decision == GuardrailDecisionType.BLOCK:
            verification_status = "blocked_by_guardrail"
        else:
            verification_status = "failed"
        verification_payload = {
            "verified": verified,
            "reviewRequired": review_required,
            "confidence": float(confidence),
            "threshold": float(threshold),
            "reviewThreshold": float(review_threshold),
            "locatorKind": chosen_locator.get("kind"),
            "fusionReason": fusion_reason,
            "coordinateClickAllowed": coordinate_click_allowed,
            "coordinateClickDenials": coordinate_click_denials,
            "guardrailDecision": guardrail_decision.value,
            "riskLevel": risk_level.value,
            "riskSignals": vision_output.get("riskSignals", []),
        }

        visual_raw_finding: RawFindingRecord | None = None
        if not verified:
            visual_raw_finding = self._create_visual_grounding_raw_finding(
                task,
                semantic_action,
                artifact_refs,
                confidence=confidence,
                severity=FindingSeverity.HIGH if risk_level == RiskLevel.HIGH else FindingSeverity.MEDIUM,
                summary="Visual grounding could not verify a safe locator for the semantic action.",
            )

        attempt = VisualGroundingAttempt(
            id=uuid4(),
            execution_id=execution.id,
            task_id=task.id,
            trace_id=UUID(context.trace_id),
            trace_span_id=trace_span_id,
            action_id=str(semantic_action["actionId"]),
            action_type=str(semantic_action["actionType"]),
            semantic_action=semantic_action,
            locator_strategy=dict(semantic_action.get("locatorStrategy", {})),
            fallback_policy=dict(semantic_action.get("fallbackPolicy", {})),
            candidate_locators=candidate_locators,
            chosen_locator=chosen_locator,
            confidence=confidence,
            threshold=threshold,
            coordinate_click_allowed=coordinate_click_allowed,
            risk_level=risk_level,
            guardrail_decision=guardrail_decision,
            verification_status=verification_status,
            verification_result=verification_payload,
            artifact_refs=artifact_refs,
            redaction_status="redacted",
            status=self._visual_attempt_status(guardrail_decision, review_required, verified),
        )
        self.db.add(attempt)
        self.db.flush()
        approval_id = None
        if review_required:
            approval_id = self._request_visual_action_review(
                execution,
                attempt,
                semantic_action,
                verification_payload,
                context,
            )
            attempt.verification_result = {
                **attempt.verification_result,
                "approvalId": approval_id,
            }
            verification_payload = {
                **verification_payload,
                "approvalId": approval_id,
            }
        verification = self._record_visual_verification_result(
            execution,
            task,
            attempt,
            context,
            status=verification_status,
            confidence=confidence,
            evidence=[
                *self._artifact_refs_by_type(artifact_refs, {"dom_snapshot", "accessibility_tree", "screenshot"}),
                {"type": "semantic_target", "ref": str(semantic_action["actionId"])},
            ],
            artifact_refs=artifact_refs,
            payload=verification_payload,
            finding_id=None,
        )
        if visual_raw_finding is not None:
            self._link_visual_raw_to_verification(visual_raw_finding, verification)
        self._attach_visual_result_to_task(task, semantic_action, attempt, approval_id=approval_id)
        return verified

    def _semantic_action_from_task(self, task: ExecutionTask) -> dict[str, object]:
        configured = dict(task.config.get("semanticAction") or {})
        action_id = str(configured.get("actionId") or f"{task.id}:default")
        return {
            "schemaVersion": str(configured.get("schemaVersion") or "phase7.v1"),
            "actionId": action_id,
            "actionType": str(configured.get("actionType") or "assert_visible"),
            "semanticTarget": dict(configured.get("semanticTarget") or {}),
            "targetHints": dict(configured.get("targetHints") or {}),
            "locatorStrategy": dict(
                configured.get("locatorStrategy")
                or {"primary": "dom", "fallback": ["accessibility", "vision", "ocr"]}
            ),
            "fallbackPolicy": dict(configured.get("fallbackPolicy") or {"allowCoordinateClick": False}),
            "assertionIntent": dict(configured.get("assertionIntent") or {}),
            "riskLevel": str(configured.get("riskLevel") or RiskLevel.MEDIUM.value),
            "policyRefs": list(configured.get("policyRefs") or []),
        }

    def _visual_policy_snapshot(self, task: ExecutionTask) -> dict[str, float]:
        policy = (
            dict(task.config.get("policySnapshot", {}).get("visualGrounding", {}))
            if isinstance(task.config.get("policySnapshot"), dict)
            else {}
        )
        return {
            "visionFallbackThreshold": float(policy.get("visionFallbackThreshold", 0.75)),
            "coordinateClickThreshold": float(policy.get("coordinateClickThreshold", 0.90)),
            "reviewThreshold": float(policy.get("reviewThreshold", 0.70)),
        }

    def _visual_risk_level(self, semantic_action: dict[str, object], environment: str) -> RiskLevel:
        proposed = str(semantic_action.get("riskLevel") or RiskLevel.MEDIUM.value).lower()
        action_type = str(semantic_action.get("actionType") or "").lower()
        target = semantic_action.get("semanticTarget") if isinstance(semantic_action.get("semanticTarget"), dict) else {}
        intent = str(target.get("intent", "")).lower() if isinstance(target, dict) else ""
        high_risk_terms = {"delete", "payment", "purchase", "permission", "admin", "prod", "production"}
        if action_type == "fill" and environment == "production":
            return RiskLevel.HIGH
        if any(term in intent for term in high_risk_terms):
            return RiskLevel.HIGH
        if proposed in RiskLevel._value2member_map_:
            return RiskLevel(proposed)
        return RiskLevel.MEDIUM

    def _visual_redaction_result(
        self,
        task: ExecutionTask,
        semantic_action: dict[str, object],
        execution: Execution,
        context: ServiceContext,
    ) -> GuardrailResult:
        redaction_config = task.config.get("visualRedaction") if isinstance(task.config.get("visualRedaction"), dict) else {}
        blocked = bool(task.config.get("simulateVisualRedactionFailure") or redaction_config.get("status") == "blocked")
        if blocked:
            result = GuardrailResult(
                rule_id="data.visual_artifact_redaction",
                decision=GuardrailDecision.BLOCK,
                reason=str(redaction_config.get("reason") or "visual artifact redaction failed"),
                evidence=["visual artifacts were not persisted"],
                metadata={"actionId": semantic_action["actionId"], "redactionStatus": "blocked"},
            )
        else:
            result = GuardrailResult(
                rule_id="data.visual_artifact_redaction",
                decision=GuardrailDecision.ALLOW,
                reason="visual artifacts are redacted before persistence",
                evidence=["redacted artifact URIs only"],
                metadata={"actionId": semantic_action["actionId"], "redactionStatus": "redacted"},
            )
        self.guardrail_engine.record_result(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="visual_artifact",
                resource_id=str(task.id),
                execution_id=execution.id,
                payload={"actionId": semantic_action["actionId"], "taskId": str(task.id)},
                metadata={"action": "visual_grounding.redaction"},
            ),
            result,
        )
        return result

    def _visual_artifact_refs(self, artifacts: list[ExecutionArtifact]) -> list[dict[str, object]]:
        return [
            {
                "artifactId": str(artifact.id),
                "artifactType": artifact.artifact_type.value,
                "uri": artifact.redacted_uri or artifact.uri,
                "redactionStatus": artifact.redaction_status,
            }
            for artifact in artifacts
        ]

    def _capture_visual_artifacts_for_task(
        self,
        execution: Execution,
        task: ExecutionTask,
        runner: object,
        context: ServiceContext,
    ) -> list[ExecutionArtifact]:
        capture = getattr(runner, "capture_visual_artifacts", None)
        if not callable(capture):
            return []
        capture_result = capture(self._build_runner_request(execution, task, context))
        artifacts = self._persist_runner_artifact_refs(task, capture_result.artifact_refs)
        for log in capture_result.logs:
            self._add_execution_log(
                task=task,
                level=log.level,
                message=log.message,
                context={
                    "runner": capture_result.runner_id,
                    "toolStatus": capture_result.tool_status,
                    "visualGrounding": True,
                    **log.context,
                },
            )
        if capture_result.status != "completed":
            self._add_execution_log(
                task=task,
                level="error",
                message=capture_result.error or "visual artifact capture failed",
                context={
                    "runner": capture_result.runner_id,
                    "toolStatus": capture_result.tool_status,
                    "visualGrounding": True,
                },
            )
        self.db.flush()
        return artifacts

    def _missing_visual_artifact_types(self, artifacts: list[ExecutionArtifact]) -> set[str]:
        artifact_types = {artifact.artifact_type.value for artifact in artifacts}
        required = {
            ArtifactType.SCREENSHOT.value,
            ArtifactType.DOM_SNAPSHOT.value,
            ArtifactType.ACCESSIBILITY_TREE.value,
        }
        return required - artifact_types

    def _visual_candidate_locators(
        self,
        semantic_action: dict[str, object],
        *,
        vision_output: dict[str, object],
        artifact_refs: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        sources = self._ordered_locator_sources(semantic_action)
        candidates: list[dict[str, object]] = []
        for source in sources:
            if source == "dom":
                candidates.extend(self._dom_candidate_locators(semantic_action, artifact_refs))
            if source == "accessibility":
                candidates.extend(self._accessibility_candidate_locators(semantic_action, artifact_refs))
            if source == "vision":
                candidates.extend(self._vision_candidate_locators(semantic_action, vision_output, artifact_refs))
            if source == "ocr":
                candidates.extend(self._ocr_candidate_locators(semantic_action, vision_output, artifact_refs))
        return self._dedupe_candidate_locators(candidates)

    def _ordered_locator_sources(self, semantic_action: dict[str, object]) -> list[str]:
        strategy = semantic_action.get("locatorStrategy") if isinstance(semantic_action.get("locatorStrategy"), dict) else {}
        primary = str(strategy.get("primary") or "dom").lower()
        fallback = strategy.get("fallback") if isinstance(strategy.get("fallback"), list) else []
        ordered: list[str] = []
        for item in [primary, *fallback]:
            normalized = str(item).lower()
            if normalized in {"dom", "accessibility", "vision", "ocr"} and normalized not in ordered:
                ordered.append(normalized)
        return ordered or ["dom", "accessibility", "vision", "ocr"]

    def _dom_candidate_locators(
        self,
        semantic_action: dict[str, object],
        artifact_refs: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        hints = semantic_action.get("targetHints") if isinstance(semantic_action.get("targetHints"), dict) else {}
        if isinstance(hints, dict):
            selector = hints.get("selector") or hints.get("css") or hints.get("testId")
            if selector:
                value = f"[data-testid='{selector}']" if hints.get("testId") and not str(selector).startswith("[") else str(selector)
                return [
                    {
                        "kind": "dom_selector",
                        "selector": value,
                        "source": "dom",
                        "confidence": 0.92,
                        "evidence": self._artifact_refs_by_type(artifact_refs, {"dom_snapshot"}),
                    }
                ]
        return []

    def _accessibility_candidate_locators(
        self,
        semantic_action: dict[str, object],
        artifact_refs: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        target = semantic_action.get("semanticTarget") if isinstance(semantic_action.get("semanticTarget"), dict) else {}
        if isinstance(target, dict) and target.get("role") and target.get("name"):
            return [
                {
                    "kind": "accessibility_node",
                    "role": str(target["role"]),
                    "name": str(target["name"]),
                    "source": "accessibility",
                    "confidence": 0.82,
                    "evidence": self._artifact_refs_by_type(artifact_refs, {"accessibility_tree"}),
                }
            ]
        return []

    def _vision_candidate_locators(
        self,
        semantic_action: dict[str, object],
        vision_output: dict[str, object],
        artifact_refs: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        hints = semantic_action.get("targetHints") if isinstance(semantic_action.get("targetHints"), dict) else {}
        candidates: list[dict[str, object]] = []
        hint_box = hints.get("boundingBox") if isinstance(hints, dict) else None
        if isinstance(hint_box, dict):
            candidates.append(
                {
                    "kind": "bounding_box",
                    "source": "targetHints",
                    "boundingBox": hint_box,
                    "confidence": float(hint_box.get("confidence", 0.86) or 0.86),
                    "evidence": self._artifact_refs_by_type(artifact_refs, {"screenshot"}),
                }
            )
        output_confidence = self._bounded_confidence(vision_output.get("targetMatchConfidence", 0.0))
        bounding_boxes = (
            vision_output.get("boundingBoxes", [])
            if isinstance(vision_output.get("boundingBoxes"), list)
            else []
        )
        for index, box in enumerate(bounding_boxes):
            if not isinstance(box, dict):
                continue
            candidates.append(
                {
                    "kind": "bounding_box",
                    "source": "model_gateway:vision",
                    "boundingBox": box,
                    "confidence": self._bounded_confidence(box.get("confidence", output_confidence)),
                    "rank": index,
                    "evidence": self._artifact_refs_by_type(artifact_refs, {"screenshot", "vision_annotation"}),
                }
            )
        return candidates

    def _ocr_candidate_locators(
        self,
        semantic_action: dict[str, object],
        vision_output: dict[str, object],
        artifact_refs: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        hints = semantic_action.get("targetHints") if isinstance(semantic_action.get("targetHints"), dict) else {}
        target = semantic_action.get("semanticTarget") if isinstance(semantic_action.get("semanticTarget"), dict) else {}
        expected_text = hints.get("text") if isinstance(hints, dict) else None
        if expected_text is None and isinstance(target, dict):
            expected_text = target.get("name")
        candidates: list[dict[str, object]] = []
        if expected_text:
            candidates.append(
                {
                    "kind": "ocr_text",
                    "source": "targetHints" if isinstance(hints, dict) and hints.get("text") else "semanticTarget",
                    "text": str(expected_text),
                    "confidence": 0.66,
                    "evidence": self._artifact_refs_by_type(artifact_refs, {"screenshot", "ocr_output"}),
                }
            )
        for item in vision_output.get("recognizedText", []) if isinstance(vision_output.get("recognizedText"), list) else []:
            if not isinstance(item, dict) or not item.get("text"):
                continue
            candidates.append(
                {
                    "kind": "ocr_text",
                    "source": "model_gateway:ocr",
                    "text": str(item["text"]),
                    "boundingBox": item.get("boundingBox"),
                    "confidence": self._bounded_confidence(item.get("confidence", 0.64)),
                    "evidence": self._artifact_refs_by_type(artifact_refs, {"screenshot", "ocr_output"}),
                }
            )
        return candidates

    def _dedupe_candidate_locators(self, candidates: list[dict[str, object]]) -> list[dict[str, object]]:
        seen: set[str] = set()
        deduped: list[dict[str, object]] = []
        for candidate in candidates:
            key = json.dumps(
                {
                    "kind": candidate.get("kind"),
                    "selector": candidate.get("selector"),
                    "role": candidate.get("role"),
                    "name": candidate.get("name"),
                    "text": candidate.get("text"),
                    "boundingBox": candidate.get("boundingBox"),
                },
                sort_keys=True,
                ensure_ascii=True,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(candidate)
        return deduped

    def _fuse_locator_candidates(self, candidates: list[dict[str, object]]) -> tuple[dict[str, object], Decimal, str]:
        if not candidates:
            return {}, Decimal("0.40"), "no candidate locator met the semantic target"
        priority = {
            "dom_selector": 4,
            "accessibility_node": 3,
            "bounding_box": 2,
            "ocr_text": 1,
        }
        chosen = max(
            candidates,
            key=lambda item: (
                float(item.get("confidence", 0.0) or 0.0),
                priority.get(str(item.get("kind")), 0),
            ),
        )
        confidence = Decimal(str(round(self._bounded_confidence(chosen.get("confidence", 0.0)), 4)))
        return chosen, confidence, f"selected {chosen.get('kind')} from {chosen.get('source')}"

    def _visual_attempt_status(self, guardrail_decision: GuardrailDecisionType, review_required: bool, verified: bool) -> str:
        if guardrail_decision == GuardrailDecisionType.BLOCK:
            return "blocked"
        if review_required:
            return "review_required"
        if verified:
            return "completed"
        return "failed"

    def _locator_has_verifiable_area(self, locator: dict[str, object]) -> bool:
        kind = str(locator.get("kind") or "")
        return kind in {"bounding_box", "screen_coordinate"} and bool(locator.get("boundingBox") or locator.get("coordinate"))

    def _coordinate_click_evaluation(
        self,
        semantic_action: dict[str, object],
        *,
        confidence: Decimal,
        threshold: Decimal,
        has_verifiable_target: bool,
        has_evidence: bool,
        risk_level: RiskLevel,
        guardrail_blocked: bool,
    ) -> tuple[bool, list[str]]:
        fallback_policy = semantic_action.get("fallbackPolicy") if isinstance(semantic_action.get("fallbackPolicy"), dict) else {}
        denials: list[str] = []
        if fallback_policy.get("allowCoordinateClick") is not True:
            denials.append("allowCoordinateClick is false by default")
        if confidence < threshold:
            denials.append("confidence below coordinate click threshold")
        if not has_verifiable_target:
            denials.append("target area is not verifiable")
        if not has_evidence:
            denials.append("required visual evidence was not captured")
        if risk_level == RiskLevel.HIGH:
            denials.append("high risk actions cannot use coordinate click")
        if guardrail_blocked:
            denials.append("guardrail blocked visual action")
        return len(denials) == 0, denials

    def _record_visual_action_guardrail(
        self,
        execution: Execution,
        task: ExecutionTask,
        context: ServiceContext,
        semantic_action: dict[str, object],
        *,
        confidence: Decimal,
        risk_level: RiskLevel,
        review_required: bool,
        coordinate_click_allowed: bool,
        coordinate_click_denials: list[str],
    ) -> GuardrailResult:
        fallback_policy = semantic_action.get("fallbackPolicy") if isinstance(semantic_action.get("fallbackPolicy"), dict) else {}
        coordinate_click_requested = fallback_policy.get("allowCoordinateClick") is True
        decision = (
            GuardrailDecision.WARN
            if review_required or (coordinate_click_requested and coordinate_click_denials)
            else GuardrailDecision.ALLOW
        )
        if task.config.get("visualGuardrailDecision") == "block":
            decision = GuardrailDecision.BLOCK
        reason = "visual action can execute under configured policy"
        if decision == GuardrailDecision.WARN:
            reason = "visual action requires approval-backed review before execution"
        if decision == GuardrailDecision.BLOCK:
            reason = "visual action was blocked by configured guardrail"
        result = GuardrailResult(
            rule_id="action.visual_grounding_controlled",
            decision=decision,
            reason=reason,
            evidence=[
                f"confidence={float(confidence):.2f}",
                f"riskLevel={risk_level.value}",
                f"coordinateClickAllowed={coordinate_click_allowed}",
                *coordinate_click_denials,
            ],
            metadata={
                "actionId": semantic_action["actionId"],
                "actionType": semantic_action["actionType"],
                "reviewRequired": review_required,
            },
        )
        self.guardrail_engine.record_result(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="visual_action",
                resource_id=str(task.id),
                execution_id=execution.id,
                payload={
                    "actionId": semantic_action["actionId"],
                    "taskId": str(task.id),
                    "confidence": float(confidence),
                    "riskLevel": risk_level.value,
                },
                metadata={"action": "visual_grounding.action"},
            ),
            result,
        )
        return result

    def _invoke_visual_resolver_if_needed(
        self,
        execution: Execution,
        task: ExecutionTask,
        context: ServiceContext,
        semantic_action: dict[str, object],
        artifact_refs: list[dict[str, object]],
    ) -> dict[str, object]:
        if "vision" not in self._ordered_locator_sources(semantic_action):
            return self._empty_visual_output()
        selected_model = self.model_tool.select_model(RiskLevel.MEDIUM, ModelRole.PRIMARY)
        if selected_model is not None and not bool(selected_model.capabilities.get("vision")):
            output = self._empty_visual_output()
            output["riskSignals"] = [
                {
                    "type": "model_capability_missing",
                    "message": "selected PRIMARY model does not declare vision capability",
                }
            ]
            return output
        raw_response = self.model_tool.invoke_json(
            trace_id=UUID(context.trace_id),
            execution_id=execution.id,
            role=ModelRole.PRIMARY,
            prompt="Resolve visual target from redacted artifact refs. Return structured JSON.",
            payload={
                "input": {
                    "artifactRefs": artifact_refs,
                    "task": "resolve_visual_target",
                    "semanticTarget": semantic_action.get("semanticTarget", {}),
                    "targetHints": semantic_action.get("targetHints", {}),
                },
                "metadata": {
                    "source": "execution-service",
                    "taskId": str(task.id),
                    "actionId": semantic_action["actionId"],
                },
            },
            validator=VisualTargetResolveOutput,
            request_id=context.request_id,
        )
        return self._extract_visual_resolver_output(raw_response)

    def _extract_visual_resolver_output(self, raw_response: dict[str, object]) -> dict[str, object]:
        candidate = raw_response.get("output")
        if not isinstance(candidate, dict):
            return self._empty_visual_output()
        return {
            "boundingBoxes": self._safe_list(candidate.get("boundingBoxes")),
            "recognizedText": self._safe_list(candidate.get("recognizedText")),
            "targetMatchConfidence": self._bounded_confidence(candidate.get("targetMatchConfidence")),
            "reasoningEvidenceRefs": self._safe_list(candidate.get("reasoningEvidenceRefs")),
            "riskSignals": self._safe_list(candidate.get("riskSignals")),
        }

    def _empty_visual_output(self) -> dict[str, object]:
        return {
            "boundingBoxes": [],
            "recognizedText": [],
            "targetMatchConfidence": 0.0,
            "reasoningEvidenceRefs": [],
            "riskSignals": [],
        }

    def _safe_list(self, value: object) -> list[object]:
        return list(value) if isinstance(value, list) else []

    def _bounded_confidence(self, value: object) -> float:
        try:
            confidence = float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(confidence, 1.0))

    def _create_visual_result_artifacts(
        self,
        execution: Execution,
        task: ExecutionTask,
        semantic_action: dict[str, object],
        vision_output: dict[str, object],
    ) -> list[ExecutionArtifact]:
        artifacts: list[ExecutionArtifact] = []
        if vision_output.get("boundingBoxes") or vision_output.get("riskSignals") or vision_output.get("reasoningEvidenceRefs"):
            artifacts.append(
                self._create_visual_artifact(
                    execution,
                    task,
                    ArtifactType.VISION_ANNOTATION,
                    semantic_action["actionId"],
                    "vision-annotation.json",
                    "redacted vision resolver output for visual grounding",
                    {
                        "boundingBoxCount": len(vision_output.get("boundingBoxes", [])),
                        "riskSignals": vision_output.get("riskSignals", []),
                        "reasoningEvidenceRefs": vision_output.get("reasoningEvidenceRefs", []),
                    },
                )
            )
        if vision_output.get("recognizedText"):
            artifacts.append(
                self._create_visual_artifact(
                    execution,
                    task,
                    ArtifactType.OCR_OUTPUT,
                    semantic_action["actionId"],
                    "ocr-output.json",
                    "redacted OCR output for visual grounding",
                    {"recognizedTextCount": len(vision_output.get("recognizedText", []))},
                )
            )
        return artifacts

    def _artifact_refs_by_type(self, artifact_refs: list[dict[str, object]], artifact_types: set[str]) -> list[dict[str, object]]:
        return [
            {"type": item["artifactType"], "ref": item["artifactId"]}
            for item in artifact_refs
            if item.get("artifactType") in artifact_types
        ]

    def _request_visual_action_review(
        self,
        execution: Execution,
        attempt: VisualGroundingAttempt,
        semantic_action: dict[str, object],
        verification_payload: dict[str, object],
        context: ServiceContext,
    ) -> str:
        from agentic_qa.services.approval_service import ApprovalService

        response = ApprovalService(self.db).request_visual_action_review(
            execution.id,
            attempt.id,
            str(semantic_action["actionId"]),
            "low-confidence or high-risk visual action requires approval-backed review",
            {
                "semanticAction": semantic_action,
                "verification": verification_payload,
                "suggestOnly": True,
            },
            context,
            commit=False,
        )
        return str(response["approvalId"])

    def _record_visual_verification_result(
        self,
        execution: Execution,
        task: ExecutionTask,
        attempt: VisualGroundingAttempt,
        context: ServiceContext,
        *,
        status: str,
        confidence: Decimal,
        evidence: list[dict[str, object]],
        artifact_refs: list[dict[str, object]],
        payload: dict[str, object],
        finding_id: UUID | None,
    ) -> VerificationResult:
        verification = VerificationResult(
            id=uuid4(),
            execution_id=execution.id,
            task_id=task.id,
            visual_attempt_id=attempt.id,
            trace_id=UUID(context.trace_id),
            verification_type="visual_grounding",
            status=status,
            confidence=confidence,
            evidence=evidence,
            artifact_refs=artifact_refs,
            result_payload=payload,
            normalized_finding_id=finding_id,
        )
        self.db.add(verification)
        self.db.flush()
        return verification

    def _link_visual_raw_to_verification(
        self,
        raw_finding: RawFindingRecord,
        verification: VerificationResult,
    ) -> None:
        raw_finding.metadata_json = {
            **raw_finding.metadata_json,
            "visualVerificationResultId": str(verification.id),
        }

    def _attach_visual_result_to_task(
        self,
        task: ExecutionTask,
        semantic_action: dict[str, object],
        attempt: VisualGroundingAttempt,
        *,
        approval_id: str | None,
    ) -> None:
        task.result_payload = {
            **task.result_payload,
            "visualGrounding": {
                "actionId": semantic_action["actionId"],
                "status": attempt.status,
                "confidence": float(attempt.confidence) if attempt.confidence is not None else None,
                "verificationStatus": attempt.verification_status,
                "approvalId": approval_id,
            },
        }

    def _create_visual_artifact(
        self,
        execution: Execution,
        task: ExecutionTask,
        artifact_type: ArtifactType,
        action_id: str,
        filename: str,
        summary: str,
        metadata: dict[str, object],
    ) -> ExecutionArtifact:
        uri = f"s3://agentic-qa-artifacts/{execution.id}/{task.id}/visual/{action_id}/{filename}"
        artifact = ExecutionArtifact(
            id=uuid4(),
            execution_id=execution.id,
            task_id=task.id,
            artifact_type=artifact_type,
            uri=uri,
            summary=redact_sensitive_text(summary),
            redaction_status="redacted",
            redacted_uri=uri,
            metadata_json=redact_sensitive_data(
                {
                    "source": "visual_grounding",
                    "actionId": action_id,
                    **metadata,
                }
            ),
        )
        self.db.add(artifact)
        self.db.flush()
        return artifact

    def _create_visual_grounding_raw_finding(
        self,
        task: ExecutionTask,
        semantic_action: dict[str, object],
        artifact_refs: list[dict[str, object]],
        *,
        confidence: Decimal,
        severity: FindingSeverity,
        summary: str,
    ) -> RawFindingRecord:
        action_id = str(semantic_action["actionId"])
        artifact_ids_by_uri = {
            str(item["uri"]): str(item["artifactId"])
            for item in artifact_refs
            if item.get("uri") and item.get("artifactId")
        }
        raw_ref = (
            str(artifact_refs[0]["uri"])
            if artifact_refs
            else f"visual-grounding://executions/{task.execution_id}/tasks/{task.id}/actions/{action_id}"
        )
        raw_finding = RawFindingRecord(
            id=uuid4(),
            execution_id=task.execution_id,
            task_id=task.id,
            source=FindingSource.VISUAL_GROUNDING.value,
            severity=severity.value,
            category=FindingCategory.FUNCTIONAL_UI.value,
            title="Visual grounding verification failed",
            summary=summary,
            confidence=confidence,
            dedupe_key=f"visual_grounding:{task.id}:{action_id}",
            raw_ref=raw_ref,
            location=redact_sensitive_data(
                {
                    "kind": "semantic_target",
                    "target": semantic_action.get("semanticTarget", {}),
                }
            ),
            evidence=redact_sensitive_data(
                (
                    [{"type": "artifact_ref", "ref": str(item["uri"])} for item in artifact_refs]
                    if artifact_refs
                    else [{"type": "semantic_target", "ref": action_id}]
                )
            ),
            metadata_json=redact_sensitive_data(
                {
                    "actionId": action_id,
                    "semanticAction": semantic_action,
                    "domain": task.domain.value,
                    "artifactIdsByUri": artifact_ids_by_uri,
                    "sourceBoundary": "execution-service.visual-grounding",
                }
            ),
        )
        self.db.add(raw_finding)
        self.db.flush()
        return raw_finding

    def _build_runner_request(self, execution: Execution, task: ExecutionTask, context: ServiceContext) -> RunnerExecutionRequest:
        timeout_seconds = int(task.config.get("timeoutSeconds", self.capability_gateway.default_timeout_seconds(task.runner)))
        deadline_at = self._runner_deadline_at(task)
        if deadline_at is not None:
            remaining_seconds = (deadline_at - datetime.now(timezone.utc)).total_seconds()
            if remaining_seconds > 0:
                timeout_seconds = min(timeout_seconds, max(1, int(remaining_seconds + 0.999)))
        parallelism = int(task.config.get("parallelism", execution.options.get("parallelism", 1)))
        return RunnerExecutionRequest(
            task_id=task.id,
            execution_id=execution.id,
            domain=task.domain,
            task_type=task.task_type,
            runner_id=task.runner,
            timeout_seconds=timeout_seconds,
            parallelism=parallelism,
            config=task.config,
            envelope=self._build_execution_envelope(execution, task, context),
            deadline_at=deadline_at,
        )

    def _runner_deadline_at(self, task: ExecutionTask) -> datetime | None:
        raw_deadline = task.config.get("deadlineAt")
        if raw_deadline is None:
            return None
        if isinstance(raw_deadline, datetime):
            parsed = raw_deadline
        elif isinstance(raw_deadline, str):
            try:
                parsed = datetime.fromisoformat(raw_deadline.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("invalid runner deadlineAt; expected an ISO-8601 timestamp") from exc
        else:
            raise ValueError("invalid runner deadlineAt; expected an ISO-8601 timestamp")
        if parsed.tzinfo is None:
            raise ValueError("invalid runner deadlineAt; timezone is required")
        return parsed.astimezone(timezone.utc)

    def _build_execution_envelope(self, execution: Execution, task: ExecutionTask, context: ServiceContext) -> dict[str, object]:
        return {
            "runContext": {
                "runId": str(execution.id),
                "requestId": context.request_id,
                "traceId": str(context.trace_id),
                "triggeredBy": str(execution.triggered_by) if execution.triggered_by else None,
                "triggerSource": execution.trigger_source,
                "queueMode": self.settings.queue_mode,
                "attempt": task.retry_count + 1,
                "startedAt": execution.started_at.isoformat() if execution.started_at else None,
            },
            "executionContext": {
                "executionId": str(execution.id),
                "planId": str(execution.plan_id),
                "environment": execution.environment,
                "stage": ExecutionStage.EXECUTE.value,
                "domains": [task.domain.value],
                "options": execution.options,
            },
            "artifactRefs": [],
            "findingRefs": [],
            "policySnapshot": {
                "routingPolicyIds": list(task.config.get("routingPolicyIds", [])),
                "guardrailPolicyIds": list(task.config.get("guardrailPolicyIds", [])),
                "gatePolicyVersion": str(task.config.get("gatePolicyVersion", "v1")),
            },
            "memorySnapshot": {
                "memoryIds": list(task.config.get("memoryIds", [])),
                "namespaces": list(task.config.get("memoryNamespaces", [])),
                "summaryRef": task.config.get("memorySummaryRef"),
            },
        }

    def _artifact_refs_for_execution(self, execution_id: UUID) -> list[dict[str, object]]:
        rows = list(self.db.scalars(
            select(ExecutionArtifact)
            .where(ExecutionArtifact.execution_id == execution_id)
            .order_by(ExecutionArtifact.created_at.asc())
        ))
        return self._artifact_refs_from_rows(rows)

    def _artifact_refs_from_rows(self, rows: list[ExecutionArtifact]) -> list[dict[str, object]]:
        return [
            {
                "id": str(row.id),
                "taskId": str(row.task_id) if row.task_id else None,
                "artifactType": row.artifact_type.value,
                "uri": row.uri,
            }
            for row in rows
        ]

    def _finding_refs_for_execution(self, execution_id: UUID) -> list[dict[str, object]]:
        rows = list(self.db.scalars(
            select(Finding)
            .where(Finding.execution_id == execution_id)
            .order_by(Finding.created_at.asc())
        ))
        return self._finding_refs_from_rows(rows)

    def _finding_refs_from_rows(self, rows: list[Finding]) -> list[dict[str, object]]:
        return [
            {
                "id": str(row.id),
                "taskId": str(row.task_id) if row.task_id else None,
                "domain": row.domain.value,
                "dedupeKey": row.dedupe_key,
                "severity": row.severity.value,
            }
            for row in rows
        ]

    def _raw_metric_refs_from_rows(self, rows: list[ExecutionMetric]) -> list[dict[str, object]]:
        return [
            {
                "id": str(row.id),
                "taskId": str(row.task_id) if row.task_id else None,
                "metricName": row.metric_name,
                "metricUnit": row.metric_unit,
                "source": row.metadata_json.get("source"),
            }
            for row in rows
        ]

    def _raw_finding_refs_from_rows(self, rows: list[RawFindingRecord]) -> list[dict[str, object]]:
        return [
            {
                "id": str(row.id),
                "taskId": str(row.task_id) if row.task_id else None,
                "source": row.source,
                "rawRef": row.raw_ref,
                "dedupeKey": row.dedupe_key,
                "severity": row.severity,
                "normalizedFindingId": str(row.normalized_finding_id) if row.normalized_finding_id else None,
            }
            for row in rows
        ]

    def _policy_snapshot_from_tasks(self, tasks: list[ExecutionTask]) -> dict[str, object]:
        routing_policy_ids: list[str] = []
        guardrail_policy_ids: list[str] = []
        gate_policy_versions: list[str] = []
        for task in sorted(tasks, key=lambda item: (item.domain.value, str(item.id))):
            routing_policy_ids.extend(str(item) for item in task.config.get("routingPolicyIds", []))
            guardrail_policy_ids.extend(str(item) for item in task.config.get("guardrailPolicyIds", []))
            if task.config.get("gatePolicyVersion"):
                gate_policy_versions.append(str(task.config["gatePolicyVersion"]))
        gate_policy_version = (
            max(gate_policy_versions, key=self._gate_policy_version_sort_key)
            if gate_policy_versions
            else "v1"
        )
        return {
            "routingPolicyIds": list(dict.fromkeys(routing_policy_ids)),
            "guardrailPolicyIds": list(dict.fromkeys(guardrail_policy_ids)),
            "gatePolicyVersion": gate_policy_version,
        }

    @staticmethod
    def _gate_policy_version_sort_key(version: str) -> tuple[int, str]:
        suffix = version.rsplit("v", 1)[-1]
        numeric_prefix = suffix.split(".", 1)[0]
        return (int(numeric_prefix) if numeric_prefix.isdigit() else -1, version)

    def _runner_skill_result(
        self,
        task: ExecutionTask,
        result: RunnerExecutionResult,
        *,
        persisted_refs: dict[str, list[dict[str, object]]] | None = None,
    ) -> dict[str, object]:
        return {
            "result": {
                "runnerId": result.runner_id,
                "status": result.status,
                "toolStatus": result.tool_status,
                "exitCode": result.exit_code,
                "timedOut": result.timed_out,
                "durationMs": result.duration_ms,
                "artifactCount": len(result.artifact_refs),
                "metricCount": len(result.raw_metrics),
                "rawFindingCount": len(result.raw_findings),
            },
            "confidence": 1.0 if result.status == "completed" else 0.0,
            "evidence": [
                {"type": "execution_task", "ref": str(task.id)},
                {"type": "runner", "ref": result.runner_id},
            ],
            "artifactRefs": list((persisted_refs or {}).get("artifactRefs") or [
                {"type": artifact.artifact_type.value, "uri": artifact.uri, "summary": artifact.summary}
                for artifact in result.artifact_refs
            ]),
            "rawFindingRefs": list((persisted_refs or {}).get("rawFindingRefs") or [
                {
                    "source": finding.source,
                    "rawRef": finding.raw_ref,
                    "dedupeKey": finding.dedupe_key,
                    "severity": finding.severity,
                }
                for finding in result.raw_findings
            ]),
            "findingCandidates": [],
            "metadata": {
                **result.metadata,
                "domain": task.domain.value,
                "taskType": task.task_type,
                "executionMode": result.metadata.get("executionMode", "simulated"),
                "errors": [result.error] if result.error else [],
            },
        }

    def _persist_runner_result(self, task: ExecutionTask, result: RunnerExecutionResult) -> dict[str, list[dict[str, object]]]:
        attempt = task.retry_count + 1
        persisted_artifacts = self._persist_runner_artifact_refs(task, result.artifact_refs, result=result)
        artifact_ids_by_uri: dict[str, UUID] = {}
        artifact_uri_remap: dict[str, str] = {}
        for source, persisted in zip(result.artifact_refs, persisted_artifacts, strict=True):
            artifact_ids_by_uri[str(source.uri)] = persisted.id
            artifact_ids_by_uri[str(persisted.uri)] = persisted.id
            artifact_uri_remap[str(source.uri)] = str(persisted.uri)

        for log in result.logs:
            self._add_execution_log(
                task=task,
                level=log.level,
                message=log.message,
                context={
                    **log.context,
                    "runner": result.runner_id,
                    "toolStatus": result.tool_status,
                    "attempt": attempt,
                },
            )

        for metric in result.raw_metrics:
            self.db.add(
                ExecutionMetric(
                    id=uuid4(),
                    execution_id=task.execution_id,
                    task_id=task.id,
                    metric_name=redact_sensitive_text(metric.name),
                    metric_value=metric.value,
                    metric_unit=(
                        redact_sensitive_text(metric.unit)
                        if metric.unit is not None
                        else None
                    ),
                    threshold_value=metric.threshold_value,
                    baseline_value=metric.baseline_value,
                    metadata_json=redact_sensitive_data(
                        {
                            **metric.metadata,
                            "runner": result.runner_id,
                            "source": result.runner_id,
                            "domain": task.domain.value,
                            "toolStatus": result.tool_status,
                            "attempt": attempt,
                        }
                    ),
                )
            )

        for finding in result.raw_findings:
            persisted_raw_ref = artifact_uri_remap.get(str(finding.raw_ref), str(finding.raw_ref))
            persisted_evidence = self._remap_runner_artifact_refs(finding.evidence, artifact_uri_remap)
            self.db.add(
                RawFindingRecord(
                    id=uuid4(),
                    execution_id=task.execution_id,
                    task_id=task.id,
                    source=finding.source,
                    severity=finding.severity,
                    category=finding.category,
                    title=redact_sensitive_text(finding.title),
                    summary=redact_sensitive_text(finding.summary),
                    confidence=Decimal(str(finding.confidence)),
                    dedupe_key=finding.dedupe_key,
                    raw_ref=redact_sensitive_text(persisted_raw_ref),
                    location=redact_sensitive_data(finding.location),
                    evidence=redact_sensitive_data(persisted_evidence),
                    metadata_json=redact_sensitive_data(
                        {
                            **finding.metadata,
                            "toolStatus": result.tool_status,
                            "domain": task.domain.value,
                            "attempt": attempt,
                            "artifactIdsByUri": {
                                uri: str(artifact_id)
                                for uri, artifact_id in artifact_ids_by_uri.items()
                            },
                        }
                    ),
                )
            )

        task.status, task.error_message = self._derive_task_status(task, result)
        task.error_message = (
            redact_sensitive_text(task.error_message)
            if task.error_message is not None
            else None
        )
        existing_payload = dict(task.result_payload or {})
        attempts = list(existing_payload.get("attempts") or [])
        attempts.append(
            {
                "attempt": attempt,
                "runnerStatus": result.status,
                "toolStatus": result.tool_status,
                "retrySafety": runner_retry_safety(result.tool_status),
                "startedAt": result.started_at.isoformat(),
                "endedAt": result.ended_at.isoformat(),
                "artifactCount": len(result.artifact_refs),
                "metricCount": len(result.raw_metrics),
                "findingCount": len(result.raw_findings),
                "logCount": len(result.logs),
            }
        )
        task.result_payload = redact_sensitive_data(
            {
                **existing_payload,
                "runner": result.runner_id,
                "runnerStatus": result.status,
                "toolStatus": result.tool_status,
                "exitCode": result.exit_code,
                "durationMs": result.duration_ms,
                "artifactCount": len(result.artifact_refs),
                "metricCount": len(result.raw_metrics),
                "findingCount": len(result.raw_findings),
                "executionMode": result.metadata.get("executionMode", "simulated"),
                "actualExecution": bool(result.metadata.get("actualExecution", False)),
                "runnerMetadata": {
                    key: result.metadata.get(key)
                    for key in (
                        "validationClass",
                        "namedTool",
                        "namedToolExecuted",
                        "customCommandExecuted",
                        "binaryName",
                        "binaryPath",
                        "binaryVersion",
                        "pinnedVersion",
                        "pinnedBinary",
                        "vus",
                        "duration",
                        "rawMetricRef",
                        "thresholdExceeded",
                        "playwrightVersion",
                        "browserName",
                        "browserVersion",
                        "browserRevision",
                        "pinnedChromium",
                        "verificationStatus",
                        "actionCount",
                        "artifactCount",
                        "availability",
                        "sandboxed",
                        "sandboxEngine",
                        "networkMode",
                        "readOnlySource",
                        "readOnlyRootFilesystem",
                        "dockerSocketAccess",
                        "hostPathAccess",
                        "image",
                        "recipe",
                    )
                    if key in result.metadata
                },
                "attempt": attempt,
                "attempts": attempts,
                "retrySafety": runner_retry_safety(result.tool_status),
            }
        )
        return {
            "artifactRefs": self._artifact_refs_from_rows(persisted_artifacts),
            "rawFindingRefs": self._raw_finding_refs_from_rows(
                list(
                    self.db.scalars(
                        select(RawFindingRecord)
                        .where(
                            RawFindingRecord.execution_id == task.execution_id,
                            RawFindingRecord.task_id == task.id,
                        )
                        .order_by(RawFindingRecord.created_at.asc(), RawFindingRecord.id.asc())
                    )
                )
            ),
        }

    @classmethod
    def _remap_runner_artifact_refs(cls, value: object, uri_map: dict[str, str]) -> object:
        if isinstance(value, str):
            return uri_map.get(value, value)
        if isinstance(value, list):
            return [cls._remap_runner_artifact_refs(item, uri_map) for item in value]
        if isinstance(value, dict):
            return {key: cls._remap_runner_artifact_refs(item, uri_map) for key, item in value.items()}
        return value

    def _normalize_raw_findings(self, execution_id: UUID, task_ids: list[UUID] | None = None) -> None:
        statement = select(RawFindingRecord).where(
            RawFindingRecord.execution_id == execution_id,
            RawFindingRecord.normalized_finding_id.is_(None),
        )
        if task_ids:
            # Execution-level P15 Coverage Gaps intentionally have no task_id.
            # They are still part of every scoped NORMALIZE pass and must not
            # remain unresolved merely because a task retry narrowed the run.
            statement = statement.where(
                or_(
                    RawFindingRecord.task_id.in_(task_ids),
                    RawFindingRecord.task_id.is_(None),
                )
            )
        rows = list(self.db.scalars(statement.order_by(RawFindingRecord.created_at.asc())))
        prepared: list[
            tuple[
                RawFindingRecord,
                ExecutionTask | None,
                TestDomain,
                FindingSource,
                FindingCategory,
                FindingSeverity,
            ]
        ] = []
        dedupe_signatures: dict[str, tuple[object, ...]] = {}
        for raw in rows:
            task = self.db.get(ExecutionTask, raw.task_id) if raw.task_id else None
            domain = (
                task.domain
                if task
                else TestDomain(str(raw.metadata_json.get("domain", TestDomain.FUNCTIONAL.value)))
            )
            source = self._map_finding_source(raw.source)
            category = self._map_finding_category(raw.category)
            severity = self._map_finding_severity(raw.severity)
            self._validate_raw_finding_for_normalization(
                raw,
                source=source,
                category=category,
                severity=severity,
            )
            signature = self._raw_finding_dedupe_signature(
                raw,
                domain=domain,
                source=source,
                category=category,
                severity=severity,
            )
            prior_signature = dedupe_signatures.get(raw.dedupe_key)
            if prior_signature is not None and prior_signature != signature:
                raise ContractValidationError(
                    "finding",
                    [f"dedupe collision contains conflicting canonical fields: {raw.dedupe_key}"],
                )
            dedupe_signatures[raw.dedupe_key] = signature
            prepared.append((raw, task, domain, source, category, severity))

        for raw, task, domain, source, category, severity in prepared:
            existing = self.db.scalar(
                select(Finding).where(
                    Finding.execution_id == execution_id,
                    Finding.dedupe_key == raw.dedupe_key,
                )
            )
            if existing is not None:
                existing_signature = self._canonical_finding_dedupe_signature(existing)
                raw_signature = self._raw_finding_dedupe_signature(
                    raw,
                    domain=domain,
                    source=source,
                    category=category,
                    severity=severity,
                )
                if existing_signature != raw_signature:
                    raise ContractValidationError(
                        "finding",
                        [f"dedupe collision conflicts with persisted canonical finding: {raw.dedupe_key}"],
                    )
                raw.normalized_finding_id = existing.id
                self._link_normalized_raw_dependencies(raw, existing.id)
                continue
            artifact_ids_by_uri = {
                str(uri): UUID(str(artifact_id))
                for uri, artifact_id in dict(raw.metadata_json.get("artifactIdsByUri", {})).items()
            }
            evidence_ref = self._resolve_evidence_ref(raw.evidence, artifact_ids_by_uri) or artifact_ids_by_uri.get(raw.raw_ref)
            finding = Finding(
                id=uuid4(),
                execution_id=execution_id,
                task_id=raw.task_id,
                domain=domain,
                source=source,
                severity=severity,
                status=FindingStatus.OPEN,
                category=category,
                title=raw.title,
                summary=raw.summary,
                description=raw.summary,
                confidence=raw.confidence,
                dedupe_key=raw.dedupe_key,
                raw_ref=raw.raw_ref,
                location=raw.location,
                evidence=raw.evidence,
                evidence_ref=evidence_ref,
                comment=None,
                metadata_json={
                    **raw.metadata_json,
                    "rawFindingId": str(raw.id),
                    "normalizedAtStage": ExecutionStage.NORMALIZE.value,
                },
            )
            self.db.add(finding)
            self.db.flush()
            raw.normalized_finding_id = finding.id
            self._link_normalized_raw_dependencies(raw, finding.id)

    def _validate_raw_finding_for_normalization(
        self,
        raw: RawFindingRecord,
        *,
        source: FindingSource,
        category: FindingCategory,
        severity: FindingSeverity,
    ) -> None:
        validate_contract(
            "finding",
            {
                "id": str(raw.id),
                "source": source.value,
                "category": category.value,
                "severity": severity.value,
                "title": raw.title,
                "summary": raw.summary,
                "evidence": raw.evidence,
                "location": raw.location,
                "confidence": float(raw.confidence),
                "dedupeKey": raw.dedupe_key,
                "rawRef": raw.raw_ref,
            },
        )

    def _raw_finding_dedupe_signature(
        self,
        raw: RawFindingRecord,
        *,
        domain: TestDomain,
        source: FindingSource,
        category: FindingCategory,
        severity: FindingSeverity,
    ) -> tuple[object, ...]:
        return (
            domain.value,
            source.value,
            category.value,
            severity.value,
            raw.title,
            raw.summary,
            self._canonical_json(raw.location),
        )

    def _canonical_finding_dedupe_signature(self, finding: Finding) -> tuple[object, ...]:
        return (
            finding.domain.value,
            finding.source.value,
            finding.category.value,
            finding.severity.value,
            finding.title,
            finding.summary,
            self._canonical_json(finding.location),
        )

    def _link_normalized_raw_dependencies(self, raw: RawFindingRecord, finding_id: UUID) -> None:
        verification_result_id = raw.metadata_json.get("visualVerificationResultId")
        if not verification_result_id:
            return
        verification = self.db.get(VerificationResult, UUID(str(verification_result_id)))
        if verification is not None:
            verification.normalized_finding_id = finding_id

    def _persist_runner_artifact_refs(
        self,
        task: ExecutionTask,
        artifact_refs,
        *,
        result: RunnerExecutionResult | None = None,
    ) -> list[ExecutionArtifact]:
        persisted: list[ExecutionArtifact] = []
        for artifact in artifact_refs:
            attempt = task.retry_count + 1
            raw_metadata = dict(artifact.metadata)
            artifact_uri = str(artifact.uri)
            cleanup_root = raw_metadata.pop("cleanupRoot", None)
            service_managed_payload = bool(raw_metadata.pop("serviceManagedArtifactPayload", False))
            try:
                if service_managed_payload:
                    source_path = self._controlled_runner_artifact_path(artifact_uri, cleanup_root)
                    payload = source_path.read_bytes()
                    if len(payload) > 64 * 1024 * 1024:
                        raise ValueError("runner artifact exceeds the service persistence limit")
                    storage = self._artifact_storage_adapter().write_artifact(
                        namespace="execution-runner-artifacts",
                        artifact_id=str(task.id),
                        filename=source_path.name,
                        payload=payload,
                    )
                    artifact_uri = str(storage["storageRef"])
                    raw_metadata = {
                        **raw_metadata,
                        "contentHash": storage["contentHash"],
                        "byteSize": storage["byteSize"],
                        "storageAdapter": storage["adapter"],
                        "hostPathPersisted": False,
                    }
                metadata = redact_sensitive_data(
                    {
                        **raw_metadata,
                        "runner": result.runner_id if result else raw_metadata.get("source"),
                        "source": result.runner_id if result else raw_metadata.get("source"),
                        "toolStatus": result.tool_status if result else "ok",
                        "attempt": attempt,
                    }
                )
                redaction_status = str(
                    metadata.get("redactionStatus")
                    or ("redacted" if metadata.get("visualGrounding") else "not_required")
                )
                row = ExecutionArtifact(
                    id=uuid4(),
                    execution_id=task.execution_id,
                    task_id=task.id,
                    artifact_type=artifact.artifact_type,
                    uri=redact_sensitive_text(artifact_uri),
                    summary=(
                        redact_sensitive_text(artifact.summary)
                        if artifact.summary is not None
                        else None
                    ),
                    redaction_status=redaction_status,
                    redacted_uri=(
                        redact_sensitive_text(artifact_uri)
                        if redaction_status == "redacted"
                        else None
                    ),
                    metadata_json=metadata,
                )
                self.db.add(row)
                self.db.flush()
                persisted.append(row)
            finally:
                if service_managed_payload and cleanup_root:
                    shutil.rmtree(str(cleanup_root), ignore_errors=True)
        return persisted

    def _controlled_runner_artifact_path(self, artifact_uri: str, cleanup_root: object) -> Path:
        if not artifact_uri.startswith("file:") or not cleanup_root:
            raise ValueError("service-managed runner artifact must be a controlled file URI")
        from urllib.request import url2pathname
        from urllib.parse import urlparse

        parsed = urlparse(artifact_uri)
        if parsed.scheme != "file" or parsed.query or parsed.fragment:
            raise ValueError("service-managed runner artifact URI is invalid")
        source = Path(url2pathname(parsed.path)).resolve()
        root = Path(str(cleanup_root)).resolve()
        try:
            source.relative_to(root)
        except ValueError as exc:
            raise ValueError("runner artifact escaped its disposable output directory") from exc
        if not source.is_file() or source.is_symlink():
            raise ValueError("runner artifact is missing or unsafe")
        return source

    def _add_execution_log(
        self,
        *,
        task: ExecutionTask,
        level: str,
        message: str,
        context: dict[str, object],
    ) -> None:
        self.db.add(
            ExecutionLog(
                id=uuid4(),
                execution_id=task.execution_id,
                task_id=task.id,
                level=level,
                message=redact_sensitive_text(message),
                context=redact_sensitive_data(context),
            )
        )

    def _resolve_evidence_ref(self, evidence: list[dict[str, object]], artifact_ids_by_uri: dict[str, UUID]) -> UUID | None:
        for item in evidence:
            if item.get("type") != "artifact_ref":
                continue
            ref = item.get("ref")
            if isinstance(ref, str) and ref in artifact_ids_by_uri:
                return artifact_ids_by_uri[ref]
        return None

    def _derive_task_status(self, task: ExecutionTask, result: RunnerExecutionResult) -> tuple[TaskStatus, str | None]:
        if result.status == "queued":
            return TaskStatus.QUEUED, None
        if result.status == "running":
            return TaskStatus.RUNNING, None
        if result.status == "cancelled":
            return TaskStatus.CANCELLED, result.error or "runner cancelled"
        if result.status != "completed":
            return TaskStatus.FAILED, result.error or result.tool_status
        if task.domain == TestDomain.PERFORMANCE:
            return TaskStatus.COMPLETED, None
        blocking_findings = [
            finding for finding in result.raw_findings if self._map_finding_severity(finding.severity) in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}
        ]
        if blocking_findings:
            return TaskStatus.FAILED, blocking_findings[0].title
        if task.domain == TestDomain.SECURITY and result.raw_findings:
            return TaskStatus.FAILED, result.raw_findings[0].title
        return TaskStatus.COMPLETED, None

    def _map_finding_severity(self, severity: str) -> FindingSeverity:
        normalized = severity.lower()
        if normalized == "critical":
            return FindingSeverity.CRITICAL
        if normalized == "high":
            return FindingSeverity.HIGH
        if normalized == "medium":
            return FindingSeverity.MEDIUM
        if normalized == "info":
            return FindingSeverity.INFO
        return FindingSeverity.LOW

    def _map_finding_source(self, source: str) -> FindingSource:
        normalized = source.lower()
        if normalized in FindingSource._value2member_map_:
            return FindingSource(normalized)
        return FindingSource.CUSTOM

    def _map_finding_category(self, category: str) -> FindingCategory:
        normalized = category.lower()
        if normalized in FindingCategory._value2member_map_:
            return FindingCategory(normalized)
        return FindingCategory.OTHER

    def _record_execution_observations(self, execution_id: UUID, task_ids: list[UUID] | None = None) -> None:
        statement = select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)
        if task_ids:
            statement = statement.where(ExecutionTask.id.in_(task_ids))
        tasks = list(self.db.scalars(statement))
        for task in tasks:
            observation = "task completed" if task.status == TaskStatus.COMPLETED else "task requires follow-up"
            self._add_execution_log(
                task=task,
                level="info" if task.status == TaskStatus.COMPLETED else "warning",
                message=observation,
                context={
                    "domain": task.domain.value,
                    "stage": ExecutionStage.OBSERVE.value,
                },
            )

    def _build_execution_summary(self, execution_id: UUID) -> dict[str, str]:
        summary = {
            "functional": "queued",
            "performance": "queued",
            "security": "queued",
        }
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)))
        for task in tasks:
            summary[task.domain.value] = self._summary_status_for_task(task)
        return summary

    def _summary_status_for_task(self, task: ExecutionTask) -> str:
        if task.status == TaskStatus.COMPLETED:
            return "passed"
        if task.status == TaskStatus.FAILED:
            return "failed"
        if task.status == TaskStatus.RUNNING:
            return "running"
        if task.status == TaskStatus.CANCELLED:
            return "cancelled"
        return "queued"

    def _tasks_for_retry_scope(self, execution_id: UUID, scope: str) -> list[ExecutionTask]:
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)))
        if scope == "all":
            return tasks
        if scope == "failed_only":
            return [
                task
                for task in tasks
                if task.status == TaskStatus.FAILED
                and str(task.result_payload.get("retrySafety") or "not_applicable") != "unsafe"
            ]
        if scope in {domain.value for domain in TestDomain}:
            return [task for task in tasks if task.domain.value == scope]
        return []

    def _reset_retry_outputs(self, execution_id: UUID, task_ids: list[UUID]) -> None:
        # Attempt evidence is append-only. A retry may replace derived analysis
        # state, but it must never delete artifacts, logs, metrics, raw findings,
        # normalized finding lineage, visual attempts, or verification evidence
        # from an earlier attempt.
        self.db.execute(delete(TriageResult).where(TriageResult.execution_id == execution_id))
        self.db.execute(delete(HealingSuggestion).where(HealingSuggestion.execution_id == execution_id))
        self.db.execute(delete(GateDecision).where(GateDecision.execution_id == execution_id))
        self.db.flush()

    def _execution_terminal_status(self, execution_id: UUID) -> TaskStatus:
        tasks = list(
            self.db.scalars(
                select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)
            )
        )
        if any(task.status == TaskStatus.CANCELLED for task in tasks):
            return TaskStatus.CANCELLED
        protocol_failed = any(
            str(task.result_payload.get("runnerStatus") or "") == "failed"
            or str(task.result_payload.get("toolStatus") or "") == "partial"
            for task in tasks
        )
        if protocol_failed or any(
            task.status in {TaskStatus.QUEUED, TaskStatus.RUNNING}
            for task in tasks
        ):
            return TaskStatus.FAILED
        return TaskStatus.COMPLETED

    def _job_status_for_execution(self, status: TaskStatus) -> JobStatus:
        if status == TaskStatus.CANCELLED:
            return JobStatus.CANCELLED
        if status == TaskStatus.FAILED:
            return JobStatus.FAILED
        return JobStatus.COMPLETED

    def _execution_terminal_error(self, execution_id: UUID) -> str:
        tasks = list(
            self.db.scalars(
                select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)
            )
        )
        messages = [
            str(task.error_message)
            for task in tasks
            if task.error_message
            and (
                str(task.result_payload.get("runnerStatus") or "") != "completed"
                or task.status == TaskStatus.CANCELLED
            )
        ]
        return "; ".join(messages) or "execution did not reach a completed protocol state"

    def _fail_nonterminal_tasks(
        self,
        execution_id: UUID,
        error_message: str,
        *,
        ended_at: datetime,
    ) -> None:
        tasks = list(
            self.db.scalars(
                select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)
            )
        )
        for task in tasks:
            if task.status in {TaskStatus.QUEUED, TaskStatus.RUNNING}:
                task.status = TaskStatus.FAILED
                task.error_message = error_message
                task.ended_at = ended_at

    def _invalidate_gate_decision(self, execution_id: UUID) -> None:
        self.db.execute(delete(GateDecision).where(GateDecision.execution_id == execution_id))
        self.db.flush()

    def _retry_requires_approval(self, scope: str) -> bool:
        return scope == "all"

    def _heal_requires_approval(self, mode: str) -> bool:
        return mode == "generate_patch"

    def _serialize_gate_decision(self, execution_id: UUID, decision: GateDecision) -> dict[str, object]:
        return {
            "executionId": str(execution_id),
            "functional": decision.functional.value,
            "performance": decision.performance.value,
            "security": decision.security.value,
            "overall": decision.overall.value,
            "reasons": decision.reasons,
            "reasonCodes": list(decision.reason_codes or []),
            "matchedRules": list(decision.matched_rules or []),
            "completeness": dict(decision.completeness or {}),
            "confidence": float(decision.confidence),
            "policyVersionId": decision.policy_version_id,
            "policyVersionHash": decision.policy_version_hash,
            "policyBindingRef": decision.policy_binding_ref,
            "inputFingerprint": decision.input_fingerprint,
            "decisionSnapshotHash": decision.decision_snapshot_hash,
            "evaluatorVersion": decision.evaluator_version,
            "runtime": self.runtime_projection(execution_id),
        }

    def _evaluate_gate(self, execution_id: UUID) -> GateDecision:
        return self._evaluate_gate_from_inputs(execution_id, self._collect_gate_inputs(execution_id))

    def _collect_gate_inputs(self, execution_id: UUID) -> _GateInputs:
        raw_findings = list(
            self.db.scalars(
                select(RawFindingRecord)
                .where(RawFindingRecord.execution_id == execution_id)
                .order_by(RawFindingRecord.created_at.asc(), RawFindingRecord.id.asc())
            )
        )
        findings = tuple(
            self.db.scalars(
                select(Finding)
                .where(Finding.execution_id == execution_id)
                .order_by(Finding.created_at.asc(), Finding.id.asc())
            )
        )
        valid_findings: list[Finding] = []
        integrity_issues: list[dict[str, str]] = []
        for finding in findings:
            try:
                validate_contract(
                    "finding",
                    {
                        "id": str(finding.id),
                        "source": finding.source.value,
                        "category": finding.category.value,
                        "severity": finding.severity.value,
                        "title": finding.title,
                        "summary": finding.summary,
                        "evidence": finding.evidence,
                        "location": finding.location,
                        "confidence": (
                            float(finding.confidence)
                            if finding.confidence is not None
                            else 0.0
                        ),
                        "dedupeKey": finding.dedupe_key,
                        "rawRef": finding.raw_ref,
                    },
                )
            except ContractValidationError as exc:
                evidence_only_missing = bool(exc.issues) and all(
                    issue.startswith("evidence has fewer than minItems")
                    for issue in exc.issues
                )
                integrity_issues.append(
                    {
                        "type": "normalized_finding",
                        "id": str(finding.id),
                        "source": (
                            "NORMALIZE_evidence_missing"
                            if evidence_only_missing
                            else "NORMALIZE_contract_validation"
                        ),
                    }
                )
            else:
                valid_findings.append(finding)

        integrity_issues.extend(self._unresolved_skill_finding_output_refs(
            execution_id,
            raw_findings=raw_findings,
        ))
        metrics = tuple(
            self.db.scalars(
                select(ExecutionMetric)
                .where(ExecutionMetric.execution_id == execution_id)
                .order_by(ExecutionMetric.metric_name.asc(), ExecutionMetric.id.asc())
            )
        )
        finding_resource_ids = select(
            func.replace(cast(Finding.id, String), "-", "")
        ).where(Finding.execution_id == execution_id)
        approvals = tuple(
            self.db.scalars(
                select(Approval)
                .where(
                    or_(
                        (
                            (Approval.resource_type == "execution")
                            & (Approval.resource_id == str(execution_id))
                        ),
                        (
                            (Approval.resource_type == "finding")
                            & (
                                func.replace(Approval.resource_id, "-", "").in_(
                                    finding_resource_ids
                                )
                            )
                        ),
                    )
                )
                .order_by(Approval.created_at.asc(), Approval.id.asc())
            )
        )
        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution_id)
                .order_by(ExecutionTask.id.asc())
            )
        )
        return _GateInputs(
            findings=tuple(valid_findings),
            metrics=metrics,
            approvals=approvals,
            policy_snapshot=self._policy_snapshot_from_tasks(tasks),
            integrity_issues=tuple(integrity_issues),
        )

    def _unresolved_skill_finding_output_refs(
        self,
        execution_id: UUID,
        *,
        raw_findings: list[RawFindingRecord],
    ) -> list[dict[str, str]]:
        raw_by_id = {str(raw.id): raw for raw in raw_findings}
        raw_by_ref = {raw.raw_ref: raw for raw in raw_findings}
        raw_by_dedupe = {raw.dedupe_key: raw for raw in raw_findings}
        invocations = list(
            self.db.scalars(
                select(SkillInvocation)
                .where(SkillInvocation.execution_id == execution_id)
                .order_by(SkillInvocation.created_at.asc(), SkillInvocation.id.asc())
            )
        )
        unresolved_outputs: list[str] = []
        for invocation in invocations:
            output = dict(invocation.output_snapshot or {})
            if "findingRefs" in output:
                unresolved_outputs.append(f"{invocation.id}:findingRefs")
            for item in output.get("rawFindingRefs", []) or []:
                if not isinstance(item, dict):
                    unresolved_outputs.append(f"{invocation.id}:rawFindingRefs")
                    continue
                raw = (
                    raw_by_id.get(str(item.get("id")))
                    or raw_by_ref.get(str(item.get("rawRef")))
                    or raw_by_dedupe.get(str(item.get("dedupeKey")))
                )
                if raw is None or raw.normalized_finding_id is None:
                    unresolved_outputs.append(f"{invocation.id}:rawFindingRefs")
            for candidate in output.get("findingCandidates", []) or []:
                if not isinstance(candidate, dict):
                    unresolved_outputs.append(f"{invocation.id}:findingCandidates")
                    continue
                raw = (
                    raw_by_ref.get(str(candidate.get("rawRef")))
                    or raw_by_dedupe.get(str(candidate.get("dedupeKey")))
                )
                if raw is None or raw.normalized_finding_id is None:
                    unresolved_outputs.append(f"{invocation.id}:findingCandidates")
        return [
            {"type": "skill_output", "id": item, "source": "skill_invocation"}
            for item in sorted(set(unresolved_outputs))
        ]

    def _evaluate_gate_from_inputs(
        self,
        execution_id: UUID,
        gate_inputs: _GateInputs,
        *,
        context: ServiceContext | None = None,
    ) -> GateDecision:
        trace_id = context.trace_id if context is not None else "00000000-0000-0000-0000-000000000000"
        request_id = context.request_id if context is not None else f"internal-gate-evaluation:{execution_id}"
        assembled = self.gate_input_assembler.assemble(
            execution_id,
            findings=gate_inputs.findings,
            metrics=gate_inputs.metrics,
            approvals=gate_inputs.approvals,
            integrity_issues=gate_inputs.integrity_issues,
            trace_id=trace_id,
            request_id=request_id,
        )
        result = self._run_gate_evaluator(assembled)
        domain_results = {item.domain: item for item in result.domainResults}
        decision = GateDecision(
            id=uuid4(),
            execution_id=execution_id,
            functional=GateResult(domain_results["functional"].decision),
            performance=GateResult(domain_results["performance"].decision),
            security=GateResult(domain_results["security"].decision),
            overall=GateResult(result.decision),
            reasons=list(result.reasons),
            decided_by="system",
            policy_version_id=result.policy.policyVersionId,
            policy_version_hash=result.policy.policyVersionHash,
            policy_binding_ref=result.policy.bindingRef,
            reason_codes=list(result.reasonCodes),
            matched_rules=list(result.matchedRules),
            completeness=result.completeness.model_dump(mode="json"),
            confidence=Decimal(str(result.confidence)),
            input_fingerprint=result.input.fingerprint,
            decision_snapshot=result.decisionSnapshot,
            decision_snapshot_hash=result.decisionSnapshotHash,
            evaluator_version=result.evaluatorVersion,
        )
        setattr(decision, "_gate_input_contract", assembled)
        return decision

    def _run_gate_evaluator(self, assembled: GateInputContract) -> GateResultContract:
        """Keep authoritative and Shadow evaluation on the single governed evaluator boundary."""

        return self.gate_evaluator.evaluate(assembled)

    def _persist_gate_input_snapshot(
        self,
        decision: GateDecision,
        gate_inputs: _GateInputs,
        context: ServiceContext,
    ) -> GateInputSnapshot:
        existing = self.db.scalar(
            select(GateInputSnapshot).where(GateInputSnapshot.gate_decision_id == decision.id)
        )
        if existing is not None:
            return existing
        assembled = getattr(decision, "_gate_input_contract", None)
        if not isinstance(assembled, GateInputContract):
            assembled = self.gate_input_assembler.assemble(
                decision.execution_id,
                findings=gate_inputs.findings,
                metrics=gate_inputs.metrics,
                approvals=gate_inputs.approvals,
                integrity_issues=gate_inputs.integrity_issues,
                trace_id=context.trace_id,
                request_id=context.request_id,
            )
        gate_input_snapshot = assembled.model_dump(mode="json")
        normalized_findings = gate_input_snapshot["normalizedFindings"]
        metrics = gate_input_snapshot["metrics"]
        approval_state = [
            {
                "type": "approval",
                "id": str(approval["id"]),
                "status": str(approval["status"]),
            }
            for approval in gate_input_snapshot["approvalState"]
        ]
        encoded_gate_input = self._canonical_json(gate_input_snapshot).encode("utf-8")
        gate_hash = "sha256:" + hashlib.sha256(encoded_gate_input).hexdigest()
        policy_snapshot = assembled.policySnapshot or {}
        policy_hash = assembled.policySnapshotHash or self._canonical_hash(policy_snapshot)
        gate_input_ref = (
            f"gate-input://{decision.execution_id}/"
            f"{str(decision.input_fingerprint or gate_hash).removeprefix('sha256:')}"
        )
        stored_gate_input: dict[str, object] = gate_input_snapshot
        external_storage_ref: str | None = None
        snapshot_id = uuid4()
        if len(encoded_gate_input) > self.GATE_INPUT_INLINE_MAX_BYTES:
            storage_adapter = self._artifact_storage_adapter()
            storage = storage_adapter.write_artifact(
                namespace="gate-input-snapshots",
                artifact_id=str(snapshot_id),
                filename="snapshot.json",
                payload=encoded_gate_input,
            )
            if storage["contentHash"] != gate_hash:
                storage_adapter.delete_artifact(str(storage["storageRef"]))
                raise ValueError("Gate input snapshot storage hash mismatch")
            storage_byte_size = storage.get("byteSize")
            if not isinstance(storage_byte_size, int):
                storage_adapter.delete_artifact(str(storage["storageRef"]))
                raise ValueError("Gate input snapshot storage byte size is invalid")
            external_storage_ref = str(storage["storageRef"])
            stored_gate_input = {
                "schemaVersion": "phase8.gate-input-snapshot-manifest.v1",
                "gateDecisionId": str(decision.id),
                "executionId": str(decision.execution_id),
                "storageMode": "external",
                "storageRef": external_storage_ref,
                "contentHash": gate_hash,
                "byteSize": storage_byte_size,
                "storageAdapter": str(storage["adapter"]),
                "contentSchemaVersion": gate_input_snapshot["schemaVersion"],
                "counts": {
                    "normalizedFindings": len(normalized_findings),
                    "metrics": len(metrics),
                    "approvalState": len(approval_state),
                    "domainInputStates": len(gate_input_snapshot["domainInputStates"]),
                },
            }
        snapshot = GateInputSnapshot(
            id=snapshot_id,
            gate_decision_id=decision.id,
            execution_id=decision.execution_id,
            gate_input_snapshot_ref=gate_input_ref,
            gate_input_snapshot_hash=gate_hash,
            gate_input_snapshot=stored_gate_input,
            policy_snapshot_ref=f"policy://gate/{decision.id}/{policy_hash.removeprefix('sha256:')}",
            policy_snapshot_hash=policy_hash,
            policy_snapshot=policy_snapshot,
            approval_refs=approval_state,
            trace_refs=[context.trace_id],
            audit_refs=[],
        )
        try:
            self.db.add(snapshot)
            self.db.flush()
        except Exception:
            if external_storage_ref is not None:
                self._artifact_storage_adapter().delete_artifact(external_storage_ref)
            raise
        return snapshot

    def resolve_gate_input_snapshot(
        self,
        snapshot: GateInputSnapshot,
    ) -> dict[str, object]:
        stored = dict(snapshot.gate_input_snapshot or {})
        if stored.get("storageMode") != "external":
            return stored
        storage_ref = str(stored.get("storageRef") or "")
        payload = self._artifact_storage_adapter().read_artifact(storage_ref)
        if len(payload) != int(stored.get("byteSize") or -1):
            raise ValueError("Gate input snapshot storage byte size mismatch")
        content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
        if (
            content_hash != snapshot.gate_input_snapshot_hash
            or content_hash != stored.get("contentHash")
        ):
            raise ValueError("Gate input snapshot storage hash mismatch")
        resolved = json.loads(payload.decode("utf-8"))
        if not isinstance(resolved, dict):
            raise ValueError("Gate input snapshot storage payload must be an object")
        return resolved

    def _artifact_storage_adapter(self) -> ArtifactStorageAdapter:
        if self._artifact_storage is None:
            self._artifact_storage = artifact_storage_adapter()
        return self._artifact_storage

    @staticmethod
    def _canonical_json(payload: object) -> str:
        return canonical_json(payload)

    @classmethod
    def _canonical_hash(cls, payload: object) -> str:
        return canonical_hash(payload)

    def _require_plan(self, plan_id: UUID) -> TestPlan:
        plan = self.db.get(TestPlan, plan_id)
        if plan is None:
            raise ValueError("test plan not found")
        return plan

    def _require_execution(self, execution_id: UUID) -> Execution:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise ValueError("execution not found")
        return execution

    def _skill_scope_for_execution(self, execution: Execution) -> dict[str, object]:
        """Return the authoritative project/environment identity for Skill governance."""

        plan = self._require_plan(execution.plan_id)
        return {
            "projectId": str(plan.project_id),
            "environmentId": str(plan.environment_id) if plan.environment_id else None,
            # Preserve the existing human-readable binding discriminator while
            # authorization relies on the server-derived environmentId.
            "environment": execution.environment,
        }

    def authorize_execution_scope(
        self,
        execution_id: UUID,
        context: ServiceContext,
        *,
        write: bool = False,
    ) -> None:
        execution = self._require_execution(execution_id)
        self._authorize_plan_scope(self._require_plan(execution.plan_id), context, write=write)

    def authorize_task_scope(
        self,
        task_id: UUID,
        context: ServiceContext,
        *,
        write: bool = False,
    ) -> None:
        task = self._require_task(task_id)
        self.authorize_execution_scope(task.execution_id, context, write=write)

    def authorize_finding_scope(
        self,
        finding_id: UUID,
        context: ServiceContext,
        *,
        write: bool = False,
    ) -> None:
        finding = self._require_finding(finding_id)
        self.authorize_execution_scope(finding.execution_id, context, write=write)

    def _authorize_plan_scope(
        self,
        plan: TestPlan,
        context: ServiceContext,
        *,
        write: bool = False,
    ) -> None:
        if plan.project_id is None:
            if {"admin", "system"}.intersection(context.user.roles):
                return
            raise ValueError("execution not found")
        try:
            ScopeAuthorizationService(self.db).resolve_project(
                plan.project_id,
                context,
                environment_id=plan.environment_id,
                write=write,
            )
        except ScopeAuthorizationError as exc:
            raise ValueError("execution not found") from exc

    def _require_job(self, job_id: UUID) -> Job:
        job = self.db.get(Job, job_id)
        if job is None:
            raise ValueError("job not found")
        return job

    def _recover_committed_job(
        self,
        job_id: UUID,
        execution_id: UUID,
    ) -> dict[str, object] | None:
        """Resolve an ambiguous commit without rewriting a committed success.

        A database connection can fail after the server accepted COMMIT.  The
        caller sees an exception, but a fresh read is authoritative: a matching
        completed job is returned idempotently instead of being overwritten as
        failed by compensation intended for a pre-commit failure.
        """

        job = self._require_job(job_id)
        if (
            job.status != JobStatus.COMPLETED
            or job.result_ref != str(execution_id)
        ):
            return None
        execution = self._require_execution(execution_id)
        return {
            "jobId": str(job.id),
            "executionId": str(execution.id),
            "status": job.status.value,
            "deduplicated": True,
            "recoveredFromAmbiguousCommit": True,
        }

    def _record_queue_dispatch_failure(
        self,
        execution_id: UUID,
        job_id: UUID,
        error: Exception,
        context: ServiceContext,
    ) -> None:
        """Persist a terminal, auditable state when the broker rejects dispatch."""

        self.db.rollback()
        execution = self._require_execution(execution_id)
        job = self._require_job(job_id)
        ended_at = datetime.now(timezone.utc)
        error_message = f"queue dispatch failed: {error}"
        execution.status = TaskStatus.FAILED
        execution.ended_at = ended_at
        job.status = JobStatus.FAILED
        job.progress = 100
        job.error_message = error_message
        job.ended_at = ended_at
        approval_id = job.payload.get("approvalId")
        self._fail_nonterminal_tasks(
            execution.id,
            error_message,
            ended_at=ended_at,
        )
        write_audit_log(
            self.db,
            str(context.user.id),
            "execution.queue_dispatch_failed",
            "execution",
            str(execution.id),
            context.request_id,
            context.trace_id,
            {
                "jobId": str(job.id),
                "jobType": job.job_type,
                "approvalId": (
                    str(approval_id)
                    if approval_id is not None
                    else None
                ),
                "retryAutomatically": False,
            },
        )
        self.db.commit()

    def _require_task(self, task_id: UUID) -> ExecutionTask:
        task = self.db.get(ExecutionTask, task_id)
        if task is None:
            raise ValueError("task not found")
        return task

    def _require_finding(self, finding_id: UUID) -> Finding:
        finding = self.db.get(Finding, finding_id)
        if finding is None:
            raise ValueError("finding not found")
        return finding

    def _max_finding_severity(self, findings: list[Finding]) -> str:
        order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        if not findings:
            return "info"
        return min(findings, key=lambda finding: order.get(finding.severity, 99)).severity.value

    def _regression_priority(self, severity: str, reason: str) -> str:
        if severity in {"critical", "high"} or reason == "failed task":
            return "high"
        if severity == "medium":
            return "medium"
        return "low"

    def _parse_model_id(self, model_response: dict[str, object] | None) -> UUID | None:
        if not model_response:
            return None
        model_id = model_response.get("modelId")
        if not model_id:
            return None
        return UUID(str(model_id))

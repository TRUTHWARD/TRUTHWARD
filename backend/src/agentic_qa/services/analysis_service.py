# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agentic_qa.agents.base import AgentResult, BaseAgent
from agentic_qa.agents.judge import JudgeAgent
from agentic_qa.agents.healer import HealerAgent
from agentic_qa.agents.perf import PerfAgent
from agentic_qa.agents.security import SecurityAgent
from agentic_qa.agents.triage import TriageAgent
from agentic_qa.domain.enums import AgentRunStatus, JobStatus, TaskStatus, TriageCategory
from agentic_qa.domain.models import AgentRun, Execution, ExecutionMetric, ExecutionTask, Finding, HealingSuggestion, Job, RawFindingRecord, SkillInvocation, TestPlan, TriageResult
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.runtime import AgentOutputGuard, RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.skill_service import ExtensionInvocationCompletion, SkillService
from agentic_qa.services.skill_runtime import (
    ManagedSkillRuntimeRegistry,
    SkillRuntimeContext,
)
from agentic_qa.tools.model_gateway import ModelGatewayTool


class AnalysisService:
    def __init__(self, db: Session, runtime_registry: ManagedSkillRuntimeRegistry | None = None) -> None:
        self.db = db
        self.triage_agent = TriageAgent()
        self.healer_agent = HealerAgent()
        self.perf_agent = PerfAgent()
        self.security_agent = SecurityAgent()
        self.judge_agent = JudgeAgent()
        self.guardrail_engine = RuntimeGuardrailEngine(db)
        self.model_tool = ModelGatewayTool(db)
        self.skill_service = SkillService(db, runtime_registry=runtime_registry)

    def get_triage(self, execution_id: UUID) -> dict[str, object]:
        rows = list(self.db.scalars(select(TriageResult).where(TriageResult.execution_id == execution_id)))
        if not rows:
            self._generate_triage(execution_id, None)
            self.db.commit()
            rows = list(self.db.scalars(select(TriageResult).where(TriageResult.execution_id == execution_id)))
        return {
            "executionId": str(execution_id),
            "results": [
                {
                    "taskId": str(row.task_id) if row.task_id else None,
                    "category": row.category.value,
                    "confidence": float(row.confidence),
                    "evidence": row.evidence,
                    "challenged": row.challenged,
                    "finalDecisionBy": row.final_decision_by,
                }
                for row in rows
            ],
        }

    def get_failure_attribution(self, execution_id: UUID) -> dict[str, object]:
        rows = list(self.db.scalars(select(TriageResult).where(TriageResult.execution_id == execution_id)))
        if not rows:
            self._generate_triage(execution_id, None)
            self.db.commit()
            rows = list(self.db.scalars(select(TriageResult).where(TriageResult.execution_id == execution_id)))
        return {
            "executionId": str(execution_id),
            "attributions": [self._to_failure_attribution(row) for row in rows],
        }

    def analyze_execution(self, execution_id: UUID, context: ServiceContext, *, reset: bool = False) -> int:
        if reset:
            self.db.execute(delete(TriageResult).where(TriageResult.execution_id == execution_id))
            self.db.flush()
        self._generate_triage(execution_id, context)
        self.db.flush()
        return len(list(self.db.scalars(select(TriageResult).where(TriageResult.execution_id == execution_id))))

    def rerun_triage(self, execution_id: UUID, context: ServiceContext) -> dict[str, object]:
        job = self.prepare_triage_job(execution_id)
        self.db.commit()
        from agentic_qa.infra.queue import enqueue_task

        enqueue_task(
            "triage.rerun",
            str(job.id),
            str(execution_id),
            str(context.user.id),
            context.user.roles,
            context.request_id,
            context.trace_id,
        )
        return {"jobId": str(job.id), "executionId": str(execution_id), "status": "queued"}

    def prepare_triage_job(self, execution_id: UUID) -> Job:
        job = Job(
            id=uuid4(),
            job_type="triage.rerun",
            status=JobStatus.QUEUED,
            payload={"executionId": str(execution_id)},
            progress=0,
        )
        self.db.add(job)
        self.db.flush()
        return job

    def run_triage_job(self, job_id: UUID, execution_id: UUID, context: ServiceContext) -> dict[str, object]:
        job = self._require_job(job_id)
        try:
            job.status = JobStatus.RUNNING
            job.progress = 20
            job.started_at = datetime.now(timezone.utc)
            self.analyze_execution(execution_id, context, reset=True)
            write_audit_log(self.db, str(context.user.id), "triage.rerun", "execution", str(execution_id), context.request_id, context.trace_id)
            job.status = JobStatus.COMPLETED
            job.progress = 100
            job.result_ref = str(execution_id)
            job.result_payload = {"executionId": str(execution_id)}
            job.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            return {"jobId": str(job.id), "executionId": str(execution_id), "status": job.status.value}
        except Exception as exc:
            self.db.rollback()
            job = self._require_job(job_id)
            job.status = JobStatus.FAILED
            job.progress = 100
            job.error_message = str(exc)
            job.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            raise

    def get_healing(self, execution_id: UUID) -> dict[str, object]:
        rows = list(self.db.scalars(select(HealingSuggestion).where(HealingSuggestion.execution_id == execution_id)))
        if not rows:
            self.generate_healing(execution_id, reset=False)
            self.db.commit()
            rows = list(self.db.scalars(select(HealingSuggestion).where(HealingSuggestion.execution_id == execution_id)))
        return {
            "executionId": str(execution_id),
            "suggestions": [
                {
                    "taskId": str(row.task_id) if row.task_id else None,
                    "type": row.suggestion_type,
                    "summary": row.summary,
                    "patch": row.patch,
                }
                for row in rows
            ],
        }

    def generate_healing(self, execution_id: UUID, context: ServiceContext | None = None, reset: bool = False) -> int:
        if reset:
            self.db.execute(delete(HealingSuggestion).where(HealingSuggestion.execution_id == execution_id))
            self.db.flush()
        self._generate_healing(execution_id, context)
        self.db.flush()
        return len(list(self.db.scalars(select(HealingSuggestion).where(HealingSuggestion.execution_id == execution_id))))

    def _generate_triage(self, execution_id: UUID, context: ServiceContext | None) -> None:
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)))
        for task in tasks:
            primary_agent, primary_input = self._build_triage_input(task)
            primary_model_response: dict[str, object] | None = None
            selected_runtime_context: SkillRuntimeContext | None = None

            def execute_primary_agent(_runtime_context=None, _runtime_request=None) -> AgentResult:
                nonlocal primary_model_response, selected_runtime_context
                selected_runtime_context = (
                    _runtime_context
                    if isinstance(_runtime_context, SkillRuntimeContext)
                    else None
                )
                primary_result, primary_model_response = self._invoke_agent(
                    agent=primary_agent,
                    execution_id=execution_id,
                    task_id=task.id,
                    context=context,
                    input_payload=primary_input,
                    prompt=self._agent_prompt(primary_agent, task),
                    span_name=f"triage.{task.domain.value}.{primary_agent.name}",
                    resource_type="triage_result",
                    resource_id=str(task.id),
                    runtime_context=selected_runtime_context,
                )
                return primary_result

            def accept_primary_result(
                primary_result: object,
                invocation: SkillInvocation | None,
            ) -> ExtensionInvocationCompletion:
                if not isinstance(primary_result, AgentResult):
                    raise ValueError("analysis Skill runtime returned an incompatible agent result")
                self._record_agent_run(
                    execution_id=execution_id,
                    task_id=task.id,
                    context=context,
                    agent=primary_agent,
                    input_payload=primary_input,
                    result=primary_result,
                    model_response=primary_model_response,
                )

                challenged = task.domain.value in {"security", "performance"}
                final_result = primary_result
                raw_output: dict[str, object] = {"primary": primary_result.payload, "primaryAgent": primary_agent.name}
                final_decision_by = "triage"

                if challenged:
                    judge_input = {
                        "domain": task.domain.value,
                        "primaryResult": primary_result.payload,
                        "taskStatus": task.status.value,
                    }
                    judge_result, judge_model_response = self._invoke_agent(
                        agent=self.judge_agent,
                        execution_id=execution_id,
                        task_id=task.id,
                        context=context,
                        input_payload=judge_input,
                        prompt=self._agent_prompt(self.judge_agent, task),
                        span_name=f"triage.{task.domain.value}.{self.judge_agent.name}",
                        resource_type="triage_result",
                        resource_id=str(task.id),
                        runtime_context=selected_runtime_context,
                    )
                    self._record_agent_run(
                        execution_id=execution_id,
                        task_id=task.id,
                        context=context,
                        agent=self.judge_agent,
                        input_payload=judge_input,
                        result=judge_result,
                        model_response=judge_model_response,
                    )
                    final_result = AgentResult(
                        result={
                            "category": str(judge_result.payload.get("category", primary_result.payload.get("category", "unknown"))),
                            "confidence": judge_result.confidence,
                            "evidence": list(dict.fromkeys([*primary_result.evidence, *judge_result.evidence])),
                            "summary": judge_result.payload.get("summary"),
                        },
                        confidence=judge_result.confidence,
                        evidence=list(dict.fromkeys([*primary_result.evidence, *judge_result.evidence])),
                        metadata={"status": str(judge_result.payload.get("category", primary_result.payload.get("category", "unknown")))},
                    )
                    raw_output["judge"] = judge_result.payload
                    raw_output["judgeAgent"] = self.judge_agent.name
                    final_decision_by = "judge"

                triage_result_id = uuid4()
                raw_output = {
                    **raw_output,
                    "final": final_result.payload,
                    "skillInvocationId": str(invocation.id) if invocation is not None else None,
                }
                self.db.add(
                    TriageResult(
                        id=triage_result_id,
                        execution_id=execution_id,
                        task_id=task.id,
                        category=self._parse_triage_category(str(final_result.payload.get("category", final_result.metadata.get("status", "unknown")))),
                        confidence=Decimal(str(final_result.payload.get("confidence", final_result.confidence))),
                        evidence=list(final_result.payload.get("evidence", final_result.evidence)),
                        challenged=challenged,
                        final_decision_by=final_decision_by,
                        raw_output=raw_output,
                    )
                )
                return ExtensionInvocationCompletion(
                    output_snapshot=self._analysis_skill_result(
                            task=task,
                            input_payload=primary_input,
                            final_result=final_result,
                            raw_output=raw_output,
                            triage_result_id=triage_result_id,
                        ),
                )

            if context is None:
                accept_primary_result(execute_primary_agent(), None)
                continue

            extension_point_id = self._analysis_extension_point(task)
            request = {
                "operation": self._analysis_operation(extension_point_id),
                "payload": {
                    "executionId": str(execution_id),
                    "taskId": str(task.id),
                    "domain": task.domain.value,
                    "taskType": task.task_type,
                    "agent": primary_agent.name,
                    "observedContext": primary_input,
                },
            }
            self.skill_service.invoke_extension(
                extension_point_id=extension_point_id,
                source_workflow="execution.analyze",
                context=context,
                execution_id=execution_id,
                request=request,
                scope={
                    **self._execution_skill_scope(execution_id),
                    "stage": "ANALYZE",
                    "domain": task.domain.value,
                },
                policy_snapshot={
                    "workflow": "execution.analyze",
                    "stage": "ANALYZE",
                    "ownedWrites": ["triage_results"],
                    "skillWritesFindings": False,
                    "skillWritesGate": False,
                },
                capabilities={"execute": execute_primary_agent},
                result_acceptor=accept_primary_result,
            )

    def _generate_healing(self, execution_id: UUID, context: ServiceContext | None) -> None:
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution_id)))
        for task in tasks:
            if task.status != TaskStatus.FAILED and not task.error_message:
                continue
            healing_input = {"taskType": task.task_type, "errorMessage": task.error_message or ""}
            result, model_response = self._invoke_agent(
                agent=self.healer_agent,
                execution_id=execution_id,
                task_id=task.id,
                context=context,
                input_payload=healing_input,
                prompt=self._agent_prompt(self.healer_agent, task),
                span_name=f"heal.{task.domain.value}.{self.healer_agent.name}",
                resource_type="healing_suggestion",
                resource_id=str(task.id),
            )
            self.db.add(
                HealingSuggestion(
                    id=uuid4(),
                    execution_id=execution_id,
                    task_id=task.id,
                    suggestion_type=result.payload["type"],
                    summary=result.payload["summary"],
                    patch=result.payload["patch"],
                    success=None,
                    metadata_json={"confidence": result.confidence},
                )
            )
            self._record_agent_run(
                execution_id=execution_id,
                task_id=task.id,
                context=context,
                agent=self.healer_agent,
                input_payload=healing_input,
                result=result,
                model_response=model_response,
            )

    def _build_triage_input(self, task: ExecutionTask) -> tuple[BaseAgent, dict[str, object]]:
        if task.domain.value == "performance":
            metrics = list(self.db.scalars(select(ExecutionMetric).where(ExecutionMetric.task_id == task.id)))
            return self.perf_agent, {
                "metrics": [self._serialize_metric(metric) for metric in metrics],
                "errorMessage": task.error_message or "",
            }
        if task.domain.value == "security":
            findings = list(self.db.scalars(select(RawFindingRecord).where(RawFindingRecord.task_id == task.id)))
            return self.security_agent, {
                "findings": [self._serialize_raw_finding(finding) for finding in findings],
                "errorMessage": task.error_message or "",
            }
        return self.triage_agent, {"domain": task.domain.value, "errorMessage": task.error_message or ""}

    def _analysis_extension_point(self, task: ExecutionTask) -> str:
        if task.domain.value == "performance":
            return "ANALYZE.performance_analysis"
        if task.domain.value == "security":
            return "ANALYZE.security_analysis"
        return "ANALYZE.finding_triage"

    def _analysis_operation(self, extension_point_id: str) -> str:
        return {
            "ANALYZE.performance_analysis": "analyze_performance",
            "ANALYZE.security_analysis": "analyze_security",
        }.get(extension_point_id, "triage_findings")

    def _analysis_skill_result(
        self,
        *,
        task: ExecutionTask,
        input_payload: dict[str, object],
        final_result: AgentResult,
        raw_output: dict[str, object],
        triage_result_id: UUID,
    ) -> dict[str, object]:
        return {
            "result": {
                "analysisIntent": self._analysis_operation(self._analysis_extension_point(task)),
                "taskId": str(task.id),
                "domain": task.domain.value,
                "candidateConclusion": final_result.payload,
                "serviceOwnedResultRef": {"type": "triage_result", "id": str(triage_result_id)},
            },
            "confidence": float(final_result.payload.get("confidence", final_result.confidence)),
            "evidence": self._analysis_evidence_refs(task, input_payload),
            "artifactRefs": [],
            "rawFindingRefs": self._analysis_raw_finding_refs(task, input_payload),
            "findingCandidates": [],
            "metadata": {
                "sourceWorkflow": "execution.analyze",
                "finalDecisionBy": raw_output.get("judgeAgent") or raw_output.get("primaryAgent"),
                "serviceOwnsPersistence": True,
                "writesFinding": False,
                "writesGate": False,
            },
        }

    def _analysis_evidence_refs(self, task: ExecutionTask, input_payload: dict[str, object]) -> list[dict[str, object]]:
        evidence: list[dict[str, object]] = [{"type": "execution_task", "ref": str(task.id)}]
        for metric in input_payload.get("metrics", []) if isinstance(input_payload.get("metrics"), list) else []:
            if isinstance(metric, dict) and metric.get("id"):
                evidence.append({"type": "metric", "ref": str(metric["id"])})
        for finding in input_payload.get("findings", []) if isinstance(input_payload.get("findings"), list) else []:
            if isinstance(finding, dict) and finding.get("id"):
                evidence.append({"type": "raw_finding", "ref": str(finding["id"])})
        return evidence

    def _analysis_raw_finding_refs(self, task: ExecutionTask, input_payload: dict[str, object]) -> list[dict[str, object]]:
        if task.domain.value != "security":
            return []
        refs: list[dict[str, object]] = []
        for finding in input_payload.get("findings", []) if isinstance(input_payload.get("findings"), list) else []:
            if isinstance(finding, dict):
                refs.append(
                    {
                        "id": str(finding.get("id")),
                        "source": str(finding.get("source")),
                        "rawRef": str(finding.get("rawRef")),
                        "dedupeKey": str(finding.get("dedupeKey")),
                    }
                )
        return refs

    def _execution_environment(self, execution_id: UUID) -> str | None:
        execution = self.db.get(Execution, execution_id)
        return execution.environment if execution is not None else None

    def _execution_skill_scope(self, execution_id: UUID) -> dict[str, object]:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise ValueError("execution not found")
        plan = self.db.get(TestPlan, execution.plan_id)
        if plan is None:
            raise ValueError("test plan not found")
        return {
            "projectId": str(plan.project_id),
            "environmentId": str(plan.environment_id) if plan.environment_id else None,
            "environment": execution.environment,
        }

    def _invoke_agent(
        self,
        *,
        agent: BaseAgent,
        execution_id: UUID,
        task_id: UUID | None,
        context: ServiceContext | None,
        input_payload: dict[str, object],
        prompt: str,
        span_name: str,
        resource_type: str,
        resource_id: str,
        runtime_context: SkillRuntimeContext | None = None,
    ) -> tuple[AgentResult, dict[str, object] | None]:
        def run_agent() -> tuple[AgentResult, dict[str, object] | None]:
            trace_uuid = UUID(context.trace_id) if context else None
            if runtime_context is not None:
                runtime_context.checkpoint()
            model_response = self.model_tool.invoke_structured(
                trace_id=trace_uuid,
                execution_id=execution_id,
                role=agent.preferred_model_role,
                prompt=prompt,
                payload={"agent": agent.name, **input_payload},
                request_id=context.request_id if context else None,
                timeout_seconds=(
                    runtime_context.remaining_seconds()
                    if runtime_context is not None
                    else None
                ),
                max_provider_retries=(0 if runtime_context is not None else None),
            )
            if runtime_context is not None:
                runtime_context.checkpoint()
            result = agent.run(input_payload)
            limitations = model_response.get("limitations")
            limitations = limitations if isinstance(limitations, list) else []
            model_status = str(model_response.get("status") or "failed")
            if model_status != "completed" or model_response.get("fallbackUsed"):
                result.metadata = {
                    **result.metadata,
                    "modelStatus": model_status,
                    "modelMode": model_response.get("mode"),
                    "fallbackUsed": True,
                    "fallbackReason": (
                        model_response.get("fallbackReason")
                        or (str(limitations[0]) if limitations else f"MODEL_{model_status.upper()}")
                    ),
                    "modelFailureReason": (
                        str(limitations[0]) if limitations else None
                    ),
                }
            return result, model_response

        if context is not None:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution_id,
                root_span_name="analysis.agent",
                span_name=span_name,
                service_name="agent-service",
                attributes={"taskId": str(task_id) if task_id else None, "agent": agent.name},
            ):
                result, model_response = run_agent()
        else:
            result, model_response = run_agent()

        self.guardrail_engine.enforce(
            GuardrailContext(
                trace_id=context.trace_id if context else None,
                request_id=context.request_id if context else None,
                actor_id=context.user.id if context else None,
                actor_roles=context.user.roles if context else [],
                resource_type=resource_type,
                resource_id=resource_id,
                execution_id=execution_id,
                payload={"agentName": agent.name, "agentResult": result},
            ),
            [AgentOutputGuard()],
        )
        return result, model_response

    def _record_agent_run(
        self,
        *,
        execution_id: UUID,
        task_id: UUID | None,
        context: ServiceContext | None,
        agent: BaseAgent,
        input_payload: dict[str, object],
        result: AgentResult,
        model_response: dict[str, object] | None,
    ) -> None:
        self.db.add(
            AgentRun(
                id=uuid4(),
                execution_id=execution_id,
                task_id=task_id,
                trace_id=UUID(context.trace_id) if context else None,
                agent_name=agent.name,
                status=AgentRunStatus.COMPLETED,
                input_payload=input_payload,
                output_payload=result.to_contract(),
                model_id=self._parse_model_id(model_response),
            )
        )

    def _agent_prompt(self, agent: BaseAgent, task: ExecutionTask) -> str:
        return f"Run {agent.name} for {task.domain.value} task {task.task_type}"

    def _serialize_metric(self, metric: ExecutionMetric) -> dict[str, object]:
        return {
            "id": str(metric.id),
            "metricName": metric.metric_name,
            "metricValue": float(metric.metric_value),
            "metricUnit": metric.metric_unit,
            "thresholdValue": float(metric.threshold_value) if metric.threshold_value is not None else None,
            "baselineValue": float(metric.baseline_value) if metric.baseline_value is not None else None,
            "metadata": metric.metadata_json,
        }

    def _serialize_finding(self, finding: Finding) -> dict[str, object]:
        return {
            "id": str(finding.id),
            "source": finding.source.value,
            "category": finding.category.value,
            "severity": finding.severity.value,
            "title": finding.title,
            "summary": finding.summary,
            "confidence": float(finding.confidence) if finding.confidence is not None else None,
            "location": finding.location,
            "evidence": finding.evidence,
            "rawRef": finding.raw_ref,
        }

    def _serialize_raw_finding(self, finding: RawFindingRecord) -> dict[str, object]:
        return {
            "id": str(finding.id),
            "source": finding.source,
            "category": finding.category,
            "severity": finding.severity,
            "title": finding.title,
            "summary": finding.summary,
            "evidence": finding.evidence,
            "location": finding.location,
            "confidence": float(finding.confidence),
            "dedupeKey": finding.dedupe_key,
            "rawRef": finding.raw_ref,
        }

    def _parse_model_id(self, model_response: dict[str, object] | None) -> UUID | None:
        if not model_response:
            return None
        model_id = model_response.get("modelId")
        if not model_id:
            return None
        return UUID(str(model_id))

    def _to_failure_attribution(self, row: TriageResult) -> dict[str, object]:
        category = self._attribution_category(row)
        confidence = float(row.confidence)
        evidence: list[str | dict[str, object]] = list(row.evidence)
        if not evidence:
            evidence.append({"type": "triage_result", "id": str(row.id)})
        return validate_contract(
            "failure-attribution",
            {
                "schemaVersion": "phase8.failure-attribution.v1",
                "executionId": str(row.execution_id),
                "taskId": str(row.task_id) if row.task_id else None,
                "category": category,
                "confidence": confidence,
                "evidence": evidence,
                "suspectedCause": self._suspected_cause(category, evidence),
                "suggestedNextAction": self._suggested_next_action(category, confidence),
                "reviewRequired": confidence < 0.75,
                "metadata": {
                    "triageResultId": str(row.id),
                    "challenged": row.challenged,
                    "finalDecisionBy": row.final_decision_by,
                },
            },
        )

    def _attribution_category(self, row: TriageResult) -> str:
        mapping = {
            TriageCategory.BUG: "product_bug",
            TriageCategory.TEST_ISSUE: "test_issue",
            TriageCategory.FLAKY: "flaky",
            TriageCategory.ENV: "environment_issue",
            TriageCategory.PERFORMANCE_ISSUE: "performance_regression",
            TriageCategory.SECURITY_ISSUE: "security_finding",
            TriageCategory.UNKNOWN: "tool_error",
        }
        raw_output = row.raw_output or {}
        final = raw_output.get("final") if isinstance(raw_output.get("final"), dict) else {}
        if isinstance(final, dict) and final.get("category") == "requirement_gap":
            return "requirement_gap"
        return mapping.get(row.category, "tool_error")

    def _suspected_cause(self, category: str, evidence: list[str | dict[str, object]]) -> str:
        if evidence:
            return str(evidence[0])
        return {
            "product_bug": "product behavior differs from expected result",
            "test_issue": "test automation or assertion may need update",
            "flaky": "non-deterministic execution signal detected",
            "environment_issue": "environment or dependency failure suspected",
            "requirement_gap": "requirement acceptance criteria may be incomplete",
            "tool_error": "runner or tool error needs inspection",
            "performance_regression": "performance metric exceeded threshold",
            "security_finding": "security scanner reported an open finding",
        }.get(category, "unknown failure cause")

    def _suggested_next_action(self, category: str, confidence: float) -> str:
        if confidence < 0.75:
            return "send attribution for human confirmation"
        return {
            "product_bug": "open or link a product defect",
            "test_issue": "review and update test asset",
            "flaky": "retry with flaky policy and inspect stability evidence",
            "environment_issue": "verify environment health before retry",
            "requirement_gap": "request requirement clarification",
            "tool_error": "inspect runner/tool logs and retry if safe",
            "performance_regression": "compare baseline metrics and performance budget",
            "security_finding": "route normalized security finding to review",
        }.get(category, "review attribution evidence")

    def _parse_triage_category(self, category: str) -> TriageCategory:
        normalized = category.lower()
        if normalized in TriageCategory._value2member_map_:
            return TriageCategory(normalized)
        return TriageCategory.UNKNOWN

    def _require_job(self, job_id: UUID) -> Job:
        job = self.db.get(Job, job_id)
        if job is None:
            raise ValueError("job not found")
        return job

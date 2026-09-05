# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import ApprovalStatus, JobStatus, TaskStatus
from agentic_qa.domain.models import (
    AuditLog,
    Approval,
    Execution,
    ExecutionPlan,
    ExecutionTask,
    ExploratorySession,
    GateDecision,
    GuardrailEvent,
    OrchestrationCheckpoint,
    OrchestrationRun,
    ReplayExportRecord,
    RequirementVersion,
    SkillInvocation,
    TestPlan,
    TestPlanDomain,
)
from agentic_qa.services.common import paginate_query, paginate_result
from agentic_qa.services.execution_service import ExecutionService
from agentic_qa.services.skill_service import SkillService


class WorkflowRunProjectionService:
    """Build a read-only user workflow projection from persisted lifecycle records."""

    schema_version = "phase8.workflow-run-projection.v1"

    def __init__(self, db: Session, user: object | None = None) -> None:
        self.db = db
        self.user = user

    def list_runs(
        self,
        *,
        page: int,
        page_size: int,
        source: str | None = None,
        status: str | None = None,
    ) -> dict[str, object]:
        statement = select(OrchestrationRun).order_by(OrchestrationRun.updated_at.desc(), OrchestrationRun.created_at.desc())
        if source:
            statement = statement.where(OrchestrationRun.source == source)
        if status:
            statement = statement.where(OrchestrationRun.status == status)
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result([self._project_run(row, include_checkpoints=False) for row in rows], total, page, page_size)

    def get_run(self, run_id: UUID) -> dict[str, object]:
        run = self.db.get(OrchestrationRun, run_id)
        if run is None:
            raise ValueError("workflow run not found")
        return self._project_run(run, include_checkpoints=True)

    def _project_run(self, run: OrchestrationRun, *, include_checkpoints: bool) -> dict[str, object]:
        requirement = self.db.get(RequirementVersion, run.linked_requirement_version_id) if run.linked_requirement_version_id else None
        plan = self.db.get(TestPlan, run.linked_plan_id) if run.linked_plan_id else None
        execution = self.db.get(Execution, run.linked_execution_id) if run.linked_execution_id else None
        execution_plan = self._load_execution_plan(run, execution)
        approvals = self._load_approvals(run, execution_plan, execution)
        gate = self._load_gate(execution)
        replay_export = self._load_replay_export(run, execution)
        checkpoints = self._load_checkpoints(run.id)
        exploratory_sessions = self._load_exploratory_sessions(run, plan, execution)
        regression_plan = self._load_regression_plan(execution)
        skill_invocations = self._load_skill_invocations(run, execution)
        guardrail_events = self._load_guardrail_events(run, execution, skill_invocations)
        audit_logs = self._load_audit_logs(run, execution, exploratory_sessions)
        capability_nodes = self._capability_nodes(plan, execution)
        test_domains = self._test_domain_projection(plan, execution)
        execution_strategies = self._execution_strategy_projection(
            execution=execution,
            exploratory_sessions=exploratory_sessions,
            regression_plan=regression_plan,
        )
        governance_status = self._governance_status(
            run=run,
            approvals=approvals,
            gate=gate,
            replay_export=replay_export,
            skill_invocations=skill_invocations,
            guardrail_events=guardrail_events,
            audit_logs=audit_logs,
            capability_nodes=capability_nodes,
        )
        stage_summaries = self._stage_summaries(
            run=run,
            requirement=requirement,
            plan=plan,
            execution=execution,
            execution_plan=execution_plan,
            approvals=approvals,
            gate=gate,
            replay_export=replay_export,
            exploratory_sessions=exploratory_sessions,
            regression_plan=regression_plan,
            governance_status=governance_status,
            checkpoints=checkpoints,
        )
        current_state = self._current_state(run)
        current_blocker = self._current_blocker(run, current_state, approvals)
        next_actions = self._next_actions(
            run=run,
            requirement=requirement,
            plan=plan,
            execution=execution,
            approvals=approvals,
            gate=gate,
            replay_export=replay_export,
            exploratory_sessions=exploratory_sessions,
            regression_plan=regression_plan,
            current_state=current_state,
        )
        checkpoint_count = len(checkpoints)
        projection: dict[str, object] = {
            "schemaVersion": self.schema_version,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "runId": str(run.id),
            "source": run.source,
            "triggerType": run.trigger_type,
            "status": self._value(run.status),
            "currentStep": run.current_step,
            "currentState": current_state,
            "blocked": bool(current_blocker["blocked"]),
            "blockedReason": current_blocker["reason"],
            "currentBlocker": current_blocker,
            "requestId": run.request_id,
            "traceId": str(run.trace_id) if run.trace_id else None,
            "linkedResources": {
                "requirement": self._serialize_requirement(requirement),
                "plan": self._serialize_plan(plan),
                "executionPlan": self._serialize_execution_plan(execution_plan),
                "execution": self._serialize_execution(execution),
                "exploratorySessions": [self._serialize_exploratory_session(item) for item in exploratory_sessions],
                "regressionPlan": self._serialize_regression_plan(regression_plan),
                "approval": self._serialize_approval(approvals[0]) if approvals else None,
                "gate": self._serialize_gate(gate),
                "replay": self._serialize_replay_export(replay_export),
            },
            "testDomains": test_domains,
            "executionStrategies": execution_strategies,
            "governanceStatus": governance_status,
            "stageSummaries": stage_summaries,
            "nextActions": next_actions,
            "checkpointCount": checkpoint_count,
            "resultSummary": self._result_summary(run.result_payload),
            "errorMessage": run.error_message,
            "startedAt": self._iso(run.started_at),
            "endedAt": self._iso(run.ended_at),
            "createdAt": self._iso(run.created_at),
            "updatedAt": self._iso(run.updated_at),
        }
        if include_checkpoints:
            projection["checkpoints"] = [self._serialize_checkpoint(checkpoint) for checkpoint in checkpoints]
        return projection

    def _stage_summaries(
        self,
        *,
        run: OrchestrationRun,
        requirement: RequirementVersion | None,
        plan: TestPlan | None,
        execution: Execution | None,
        execution_plan: ExecutionPlan | None,
        approvals: list[Approval],
        gate: GateDecision | None,
        replay_export: ReplayExportRecord | dict[str, object] | None,
        exploratory_sessions: list[ExploratorySession],
        regression_plan: dict[str, object] | None,
        governance_status: dict[str, object],
        checkpoints: list[OrchestrationCheckpoint],
    ) -> list[dict[str, object]]:
        checkpoints_by_stage = {
            "requirement": self._checkpoint_refs(checkpoints, {"REQUIREMENT", "CLARIFICATION"}),
            "plan": self._checkpoint_refs(checkpoints, {"PLAN", "ASSET_REVIEW"}),
            "approval": self._checkpoint_refs(checkpoints, {"EXECUTION_PLAN_REVIEW"}),
            "execution": self._checkpoint_refs(checkpoints, {"EXECUTE", "OBSERVE", "ANALYZE", "NORMALIZE"}),
            "exploratory": self._checkpoint_refs(checkpoints, {"EXPLORATORY"}),
            "regression": self._checkpoint_refs(checkpoints, {"REGRESSION", "REGRESSION_SCOPE"}),
            "gate": self._checkpoint_refs(checkpoints, {"GATE"}),
            "replay": self._checkpoint_refs(checkpoints, {"EXPORT", "MEMORY"}),
        }
        approval_status = self._approval_stage_status(approvals, execution_plan)
        return [
            {
                "stageKey": "requirement",
                "label": "Requirement",
                "status": self._requirement_stage_status(run, requirement),
                "statusReason": self._stage_reason(run, "CLARIFICATION"),
                "refs": {"requirementVersionId": str(requirement.id) if requirement else None},
                "checkpointRefs": checkpoints_by_stage["requirement"],
            },
            {
                "stageKey": "plan",
                "label": "Plan",
                "status": self._plan_stage_status(run, plan),
                "statusReason": self._stage_reason(run, "PLAN"),
                "refs": {"planId": str(plan.id) if plan else None},
                "checkpointRefs": checkpoints_by_stage["plan"],
            },
            {
                "stageKey": "approval",
                "label": "Approval",
                "status": approval_status,
                "statusReason": self._approval_reason(run, approvals, execution_plan),
                "refs": {
                    "approvalId": str(approvals[0].id) if approvals else None,
                    "executionPlanId": str(execution_plan.id) if execution_plan else None,
                },
                "checkpointRefs": checkpoints_by_stage["approval"],
            },
            {
                "stageKey": "execution",
                "label": "Execution",
                "status": self._execution_stage_status(run, execution),
                "statusReason": self._stage_reason(run, "EXECUTE"),
                "refs": {"executionId": str(execution.id) if execution else None},
                "checkpointRefs": checkpoints_by_stage["execution"],
                "governanceRefs": self._stage_governance_refs(governance_status, "EXECUTE"),
            },
            {
                "stageKey": "exploratory",
                "label": "Exploratory Testing",
                "status": self._exploratory_stage_status(exploratory_sessions),
                "statusReason": "service_owned_session_workflow" if exploratory_sessions else "available_from_main_flow",
                "refs": {
                    "sessionIds": [str(session.id) for session in exploratory_sessions],
                    "backingExecutionIds": [str(session.backing_execution_id) for session in exploratory_sessions],
                },
                "checkpointRefs": checkpoints_by_stage["exploratory"],
                "governanceRefs": self._stage_governance_refs(
                    governance_status,
                    "EXECUTE",
                    {"PREPARE.exploratory_charter", "EXECUTE.exploratory_assist"},
                ),
            },
            {
                "stageKey": "regression",
                "label": "Regression Scope",
                "status": self._regression_stage_status(execution, regression_plan),
                "statusReason": "execution_service_recommendation" if regression_plan else "pending_execution_context",
                "refs": self._regression_refs(regression_plan),
                "checkpointRefs": checkpoints_by_stage["regression"],
                "governanceRefs": self._stage_governance_refs(governance_status, "PREPARE", {"PREPARE.regression_scope"}),
            },
            {
                "stageKey": "gate",
                "label": "Gate",
                "status": self._gate_stage_status(run, gate),
                "statusReason": self._stage_reason(run, "GATE"),
                "refs": {"gateDecisionId": str(gate.id) if gate else None},
                "checkpointRefs": checkpoints_by_stage["gate"],
                "governanceRefs": self._stage_governance_refs(governance_status, "GATE"),
            },
            {
                "stageKey": "replay",
                "label": "Replay",
                "status": "completed" if replay_export is not None else "pending",
                "statusReason": None,
                "refs": self._replay_refs(replay_export),
                "checkpointRefs": checkpoints_by_stage["replay"],
                "governanceRefs": self._stage_governance_refs(governance_status, "REPLAY"),
            },
        ]

    def _current_state(self, run: OrchestrationRun) -> str:
        if run.status == JobStatus.COMPLETED:
            return "completed"
        step = run.current_step.upper()
        if step == "CLARIFICATION":
            return "clarification"
        if step == "EXECUTION_PLAN_REVIEW":
            return "approval"
        if step == "GATE":
            return "gate"
        if step == "EXPLORATORY":
            return "exploratory"
        if step in {"REGRESSION", "REGRESSION_SCOPE"}:
            return "regression"
        if step in {"EXECUTE", "OBSERVE", "ANALYZE", "NORMALIZE"}:
            return "execution"
        if run.status in {JobStatus.FAILED, JobStatus.CANCELLED}:
            if step in {"PLAN", "ASSET_REVIEW"}:
                return "plan"
            return "execution"
        return "plan"

    def _current_blocker(self, run: OrchestrationRun, current_state: str, approvals: list[Approval]) -> dict[str, object]:
        result = dict(run.result_payload or {})
        blocked = bool(result.get("blocked")) or run.status in {JobStatus.FAILED, JobStatus.CANCELLED}
        pending_approval = next((approval for approval in approvals if approval.status == ApprovalStatus.PENDING), None)
        reason = self._string_or_none(result.get("reason")) or run.error_message
        if current_state == "approval" and pending_approval is not None:
            blocked = True
            reason = reason or "approval_required"
        if current_state == "completed":
            blocked = False
            reason = "completed"
        return {
            "category": current_state,
            "blocked": blocked,
            "reason": reason,
            "sourceStep": run.current_step,
            "approvalId": str(pending_approval.id) if pending_approval else None,
        }

    def _next_actions(
        self,
        *,
        run: OrchestrationRun,
        requirement: RequirementVersion | None,
        plan: TestPlan | None,
        execution: Execution | None,
        approvals: list[Approval],
        gate: GateDecision | None,
        replay_export: ReplayExportRecord | dict[str, object] | None,
        exploratory_sessions: list[ExploratorySession],
        regression_plan: dict[str, object] | None,
        current_state: str,
    ) -> list[dict[str, object]]:
        actions: list[dict[str, object]] = []
        if current_state == "clarification":
            actions.append(self._action("answer-clarification", "Answer clarifications", "/workflow", "orchestration_run", str(run.id)))
        if current_state == "approval" and approvals:
            actions.append(self._action("review-approval", "Review approval", "/workflow", "approval", str(approvals[0].id)))
        if requirement is not None:
            actions.append(self._action("open-requirement", "Open requirement", "/workflow", "requirement_version", str(requirement.id)))
        if plan is not None:
            actions.append(self._action("open-plan", "Open plan", "/test-assets", "test_plan", str(plan.id)))
        if execution is not None:
            actions.append(self._action("open-execution", "Open execution", "/executions", "execution", str(execution.id)))
            actions.append(self._action("open-regression", "Open regression scope", "/executions", "regression_plan", str(execution.id)))
        if exploratory_sessions:
            actions.append(
                self._action(
                    "open-exploratory",
                    "Open exploratory session",
                    "/exploratory-sessions",
                    "exploratory_session",
                    str(exploratory_sessions[0].id),
                )
            )
        else:
            target_id = str(execution.id) if execution is not None else str(plan.id) if plan is not None else str(run.id)
            actions.append(self._action("create-or-link-exploratory", "Create or link exploratory testing", "/exploratory-sessions", "workflow_context", target_id))
        if gate is not None and execution is not None:
            actions.append(self._action("open-gate", "Open Gate", "/gate-decisions", "gate_decision", str(gate.id)))
        if replay_export is not None and execution is not None:
            replay_ref = self._replay_refs(replay_export)
            target_id = self._string_or_none(replay_ref.get("exportId") or replay_ref.get("exportHash")) or str(execution.id)
            actions.append(self._action("open-replay", "Open Replay", "/replay-center", "replay_export", target_id))
        return actions

    def _action(self, action_id: str, label: str, target_route: str, target_type: str, target_id: str) -> dict[str, object]:
        return {
            "actionId": action_id,
            "label": label,
            "targetRoute": target_route,
            "targetResourceType": target_type,
            "targetResourceId": target_id,
            "mutation": False,
        }

    def _load_checkpoints(self, run_id: UUID) -> list[OrchestrationCheckpoint]:
        return list(
            self.db.scalars(
                select(OrchestrationCheckpoint)
                .where(OrchestrationCheckpoint.run_id == run_id)
                .order_by(OrchestrationCheckpoint.sequence_no.asc(), OrchestrationCheckpoint.created_at.asc())
            )
        )

    def _load_execution_plan(self, run: OrchestrationRun, execution: Execution | None) -> ExecutionPlan | None:
        if execution and execution.execution_plan_id:
            return self.db.get(ExecutionPlan, execution.execution_plan_id)
        result = dict(run.result_payload or {})
        execution_plan_payload = result.get("executionPlan")
        if isinstance(execution_plan_payload, dict):
            execution_plan_id = execution_plan_payload.get("executionPlanId") or execution_plan_payload.get("id")
            if execution_plan_id:
                return self.db.get(ExecutionPlan, UUID(str(execution_plan_id)))
        return None

    def _load_approvals(
        self,
        run: OrchestrationRun,
        execution_plan: ExecutionPlan | None,
        execution: Execution | None,
    ) -> list[Approval]:
        conditions = []
        if execution_plan is not None:
            conditions.append(and_(Approval.resource_type == "execution_plan", Approval.resource_id == str(execution_plan.id)))
        if execution is not None:
            conditions.append(and_(Approval.resource_type == "execution", Approval.resource_id == str(execution.id)))
        if not conditions:
            result = dict(run.result_payload or {})
            approval_payload = result.get("approval")
            if isinstance(approval_payload, dict) and approval_payload.get("approvalId"):
                approval = self.db.get(Approval, UUID(str(approval_payload["approvalId"])))
                return [approval] if approval else []
            return []
        return list(self.db.scalars(select(Approval).where(or_(*conditions)).order_by(Approval.created_at.desc())))

    def _load_gate(self, execution: Execution | None) -> GateDecision | None:
        if execution is None:
            return None
        return self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution.id))

    def _load_replay_export(self, run: OrchestrationRun, execution: Execution | None) -> ReplayExportRecord | dict[str, object] | None:
        if execution is not None:
            record = self.db.scalar(
                select(ReplayExportRecord)
                .where(ReplayExportRecord.execution_id == execution.id)
                .order_by(ReplayExportRecord.created_at.desc())
            )
            if record is not None:
                return record
        result = dict(run.result_payload or {})
        replay_export = result.get("replayExport")
        return replay_export if isinstance(replay_export, dict) else None

    def _load_exploratory_sessions(
        self,
        run: OrchestrationRun,
        plan: TestPlan | None,
        execution: Execution | None,
    ) -> list[ExploratorySession]:
        conditions = []
        if execution is not None:
            conditions.append(ExploratorySession.backing_execution_id == execution.id)
        if plan is not None:
            conditions.append(ExploratorySession.backing_plan_id == plan.id)
        result = dict(run.result_payload or {})
        session_id = result.get("exploratorySessionId")
        if session_id:
            conditions.append(ExploratorySession.id == UUID(str(session_id)))
        if not conditions:
            return []
        return list(
            self.db.scalars(
                select(ExploratorySession)
                .where(or_(*conditions))
                .order_by(ExploratorySession.created_at.desc())
            )
        )

    def _load_regression_plan(self, execution: Execution | None) -> dict[str, object] | None:
        if execution is None:
            return None
        try:
            return ExecutionService(self.db).plan_regression(execution.id)
        except ValueError:
            return None

    def _load_skill_invocations(self, run: OrchestrationRun, execution: Execution | None) -> list[SkillInvocation]:
        conditions = []
        if execution is not None:
            conditions.append(SkillInvocation.execution_id == execution.id)
        if run.trace_id is not None:
            conditions.append(SkillInvocation.trace_id == run.trace_id)
        if not conditions:
            return []
        return list(
            self.db.scalars(
                select(SkillInvocation)
                .where(or_(*conditions))
                .order_by(SkillInvocation.created_at.asc())
            )
        )

    def _load_guardrail_events(
        self,
        run: OrchestrationRun,
        execution: Execution | None,
        skill_invocations: list[SkillInvocation],
    ) -> list[GuardrailEvent]:
        conditions = []
        if execution is not None:
            conditions.append(GuardrailEvent.execution_id == execution.id)
        if run.trace_id is not None:
            conditions.append(GuardrailEvent.trace_id == run.trace_id)
        invocation_ids = [item.id for item in skill_invocations]
        if invocation_ids:
            conditions.append(GuardrailEvent.skill_invocation_id.in_(invocation_ids))
        if not conditions:
            return []
        return list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(or_(*conditions))
                .order_by(GuardrailEvent.created_at.asc())
            )
        )

    def _load_audit_logs(
        self,
        run: OrchestrationRun,
        execution: Execution | None,
        exploratory_sessions: list[ExploratorySession],
    ) -> list[AuditLog]:
        conditions = []
        if run.trace_id is not None:
            conditions.append(AuditLog.trace_id == run.trace_id)
        resource_ids = [str(run.id)]
        if execution is not None:
            resource_ids.append(str(execution.id))
        resource_ids.extend(str(session.id) for session in exploratory_sessions)
        if resource_ids:
            conditions.append(AuditLog.resource_id.in_(resource_ids))
        return list(
            self.db.scalars(
                select(AuditLog)
                .where(or_(*conditions))
                .order_by(AuditLog.created_at.asc())
            )
        ) if conditions else []

    def _capability_nodes(self, plan: TestPlan | None, execution: Execution | None) -> list[dict[str, object]]:
        scope = {
            "projectId": str(plan.project_id) if plan and plan.project_id else None,
            "environment": execution.environment if execution else plan.environment if plan else None,
            "stage": execution.stage.value if execution else None,
            "domain": None,
        }
        try:
            return list(SkillService(self.db).workflow_capability_graph(scope)["nodes"])
        except ValueError:
            return []

    def _test_domain_projection(self, plan: TestPlan | None, execution: Execution | None) -> list[dict[str, object]]:
        domain_keys: list[str] = []
        if plan is not None:
            domain_keys = [
                row.domain.value
                for row in self.db.scalars(
                    select(TestPlanDomain)
                    .where(TestPlanDomain.plan_id == plan.id)
                    .order_by(TestPlanDomain.domain.asc())
                )
            ]
        if not domain_keys and execution is not None:
            domain_keys = sorted({task.domain.value for task in self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution.id))})
        if not domain_keys and execution is not None:
            domain_keys = sorted(str(key) for key in dict(execution.summary or {}).keys() if key in {"functional", "performance", "security"})
        summary = dict(execution.summary or {}) if execution is not None else {}
        return [
            {
                "domain": domain,
                "status": str(summary.get(domain) or "planned"),
                "refs": {"planId": str(plan.id) if plan else None, "executionId": str(execution.id) if execution else None},
            }
            for domain in domain_keys
        ]

    def _execution_strategy_projection(
        self,
        *,
        execution: Execution | None,
        exploratory_sessions: list[ExploratorySession],
        regression_plan: dict[str, object] | None,
    ) -> list[dict[str, object]]:
        tasks = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id == execution.id))) if execution else []
        automated_tasks = [task for task in tasks if not task.config.get("manualSimulation")]
        manual_tasks = [task for task in tasks if task.config.get("manualSimulation")]
        regression_suite = list(regression_plan.get("recommendedRegressionSuite") or []) if regression_plan else []
        return [
            {
                "strategy": "automated",
                "status": self._strategy_status(automated_tasks, execution),
                "requiredCapability": "executions.manage",
                "refs": {"taskIds": [str(task.id) for task in automated_tasks]},
            },
            {
                "strategy": "manual_simulation",
                "status": self._strategy_status(manual_tasks, execution) if manual_tasks else "available",
                "requiredCapability": "executions.manage",
                "refs": {"taskIds": [str(task.id) for task in manual_tasks]},
            },
            {
                "strategy": "exploratory",
                "status": self._exploratory_stage_status(exploratory_sessions),
                "requiredCapability": "exploratory_sessions.manage",
                "refs": {"sessionIds": [str(session.id) for session in exploratory_sessions]},
            },
            {
                "strategy": "regression",
                "status": "recommended" if regression_suite else "pending",
                "requiredCapability": "executions.manage",
                "refs": {"recommendedCaseCount": len(regression_suite), "executionId": str(execution.id) if execution else None},
            },
        ]

    def _governance_status(
        self,
        *,
        run: OrchestrationRun,
        approvals: list[Approval],
        gate: GateDecision | None,
        replay_export: ReplayExportRecord | dict[str, object] | None,
        skill_invocations: list[SkillInvocation],
        guardrail_events: list[GuardrailEvent],
        audit_logs: list[AuditLog],
        capability_nodes: list[dict[str, object]],
    ) -> dict[str, object]:
        required_capabilities = sorted(
            {
                str(node.get("requiredCapability"))
                for node in capability_nodes
                if node.get("requiredCapability")
            }
            | {"executions.manage", "exploratory_sessions.manage"}
        )
        user_capabilities = set(getattr(self.user, "capabilities", []) or [])
        active_bindings = [
            {
                "extensionPointId": node.get("extensionPointId"),
                "lifecycleStage": node.get("lifecycleStage"),
                "binding": node.get("currentBindingSummary"),
            }
            for node in capability_nodes
            if node.get("bindable")
        ]
        return {
            "requiredCapabilities": required_capabilities,
            "currentUserCapabilityState": {
                capability: "granted" if capability in user_capabilities else "missing"
                for capability in required_capabilities
            },
            "activeSkillBindings": active_bindings,
            "skillInvocationRefs": [
                {
                    "id": str(item.id),
                    "skillId": self._skill_id_for_invocation(item),
                    "extensionPointId": item.extension_point_id,
                    "status": item.status,
                }
                for item in skill_invocations
            ],
            "approvalState": self._approval_state(approvals),
            "approvalRefs": [self._serialize_approval(item) for item in approvals],
            "guardrailEventRefs": [
                {"id": str(item.id), "ruleId": item.rule_id, "decision": self._value(item.decision)}
                for item in guardrail_events
            ],
            "auditRefs": [
                {"id": str(item.id), "action": item.action, "resourceType": item.resource_type, "resourceId": item.resource_id}
                for item in audit_logs
            ],
            "traceRefs": [str(run.trace_id)] if run.trace_id else [],
            "replayRefs": [self._replay_refs(replay_export)] if replay_export is not None else [],
            "gatePolicyEvidence": self._serialize_gate(gate),
        }

    def _strategy_status(self, tasks: list[ExecutionTask], execution: Execution | None) -> str:
        if not tasks:
            return "pending" if execution is None else "available"
        if any(task.status == TaskStatus.RUNNING for task in tasks):
            return "active"
        if all(task.status == TaskStatus.COMPLETED for task in tasks):
            return "completed"
        if any(task.status == TaskStatus.FAILED for task in tasks):
            return "failed"
        return "pending"

    def _requirement_stage_status(self, run: OrchestrationRun, requirement: RequirementVersion | None) -> str:
        if run.current_step == "CLARIFICATION" and run.status != JobStatus.COMPLETED:
            return "blocked"
        return "completed" if requirement is not None else "pending"

    def _plan_stage_status(self, run: OrchestrationRun, plan: TestPlan | None) -> str:
        if plan is not None:
            return "completed"
        if run.current_step in {"PLAN", "ASSET_REVIEW"}:
            return "active" if run.status == JobStatus.RUNNING else "blocked"
        return "pending"

    def _approval_stage_status(self, approvals: list[Approval], execution_plan: ExecutionPlan | None) -> str:
        if approvals:
            if any(approval.status == ApprovalStatus.PENDING for approval in approvals):
                return "blocked"
            if any(approval.status == ApprovalStatus.APPROVED for approval in approvals):
                return "completed"
            return self._value(approvals[0].status)
        if execution_plan is not None and not execution_plan.approval_required:
            return "not_required"
        return "pending"

    def _execution_stage_status(self, run: OrchestrationRun, execution: Execution | None) -> str:
        if execution is None:
            return "pending"
        if execution.status in {TaskStatus.RUNNING, TaskStatus.ANALYZING, TaskStatus.QUEUED}:
            return "active"
        return self._value(execution.status)

    def _exploratory_stage_status(self, sessions: list[ExploratorySession]) -> str:
        if not sessions:
            return "available"
        if any(session.status == "active" for session in sessions):
            return "active"
        if all(session.status == "completed" for session in sessions):
            return "completed"
        return "blocked"

    def _regression_stage_status(self, execution: Execution | None, regression_plan: dict[str, object] | None) -> str:
        if execution is None:
            return "pending"
        if regression_plan is None:
            return "pending"
        suite = list(regression_plan.get("recommendedRegressionSuite") or [])
        if suite:
            return "recommended"
        return "available"

    def _gate_stage_status(self, run: OrchestrationRun, gate: GateDecision | None) -> str:
        if gate is not None:
            return "completed"
        if run.current_step == "GATE":
            return "active" if run.status == JobStatus.RUNNING else "failed"
        return "pending"

    def _stage_reason(self, run: OrchestrationRun, stage_step: str) -> str | None:
        if run.current_step == stage_step:
            return self._string_or_none(dict(run.result_payload or {}).get("reason")) or run.error_message
        return None

    def _approval_reason(self, run: OrchestrationRun, approvals: list[Approval], execution_plan: ExecutionPlan | None) -> str | None:
        if approvals and any(approval.status == ApprovalStatus.PENDING for approval in approvals):
            return "approval_required"
        if execution_plan is not None and not execution_plan.approval_required:
            return "approval_not_required"
        return self._stage_reason(run, "EXECUTION_PLAN_REVIEW")

    def _regression_refs(self, regression_plan: dict[str, object] | None) -> dict[str, object]:
        if regression_plan is None:
            return {"executionId": None, "recommendedCaseCount": 0, "evidenceRefs": []}
        base_ref = dict(regression_plan.get("baseRef") or {})
        suite = list(regression_plan.get("recommendedRegressionSuite") or [])
        return {
            "executionId": base_ref.get("executionId"),
            "planId": base_ref.get("planId"),
            "recommendedCaseCount": len(suite),
            "evidenceRefs": list(regression_plan.get("evidenceRefs") or []),
            "replayRefs": list(regression_plan.get("replayRefs") or []),
        }

    def _stage_governance_refs(
        self,
        governance_status: dict[str, object],
        lifecycle_stage: str,
        extension_point_ids: set[str] | None = None,
    ) -> dict[str, object]:
        active_bindings = [
            item
            for item in governance_status.get("activeSkillBindings", [])
            if isinstance(item, dict)
            and (
                str(item.get("lifecycleStage")) == lifecycle_stage
                or str(item.get("extensionPointId")) in (extension_point_ids or set())
            )
        ]
        return {
            "requiredCapabilities": governance_status.get("requiredCapabilities", []),
            "capabilityState": governance_status.get("currentUserCapabilityState", {}),
            "activeSkillBindings": active_bindings,
            "skillInvocationRefs": governance_status.get("skillInvocationRefs", []),
            "approvalState": governance_status.get("approvalState"),
            "guardrailEventRefs": governance_status.get("guardrailEventRefs", []),
            "auditRefs": governance_status.get("auditRefs", []),
            "traceRefs": governance_status.get("traceRefs", []),
            "replayRefs": governance_status.get("replayRefs", []),
        }

    def _approval_state(self, approvals: list[Approval]) -> str:
        if any(approval.status == ApprovalStatus.PENDING for approval in approvals):
            return "pending"
        if any(approval.status == ApprovalStatus.REJECTED for approval in approvals):
            return "rejected"
        if any(approval.status == ApprovalStatus.APPROVED for approval in approvals):
            return "approved"
        if approvals:
            return self._value(approvals[0].status)
        return "not_required"

    def _checkpoint_refs(self, checkpoints: list[OrchestrationCheckpoint], step_names: set[str]) -> list[dict[str, object]]:
        return [
            {
                "checkpointId": str(checkpoint.id),
                "sequenceNo": checkpoint.sequence_no,
                "stepName": checkpoint.step_name,
                "status": self._value(checkpoint.status),
                "createdAt": self._iso(checkpoint.created_at),
            }
            for checkpoint in checkpoints
            if checkpoint.step_name in step_names
        ]

    def _serialize_requirement(self, requirement: RequirementVersion | None) -> dict[str, object] | None:
        if requirement is None:
            return None
        return {
            "requirementVersionId": str(requirement.id),
            "sourceRef": requirement.source_ref,
            "versionNo": requirement.version_no,
            "contentHash": requirement.content_hash,
            "requirementCount": len(requirement.requirements or []),
            "acceptanceCriteriaCount": len(requirement.acceptance_criteria or []),
        }

    def _serialize_plan(self, plan: TestPlan | None) -> dict[str, object] | None:
        if plan is None:
            return None
        return {
            "planId": str(plan.id),
            "name": plan.name,
            "status": self._value(plan.status),
            "environment": plan.environment,
            "riskLevel": self._value(plan.risk_level),
            "requirementVersionId": str(plan.requirement_version_id) if plan.requirement_version_id else None,
            "projectId": str(plan.project_id) if plan.project_id else None,
            "environmentId": str(plan.environment_id) if plan.environment_id else None,
        }

    def _serialize_execution_plan(self, execution_plan: ExecutionPlan | None) -> dict[str, object] | None:
        if execution_plan is None:
            return None
        return {
            "executionPlanId": str(execution_plan.id),
            "status": execution_plan.status,
            "riskLevel": self._value(execution_plan.risk_level),
            "approvalRequired": execution_plan.approval_required,
            "taskCount": len(execution_plan.tasks or []),
        }

    def _serialize_execution(self, execution: Execution | None) -> dict[str, object] | None:
        if execution is None:
            return None
        return {
            "executionId": str(execution.id),
            "planId": str(execution.plan_id),
            "status": self._value(execution.status),
            "stage": self._value(execution.stage),
            "environment": execution.environment,
            "startedAt": self._iso(execution.started_at),
            "endedAt": self._iso(execution.ended_at),
        }

    def _serialize_exploratory_session(self, session: ExploratorySession) -> dict[str, object]:
        return {
            "sessionId": str(session.id),
            "projectId": str(session.project_id),
            "environmentId": str(session.environment_id),
            "backingPlanId": str(session.backing_plan_id),
            "backingExecutionId": str(session.backing_execution_id),
            "charter": session.charter,
            "status": session.status,
            "timeboxMinutes": session.timebox_minutes,
            "traceId": str(session.trace_id) if session.trace_id else None,
            "replayRefs": session.replay_refs,
            "workflowRunId": session.metadata_json.get("workflowRunId"),
        }

    def _serialize_regression_plan(self, regression_plan: dict[str, object] | None) -> dict[str, object] | None:
        if regression_plan is None:
            return None
        suite = list(regression_plan.get("recommendedRegressionSuite") or [])
        return {
            "schemaVersion": regression_plan.get("schemaVersion"),
            "baseRef": regression_plan.get("baseRef"),
            "recommendedCaseCount": len(suite),
            "recommendedRegressionSuite": suite,
            "riskBasedPriority": regression_plan.get("riskBasedPriority"),
            "evidenceRefs": regression_plan.get("evidenceRefs"),
            "replayRefs": regression_plan.get("replayRefs"),
            "metadata": regression_plan.get("metadata"),
        }

    def _serialize_approval(self, approval: Approval | None) -> dict[str, object] | None:
        if approval is None:
            return None
        return {
            "approvalId": str(approval.id),
            "type": self._value(approval.type),
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "summary": approval.summary,
            "status": self._value(approval.status),
            "createdAt": self._iso(approval.created_at),
            "decidedAt": self._iso(approval.decided_at),
        }

    def _serialize_gate(self, gate: GateDecision | None) -> dict[str, object] | None:
        if gate is None:
            return None
        return {
            "gateDecisionId": str(gate.id),
            "executionId": str(gate.execution_id),
            "overall": self._value(gate.overall),
            "functional": self._value(gate.functional),
            "performance": self._value(gate.performance),
            "security": self._value(gate.security),
            "reasons": gate.reasons,
            "reasonCodes": list(gate.reason_codes or []),
            "matchedRules": list(gate.matched_rules or []),
            "completeness": dict(gate.completeness or {}),
            "confidence": float(gate.confidence),
            "policyVersionId": gate.policy_version_id,
            "policyVersionHash": gate.policy_version_hash,
            "policyBindingRef": gate.policy_binding_ref,
            "inputFingerprint": gate.input_fingerprint,
            "decisionSnapshotHash": gate.decision_snapshot_hash,
            "evaluatorVersion": gate.evaluator_version,
            "decidedBy": gate.decided_by,
        }

    def _serialize_replay_export(self, replay_export: ReplayExportRecord | dict[str, object] | None) -> dict[str, object] | None:
        if replay_export is None:
            return None
        refs = self._replay_refs(replay_export)
        return {
            "exportId": refs.get("exportId"),
            "executionId": refs.get("executionId"),
            "exportHash": refs.get("exportHash"),
            "exportPayloadHash": refs.get("exportPayloadHash"),
            "redactionStatus": refs.get("redactionStatus"),
            "persistedAt": refs.get("persistedAt"),
        }

    def _replay_refs(self, replay_export: ReplayExportRecord | dict[str, object] | None) -> dict[str, object | None]:
        if replay_export is None:
            return {"exportId": None, "executionId": None, "exportHash": None}
        if isinstance(replay_export, ReplayExportRecord):
            payload = replay_export.payload or {}
            if payload.get("storageMode") == "external":
                payload = payload.get("projection") or {}
            return {
                "exportId": replay_export.export_id,
                "executionId": str(replay_export.execution_id),
                "exportHash": replay_export.export_hash,
                "exportPayloadHash": replay_export.export_payload_hash,
                "redactionStatus": replay_export.redaction_status,
                "persistedAt": self._iso(replay_export.created_at),
                "traceabilitySnapshotRef": payload.get("traceabilitySnapshotRef"),
                "traceabilitySnapshotHash": payload.get("traceabilitySnapshotHash"),
            }
        return {
            "exportId": self._string_or_none(replay_export.get("exportId")),
            "executionId": self._string_or_none(replay_export.get("executionId")),
            "exportHash": self._string_or_none(replay_export.get("exportHash")),
            "exportPayloadHash": self._string_or_none(replay_export.get("exportPayloadHash")),
            "redactionStatus": self._string_or_none(replay_export.get("redactionStatus")),
            "persistedAt": self._string_or_none(replay_export.get("persistedAt") or replay_export.get("exportedAt")),
            "traceabilitySnapshotRef": self._string_or_none(replay_export.get("traceabilitySnapshotRef")),
            "traceabilitySnapshotHash": self._string_or_none(replay_export.get("traceabilitySnapshotHash")),
        }

    def _serialize_checkpoint(self, checkpoint: OrchestrationCheckpoint) -> dict[str, object]:
        return {
            "checkpointId": str(checkpoint.id),
            "sequenceNo": checkpoint.sequence_no,
            "stepName": checkpoint.step_name,
            "executionStage": checkpoint.execution_stage,
            "status": self._value(checkpoint.status),
            "traceId": str(checkpoint.trace_id) if checkpoint.trace_id else None,
            "executionId": str(checkpoint.execution_id) if checkpoint.execution_id else None,
            "resultSummary": self._result_summary(checkpoint.result_payload),
            "errorMessage": checkpoint.error_message,
            "startedAt": self._iso(checkpoint.started_at),
            "endedAt": self._iso(checkpoint.ended_at),
            "createdAt": self._iso(checkpoint.created_at),
        }

    def _result_summary(self, payload: dict[str, Any] | None) -> dict[str, object]:
        payload = payload or {}
        summary: dict[str, object] = {}
        for key in (
            "reason",
            "blocked",
            "gate",
            "coverage",
            "assetReview",
            "executionPlan",
            "execution",
            "replayExport",
        ):
            value = payload.get(key)
            if value is not None:
                summary[key] = value
        for key in ("exploratory", "regressionPlan", "governance"):
            value = payload.get(key)
            if value is not None:
                summary[key] = value
        return summary

    def _skill_id_for_invocation(self, invocation: SkillInvocation) -> str | None:
        resolution = dict(invocation.resolution_snapshot or {})
        value = resolution.get("skillId") or resolution.get("resolvedSkillId")
        return str(value) if value is not None else None

    def _value(self, value: Any) -> str:
        return str(value.value) if hasattr(value, "value") else str(value)

    def _string_or_none(self, value: object) -> str | None:
        if value is None:
            return None
        return str(value)

    def _iso(self, value: datetime | None) -> str | None:
        return value.isoformat() if value else None

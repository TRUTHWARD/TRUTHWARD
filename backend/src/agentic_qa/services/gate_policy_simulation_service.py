# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import GatePolicyMode, GatePolicyScopeType, GatePolicyStatus, JobStatus
from agentic_qa.domain.models import (
    Execution,
    GateDecision,
    GateInputSnapshot,
    GatePolicy,
    GatePolicyBinding,
    GatePolicySimulationCase,
    GatePolicySimulationRun,
    GatePolicyVersion,
    Job,
    TestPlan,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import traced_operation
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailViolationError
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.guardrails.runtime.gate_policy import GatePolicyMutationGuard
from agentic_qa.schemas.gate_evaluator import GateInputContract
from agentic_qa.schemas.gate_policy import (
    GatePolicyResolutionSnapshotContract,
    validate_gate_policy_document,
)
from agentic_qa.schemas.gate_policy_simulation import (
    CancelSimulationRequest,
    SimulationCaseDiff,
    SimulationListProjection,
    SimulationRequest,
    SimulationRun,
    SimulationSummary,
)
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
)
from agentic_qa.services.execution_service import ExecutionService
from agentic_qa.services.gate_evaluator import (
    GATE_EVALUATOR_VERSION,
    GateEvaluator,
    compute_gate_input_fingerprint,
)
from agentic_qa.services.gate_policy_governance_service import (
    GatePolicyGovernanceError,
    GatePolicyGovernanceService,
)


CAPABILITY_READ = "gate_policy.read"
CAPABILITY_SIMULATE = "gate_policy.simulate"
MAX_SIMULATION_CASES = 500
DEFAULT_RETENTION_DAYS = 90


class GatePolicySimulationService:
    """Re-evaluate frozen Gate input snapshots without writing authoritative Gate history."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.evaluator = GateEvaluator()
        self.execution_service = ExecutionService(db)

    def create_simulation(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        payload: SimulationRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_SIMULATE)
        governance = GatePolicyGovernanceService(self.db)
        policy, tenant_id, workspace_id = governance._scoped_policy(
            project_id, policy_id, context, write=True
        )
        source_version = governance._scoped_version(
            project_id,
            policy_id,
            payload.policyVersionId,
            context,
            write=True,
            for_update=True,
        )
        snapshot_refs = self._select_case_snapshot_refs(
            project_id=project_id,
            requested_ids=payload.caseSnapshotIds,
            max_cases=payload.maxCases,
        )
        if not snapshot_refs:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_DATASET_UNAVAILABLE",
                status_code=409,
                details={"reason": "no_complete_frozen_gate_input_snapshots"},
            )
        dataset_fingerprint = canonical_hash(snapshot_refs)
        request_hash = canonical_hash(
            {
                "projectId": str(project_id),
                "policyId": str(policy_id),
                "sourcePolicyVersionId": str(source_version.id),
                "sourcePolicyVersionHash": source_version.content_hash,
                "datasetFingerprint": dataset_fingerprint,
                "timeoutSeconds": payload.timeoutSeconds,
            }
        )
        acquire_transaction_advisory_lock(
            self.db,
            "gate-policy-simulation-request",
            f"{tenant_id}:{workspace_id}:{payload.idempotencyKey}",
        )
        existing = self.db.scalar(
            select(GatePolicySimulationRun).where(
                GatePolicySimulationRun.tenant_id == tenant_id,
                GatePolicySimulationRun.workspace_id == workspace_id,
                GatePolicySimulationRun.run_type == "historical",
                GatePolicySimulationRun.idempotency_key == payload.idempotencyKey,
            )
        )
        if existing is not None:
            if existing.request_hash != request_hash or existing.project_id != project_id:
                raise GatePolicyGovernanceError(
                    "GATE_POLICY_IDEMPOTENCY_CONFLICT",
                    status_code=409,
                    field="idempotencyKey",
                )
            return self._run_projection(existing, include_cases=True)

        candidate = self._freeze_simulation_candidate(policy, source_version, context)
        run_id = uuid4()
        job = Job(
            id=uuid4(),
            job_type="gate_policy.simulate",
            status=JobStatus.QUEUED,
            payload={
                "simulationRunId": str(run_id),
                "timeoutSeconds": payload.timeoutSeconds,
            },
            progress=0,
            idempotency_key=f"gate-policy.simulate:{run_id}",
        )
        run = GatePolicySimulationRun(
            id=run_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            project_id=project_id,
            policy_id=policy.id,
            source_policy_version_id=source_version.id,
            policy_version_id=candidate.id,
            policy_version_hash=candidate.content_hash,
            evaluator_version=GATE_EVALUATOR_VERSION,
            run_type="historical",
            status="queued",
            dataset_fingerprint=dataset_fingerprint,
            case_snapshot_refs=snapshot_refs,
            total_cases=len(snapshot_refs),
            job_id=job.id,
            idempotency_key=payload.idempotencyKey,
            request_hash=request_hash,
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
            retention_until=datetime.now(timezone.utc) + timedelta(days=DEFAULT_RETENTION_DAYS),
        )
        self._preflight(
            context,
            action="simulation_create",
            resource_type="gate_policy_simulation_run",
            resource_id=run.id,
            payload={
                "policyVersionId": str(candidate.id),
                "datasetFingerprint": dataset_fingerprint,
                "caseCount": len(snapshot_refs),
            },
        )
        # The simulation run owns a database FK to the queued Job, but the
        # models intentionally do not expose an ORM relationship.  Flush the
        # parent explicitly so PostgreSQL never depends on unit-of-work table
        # ordering; the surrounding transaction remains atomic.
        self.db.add(job)
        self.db.flush()
        self.db.add(run)
        write_audit_log(
            self.db,
            str(context.user.id),
            "gate_policy.simulation.create",
            "gate_policy_simulation_run",
            str(run.id),
            context.request_id,
            context.trace_id,
            {
                "projectId": str(project_id),
                "policyId": str(policy.id),
                "sourcePolicyVersionId": str(source_version.id),
                "policyVersionId": str(candidate.id),
                "policyVersionHash": candidate.content_hash,
                "datasetFingerprint": dataset_fingerprint,
                "caseCount": len(snapshot_refs),
                "authoritative": False,
                "writesGateDecision": False,
            },
        )
        self.db.commit()

        from agentic_qa.infra.queue import enqueue_task

        try:
            queue_task = enqueue_task(
                "gate_policy.simulate",
                str(run.id),
                str(job.id),
                payload.timeoutSeconds,
                str(context.user.id),
                context.user.roles,
                context.request_id,
                context.trace_id,
            )
        except Exception as exc:
            self.db.rollback()
            run = self._require_run(run.id)
            failed_job = self.db.get(Job, job.id)
            run.status = "failed"
            run.error_code = "GATE_POLICY_SIMULATION_QUEUE_FAILED"
            run.completed_at = datetime.now(timezone.utc)
            if failed_job is not None:
                failed_job.status = JobStatus.FAILED
                failed_job.error_message = "Gate Policy simulation queue dispatch failed"
                failed_job.progress = 100
                failed_job.ended_at = run.completed_at
            self.db.commit()
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_QUEUE_FAILED", status_code=503
            ) from exc
        queued_job = self.db.get(Job, job.id)
        if queued_job is not None:
            queued_job.payload = {**queued_job.payload, "queueTaskId": str(queue_task.id)}
            self.db.commit()
        self.db.expire_all()
        return self._run_projection(self._require_run(run.id), include_cases=True)

    def run_simulation_job(
        self,
        run_id: UUID,
        job_id: UUID,
        timeout_seconds: int,
        context: ServiceContext,
    ) -> dict[str, object]:
        acquire_transaction_advisory_lock(self.db, "gate-policy-simulation-run", str(run_id))
        run = self._require_run(run_id, for_update=True)
        job = self.db.get(Job, job_id)
        if job is None or run.job_id != job.id:
            raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_JOB_NOT_FOUND", status_code=404)
        if run.status in {"completed", "partial", "failed", "cancelled", "timed_out"}:
            return self._run_projection(run, include_cases=False)
        run.status = "running"
        started_at = datetime.now(timezone.utc)
        run.started_at = started_at
        job.status = JobStatus.RUNNING
        job.started_at = run.started_at
        job.progress = 5
        self.db.commit()

        deadline = started_at + timedelta(seconds=timeout_seconds)
        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=None,
                root_span_name="gate_policy.simulation",
                span_name="gate_policy.simulation.evaluate",
                service_name="orchestrator-service",
                attributes={
                    "simulationRunId": str(run.id),
                    "datasetFingerprint": run.dataset_fingerprint,
                    "policyVersionHash": run.policy_version_hash,
                    "authoritative": False,
                },
            ):
                self._evaluate_run(run, deadline=deadline, source="simulation", job=job)
            if run.status != "cancelled":
                write_audit_log(
                    self.db,
                    str(context.user.id),
                    "gate_policy.simulation.result",
                    "gate_policy_simulation_run",
                    str(run.id),
                    context.request_id,
                    context.trace_id,
                    {
                        "status": run.status,
                        "datasetFingerprint": run.dataset_fingerprint,
                        "policyVersionHash": run.policy_version_hash,
                        "evaluatorVersion": run.evaluator_version,
                        "summary": run.summary,
                        "authoritative": False,
                        "writesGateDecision": False,
                    },
                )
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            run = self._require_run(run_id, for_update=True)
            job = self.db.get(Job, job_id)
            run.status = "failed"
            run.error_code = "GATE_POLICY_SIMULATION_FAILED"
            run.completed_at = datetime.now(timezone.utc)
            if job is not None:
                job.status = JobStatus.FAILED
                job.progress = 100
                job.error_message = "Gate Policy simulation failed"
                job.ended_at = run.completed_at
            write_audit_log(
                self.db,
                str(context.user.id),
                "gate_policy.simulation.failed",
                "gate_policy_simulation_run",
                str(run.id),
                context.request_id,
                context.trace_id,
                {"errorCode": run.error_code, "authoritative": False},
            )
            self.db.commit()
            raise GatePolicyGovernanceError(run.error_code, status_code=503) from exc
        return self._run_projection(self._require_run(run_id), include_cases=False)

    def list_simulations(
        self,
        *,
        project_id: UUID,
        page: int,
        page_size: int,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_READ)
        _project, tenant_id, workspace_id = GatePolicyGovernanceService(self.db)._project_scope(
            project_id, context, write=False
        )
        statement = select(GatePolicySimulationRun).where(
            GatePolicySimulationRun.project_id == project_id,
            GatePolicySimulationRun.tenant_id == tenant_id,
            GatePolicySimulationRun.workspace_id == workspace_id,
        )
        total = int(self.db.scalar(select(func.count()).select_from(statement.subquery())) or 0)
        rows = list(
            self.db.scalars(
                statement.order_by(GatePolicySimulationRun.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        return SimulationListProjection(
            items=[SimulationRun.model_validate(self._run_projection(item, include_cases=False)) for item in rows],
            total=total,
            page=page,
            pageSize=page_size,
        ).model_dump(mode="json")

    def get_simulation(
        self,
        *,
        project_id: UUID,
        run_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_READ)
        _project, tenant_id, workspace_id = GatePolicyGovernanceService(self.db)._project_scope(
            project_id, context, write=False
        )
        run = self.db.scalar(
            select(GatePolicySimulationRun).where(
                GatePolicySimulationRun.id == run_id,
                GatePolicySimulationRun.project_id == project_id,
                GatePolicySimulationRun.tenant_id == tenant_id,
                GatePolicySimulationRun.workspace_id == workspace_id,
            )
        )
        if run is None:
            raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_NOT_FOUND", status_code=404)
        return self._run_projection(run, include_cases=True)

    def cancel_simulation(
        self,
        *,
        project_id: UUID,
        run_id: UUID,
        payload: CancelSimulationRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_SIMULATE)
        _project, tenant_id, workspace_id = GatePolicyGovernanceService(self.db)._project_scope(
            project_id, context, write=True
        )
        run = self.db.scalar(
            select(GatePolicySimulationRun)
            .where(
                GatePolicySimulationRun.id == run_id,
                GatePolicySimulationRun.project_id == project_id,
                GatePolicySimulationRun.tenant_id == tenant_id,
                GatePolicySimulationRun.workspace_id == workspace_id,
            )
            .with_for_update()
        )
        if run is None:
            raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_NOT_FOUND", status_code=404)
        if run.status != payload.expectedStatus:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_STATUS_CONFLICT",
                status_code=409,
                details={"currentStatus": run.status},
            )
        self._preflight(
            context,
            action="simulation_cancel",
            resource_type="gate_policy_simulation_run",
            resource_id=run.id,
            payload={"status": run.status},
        )
        run.status = "cancelled"
        run.completed_at = datetime.now(timezone.utc)
        run.error_code = "GATE_POLICY_SIMULATION_CANCELLED"
        job = self.db.get(Job, run.job_id) if run.job_id else None
        if job is not None and job.status in {JobStatus.QUEUED, JobStatus.RUNNING}:
            job.status = JobStatus.CANCELLED
            job.progress = 100
            job.ended_at = run.completed_at
        write_audit_log(
            self.db,
            str(context.user.id),
            "gate_policy.simulation.cancel",
            "gate_policy_simulation_run",
            str(run.id),
            context.request_id,
            context.trace_id,
            {"reason": payload.reason, "authoritative": False},
        )
        self.db.commit()
        return self._run_projection(run, include_cases=True)

    def run_shadow_for_execution(
        self,
        *,
        execution_id: UUID,
        gate_decision_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object] | None:
        execution = self.db.get(Execution, execution_id)
        decision = self.db.get(GateDecision, gate_decision_id)
        if execution is None or decision is None:
            return None
        plan = self.db.get(TestPlan, execution.plan_id)
        if plan is None or plan.project_id is None:
            return None
        project_record, tenant_id, workspace_id = GatePolicyGovernanceService(self.db)._project_scope(
            plan.project_id, context, write=False
        )
        del project_record
        now = datetime.now(timezone.utc)
        bindings = list(self.db.scalars(
            select(GatePolicyBinding)
            .where(
                GatePolicyBinding.tenant_id == tenant_id,
                GatePolicyBinding.workspace_id == workspace_id,
                GatePolicyBinding.scope_type == GatePolicyScopeType.PROJECT,
                GatePolicyBinding.scope_key == str(plan.project_id),
                GatePolicyBinding.mode == GatePolicyMode.SHADOW,
                GatePolicyBinding.status == GatePolicyStatus.ACTIVE,
                GatePolicyBinding.effective_from <= now,
                (GatePolicyBinding.effective_until.is_(None) | (GatePolicyBinding.effective_until > now)),
            )
            .order_by(GatePolicyBinding.effective_from.desc(), GatePolicyBinding.id.desc())
        ))
        if not bindings:
            return None
        if len(bindings) > 1:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SHADOW_BINDING_CONFLICT", status_code=409
            )
        binding = bindings[0]
        snapshot = self.db.scalar(
            select(GateInputSnapshot).where(GateInputSnapshot.gate_decision_id == decision.id)
        )
        version = self.db.get(GatePolicyVersion, binding.policy_version_id)
        if snapshot is None or version is None or version.content_hash != binding.policy_version_hash:
            return None
        idempotency_key = f"shadow:{binding.id}:{decision.id}"
        existing = self.db.scalar(
            select(GatePolicySimulationRun).where(
                GatePolicySimulationRun.tenant_id == tenant_id,
                GatePolicySimulationRun.workspace_id == workspace_id,
                GatePolicySimulationRun.run_type == "shadow",
                GatePolicySimulationRun.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            return self._run_projection(existing, include_cases=True)
        ref = self._case_ref(snapshot, decision)
        run = GatePolicySimulationRun(
            id=uuid4(),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            project_id=plan.project_id,
            policy_id=version.policy_id,
            source_policy_version_id=None,
            policy_version_id=version.id,
            policy_version_hash=version.content_hash,
            evaluator_version=GATE_EVALUATOR_VERSION,
            run_type="shadow",
            status="running",
            dataset_fingerprint=canonical_hash([ref]),
            case_snapshot_refs=[ref],
            total_cases=1,
            idempotency_key=idempotency_key,
            request_hash=canonical_hash({"bindingId": str(binding.id), "gateDecisionId": str(decision.id)}),
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
            started_at=now,
            retention_until=now + timedelta(days=DEFAULT_RETENTION_DAYS),
        )
        self._preflight(
            context,
            action="shadow_evaluate",
            resource_type="gate_policy_simulation_run",
            resource_id=run.id,
            payload={"mode": "shadow", "bindingId": str(binding.id)},
        )
        self.db.add(run)
        self.db.flush()
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=execution.id,
            root_span_name="gate_policy.shadow",
            span_name="gate_policy.shadow.evaluate",
            service_name="execution-service",
            attributes={
                "simulationRunId": str(run.id),
                "bindingId": str(binding.id),
                "policyVersionHash": version.content_hash,
                "authoritative": False,
                "blocksGate": False,
            },
        ):
            self._evaluate_run(run, deadline=now + timedelta(seconds=60), source="shadow", job=None)
        write_audit_log(
            self.db,
            str(context.user.id),
            "gate_policy.shadow.evaluate",
            "gate_policy_simulation_run",
            str(run.id),
            context.request_id,
            context.trace_id,
            {
                "bindingId": str(binding.id),
                "gateDecisionId": str(decision.id),
                "authoritative": False,
                "writesGateDecision": False,
            },
            execution_id=execution.id,
        )
        self.db.commit()
        return self._run_projection(run, include_cases=True)

    def _evaluate_run(
        self,
        run: GatePolicySimulationRun,
        *,
        deadline: datetime,
        source: str,
        job: Job | None,
    ) -> None:
        version = self.db.get(GatePolicyVersion, run.policy_version_id)
        if (
            version is None
            or version.status != GatePolicyStatus.ACTIVE
            or version.content_hash != run.policy_version_hash
            or canonical_hash(version.policy_snapshot) != run.policy_version_hash
        ):
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_POLICY_INCOMPATIBLE", status_code=409
            )
        if run.evaluator_version != GATE_EVALUATOR_VERSION:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_EVALUATOR_INCOMPATIBLE", status_code=409
            )
        existing_cases = list(
            self.db.scalars(
                select(GatePolicySimulationCase).where(
                    GatePolicySimulationCase.simulation_run_id == run.id
                )
            )
        )
        if existing_cases:
            self._finalize_run(run, existing_cases, timed_out=False, job=job)
            return
        cases: list[GatePolicySimulationCase] = []
        timed_out = False
        for index, ref in enumerate(run.case_snapshot_refs):
            with self.db.no_autoflush:
                self.db.refresh(run)
            if run.status == "cancelled":
                self._discard_pending_cases(cases)
                if job is not None:
                    self.db.expire(job)
                return
            if datetime.now(timezone.utc) >= deadline:
                timed_out = True
                break
            case = self._evaluate_case(run, version, index, ref, source=source)
            self.db.add(case)
            cases.append(case)
            run.completed_cases = sum(item.status == "completed" for item in cases)
            run.unavailable_cases = sum(item.status == "unavailable" for item in cases)
            run.failed_cases = sum(item.status == "failed" for item in cases)
            if job is not None:
                job.progress = min(95, 5 + int(90 * len(cases) / max(run.total_cases, 1)))
        with self.db.no_autoflush:
            locked_run = self.db.scalar(
                select(GatePolicySimulationRun)
                .where(GatePolicySimulationRun.id == run.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        if locked_run is None:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_NOT_FOUND", status_code=404
            )
        if locked_run.status == "cancelled":
            self._discard_pending_cases(cases)
            if job is not None:
                self.db.expire(job)
            return
        self._finalize_run(locked_run, cases, timed_out=timed_out, job=job)

    def _discard_pending_cases(self, cases: list[GatePolicySimulationCase]) -> None:
        """Keep a concurrently cancelled run internally consistent."""

        for case in cases:
            if case in self.db:
                self.db.expunge(case)

    def _evaluate_case(
        self,
        run: GatePolicySimulationRun,
        version: GatePolicyVersion,
        index: int,
        ref: dict[str, object],
        *,
        source: str,
    ) -> GatePolicySimulationCase:
        snapshot_id = self._uuid_or_none(ref.get("snapshotId"))
        decision_id = self._uuid_or_none(ref.get("gateDecisionId"))
        snapshot = self.db.get(GateInputSnapshot, snapshot_id) if snapshot_id else None
        decision = self.db.get(GateDecision, decision_id) if decision_id else None
        base = {
            "id": uuid4(),
            "simulation_run_id": run.id,
            "case_index": index,
            "gate_input_snapshot_id": snapshot.id if snapshot else None,
            "gate_decision_id": decision.id if decision else None,
            "execution_id": decision.execution_id if decision else None,
            "gate_input_snapshot_ref": str(ref.get("snapshotRef") or f"unavailable://{index}"),
            "gate_input_snapshot_hash": str(ref.get("snapshotHash") or "sha256:" + "0" * 64),
            "input_fingerprint": str(ref.get("inputFingerprint")) if ref.get("inputFingerprint") else None,
            "case_snapshot_hash": str(ref.get("caseSnapshotHash") or canonical_hash(ref)),
        }
        if snapshot is None or decision is None or snapshot.gate_decision_id != decision.id:
            return GatePolicySimulationCase(
                **base,
                status="unavailable",
                error_code="GATE_POLICY_SIMULATION_CASE_UNAVAILABLE",
            )
        try:
            raw_input = self.execution_service.resolve_gate_input_snapshot(snapshot)
            if canonical_hash(raw_input) != snapshot.gate_input_snapshot_hash:
                raise ValueError("snapshot hash mismatch")
            if snapshot.gate_input_snapshot_hash != ref.get("snapshotHash"):
                raise ValueError("dataset snapshot changed")
            if decision.decision_snapshot_hash != ref.get("decisionSnapshotHash"):
                raise ValueError("decision snapshot changed")
            if (
                not decision.decision_snapshot_hash
                or canonical_hash(decision.decision_snapshot) != decision.decision_snapshot_hash
            ):
                raise ValueError("decision snapshot hash mismatch")
            decision_snapshot = dict(decision.decision_snapshot or {})
            old_decision = str(decision_snapshot.get("decision") or "")
            old_reason_codes = set(decision_snapshot.get("reasonCodes") or [])
            old_input = dict(decision_snapshot.get("input") or {})
            if old_decision not in {"pass", "warn", "fail", "blocked"}:
                raise ValueError("decision snapshot is incomplete")
            if (
                raw_input.get("inputFingerprint") != decision.input_fingerprint
                or decision.input_fingerprint != ref.get("inputFingerprint")
                or old_input.get("fingerprint") != decision.input_fingerprint
            ):
                raise ValueError("historical input fingerprint mismatch")
            gate_input = self._candidate_gate_input(raw_input, version, source=source)
            result = self.evaluator.evaluate(gate_input)
            new_reason_codes = set(result.reasonCodes)
            new_decision = result.decision
            false_pass_risk = old_decision in {"fail", "blocked"} and new_decision in {"pass", "warn"}
            new_block = old_decision in {"pass", "warn"} and new_decision in {"fail", "blocked"}
            return GatePolicySimulationCase(
                **base,
                status="completed",
                old_decision=old_decision,
                new_decision=new_decision,
                old_decision_snapshot_hash=decision.decision_snapshot_hash,
                new_decision_snapshot_hash=result.decisionSnapshotHash,
                reason_diff={
                    "addedReasonCodes": sorted(new_reason_codes - old_reason_codes),
                    "removedReasonCodes": sorted(old_reason_codes - new_reason_codes),
                },
                false_pass_risk=false_pass_risk,
                new_block=new_block,
            )
        except (ValueError, TypeError, KeyError):
            return GatePolicySimulationCase(
                **base,
                status="unavailable",
                old_decision=decision.overall.value,
                old_decision_snapshot_hash=decision.decision_snapshot_hash,
                error_code="GATE_POLICY_SIMULATION_CASE_INTEGRITY_UNAVAILABLE",
            )

    def _candidate_gate_input(
        self,
        raw_input: dict[str, object],
        version: GatePolicyVersion,
        *,
        source: str,
    ) -> GateInputContract:
        payload = deepcopy(raw_input)
        raw_execution_context = payload.get("executionContext")
        raw_evaluation_context = payload.get("evaluationContext")
        execution_context = (
            dict(raw_execution_context) if isinstance(raw_execution_context, dict) else {}
        )
        evaluation_context = (
            dict(raw_evaluation_context) if isinstance(raw_evaluation_context, dict) else {}
        )
        policy = validate_gate_policy_document(deepcopy(version.policy_snapshot))
        scope = dict(policy["scope"])
        request = {
            "schemaVersion": "phase8.gate-policy-resolution-request.v1",
            "tenantId": execution_context["tenantId"],
            "workspaceId": execution_context["workspaceId"],
            "projectId": execution_context.get("projectId"),
            "environment": execution_context.get("environmentId"),
            "stage": "GATE",
            "domain": None,
            "evaluationTime": evaluation_context["evaluationTime"],
        }
        resolution_snapshot = GatePolicyResolutionSnapshotContract.model_validate(
            {
                "schemaVersion": "phase8.gate-policy-resolution-snapshot.v1",
                "request": request,
                "source": source,
                "policyId": str(version.policy_id),
                "policyRef": f"gate-policy://{version.policy_id}",
                "policyKey": policy["identity"]["policyKey"],
                "policyVersionId": str(version.id),
                "policyVersionRef": version.version_ref,
                "policyVersionNumber": version.version_number,
                "policySchemaVersion": "gate-policy.v1",
                "policyVersionHash": version.content_hash,
                "binding": None,
                "resolvedScope": {"type": scope["type"], "scopeId": scope.get("scopeId")},
                "fallbackReason": "explicit_selection",
                "resolutionTrace": [
                    {
                        "scope": scope["type"],
                        "requestedScopeId": scope.get("scopeId"),
                        "outcome": "selected",
                        "reason": "explicit_selection",
                        "candidateCount": 1,
                        "checkedBindingRefs": [],
                    }
                ],
                "policy": policy,
            }
        ).model_dump(mode="json")
        payload["policySnapshot"] = resolution_snapshot
        payload["policySnapshotHash"] = canonical_hash(resolution_snapshot)
        raw_metadata = payload.get("metadata")
        metadata = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
        metadata.update(
            {
                "policySource": source,
                "authoritative": False,
                "writesGateDecision": False,
            }
        )
        payload["metadata"] = metadata
        payload["inputFingerprint"] = "sha256:" + "0" * 64
        normalized = GateInputContract.model_validate(payload)
        payload = normalized.model_dump(mode="json")
        payload["inputFingerprint"] = compute_gate_input_fingerprint(payload)
        return GateInputContract.model_validate(payload)

    def _freeze_simulation_candidate(
        self,
        policy: GatePolicy,
        source: GatePolicyVersion,
        context: ServiceContext,
    ) -> GatePolicyVersion:
        if source.status == GatePolicyStatus.ACTIVE:
            if canonical_hash(source.policy_snapshot) != source.content_hash:
                raise GatePolicyGovernanceError("GATE_POLICY_HASH_MISMATCH", status_code=409)
            return source
        if source.status != GatePolicyStatus.DRAFT:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_VERSION_UNAVAILABLE", status_code=409
            )
        if source.validation_status != "valid" or source.governance_status != "review_approved":
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_VERSION_NOT_APPROVED",
                status_code=409,
                details={
                    "validationStatus": source.validation_status,
                    "governanceStatus": source.governance_status,
                },
            )
        for candidate in self.db.scalars(
            select(GatePolicyVersion).where(
                GatePolicyVersion.policy_id == policy.id,
                GatePolicyVersion.tenant_id == source.tenant_id,
                GatePolicyVersion.workspace_id == source.workspace_id,
                GatePolicyVersion.status == GatePolicyStatus.ACTIVE,
            )
        ):
            if str((candidate.validation_report or {}).get("sourceDraftVersionId") or "") == str(source.id):
                return candidate
        acquire_transaction_advisory_lock(self.db, "gate-policy-publish-candidate", str(policy.id))
        # Re-read after taking the transaction-scoped lock. Two retrying API
        # requests may both pass the optimistic lookup above, but only one may
        # freeze the reviewed draft into an immutable simulation candidate.
        for candidate in self.db.scalars(
            select(GatePolicyVersion).where(
                GatePolicyVersion.policy_id == policy.id,
                GatePolicyVersion.tenant_id == source.tenant_id,
                GatePolicyVersion.workspace_id == source.workspace_id,
                GatePolicyVersion.status == GatePolicyStatus.ACTIVE,
            )
        ):
            if str((candidate.validation_report or {}).get("sourceDraftVersionId") or "") == str(source.id):
                return candidate
        next_number = int(
            self.db.scalar(
                select(func.max(GatePolicyVersion.version_number)).where(
                    GatePolicyVersion.policy_id == policy.id
                )
            )
            or 0
        ) + 1
        candidate_id = uuid4()
        snapshot = deepcopy(source.policy_snapshot)
        snapshot["version"] = {
            "versionId": str(candidate_id),
            "versionNumber": next_number,
        }
        snapshot["status"] = "active"
        snapshot = validate_gate_policy_document(snapshot)
        content_hash = canonical_hash(snapshot)
        candidate = GatePolicyVersion(
            id=candidate_id,
            policy_id=policy.id,
            tenant_id=source.tenant_id,
            workspace_id=source.workspace_id,
            version_number=next_number,
            version_ref=f"gate-policy-version://{candidate_id}",
            schema_version=source.schema_version,
            status=GatePolicyStatus.ACTIVE,
            policy_snapshot=snapshot,
            content_hash=content_hash,
            capability_ref=source.capability_ref,
            approval_policy_ref=source.approval_policy_ref,
            validation_status="valid",
            validation_report={
                "status": "valid",
                "contentHash": content_hash,
                "sourceDraftVersionId": str(source.id),
                "validatedAt": datetime.now(timezone.utc).isoformat(),
                "validatedBy": str(context.user.id),
                "errors": [],
                "warnings": [],
            },
            validated_at=datetime.now(timezone.utc),
            validated_by=context.user.id,
            governance_status="review_approved",
            created_by=context.user.id,
            updated_by=context.user.id,
        )
        self.db.add(candidate)
        self.db.flush()
        return candidate

    def _select_case_snapshot_refs(
        self,
        *,
        project_id: UUID,
        requested_ids: list[UUID],
        max_cases: int,
    ) -> list[dict[str, object]]:
        statement = (
            select(GateInputSnapshot, GateDecision)
            .join(GateDecision, GateDecision.id == GateInputSnapshot.gate_decision_id)
            .join(Execution, Execution.id == GateInputSnapshot.execution_id)
            .join(TestPlan, TestPlan.id == Execution.plan_id)
            .where(
                TestPlan.project_id == project_id,
                GateDecision.decision_snapshot_hash.is_not(None),
                GateDecision.input_fingerprint.is_not(None),
            )
            .order_by(GateInputSnapshot.created_at.desc(), GateInputSnapshot.id.desc())
        )
        if requested_ids:
            statement = statement.where(GateInputSnapshot.id.in_(requested_ids))
        rows = list(self.db.execute(statement.limit(min(max_cases, MAX_SIMULATION_CASES))).all())
        if requested_ids and {item.id for item, _decision in rows} != set(requested_ids):
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SIMULATION_CASE_NOT_FOUND", status_code=404
            )
        rows.sort(key=lambda item: str(item[0].id))
        return [self._case_ref(snapshot, decision) for snapshot, decision in rows]

    @staticmethod
    def _case_ref(snapshot: GateInputSnapshot, decision: GateDecision) -> dict[str, object]:
        ref = {
            "snapshotId": str(snapshot.id),
            "snapshotRef": snapshot.gate_input_snapshot_ref,
            "snapshotHash": snapshot.gate_input_snapshot_hash,
            "gateDecisionId": str(decision.id),
            "decisionSnapshotHash": decision.decision_snapshot_hash,
            "inputFingerprint": decision.input_fingerprint,
            "evaluatorVersion": decision.evaluator_version,
        }
        return {**ref, "caseSnapshotHash": canonical_hash(ref)}

    def _finalize_run(
        self,
        run: GatePolicySimulationRun,
        cases: list[GatePolicySimulationCase],
        *,
        timed_out: bool,
        job: Job | None,
    ) -> None:
        completed = [item for item in cases if item.status == "completed"]
        transitions: dict[str, int] = {}
        for item in completed:
            key = f"{item.old_decision}->{item.new_decision}"
            transitions[key] = transitions.get(key, 0) + 1
        run.completed_cases = len(completed)
        run.unavailable_cases = sum(item.status == "unavailable" for item in cases)
        run.failed_cases = sum(item.status == "failed" for item in cases)
        changed = sum(item.old_decision != item.new_decision for item in completed)
        summary = SimulationSummary(
            totalCases=run.total_cases,
            completedCases=run.completed_cases,
            changedCases=changed,
            unchangedCases=run.completed_cases - changed,
            falsePassRiskCount=sum(item.false_pass_risk for item in completed),
            newBlockCount=sum(item.new_block for item in completed),
            unavailableCases=run.unavailable_cases + max(0, run.total_cases - len(cases)),
            failedCases=run.failed_cases,
            decisionTransitions=transitions,
            complete=(not timed_out and len(cases) == run.total_cases and all(item.status == "completed" for item in cases)),
            authoritative=False,
        )
        run.summary = summary.model_dump(mode="json")
        run.completed_at = datetime.now(timezone.utc)
        if timed_out:
            run.status = "timed_out"
            run.error_code = "GATE_POLICY_SIMULATION_TIMED_OUT"
        elif summary.complete:
            run.status = "completed"
        elif completed:
            run.status = "partial"
            run.error_code = "GATE_POLICY_SIMULATION_PARTIAL"
        else:
            run.status = "failed"
            run.error_code = "GATE_POLICY_SIMULATION_NO_AVAILABLE_CASES"
        if job is not None:
            job.status = JobStatus.COMPLETED if run.status in {"completed", "partial"} else JobStatus.FAILED
            job.progress = 100
            job.result_ref = str(run.id)
            job.result_payload = {
                "simulationRunId": str(run.id),
                "status": run.status,
                "summary": run.summary,
                "authoritative": False,
            }
            job.error_message = run.error_code if job.status == JobStatus.FAILED else None
            job.ended_at = run.completed_at

    def _run_projection(self, run: GatePolicySimulationRun, *, include_cases: bool) -> dict[str, object]:
        cases = (
            list(
                self.db.scalars(
                    select(GatePolicySimulationCase)
                    .where(GatePolicySimulationCase.simulation_run_id == run.id)
                    .order_by(GatePolicySimulationCase.case_index.asc())
                )
            )
            if include_cases
            else []
        )
        summary = SimulationSummary.model_validate(run.summary) if run.summary else None
        payload = SimulationRun.model_validate(
            {
                "simulationRunId": run.id,
                "projectId": run.project_id,
                "policyId": run.policy_id,
                "sourcePolicyVersionId": run.source_policy_version_id,
                "policyVersionId": run.policy_version_id,
                "policyVersionHash": run.policy_version_hash,
                "evaluatorVersion": run.evaluator_version,
                "runType": run.run_type,
                "status": run.status,
                "datasetFingerprint": run.dataset_fingerprint,
                "totalCases": run.total_cases,
                "completedCases": run.completed_cases,
                "unavailableCases": run.unavailable_cases,
                "failedCases": run.failed_cases,
                "summary": summary,
                "cases": [self._case_projection(item) for item in cases],
                "jobId": run.job_id,
                "traceRef": f"trace://{run.trace_id}" if run.trace_id else None,
                "errorCode": run.error_code,
                "retentionUntil": self._aware(run.retention_until),
                "createdAt": self._aware(run.created_at),
                "startedAt": self._aware(run.started_at),
                "completedAt": self._aware(run.completed_at),
                "authoritative": False,
                "writesGateDecision": False,
            }
        )
        return payload.model_dump(mode="json")

    @staticmethod
    def _case_projection(case: GatePolicySimulationCase) -> SimulationCaseDiff:
        diff = case.reason_diff or {}
        return SimulationCaseDiff.model_validate(
            {
                "caseId": case.id,
                "caseIndex": case.case_index,
                "gateDecisionId": case.gate_decision_id,
                "executionId": case.execution_id,
                "gateInputSnapshotRef": case.gate_input_snapshot_ref,
                "gateInputSnapshotHash": case.gate_input_snapshot_hash,
                "inputFingerprint": case.input_fingerprint,
                "status": case.status,
                "oldDecision": case.old_decision,
                "newDecision": case.new_decision,
                "addedReasonCodes": list(diff.get("addedReasonCodes") or []),
                "removedReasonCodes": list(diff.get("removedReasonCodes") or []),
                "falsePassRisk": case.false_pass_risk,
                "newBlock": case.new_block,
                "errorCode": case.error_code,
                "authoritative": False,
            }
        )

    def _require_run(self, run_id: UUID, *, for_update: bool = False) -> GatePolicySimulationRun:
        statement = select(GatePolicySimulationRun).where(GatePolicySimulationRun.id == run_id)
        if for_update:
            statement = statement.with_for_update()
        run = self.db.scalar(statement)
        if run is None:
            raise GatePolicyGovernanceError("GATE_POLICY_SIMULATION_NOT_FOUND", status_code=404)
        return run

    @staticmethod
    def _uuid_or_none(value: object) -> UUID | None:
        try:
            return UUID(str(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _aware(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require_capability(context: ServiceContext, capability: str) -> None:
        if capability not in set(context.user.capabilities):
            raise GatePolicyGovernanceError(
                "CAPABILITY_REQUIRED", status_code=403, details={"capability": capability}
            )

    def _preflight(
        self,
        context: ServiceContext,
        *,
        action: str,
        resource_type: str,
        resource_id: UUID,
        payload: dict[str, object],
    ) -> None:
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type=resource_type,
            resource_id=str(resource_id),
            payload=payload,
            metadata={"action": action},
        )
        try:
            RuntimeGuardrailEngine(self.db).enforce(guardrail_context, [GatePolicyMutationGuard()])
        except GuardrailViolationError as exc:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_GUARDRAIL_BLOCKED",
                status_code=403,
                details={"ruleId": exc.result.rule_id, "decision": exc.result.decision.value},
            ) from exc

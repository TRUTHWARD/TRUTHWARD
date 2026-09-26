# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
from contextlib import contextmanager
from threading import Lock
from uuid import UUID
from weakref import WeakValueDictionary

from celery import Celery, __version__ as celery_version
from celery import chain, group
from sqlalchemy import text
from sqlalchemy.orm import Session

from agentic_qa.db.session import SessionLocal, engine
from agentic_qa.domain.enums import UserRole
from agentic_qa.infra.security import CurrentUser
from agentic_qa.infra.operational_controls import operational_metrics
from agentic_qa.infra.settings import get_settings
from agentic_qa.services.analysis_service import AnalysisService
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.execution_service import ExecutionService
from agentic_qa.services.gate_policy_simulation_service import GatePolicySimulationService
from agentic_qa.services.memory_service import MemoryService
from agentic_qa.services.plan_service import TestPlanService


settings = get_settings()
is_inline_mode = settings.queue_mode == "inline"
broker_url = "memory://" if is_inline_mode else settings.redis_url
backend_url = "cache+memory://" if is_inline_mode else settings.redis_url

celery_app = Celery(
    "agentic_qa",
    broker=broker_url,
    backend=backend_url,
)


TASK_QUEUE_CLASS = {
    "runtime.ping": "control",
    "plan.generate": "control",
    "execution.run": "control",
    "execution.run_task": "execution",
    "execution.finalize": "analysis",
    "execution.retry": "execution",
    "execution.heal": "analysis",
    "execution.gate": "analysis",
    "triage.rerun": "analysis",
    "gate_policy.simulate": "analysis",
    "memory.summarize": "maintenance",
    "memory.compress": "maintenance",
    "retention.mark_expired": "maintenance",
    "scm.webhook.process": "control",
    "admission.run": "execution",
    "requirement.pipeline.run": "execution",
}

_PIPELINE_LOCKS_GUARD = Lock()
_PIPELINE_LOCKS: WeakValueDictionary[UUID, Lock] = WeakValueDictionary()


def queue_name_for_task(task_name: str) -> str:
    """Return the configured queue without letting callers choose arbitrary routes."""

    if not settings.celery_queue_routing_enabled:
        return settings.celery_queue_name
    queue_class = TASK_QUEUE_CLASS.get(task_name, "control")
    return {
        "control": settings.celery_control_queue_name,
        "execution": settings.celery_execution_queue_name,
        "analysis": settings.celery_analysis_queue_name,
        "maintenance": settings.celery_maintenance_queue_name,
    }[queue_class]


TASK_ROUTES = {
    task_name: {"queue": queue_name_for_task(task_name)}
    for task_name in TASK_QUEUE_CLASS
}

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    task_default_queue=settings.celery_queue_name,
    task_routes=TASK_ROUTES,
    # Inline mode keeps tests and local smoke runs self-contained without Redis.
    task_always_eager=is_inline_mode,
    task_store_eager_result=False,
    # A worker must acknowledge only after the Service transaction completes.
    # Job handlers are idempotent and recover committed results on redelivery.
    task_acks_late=not is_inline_mode,
    task_reject_on_worker_lost=not is_inline_mode,
    worker_prefetch_multiplier=1,
    broker_transport_options=(
        {
            "visibility_timeout": (
                settings.celery_visibility_timeout_seconds
            )
        }
        if not is_inline_mode
        else {}
    ),
)

if settings.retention_maintenance_enabled:
    celery_app.conf.beat_schedule = {
        "mark-expired-retention-records": {
            "task": "retention.mark_expired",
            "schedule": settings.retention_scan_interval_seconds,
            "options": {"queue": queue_name_for_task("retention.mark_expired")},
        }
    }


@celery_app.task(name="runtime.ping")
def runtime_ping_job() -> dict[str, object]:
    return {
        "status": "ok",
        "queueMode": get_settings().queue_mode,
        "queueName": str(celery_app.conf.task_default_queue),
        "queueRoutingEnabled": settings.celery_queue_routing_enabled,
        "queueTopology": {
            name: queue_name_for_task(name)
            for name in sorted(TASK_QUEUE_CLASS)
        },
        "taskAlwaysEager": bool(celery_app.conf.task_always_eager),
        "workerPid": os.getpid(),
        "celeryVersion": celery_version,
    }


def enqueue_task(task_name: str, *args, _publish_retry: bool | None = None, **kwargs):
    """Dispatch a known Celery task and honor eager mode for tests/local dev."""

    task = celery_app.tasks[task_name]
    operational_metrics.increment("queue.dispatch.total")
    operational_metrics.increment(f"queue.dispatch.{TASK_QUEUE_CLASS.get(task_name, 'control')}")
    publish_options = {} if _publish_retry is None else {"retry": _publish_retry}
    return task.apply_async(
        args=args,
        kwargs=kwargs,
        queue=queue_name_for_task(task_name),
        **publish_options,
    )


def _build_context(actor_id: str, actor_roles: list[str], request_id: str, trace_id: str) -> ServiceContext:
    roles = actor_roles or [UserRole.SYSTEM.value]
    return ServiceContext(
        user=CurrentUser(
            id=UUID(str(actor_id)),
            name="queue-worker",
            email="queue-worker@example.com",
            roles=roles,
        ),
        request_id=request_id,
        trace_id=trace_id,
    )


@contextmanager
def _locked_requirement_pipeline_session(run_id: UUID):
    """Keep a PostgreSQL session lock across stage commits and worker redelivery."""
    if engine.dialect.name != "postgresql":
        with _PIPELINE_LOCKS_GUARD:
            lock = _PIPELINE_LOCKS.setdefault(run_id, Lock())
        if not lock.acquire(blocking=False):
            yield None
            return
        try:
            with SessionLocal() as db:
                yield db
        finally:
            lock.release()
        return

    lock_id = int.from_bytes(run_id.bytes[:8], byteorder="big", signed=True)
    with engine.connect() as connection:
        acquired = bool(connection.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": lock_id}).scalar())
        connection.commit()
        if not acquired:
            yield None
            return
        try:
            with Session(bind=connection) as db:
                yield db
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": lock_id})
            connection.commit()


@celery_app.task(name="requirement.pipeline.run")
def run_requirement_pipeline_job(run_id: str, actor_id: str, request_id: str, trace_id: str) -> dict[str, object]:
    """Run a persisted requirement selection; no document or credential enters the broker."""
    from agentic_qa.domain.models import User
    from agentic_qa.infra.security import CurrentUser
    from agentic_qa.services.capability_service import COMMUNITY_CAPABILITIES, CapabilityService
    from agentic_qa.services.orchestrator_service import OrchestratorService

    run_uuid = UUID(str(run_id))
    with _locked_requirement_pipeline_session(run_uuid) as db:
        if db is None:
            return {"orchestrationId": str(run_uuid), "status": "already_running"}
        user = db.get(User, UUID(str(actor_id)))
        deployment_profile = get_settings().deployment_profile
        if (
            user is not None
            and getattr(user.status, "value", user.status) == "active"
            and (deployment_profile != "oss" or user.edition == "community")
        ):
            edition, capabilities, projection = CapabilityService(db).effective_access_projection_for_user(
                user.id,
                user.edition,
                edition_override="community" if deployment_profile == "oss" else None,
                capability_ceiling=COMMUNITY_CAPABILITIES if deployment_profile == "oss" else None,
            )
            actor = CurrentUser(
                id=user.id,
                name=user.display_name or user.name,
                email=user.email,
                roles=[str(role) for role in (user.roles or [])],
                edition=edition,
                capabilities=capabilities,
                deployment_profile=deployment_profile,
                authorization_revision=str(projection["authorizationRevision"]),
            )
        else:
            actor = CurrentUser(
                id=UUID(str(actor_id)),
                name="unavailable-actor",
                email="unavailable-actor@example.invalid",
                roles=[],
                edition="community" if deployment_profile == "oss" else "basic",
                capabilities=[],
                deployment_profile=deployment_profile,
            )
        context = ServiceContext(user=actor, request_id=request_id, trace_id=trace_id)
        return OrchestratorService(db).run_queued_requirement_pipeline(run_uuid, context)


@celery_app.task(
    name="scm.webhook.process",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def process_scm_webhook_job(receipt_id: str, request_id: str, trace_id: str) -> dict[str, object]:
    """Retry the idempotent Service handler by receipt ID; no secret or raw payload enters the queue."""
    from agentic_qa.services.scm_pr_context_service import ScmPrContextService

    with SessionLocal() as db:
        return ScmPrContextService(db).process_receipt(
            UUID(str(receipt_id)),
            request_id=request_id,
            trace_id=trace_id,
        )


@celery_app.task(name="admission.run")
def run_admission_job(
    run_id: str,
    actor_id: str,
    actor_roles: list[str],
    request_id: str,
    trace_id: str,
) -> dict[str, object]:
    """Run only the service-owned P21 recipe; no command or source payload enters the queue."""
    from agentic_qa.services.admission_service import AdmissionService

    with SessionLocal() as db:
        return AdmissionService(db).run_job(
            UUID(str(run_id)),
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="plan.generate")
def generate_plan_job(job_id: str, plan_id: str, actor_id: str, actor_roles: list[str], request_id: str, trace_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        service = TestPlanService(db)
        return service.run_generate_plan_job(
            UUID(str(job_id)),
            UUID(str(plan_id)),
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="triage.rerun")
def rerun_triage_job(job_id: str, execution_id: str, actor_id: str, actor_roles: list[str], request_id: str, trace_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        service = AnalysisService(db)
        return service.run_triage_job(
            UUID(str(job_id)),
            UUID(str(execution_id)),
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="memory.summarize")
def summarize_memory_job(job_id: str, scope: str, namespace: str | None, actor_id: str, actor_roles: list[str], request_id: str, trace_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        service = MemoryService(db)
        return service.run_memory_job(
            UUID(str(job_id)),
            job_type="memory.summarize",
            scope=scope,
            namespace=namespace,
            context=_build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="memory.compress")
def compress_memory_job(job_id: str, scope: str, namespace: str | None, actor_id: str, actor_roles: list[str], request_id: str, trace_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        service = MemoryService(db)
        return service.run_memory_job(
            UUID(str(job_id)),
            job_type="memory.compress",
            scope=scope,
            namespace=namespace,
            context=_build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="retention.mark_expired")
def mark_expired_retention_records_job() -> dict[str, object]:
    """Mark bounded expired records eligible; destructive purge remains governed."""

    from agentic_qa.services.observability_service import ObservabilityService
    from agentic_qa.services.replay_repository_service import ReplayRepositoryService

    with SessionLocal() as db:
        batch_size = get_settings().retention_scan_batch_size
        audit_count = ObservabilityService(db).mark_expired_audit_logs_purge_eligible(
            batch_size=batch_size
        )
        replay_count = ReplayRepositoryService(
            db
        ).mark_expired_entries_purge_eligible(batch_size=batch_size)
        db.commit()
    operational_metrics.increment("retention.eligible.audit", audit_count)
    operational_metrics.increment("retention.eligible.replay", replay_count)
    return {
        "status": "completed",
        "auditLogCount": audit_count,
        "replayRepositoryCount": replay_count,
        "destructivePurgePerformed": False,
    }


@celery_app.task(bind=True, name="execution.run")
def run_execution_job(self, job_id: str, execution_id: str, actor_id: str, actor_roles: list[str], request_id: str, trace_id: str) -> dict[str, object]:
    context = _build_context(actor_id, actor_roles, request_id, trace_id)
    if not settings.execution_task_fanout_enabled or is_inline_mode:
        with SessionLocal() as db:
            service = ExecutionService(db)
            return service.run_execution_job(
                UUID(str(job_id)),
                UUID(str(execution_id)),
                context,
            )

    with SessionLocal() as db:
        service = ExecutionService(db)
        preparation = service.prepare_parallel_execution_job(
            UUID(str(job_id)),
            UUID(str(execution_id)),
            context,
        )
    raw_task_ids = preparation.get("taskIds")
    task_ids = (
        [str(task_id) for task_id in raw_task_ids]
        if isinstance(raw_task_ids, list)
        else []
    )
    if not task_ids:
        if preparation.get("status") == "running":
            with SessionLocal() as db:
                return ExecutionService(db).finalize_parallel_execution_job(
                    UUID(str(job_id)),
                    UUID(str(execution_id)),
                    context,
                )
        return preparation

    raw_parallelism = preparation.get("parallelism")
    parallelism = max(1, raw_parallelism if isinstance(raw_parallelism, int) else 1)
    batches = [task_ids[index:index + parallelism] for index in range(0, len(task_ids), parallelism)]
    workflow_steps = [
        group(
            run_execution_task_job.si(
                job_id,
                execution_id,
                task_id,
                actor_id,
                actor_roles,
                request_id,
                trace_id,
            ).set(queue=queue_name_for_task("execution.run_task"))
            for task_id in batch
        )
        for batch in batches
    ]
    workflow_steps.append(
        finalize_execution_job.si(
            job_id,
            execution_id,
            actor_id,
            actor_roles,
            request_id,
            trace_id,
        ).set(queue=queue_name_for_task("execution.finalize"))
    )
    operational_metrics.increment("execution.fanout.dispatched")
    operational_metrics.increment("execution.fanout.tasks", len(task_ids))
    return self.replace(chain(*workflow_steps))


@celery_app.task(name="execution.run_task")
def run_execution_task_job(
    job_id: str,
    execution_id: str,
    task_id: str,
    actor_id: str,
    actor_roles: list[str],
    request_id: str,
    trace_id: str,
) -> dict[str, object]:
    with SessionLocal() as db:
        return ExecutionService(db).run_parallel_execution_task_job(
            UUID(str(job_id)),
            UUID(str(execution_id)),
            UUID(str(task_id)),
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="execution.finalize")
def finalize_execution_job(
    job_id: str,
    execution_id: str,
    actor_id: str,
    actor_roles: list[str],
    request_id: str,
    trace_id: str,
) -> dict[str, object]:
    with SessionLocal() as db:
        return ExecutionService(db).finalize_parallel_execution_job(
            UUID(str(job_id)),
            UUID(str(execution_id)),
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="execution.retry")
def retry_execution_job(
    job_id: str,
    execution_id: str,
    scope: str,
    actor_id: str,
    actor_roles: list[str],
    request_id: str,
    trace_id: str,
) -> dict[str, object]:
    with SessionLocal() as db:
        service = ExecutionService(db)
        return service.run_retry_job(
            UUID(str(job_id)),
            UUID(str(execution_id)),
            scope,
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="execution.heal")
def heal_execution_job(
    job_id: str,
    execution_id: str,
    mode: str,
    actor_id: str,
    actor_roles: list[str],
    request_id: str,
    trace_id: str,
) -> dict[str, object]:
    with SessionLocal() as db:
        service = ExecutionService(db)
        return service.run_heal_job(
            UUID(str(job_id)),
            UUID(str(execution_id)),
            mode,
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="execution.gate")
def gate_execution_job(job_id: str, execution_id: str, actor_id: str, actor_roles: list[str], request_id: str, trace_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        service = ExecutionService(db)
        return service.run_gate_job(
            UUID(str(job_id)),
            UUID(str(execution_id)),
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )


@celery_app.task(name="gate_policy.simulate")
def simulate_gate_policy_job(
    run_id: str,
    job_id: str,
    timeout_seconds: int,
    actor_id: str,
    actor_roles: list[str],
    request_id: str,
    trace_id: str,
) -> dict[str, object]:
    with SessionLocal() as db:
        return GatePolicySimulationService(db).run_simulation_job(
            UUID(str(run_id)),
            UUID(str(job_id)),
            timeout_seconds,
            _build_context(actor_id, actor_roles, request_id, trace_id),
        )

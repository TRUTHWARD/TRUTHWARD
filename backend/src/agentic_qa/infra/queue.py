# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
from uuid import UUID

from celery import Celery, __version__ as celery_version

from agentic_qa.db.session import SessionLocal
from agentic_qa.domain.enums import UserRole
from agentic_qa.infra.security import CurrentUser
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

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    task_default_queue=settings.celery_queue_name,
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


@celery_app.task(name="runtime.ping")
def runtime_ping_job() -> dict[str, object]:
    return {
        "status": "ok",
        "queueMode": get_settings().queue_mode,
        "queueName": str(celery_app.conf.task_default_queue),
        "taskAlwaysEager": bool(celery_app.conf.task_always_eager),
        "workerPid": os.getpid(),
        "celeryVersion": celery_version,
    }


def enqueue_task(task_name: str, *args, **kwargs):
    """Dispatch a known Celery task and honor eager mode for tests/local dev."""

    task = celery_app.tasks[task_name]
    return task.apply_async(args=args, kwargs=kwargs)


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


@celery_app.task(name="execution.run")
def run_execution_job(job_id: str, execution_id: str, actor_id: str, actor_roles: list[str], request_id: str, trace_id: str) -> dict[str, object]:
    with SessionLocal() as db:
        service = ExecutionService(db)
        return service.run_execution_job(
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

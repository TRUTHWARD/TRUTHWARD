# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import JobStatus, MemoryScope, MemoryType
from agentic_qa.domain.models import Job, Memory, MemoryJob
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.runtime import MemoryWriteGuard, PromptSafetyGuard, RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.services.common import (
    IdempotencyConflictError,
    ServiceContext,
    acquire_transaction_advisory_lock,
    paginate_query,
    paginate_result,
)


class MemoryService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.guardrail_engine = RuntimeGuardrailEngine(db)
        self.prompt_safety_guard = PromptSafetyGuard()

    def create_memory(self, payload, context: ServiceContext) -> dict[str, object]:
        sanitized_content, sanitized_metadata, prompt_result = self.prompt_safety_guard.sanitize_text_and_metadata(
            payload.content,
            payload.metadata,
        )
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=context.user.roles,
            resource_type="memory",
            resource_id=payload.namespace,
            payload={
                "scope": payload.scope.value,
                "namespace": payload.namespace,
                "metadata": payload.metadata,
            },
        )
        self.guardrail_engine.record_result(guardrail_context, prompt_result)
        self.guardrail_engine.enforce(guardrail_context, [MemoryWriteGuard()])
        memory = Memory(
            id=uuid4(),
            type=payload.type,
            scope=payload.scope,
            namespace=payload.namespace,
            content=sanitized_content,
            metadata_json=sanitized_metadata,
        )
        self.db.add(memory)
        write_audit_log(self.db, str(context.user.id), "memory.create", "memory", str(memory.id), context.request_id, context.trace_id)
        self.db.commit()
        return {"id": str(memory.id)}

    def search(self, q: str, page: int, page_size: int, namespace: str | None = None, memory_type: str | None = None, scope: str | None = None) -> dict[str, object]:
        statement = select(Memory).where(Memory.archived.is_(False)).order_by(Memory.updated_at.desc())
        if q:
            statement = statement.where(Memory.content.ilike(f"%{q}%"))
        if namespace:
            statement = statement.where(Memory.namespace == namespace)
        if memory_type:
            statement = statement.where(Memory.type == memory_type)
        if scope:
            statement = statement.where(Memory.scope == scope)
        rows, total = paginate_query(self.db, statement, page, page_size)
        items = [
            {
                "id": str(row.id),
                "type": row.type.value,
                "scope": row.scope.value,
                "namespace": row.namespace,
                "content": row.content,
                "metadata": row.metadata_json,
            }
            for row in rows
        ]
        return paginate_result(items, total, page, page_size)

    def promote_test_knowledge_entry(self, entry: dict[str, object], context: ServiceContext) -> dict[str, object]:
        validated = validate_contract("test-knowledge-entry", entry)  # type: ignore[arg-type]
        content = validated["content"]
        summary = str(content.get("summary") or content.get("title") or validated["knowledgeId"])
        namespace = str(validated["metadata"].get("namespace") or "test-knowledge")
        existing_memories = self.db.scalars(
            select(Memory).where(
                Memory.type == MemoryType.SEMANTIC,
                Memory.scope == MemoryScope.PROJECT,
                Memory.namespace == namespace,
                Memory.archived.is_(False),
            )
        )
        for existing in existing_memories:
            existing_entry = existing.metadata_json.get("knowledgeEntry", {})
            if existing_entry.get("knowledgeId") != validated["knowledgeId"]:
                continue
            if existing_entry != validated:
                raise ValueError("conflicting Test Knowledge entry for existing knowledgeId")
            return {
                "id": str(existing.id),
                "knowledgeId": validated["knowledgeId"],
                "status": "promoted",
                "deduplicated": True,
            }
        memory_metadata = {
            "source": "test-knowledge",
            "verified": True,
            "confirmedFact": True,
            "knowledgeEntry": validated,
            "traceId": context.trace_id,
        }
        sanitized_summary, sanitized_metadata, prompt_result = self.prompt_safety_guard.sanitize_text_and_metadata(
            summary,
            memory_metadata,
        )
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=context.user.roles,
            resource_type="memory",
            resource_id=namespace,
            payload={
                "scope": MemoryScope.PROJECT.value,
                "namespace": namespace,
                "metadata": sanitized_metadata,
            },
        )
        self.guardrail_engine.record_result(guardrail_context, prompt_result)
        self.guardrail_engine.enforce(guardrail_context, [MemoryWriteGuard()])
        memory = Memory(
            id=uuid4(),
            type=MemoryType.SEMANTIC,
            scope=MemoryScope.PROJECT,
            namespace=namespace,
            content=sanitized_summary,
            metadata_json=sanitized_metadata,
        )
        self.db.add(memory)
        write_audit_log(self.db, str(context.user.id), "test_knowledge.promote", "memory", str(memory.id), context.request_id, context.trace_id)
        self.db.commit()
        return {
            "id": str(memory.id),
            "knowledgeId": validated["knowledgeId"],
            "status": "promoted",
            "deduplicated": False,
        }

    def promote_lesson_knowledge_entry(
        self,
        entry: dict[str, object],
        *,
        project_id: UUID,
        candidate_id: UUID,
        memory_type: str,
        raw_refs: list[dict[str, object]],
        context: ServiceContext,
    ) -> dict[str, object]:
        """Project a reviewed Lesson governance fact into existing Memory storage.

        This adapter is intentionally callable only from a Service-owned promotion
        workflow. Candidate generation, feedback, review, Skills, Tools, and
        Connectors never call it.
        """
        validated = validate_contract("test-knowledge-entry", entry)  # type: ignore[arg-type]
        if not raw_refs or not validated["evidenceRefs"] or not validated["sourceRefs"]:
            raise ValueError("Lesson promotion requires evidence, source, and raw refs")
        if validated["metadata"].get("confirmedFact") is not True:
            raise ValueError("Lesson promotion requires confirmedFact=true")
        selected_type = MemoryType(memory_type)
        namespace = f"lessons:{project_id}"
        source_ref = str(candidate_id)
        existing = self.db.scalar(
            select(Memory).where(
                Memory.type == selected_type,
                Memory.scope == MemoryScope.PROJECT,
                Memory.namespace == namespace,
                Memory.source_type == "lesson_candidate",
                Memory.source_ref == source_ref,
                Memory.archived.is_(False),
            )
        )
        if existing is not None:
            existing_entry = existing.metadata_json.get("knowledgeEntry", {})
            if existing_entry != validated:
                raise ValueError("conflicting Lesson knowledge for existing candidate")
            return {
                "id": str(existing.id),
                "knowledgeId": validated["knowledgeId"],
                "status": "promoted",
                "deduplicated": True,
            }

        content = validated["content"]
        summary = str(content.get("summary") or content.get("title") or validated["knowledgeId"])
        memory_metadata = {
            "source": "lesson_candidate",
            "verified": True,
            "confirmedFact": True,
            "projectId": str(project_id),
            "candidateId": str(candidate_id),
            "rawRefs": raw_refs,
            "knowledgeEntry": validated,
            "traceId": context.trace_id,
        }
        sanitized_summary, sanitized_metadata, prompt_result = self.prompt_safety_guard.sanitize_text_and_metadata(
            summary,
            memory_metadata,
        )
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=context.user.roles,
            resource_type="memory",
            resource_id=namespace,
            payload={
                "scope": MemoryScope.PROJECT.value,
                "namespace": namespace,
                "metadata": sanitized_metadata,
            },
        )
        self.guardrail_engine.record_result(guardrail_context, prompt_result)
        self.guardrail_engine.enforce(guardrail_context, [MemoryWriteGuard()])
        memory = Memory(
            id=uuid4(),
            type=selected_type,
            scope=MemoryScope.PROJECT,
            namespace=namespace,
            content=sanitized_summary,
            metadata_json=sanitized_metadata,
            source_type="lesson_candidate",
            source_ref=source_ref,
        )
        self.db.add(memory)
        write_audit_log(
            self.db,
            str(context.user.id),
            "lesson_knowledge.promote",
            "memory",
            str(memory.id),
            context.request_id,
            context.trace_id,
            {"projectId": str(project_id), "candidateId": str(candidate_id)},
        )
        self.db.commit()
        return {
            "id": str(memory.id),
            "knowledgeId": validated["knowledgeId"],
            "status": "promoted",
            "deduplicated": False,
        }

    def summarize(self, payload, context: ServiceContext) -> dict[str, object]:
        return self.enqueue_memory_job(
            job_type="memory.summarize",
            scope=payload.scope,
            namespace=payload.namespace,
            context=context,
        )

    def compress(self, payload, context: ServiceContext) -> dict[str, object]:
        return self.enqueue_memory_job(
            job_type="memory.compress",
            scope=payload.scope,
            namespace=payload.namespace,
            context=context,
        )

    def enqueue_memory_job(
        self,
        *,
        job_type: str,
        scope: MemoryScope,
        namespace: str | None,
        context: ServiceContext,
        idempotency_key: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        job_payload = {
            "scope": scope.value,
            "namespace": namespace,
            "metadata": metadata or {},
        }
        if idempotency_key:
            acquire_transaction_advisory_lock(
                self.db,
                "memory-job",
                idempotency_key,
            )
            existing = self.db.scalar(select(Job).where(Job.idempotency_key == idempotency_key))
            if existing is not None:
                if existing.job_type != job_type or existing.payload != job_payload:
                    raise IdempotencyConflictError(
                        f"idempotency conflict for memory job '{idempotency_key}'"
                    )
                return {"jobId": str(existing.id), "status": existing.status.value, "deduplicated": True}

        job = Job(
            id=uuid4(),
            job_type=job_type,
            status=JobStatus.QUEUED,
            progress=0,
            payload=job_payload,
            idempotency_key=idempotency_key,
        )
        self.db.add(job)
        self.db.flush()
        write_audit_log(
            self.db,
            str(context.user.id),
            "memory.job.enqueue",
            "job",
            str(job.id),
            context.request_id,
            context.trace_id,
            details={
                "jobType": job_type,
                "scope": scope.value,
                "namespace": namespace,
                "idempotencyKey": idempotency_key,
            },
        )
        self.db.commit()
        from agentic_qa.infra.queue import enqueue_task

        enqueue_task(
            job_type,
            str(job.id),
            scope.value,
            namespace,
            str(context.user.id),
            context.user.roles,
            context.request_id,
            context.trace_id,
        )
        return {"jobId": str(job.id), "status": JobStatus.QUEUED.value, "deduplicated": False}

    def run_memory_job(self, job_id: UUID, job_type: str, scope: str, namespace: str | None, context: ServiceContext) -> dict[str, object]:
        job = self._require_job(job_id)
        try:
            job.status = JobStatus.RUNNING
            job.progress = 20
            job.started_at = datetime.now(timezone.utc)
            self.db.flush()

            scope_enum = MemoryScope(scope)
            statement = select(Memory).where(Memory.archived.is_(False)).where(Memory.scope == scope_enum)
            if namespace:
                statement = statement.where(Memory.namespace == namespace)
            memories = list(self.db.scalars(statement.order_by(Memory.updated_at.desc())))
            job.progress = 70

            if job_type == "memory.summarize":
                namespace_count = len({memory.namespace for memory in memories})
                result_payload = {
                    "scope": scope,
                    "namespace": namespace,
                    "memoryCount": len(memories),
                    "namespaceCount": namespace_count,
                    "summary": f"summarized {len(memories)} memories across {namespace_count or 1} namespace(s)",
                }
                audit_action = "memory.summarize"
            else:
                duplicate_count = self._duplicate_content_count(memories)
                result_payload = {
                    "scope": scope,
                    "namespace": namespace,
                    "memoryCount": len(memories),
                    "duplicateCount": duplicate_count,
                    "compressed": True,
                }
                audit_action = "memory.compress"

            self.db.add(
                MemoryJob(
                    id=uuid4(),
                    job_type=job_type.split(".", 1)[1],
                    scope=scope_enum,
                    namespace=namespace,
                    status=JobStatus.COMPLETED,
                    progress=100,
                    result_payload=result_payload,
                )
            )
            write_audit_log(self.db, str(context.user.id), audit_action, "memory_job", str(job.id), context.request_id, context.trace_id)
            job.status = JobStatus.COMPLETED
            job.progress = 100
            job.result_payload = result_payload
            job.result_ref = namespace or scope
            job.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            return {"jobId": str(job.id), "status": job.status.value}
        except Exception as exc:
            self.db.rollback()
            job = self._require_job(job_id)
            job.status = JobStatus.FAILED
            job.progress = 100
            job.error_message = str(exc)
            job.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            raise

    def _require_job(self, job_id: UUID) -> Job:
        job = self.db.get(Job, job_id)
        if job is None:
            raise ValueError("job not found")
        return job

    def _duplicate_content_count(self, memories: list[Memory]) -> int:
        seen: dict[str, int] = {}
        duplicates = 0
        for memory in memories:
            seen[memory.content] = seen.get(memory.content, 0) + 1
        for count in seen.values():
            if count > 1:
                duplicates += count - 1
        return duplicates

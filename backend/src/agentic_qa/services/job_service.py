# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import Job
from agentic_qa.services.common import paginate_query, paginate_result


class JobService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_jobs(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        job_type: str | None = None,
    ) -> dict[str, object]:
        statement = select(Job).order_by(Job.created_at.desc())
        if status:
            statement = statement.where(Job.status == status)
        if job_type:
            statement = statement.where(Job.job_type == job_type)
        rows, total = paginate_query(self.db, statement, page, page_size)
        items = [self.serialize_job(job) for job in rows]
        return paginate_result(items, total, page, page_size)

    def get_job(self, job_id: UUID) -> dict[str, object]:
        job = self.db.get(Job, job_id)
        if job is None:
            raise ValueError("job not found")
        return self.serialize_job(job)

    def serialize_job(self, job: Job) -> dict[str, object]:
        return {
            "id": str(job.id),
            "jobType": job.job_type,
            "status": job.status.value,
            "progress": job.progress,
            "payload": job.payload,
            "result": job.result_payload,
            "resultRef": job.result_ref,
            "errorMessage": job.error_message,
            "startedAt": job.started_at.isoformat() if job.started_at else None,
            "endedAt": job.ended_at.isoformat() if job.ended_at else None,
            "createdAt": job.created_at.isoformat(),
            "updatedAt": job.updated_at.isoformat(),
        }

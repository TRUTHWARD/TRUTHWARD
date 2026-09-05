# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from agentic_qa.api.deps import get_current_user, get_db
from agentic_qa.api.responses import success_response
from agentic_qa.services.job_service import JobService


router = APIRouter(tags=["jobs"])


@router.get("/jobs")
def list_jobs(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default=None),
    jobType: str | None = Query(default=None),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = JobService(db)
    data = service.list_jobs(page=page, page_size=page_size, status=status, job_type=jobType)
    return success_response(request, data)


@router.get("/jobs/{job_id}")
def get_job(request: Request, job_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = JobService(db)
    try:
        data = service.get_job(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)

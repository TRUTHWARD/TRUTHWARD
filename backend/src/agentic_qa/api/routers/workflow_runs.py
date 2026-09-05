# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from agentic_qa.api.deps import get_current_user, get_db
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.workflow_runs import WorkflowRunProjection, WorkflowRunProjectionList
from agentic_qa.services.workflow_run_projection_service import WorkflowRunProjectionService


router = APIRouter(prefix="/workflow-runs", tags=["workflow-runs"])


@router.get("")
def list_workflow_runs(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    source: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    data = WorkflowRunProjectionService(db, user=user).list_runs(
        page=page,
        page_size=page_size,
        source=source,
        status=status_filter,
    )
    WorkflowRunProjectionList.model_validate(data)
    return success_response(request, data)


@router.get("/{run_id}")
def get_workflow_run(
    request: Request,
    run_id: UUID,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    try:
        data = WorkflowRunProjectionService(db, user=user).get_run(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    WorkflowRunProjection.model_validate(data)
    return success_response(request, data)

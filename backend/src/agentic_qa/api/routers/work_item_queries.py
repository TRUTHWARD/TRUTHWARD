# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from agentic_qa.api.deps import (
    capability_dependency,
    get_db,
    get_parent_span_id,
    get_request_id,
    get_trace_id,
)
from agentic_qa.api.responses import success_response
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.work_item_query_service import WorkItemQueryService


router = APIRouter(tags=["work-items"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
        parent_span_id=get_parent_span_id(request),
    )


def _raise_service_error(exc: Exception) -> None:
    if isinstance(exc, LookupError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/work-items")
def list_work_items(
    request: Request,
    project_id: UUID | None = Query(None, alias="projectId"),
    status_filter: str | None = Query(None, alias="status"),
    assignee_id: UUID | None = Query(None, alias="assigneeId"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    db=Depends(get_db),
    user=Depends(capability_dependency("work_items.read")),
) -> dict[str, object]:
    service = WorkItemQueryService(db)
    try:
        data = service.list_work_items(
            page,
            page_size,
            context=_context(request, user),
            project_id=project_id,
            status=status_filter,
            assignee_id=assignee_id,
        )
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data)


@router.get("/work-items/{work_item_id}")
def get_work_item(
    request: Request,
    work_item_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("work_items.read")),
) -> dict[str, object]:
    service = WorkItemQueryService(db)
    try:
        data = service.get_work_item(work_item_id, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data)


__all__ = ["router"]

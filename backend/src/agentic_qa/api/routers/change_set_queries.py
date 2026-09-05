# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from agentic_qa.api.deps import (
    capability_dependency,
    get_db,
    get_parent_span_id,
    get_request_id,
    get_trace_id,
)
from agentic_qa.api.responses import success_response
from agentic_qa.services.change_set_query_service import ChangeSetError, ChangeSetQueryService
from agentic_qa.services.common import ServiceContext


router = APIRouter(tags=["change-sets"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
        parent_span_id=get_parent_span_id(request),
    )


def _raise_http(exc: ChangeSetError) -> None:
    detail: dict[str, object] = {"errorCode": exc.code}
    if exc.field:
        detail["field"] = exc.field
    raise HTTPException(status_code=exc.status_code, detail=detail) from exc


@router.get("/projects/{project_id}/change-sets")
def list_change_sets(
    request: Request,
    project_id: UUID,
    change_set_type: str | None = Query(
        default=None, alias="changeSetType", pattern="^(requirement|code)$"
    ),
    status: str | None = Query(default=None, pattern="^(completed|partial|unknown)$"),
    environment_id: UUID | None = Query(default=None, alias="environmentId"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
    db=Depends(get_db),
    user=Depends(capability_dependency("change.read")),
) -> dict[str, object]:
    try:
        data = ChangeSetQueryService(db).list_change_sets(
            project_id,
            _context(request, user),
            page=page,
            page_size=page_size,
            change_set_type=change_set_type,
            status=status,
            environment_id=environment_id,
        )
    except ChangeSetError as exc:
        _raise_http(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}/change-sets/{change_set_id}")
def get_change_set(
    request: Request,
    project_id: UUID,
    change_set_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("change.read")),
) -> dict[str, object]:
    try:
        data = ChangeSetQueryService(db).get_change_set(
            project_id, change_set_id, _context(request, user)
        )
    except ChangeSetError as exc:
        _raise_http(exc)
    return success_response(request, data)


__all__ = ["router"]

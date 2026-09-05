# SPDX-License-Identifier: Apache-2.0
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
from agentic_qa.services.exploratory_session_query_service import ExploratorySessionQueryService
from agentic_qa.services.scope_service import ScopeAuthorizationError


router = APIRouter(tags=["exploratory-sessions"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
        parent_span_id=get_parent_span_id(request),
    )


@router.get("/exploratory-sessions")
def list_exploratory_sessions(
    request: Request,
    projectId: UUID | None = Query(default=None),
    environmentId: UUID | None = Query(default=None),
    sessionStatus: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.read")),
) -> dict[str, object]:
    try:
        data = ExploratorySessionQueryService(db).list_sessions(
            page,
            page_size,
            context=_context(request, user),
            project_id=projectId,
            environment_id=environmentId,
            status=sessionStatus,
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    return success_response(request, data)


@router.get("/exploratory-sessions/{session_id}")
def get_exploratory_session(
    request: Request,
    session_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.read")),
) -> dict[str, object]:
    try:
        data = ExploratorySessionQueryService(db).get_session(
            session_id,
            _context(request, user),
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    return success_response(request, data)


@router.get("/exploratory-sessions/{session_id}/report")
def get_exploratory_report(
    request: Request,
    session_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.read")),
) -> dict[str, object]:
    try:
        data = ExploratorySessionQueryService(db).get_report(
            session_id,
            _context(request, user),
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    return success_response(request, data)


def _http_error(exc: ValueError) -> HTTPException:
    if isinstance(exc, ScopeAuthorizationError):
        return HTTPException(status_code=exc.status_code, detail=exc.code)
    message = str(exc)
    code = status.HTTP_404_NOT_FOUND if "not found" in message else status.HTTP_400_BAD_REQUEST
    return HTTPException(status_code=code, detail=message)


__all__ = ["router"]

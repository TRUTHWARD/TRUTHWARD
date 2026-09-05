# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from agentic_qa.api.deps import (
    capability_dependency,
    get_db,
    get_request_id,
    get_trace_id,
)
from agentic_qa.api.responses import success_response
from agentic_qa.services.candidate_graph_query_service import (
    CandidateGraphError,
    CandidateGraphQueryService,
)
from agentic_qa.services.common import ServiceContext


router = APIRouter(tags=["candidate-execution-graph"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
    )


def _raise_http(exc: CandidateGraphError) -> None:
    detail: dict[str, object] = {"errorCode": exc.code}
    if exc.field:
        detail["field"] = exc.field
    raise HTTPException(status_code=exc.status_code, detail=detail) from exc


@router.get(
    "/internal/projects/{project_id}/execution-graph-candidates/builds",
    include_in_schema=False,
)
def list_execution_graph_candidate_builds(
    request: Request,
    project_id: UUID,
    graph_id: UUID | None = Query(default=None, alias="graphId"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100, alias="pageSize"),
    db=Depends(get_db),
    user=Depends(capability_dependency("graph.candidate.read")),
) -> dict[str, object]:
    try:
        data = CandidateGraphQueryService(db).list_builds(
            project_id,
            _context(request, user),
            graph_id=graph_id,
            page=page,
            page_size=page_size,
        )
    except CandidateGraphError as exc:
        _raise_http(exc)
    return success_response(request, data)


@router.get(
    "/internal/projects/{project_id}/execution-graph-candidates/builds/{build_id}",
    include_in_schema=False,
)
def get_execution_graph_candidate_build(
    request: Request,
    project_id: UUID,
    build_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("graph.candidate.read")),
) -> dict[str, object]:
    try:
        data = CandidateGraphQueryService(db).get_build(
            project_id,
            build_id,
            _context(request, user),
        )
    except CandidateGraphError as exc:
        _raise_http(exc)
    return success_response(request, data)


__all__ = ["router"]

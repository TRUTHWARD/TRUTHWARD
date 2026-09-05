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
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.impact_analysis_query_service import (
    ImpactAnalysisError,
    ImpactAnalysisQueryService,
    SelectiveReplayQueryService,
)


router = APIRouter(tags=["impact-analysis"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
        parent_span_id=get_parent_span_id(request),
    )


def _raise_http(exc: ImpactAnalysisError) -> None:
    detail: dict[str, object] = {"errorCode": exc.code}
    if exc.field:
        detail["field"] = exc.field
    raise HTTPException(status_code=exc.status_code, detail=detail) from exc


def _raise_replay_http(exc: ValueError) -> None:
    code = str(exc)
    if "CAPABILITY_REQUIRED" in code:
        status_code = 403
    elif "NOT_FOUND" in code:
        status_code = 404
    elif "IDEMPOTENCY_CONFLICT" in code or "HEAD_REVISION_MISMATCH" in code:
        status_code = 409
    else:
        status_code = 422
    raise HTTPException(status_code=status_code, detail={"errorCode": code}) from exc


@router.get("/projects/{project_id}/capability-mappings")
def list_capability_mappings(
    request: Request,
    project_id: UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
    db=Depends(get_db),
    user=Depends(capability_dependency("impact.read")),
) -> dict[str, object]:
    try:
        data = ImpactAnalysisQueryService(db).list_mappings(
            project_id, _context(request, user), page=page, page_size=page_size
        )
    except ImpactAnalysisError as exc:
        _raise_http(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}/impact-results")
def list_impact_results(
    request: Request,
    project_id: UUID,
    change_set_id: UUID | None = Query(default=None, alias="changeSetId"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
    db=Depends(get_db),
    user=Depends(capability_dependency("impact.read")),
) -> dict[str, object]:
    try:
        data = ImpactAnalysisQueryService(db).list_results(
            project_id,
            _context(request, user),
            change_set_id=change_set_id,
            page=page,
            page_size=page_size,
        )
    except ImpactAnalysisError as exc:
        _raise_http(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}/impact-results/{impact_result_id}")
def get_impact_result(
    request: Request,
    project_id: UUID,
    impact_result_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("impact.read")),
) -> dict[str, object]:
    try:
        data = ImpactAnalysisQueryService(db).get_result(
            project_id, impact_result_id, _context(request, user)
        )
    except ImpactAnalysisError as exc:
        _raise_http(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}/selective-replay-plans")
def list_selective_replay_plans(
    request: Request,
    project_id: UUID,
    impact_result_id: UUID | None = Query(default=None, alias="impactResultId"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.plan.read")),
) -> dict[str, object]:
    try:
        data = SelectiveReplayQueryService(db).list_selective_replay_plans(
            project_id,
            _context(request, user),
            impact_result_id=impact_result_id,
            page=page,
            page_size=page_size,
        )
    except ValueError as exc:
        _raise_replay_http(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}/selective-replay-plans/{plan_id}")
def get_selective_replay_plan(
    request: Request,
    project_id: UUID,
    plan_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.plan.read")),
) -> dict[str, object]:
    try:
        data = SelectiveReplayQueryService(db).get_selective_replay_plan(
            project_id, plan_id, _context(request, user)
        )
    except ValueError as exc:
        _raise_replay_http(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}/selective-replay-plans/{plan_id}/confirmation")
def get_selective_replay_confirmation(
    request: Request,
    project_id: UUID,
    plan_id: UUID,
    current_head_revision: str | None = Query(
        default=None,
        min_length=1,
        max_length=255,
        alias="currentHeadRevision",
    ),
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.plan.read")),
) -> dict[str, object]:
    try:
        data = SelectiveReplayQueryService(db).selective_replay_confirmation_projection(
            project_id,
            plan_id,
            _context(request, user),
            current_head_revision=current_head_revision,
        )
    except ValueError as exc:
        _raise_replay_http(exc)
    return success_response(request, data)


__all__ = ["router"]

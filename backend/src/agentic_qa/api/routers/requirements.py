# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response, status

from agentic_qa.api.deps import capability_dependency, get_db, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.core_loop import (
    ClarificationAnswerRequest,
    CorrectionApplyRequest,
    RequirementLibraryPipelineRequest,
    RequirementPipelineRequest,
)
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.core_loop_service import CoreLoopService
from agentic_qa.services.orchestrator_service import (
    OrchestrationConflictError,
    OrchestratorService,
    RequirementPipelineQueueUnavailable,
)
from agentic_qa.services.requirement_library_service import RequirementLibraryService
from agentic_qa.services.scope_service import ScopeAuthorizationError


router = APIRouter(tags=["requirements"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request))


def _raise_scope_error(exc: ScopeAuthorizationError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc


@router.post("/requirements/pipelines")
def create_requirement_pipeline(
    request: Request,
    payload: RequirementPipelineRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = OrchestratorService(db).run_requirement_pipeline(payload, _context(request, user))
    except ScopeAuthorizationError as exc:
        _raise_scope_error(exc)
    return success_response(request, data, "accepted")


@router.get("/requirements/library")
def list_requirement_library(
    request: Request,
    project_id: UUID | None = Query(default=None, alias="projectId"),
    environment_id: UUID | None = Query(default=None, alias="environmentId"),
    requirement_version_id: UUID | None = Query(default=None, alias="requirementVersionId"),
    source_type: str | None = Query(default=None, alias="sourceType"),
    status_filter: str | None = Query(default=None, alias="status"),
    keyword: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100, alias="pageSize"),
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.read")),
) -> dict[str, object]:
    try:
        data = RequirementLibraryService(db).list_library(
            page=page,
            page_size=page_size,
            project_id=project_id,
            environment_id=environment_id,
            requirement_version_id=requirement_version_id,
            source_type=source_type,
            status=status_filter,
            keyword=keyword,
            context=_context(request, user),
        )
    except ScopeAuthorizationError as exc:
        _raise_scope_error(exc)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/requirements/library/pipelines")
def create_requirement_library_pipeline(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    payload: RequirementLibraryPipelineRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    context = _context(request, user)
    defer_execution = user.edition == "community"
    try:
        data = OrchestratorService(db).run_requirement_library_pipeline(
            payload, context, defer_execution=defer_execution
        )
    except ScopeAuthorizationError as exc:
        _raise_scope_error(exc)
    except OrchestrationConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if defer_execution:
        response.status_code = status.HTTP_202_ACCEPTED
        try:
            OrchestratorService.dispatch_queued_requirement_pipeline(data, context, background_tasks.add_task)
        except RequirementPipelineQueueUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "PIPELINE_QUEUE_UNAVAILABLE", "orchestrationId": exc.orchestration_id},
            ) from exc
    return success_response(request, data, "accepted")


@router.get("/requirements/pipelines/{run_id}")
def get_requirement_pipeline(
    request: Request,
    run_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.read")),
) -> dict[str, object]:
    try:
        data = OrchestratorService(db).get_pipeline(run_id, _context(request, user))
    except ScopeAuthorizationError as exc:
        _raise_scope_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/requirements/pipelines/{run_id}/replay")
def replay_requirement_pipeline(
    request: Request,
    run_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.read")),
) -> dict[str, object]:
    try:
        data = OrchestratorService(db).replay_pipeline(run_id, _context(request, user))
    except ScopeAuthorizationError as exc:
        _raise_scope_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/requirements/pipelines/{run_id}/clarifications")
def list_requirement_clarifications(
    request: Request,
    run_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.read")),
) -> dict[str, object]:
    try:
        pipeline = OrchestratorService(db).get_pipeline(run_id, _context(request, user))
    except ScopeAuthorizationError as exc:
        _raise_scope_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    requirement_version_id = pipeline.get("requirementVersionId")
    if requirement_version_id is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="pipeline has no requirement version")
    return success_response(
        request,
        {"items": CoreLoopService(db).list_clarifications(UUID(str(requirement_version_id)))},
    )


@router.post("/requirements/pipelines/{run_id}/clarifications/{clarification_id}/answer")
def answer_requirement_clarification(
    request: Request,
    run_id: UUID,
    clarification_id: UUID,
    payload: ClarificationAnswerRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = OrchestratorService(db).answer_requirement_clarification(
            run_id,
            clarification_id,
            payload.answer,
            _context(request, user),
        )
    except OrchestrationConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/requirements/pipelines/{run_id}/corrections")
def apply_requirement_correction(
    request: Request,
    run_id: UUID,
    payload: CorrectionApplyRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = OrchestratorService(db).apply_requirement_correction(run_id, payload, _context(request, user))
    except OrchestrationConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/requirements/{requirement_version_id}/events")
def list_requirement_events(
    request: Request,
    requirement_version_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.read")),
) -> dict[str, object]:
    try:
        RequirementLibraryService(db).authorize_requirement_version(
            requirement_version_id,
            _context(request, user),
            write=False,
        )
    except ScopeAuthorizationError as exc:
        _raise_scope_error(exc)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    events = CoreLoopService(db).list_events("requirementVersionId", str(requirement_version_id))
    return success_response(request, {"items": events})

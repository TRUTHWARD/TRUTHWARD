# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from agentic_qa.api.deps import capability_dependency, get_current_user, get_db, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.guardrails.result import GuardrailViolationError
from agentic_qa.schemas.executions import CreateExecutionRequest, HealExecutionRequest, RetryExecutionRequest, UpdateFindingRequest
from agentic_qa.services.analysis_service import AnalysisService
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.execution_service import ExecutionService


router = APIRouter(tags=["executions"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
    )


def _authorize_execution(db, execution_id: UUID, request: Request, user, *, write: bool = False) -> None:
    try:
        ExecutionService(db).authorize_execution_scope(
            execution_id,
            _context(request, user),
            write=write,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="execution not found") from exc


def _authorize_task(db, task_id: UUID, request: Request, user) -> None:
    try:
        ExecutionService(db).authorize_task_scope(task_id, _context(request, user))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found") from exc


def _authorize_finding(db, finding_id: UUID, request: Request, user, *, write: bool = False) -> None:
    try:
        ExecutionService(db).authorize_finding_scope(
            finding_id,
            _context(request, user),
            write=write,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found") from exc


@router.post("/executions")
def create_execution(request: Request, payload: CreateExecutionRequest, db=Depends(get_db), user=Depends(capability_dependency("executions.manage"))) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        data = service.create_execution(payload, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data, "accepted")


@router.get("/executions")
def list_executions(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ExecutionService(db)
    return success_response(request, service.list_executions(page, page_size, _context(request, user)))


@router.get("/executions/{execution_id}")
def get_execution(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        data = service.get_execution(execution_id, _context(request, user))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/executions/{execution_id}/progress")
def get_progress(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        _authorize_execution(db, execution_id, request, user)
        data = service.progress(execution_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/executions/{execution_id}/cancel")
def cancel_execution(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(capability_dependency("executions.manage"))) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        data = service.cancel(execution_id, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/executions/{execution_id}/retry")
def retry_execution(request: Request, execution_id: UUID, payload: RetryExecutionRequest, db=Depends(get_db), user=Depends(capability_dependency("executions.manage"))) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        data = service.retry(execution_id, payload.scope, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data, "accepted")


@router.post("/executions/{execution_id}/heal")
def heal_execution(request: Request, execution_id: UUID, payload: HealExecutionRequest, db=Depends(get_db), user=Depends(capability_dependency("executions.manage"))) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        data = service.heal(execution_id, payload.mode, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except GuardrailViolationError:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data, "accepted")


@router.post("/executions/{execution_id}/gate")
def gate_execution(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(capability_dependency("executions.manage"))) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        data = service.gate(execution_id, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/executions/{execution_id}/tasks")
def list_tasks(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    _authorize_execution(db, execution_id, request, user)
    return success_response(request, service.list_tasks(execution_id))


@router.get("/tasks/{task_id}")
def get_task(request: Request, task_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        _authorize_task(db, task_id, request, user)
        data = service.get_task(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/tasks/{task_id}/artifacts")
def list_artifacts(request: Request, task_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    _authorize_task(db, task_id, request, user)
    return success_response(request, service.list_artifacts(task_id))


@router.get("/tasks/{task_id}/logs")
def list_logs(request: Request, task_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    _authorize_task(db, task_id, request, user)
    return success_response(request, service.list_logs(task_id))


@router.get("/tasks/{task_id}/metrics")
def list_metrics(request: Request, task_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    _authorize_task(db, task_id, request, user)
    return success_response(request, service.list_metrics(task_id))


@router.get("/executions/{execution_id}/triage")
def get_triage(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    _authorize_execution(db, execution_id, request, user)
    service = AnalysisService(db)
    return success_response(request, service.get_triage(execution_id))


@router.post("/executions/{execution_id}/triage")
def rerun_triage(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(capability_dependency("executions.manage"))) -> dict[str, object]:
    _authorize_execution(db, execution_id, request, user, write=True)
    service = AnalysisService(db)
    data = service.rerun_triage(execution_id, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    return success_response(request, data, "accepted")


@router.get("/executions/{execution_id}/healing")
def get_healing(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    _authorize_execution(db, execution_id, request, user)
    service = AnalysisService(db)
    return success_response(request, service.get_healing(execution_id))


@router.get("/executions/{execution_id}/failure-attribution")
def get_failure_attribution(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    _authorize_execution(db, execution_id, request, user)
    return success_response(request, AnalysisService(db).get_failure_attribution(execution_id))


@router.post("/executions/{execution_id}/regression-plan")
def create_regression_presentation(
    request: Request, execution_id: UUID, db=Depends(get_db),
    user=Depends(capability_dependency("executions.manage")),
) -> dict[str, object]:
    _authorize_execution(db, execution_id, request, user, write=True)
    try:
        data = ExecutionService(db).plan_regression(execution_id, context=_context(request, user))
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/executions/{execution_id}/regression-plan")
def get_regression_plan(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    try:
        _authorize_execution(db, execution_id, request, user)
        data = ExecutionService(db).plan_regression(execution_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/executions/{execution_id}/findings")
def list_findings(
    request: Request,
    execution_id: UUID,
    domain: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=100),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ExecutionService(db)
    _authorize_execution(db, execution_id, request, user)
    return success_response(
        request,
        service.list_findings(
            execution_id,
            domain=domain,
            severity=severity,
            page=page,
            page_size=page_size,
        ),
    )


@router.get("/executions/{execution_id}/visual-grounding-attempts")
def list_visual_grounding_attempts(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    _authorize_execution(db, execution_id, request, user)
    return success_response(request, service.list_visual_grounding_attempts(execution_id))


@router.get("/executions/{execution_id}/verification-results")
def list_verification_results(request: Request, execution_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    _authorize_execution(db, execution_id, request, user)
    return success_response(request, service.list_verification_results(execution_id))


@router.get("/findings/{finding_id}")
def get_finding(request: Request, finding_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        _authorize_finding(db, finding_id, request, user)
        data = service.get_finding(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.patch("/findings/{finding_id}")
def update_finding(request: Request, finding_id: UUID, payload: UpdateFindingRequest, db=Depends(get_db), user=Depends(capability_dependency("executions.manage"))) -> dict[str, object]:
    service = ExecutionService(db)
    try:
        _authorize_finding(db, finding_id, request, user, write=True)
        data = service.update_finding(
            finding_id,
            payload.status,
            payload.comment,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)

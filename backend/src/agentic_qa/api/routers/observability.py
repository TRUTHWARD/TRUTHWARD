# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import ValidationError

from agentic_qa.api.deps import capability_dependency, get_current_user, get_db, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.observability import AuditRetentionActionRequest
from agentic_qa.schemas.decision_timeline import (
    TimelineLifecycleStage,
    TimelineQuery,
)
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.decision_timeline_service import (
    DecisionTimelineError,
    DecisionTimelineProjectionService,
)
from agentic_qa.services.observability_service import (
    AuditRetentionConflictError,
    ObservabilityService,
    ReplayExportIntegrityError,
)


router = APIRouter(tags=["observability"])


@router.get("/traces")
def list_traces(
    request: Request,
    executionId: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ObservabilityService(db)
    data = service.list_traces(page=page, page_size=page_size, execution_id=executionId)
    return success_response(request, data)


@router.get("/traces/{trace_id}")
def get_trace(request: Request, trace_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ObservabilityService(db)
    try:
        data = service.get_trace(trace_id)
    except AuditRetentionConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/observability/executions/{execution_id}/decision-timeline")
def execution_decision_timeline(
    request: Request,
    execution_id: UUID,
    traceId: UUID | None = Query(default=None),
    lifecycleStage: list[TimelineLifecycleStage] | None = Query(default=None),
    eventType: list[str] | None = Query(default=None),
    eventStatus: list[str] | None = Query(default=None),
    actorType: list[str] | None = Query(default=None),
    occurredAfter: datetime | None = Query(default=None),
    occurredBefore: datetime | None = Query(default=None),
    cursor: str | None = Query(default=None, max_length=4096),
    snapshotAt: datetime | None = Query(default=None),
    page_size: int = Query(default=50, ge=1, le=200),
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.read")),
) -> dict[str, object]:
    try:
        query = TimelineQuery(
            executionId=execution_id,
            traceId=traceId,
            lifecycleStages=lifecycleStage or [],
            eventTypes=eventType or [],
            statuses=eventStatus or [],
            actorTypes=actorType or [],
            occurredAfter=occurredAfter,
            occurredBefore=occurredBefore,
            cursor=cursor,
            snapshotAt=snapshotAt,
            pageSize=page_size,
        )
        data = DecisionTimelineProjectionService(db).project(
            query,
            ServiceContext(
                user=user,
                request_id=get_request_id(request),
                trace_id=get_trace_id(request),
            ),
        )
    except DecisionTimelineError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"errorCode": exc.code},
        ) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"errorCode": "DECISION_TIMELINE_QUERY_INVALID"},
        ) from exc
    return success_response(request, data)


@router.get("/executions/{execution_id}/replay")
def replay_execution(
    request: Request,
    execution_id: UUID,
    compact: bool = Query(default=False),
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.read")),
) -> dict[str, object]:
    service = ObservabilityService(db)
    try:
        data = service.replay_execution(execution_id, compact=compact)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/executions/{execution_id}/replay/export")
def export_execution_replay(
    request: Request,
    execution_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.export.read")),
) -> dict[str, object]:
    service = ObservabilityService(db)
    try:
        data = service.export_execution_replay(execution_id, request_id=request.state.request_id, actor_id=user.id)
    except ReplayExportIntegrityError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/replay-exports")
def list_replay_exports(
    request: Request,
    executionId: UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.export.read")),
) -> dict[str, object]:
    try:
        data = ObservabilityService(db).list_replay_exports(
            page=page,
            page_size=page_size,
            execution_id=executionId,
        )
    except ReplayExportIntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return success_response(request, data)


@router.get("/replay-exports/{export_id}")
def get_replay_export(
    request: Request,
    export_id: str,
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.export.read")),
) -> dict[str, object]:
    service = ObservabilityService(db)
    try:
        data = service.get_replay_export(export_id)
    except ReplayExportIntegrityError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/executions/{execution_id}/replay/compare")
def compare_execution_replay(
    request: Request,
    execution_id: UUID,
    baselineExecutionId: UUID = Query(...),
    db=Depends(get_db),
    user=Depends(capability_dependency("replay.compare")),
) -> dict[str, object]:
    service = ObservabilityService(db)
    try:
        data = service.compare_replays(
            baseline_execution_id=baselineExecutionId,
            candidate_execution_id=execution_id,
            request_id=request.state.request_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/observability/minimum-metrics")
def minimum_observability_metrics(
    request: Request,
    executionId: UUID | None = Query(default=None),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    return success_response(request, ObservabilityService(db).minimum_observability_metrics(executionId))


@router.get("/observability/metrics")
def observability_metrics(
    request: Request,
    executionId: UUID | None = Query(default=None),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    return success_response(request, ObservabilityService(db).observability_metrics(executionId))


@router.get("/observability/quality-dashboard")
def quality_dashboard(
    request: Request,
    executionId: UUID | None = Query(default=None),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    return success_response(request, ObservabilityService(db).quality_dashboard(executionId))


@router.get("/observability/logs")
def structured_logs(
    request: Request,
    executionId: UUID | None = Query(default=None),
    traceId: UUID | None = Query(default=None),
    level: str | None = Query(default=None),
    component: str | None = Query(default=None),
    resourceType: str | None = Query(default=None),
    resourceId: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db=Depends(get_db),
    user=Depends(capability_dependency("audit.logs.read")),
) -> dict[str, object]:
    return success_response(
        request,
        ObservabilityService(db).list_structured_logs(
            page=page,
            page_size=page_size,
            execution_id=executionId,
            trace_id=traceId,
            level=level,
            component=component,
            resource_type=resourceType,
            resource_id=resourceId,
        ),
    )


@router.get("/observability/audit-log-projection")
def audit_log_projection(
    request: Request,
    executionId: UUID | None = Query(default=None),
    traceId: UUID | None = Query(default=None),
    level: str | None = Query(default=None),
    component: str | None = Query(default=None),
    resourceType: str | None = Query(default=None),
    resourceId: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db=Depends(get_db),
    user=Depends(capability_dependency("audit.logs.read")),
) -> dict[str, object]:
    return success_response(
        request,
        ObservabilityService(db).audit_log_projection(
            page=page,
            page_size=page_size,
            execution_id=executionId,
            trace_id=traceId,
            level=level,
            component=component,
            resource_type=resourceType,
            resource_id=resourceId,
        ),
    )


@router.get("/observability/audit-retention/policy")
def audit_retention_policy(
    request: Request,
    db=Depends(get_db),
    user=Depends(capability_dependency("audit.logs.read")),
) -> dict[str, object]:
    return success_response(request, ObservabilityService(db).audit_retention_policy())


@router.post("/observability/audit-retention/actions")
def request_audit_retention_action(
    request: Request,
    payload: AuditRetentionActionRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("audit.retention.manage")),
) -> dict[str, object]:
    try:
        data = ObservabilityService(db).request_audit_retention_action(
            payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except AuditRetentionConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)

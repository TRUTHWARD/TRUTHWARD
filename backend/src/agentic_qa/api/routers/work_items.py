# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from agentic_qa.api.deps import capability_dependency, get_db, get_parent_span_id, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.work_items import WorkItemAssignRequest, WorkItemCreateRequest, WorkItemTransitionRequest
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.work_item_service import WorkItemService


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


@router.post("/work-items")
def create_work_item(
    request: Request,
    payload: WorkItemCreateRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("work_items.manage")),
) -> dict[str, object]:
    service = WorkItemService(db)
    try:
        data = service.create_work_item(payload, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "created")


@router.post("/work-items/{work_item_id}/assign")
def assign_work_item(
    request: Request,
    work_item_id: UUID,
    payload: WorkItemAssignRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("work_items.manage")),
) -> dict[str, object]:
    service = WorkItemService(db)
    try:
        data = service.assign_work_item(work_item_id, payload, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "updated")


@router.post("/work-items/{work_item_id}/claim")
def claim_work_item(
    request: Request,
    work_item_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("work_items.manage")),
) -> dict[str, object]:
    service = WorkItemService(db)
    try:
        data = service.claim_work_item(work_item_id, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "updated")


@router.post("/work-items/{work_item_id}/transition")
def transition_work_item(
    request: Request,
    work_item_id: UUID,
    payload: WorkItemTransitionRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("work_items.manage")),
) -> dict[str, object]:
    service = WorkItemService(db)
    try:
        data = service.transition_work_item(work_item_id, payload, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "updated")

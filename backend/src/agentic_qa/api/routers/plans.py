# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from agentic_qa.api.deps import capability_dependency, get_current_user, get_db, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.plans import CreateTestPlanRequest, UpdateTestPlanRequest
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.plan_service import TestPlanService


router = APIRouter(tags=["test-plans"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
    )


@router.post("/test-plans")
def create_plan(request: Request, payload: CreateTestPlanRequest, db=Depends(get_db), user=Depends(capability_dependency("test_plans.manage"))) -> dict[str, object]:
    service = TestPlanService(db)
    try:
        data = service.create_plan(payload, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data, "created")


@router.get("/test-plans")
def list_plans(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = TestPlanService(db)
    return success_response(request, service.list_plans(page, page_size, _context(request, user)))


@router.get("/test-plans/{plan_id}")
def get_plan(request: Request, plan_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = TestPlanService(db)
    try:
        data = service.get_plan(plan_id, _context(request, user))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.put("/test-plans/{plan_id}")
def update_plan(request: Request, plan_id: UUID, payload: UpdateTestPlanRequest, db=Depends(get_db), user=Depends(capability_dependency("test_plans.manage"))) -> dict[str, object]:
    service = TestPlanService(db)
    try:
        data = service.update_plan(plan_id, payload, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.delete("/test-plans/{plan_id}")
def delete_plan(request: Request, plan_id: UUID, db=Depends(get_db), user=Depends(capability_dependency("test_plans.manage"))) -> dict[str, object]:
    service = TestPlanService(db)
    try:
        data = service.delete_plan(plan_id, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/test-plans/{plan_id}/generate")
def generate_plan(request: Request, plan_id: UUID, db=Depends(get_db), user=Depends(capability_dependency("test_plans.manage"))) -> dict[str, object]:
    service = TestPlanService(db)
    try:
        data = service.generate_plan(plan_id, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data, "accepted")


@router.get("/test-plans/{plan_id}/coverage")
def analyze_plan_coverage(request: Request, plan_id: UUID, db=Depends(get_db), user=Depends(capability_dependency("coverage.read"))) -> dict[str, object]:
    try:
        data = TestPlanService(db).analyze_coverage(plan_id, _context(request, user))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)

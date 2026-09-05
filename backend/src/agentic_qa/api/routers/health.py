# SPDX-License-Identifier: Apache-2.0
from fastapi import APIRouter, Depends, Request

from agentic_qa.api.deps import get_db
from agentic_qa.api.responses import success_response
from agentic_qa.services.health_service import HealthService


router = APIRouter(tags=["health"])


@router.get("/health")
def get_health(request: Request, db=Depends(get_db)) -> dict[str, object]:
    service = HealthService(db)
    return success_response(request, service.get_health())


@router.get("/readiness")
def get_readiness(request: Request, db=Depends(get_db)) -> dict[str, object]:
    service = HealthService(db)
    return success_response(request, service.get_readiness())

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from agentic_qa.api.deps import get_current_user, get_db
from agentic_qa.api.responses import success_response
from agentic_qa.services.agent_query_service import AgentCatalogQueryService


router = APIRouter(tags=["agents"])


@router.get("/agents")
def list_agents(
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = AgentCatalogQueryService(db)
    return success_response(request, service.list_agents())


@router.get("/agent-runs")
def list_agent_runs(
    request: Request,
    agentName: str | None = Query(default=None),
    executionId: str | None = Query(default=None),
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = AgentCatalogQueryService(db)
    data = service.list_runs(
        page=page,
        page_size=page_size,
        agent_name=agentName,
        execution_id=executionId,
        status=status,
    )
    return success_response(request, data)


__all__ = ["router"]

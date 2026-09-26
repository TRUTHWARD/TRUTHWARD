# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from agentic_qa.api.deps import (
    capability_dependency,
    get_db,
    get_parent_span_id,
    get_request_id,
    get_trace_id,
)
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.community_analysis import CommunityAnalysisMaterializeRequest
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.community_analysis_materialization_service import (
    CommunityAnalysisMaterializationError,
    CommunityAnalysisMaterializationService,
)


router = APIRouter(tags=["community-analysis"])


@router.post("/projects/{project_id}/coverage-materialization")
def materialize_community_coverage(
    request: Request,
    project_id: UUID,
    payload: CommunityAnalysisMaterializeRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("coverage.materialize")),
) -> dict[str, object]:
    context = ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
        parent_span_id=get_parent_span_id(request),
    )
    try:
        data = CommunityAnalysisMaterializationService(db).materialize(
            project_id,
            payload,
            context,
        )
    except CommunityAnalysisMaterializationError as exc:
        detail: dict[str, object] = {"errorCode": exc.code}
        if exc.field:
            detail["field"] = exc.field
        raise HTTPException(status_code=exc.status_code, detail=detail) from exc
    return success_response(request, data)


__all__ = ["router"]

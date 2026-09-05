# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from fastapi import HTTPException, Request, status

from agentic_qa.api.deps import get_parent_span_id, get_request_id, get_trace_id
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.scope_service import ScopeAuthorizationError


def project_settings_context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
        parent_span_id=get_parent_span_id(request),
    )


def raise_project_settings_error(exc: Exception) -> None:
    if isinstance(exc, ScopeAuthorizationError):
        detail: dict[str, object] = {"errorCode": exc.code}
        if exc.field:
            detail["field"] = exc.field
        raise HTTPException(status_code=exc.status_code, detail=detail) from exc
    if isinstance(exc, LookupError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


__all__ = ["project_settings_context", "raise_project_settings_error"]

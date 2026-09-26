# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from agentic_qa.api.deps import capability_dependency, get_db, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.exploratory_sessions import (
    AddExploratoryEvidenceRequest,
    AddExploratoryNoteRequest,
    CreateBugCandidateRequest,
    CreateExploratorySessionRequest,
    EndExploratorySessionRequest,
)
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.exploratory_session_service import (
    MAX_EXPLORATORY_IMAGE_BYTES,
    ExploratorySessionService,
)
from agentic_qa.services.scope_service import ScopeAuthorizationError


router = APIRouter(tags=["exploratory-sessions"])


@router.post("/exploratory-sessions")
def create_exploratory_session(
    request: Request,
    payload: CreateExploratorySessionRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.manage")),
) -> dict[str, object]:
    service = ExploratorySessionService(db)
    try:
        data = service.create_session(
            payload,
            ServiceContext(
                user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)
            ),
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    return success_response(request, data, "created")


@router.post("/exploratory-sessions/{session_id}/notes")
def add_exploratory_note(
    request: Request,
    session_id: UUID,
    payload: AddExploratoryNoteRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.manage")),
) -> dict[str, object]:
    try:
        data = ExploratorySessionService(db).add_note(
            session_id,
            payload,
            ServiceContext(
                user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)
            ),
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    return success_response(request, data, "created")


@router.post("/exploratory-sessions/{session_id}/evidence-refs")
def add_exploratory_evidence_ref(
    request: Request,
    session_id: UUID,
    payload: AddExploratoryEvidenceRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.manage")),
) -> dict[str, object]:
    try:
        data = ExploratorySessionService(db).add_evidence(
            session_id,
            payload,
            ServiceContext(
                user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)
            ),
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    return success_response(request, data, "created")


@router.post("/exploratory-sessions/{session_id}/evidence-uploads")
async def upload_exploratory_evidence_image(
    request: Request,
    session_id: UUID,
    file: UploadFile = File(...),
    summary: str | None = Form(default=None),
    confirm_safe: bool = Form(..., alias="confirmSafe"),
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.manage")),
) -> dict[str, object]:
    try:
        payload = await _read_bounded_upload(file)
        data = ExploratorySessionService(db).upload_evidence_image(
            session_id,
            filename=file.filename or "screenshot",
            content_type=file.content_type,
            payload=payload,
            summary=summary,
            confirm_safe=confirm_safe,
            context=ServiceContext(
                user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)
            ),
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    finally:
        await file.close()
    return success_response(request, data, "created")


@router.post("/exploratory-sessions/{session_id}/bug-candidates")
def create_exploratory_bug_candidate(
    request: Request,
    session_id: UUID,
    payload: CreateBugCandidateRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.manage")),
) -> dict[str, object]:
    try:
        data = ExploratorySessionService(db).create_bug_candidate(
            session_id,
            payload,
            ServiceContext(
                user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)
            ),
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    return success_response(request, data, "created")


@router.post("/exploratory-sessions/{session_id}/end")
def end_exploratory_session(
    request: Request,
    session_id: UUID,
    payload: EndExploratorySessionRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("exploratory_sessions.manage")),
) -> dict[str, object]:
    try:
        data = ExploratorySessionService(db).end_session(
            session_id,
            payload,
            ServiceContext(
                user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)
            ),
        )
    except ValueError as exc:
        raise _http_error(exc) from exc
    return success_response(request, data)


def _http_error(exc: ValueError) -> HTTPException:
    if isinstance(exc, ScopeAuthorizationError):
        return HTTPException(status_code=exc.status_code, detail=exc.code)
    message = str(exc)
    if message.startswith("EXPLORATORY_IMAGE_TOO_LARGE"):
        return HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=message)
    if message.startswith("EXPLORATORY_IMAGE_UNSUPPORTED"):
        return HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=message)
    if message.startswith(("EXPLORATORY_IMAGE_INVALID", "EXPLORATORY_IMAGE_CONFIRMATION_REQUIRED")):
        return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=message)
    code = status.HTTP_404_NOT_FOUND if "not found" in message else status.HTTP_400_BAD_REQUEST
    return HTTPException(status_code=code, detail=message)


async def _read_bounded_upload(file: UploadFile) -> bytes:
    payload = await file.read(MAX_EXPLORATORY_IMAGE_BYTES + 1)
    if len(payload) > MAX_EXPLORATORY_IMAGE_BYTES:
        raise ValueError("EXPLORATORY_IMAGE_TOO_LARGE")
    return payload


__all__ = ["router"]

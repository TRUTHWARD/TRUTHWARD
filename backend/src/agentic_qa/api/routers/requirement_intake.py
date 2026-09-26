# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status

from agentic_qa.api.deps import capability_dependency, get_db, get_parent_span_id, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.requirement_intake import (
    RequirementIntakeBatchConfirmRequest,
    RequirementIntakeBatchCreateRequest,
    RequirementIntakeBatchSourceRetryRequest,
    RequirementIntakeConfirmRequest,
    RequirementIntakeDraftCreateRequest,
    RequirementIntakePreviewCreateRequest,
)
from agentic_qa.services.common import IdempotencyConflictError, ServiceContext
from agentic_qa.services.orchestrator_service import OrchestrationConflictError
from agentic_qa.services.requirement_intake_service import (
    MAX_OCR_UPLOAD_BYTES,
    MAX_UPLOAD_BYTES,
    RequirementIntakeDuplicateError,
    RequirementIntakeService,
)
from agentic_qa.services.scope_service import ScopeAuthorizationError


router = APIRouter(prefix="/requirement-intake", tags=["requirement-intake"])


def _context(request: Request, user) -> ServiceContext:
    return ServiceContext(
        user=user,
        request_id=get_request_id(request),
        trace_id=get_trace_id(request),
        parent_span_id=get_parent_span_id(request),
    )


def _raise_service_error(exc: Exception) -> None:
    if isinstance(exc, ScopeAuthorizationError):
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
    if isinstance(exc, RequirementIntakeDuplicateError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": exc.code,
                "message": str(exc),
                "draftId": str(exc.draft_id),
                "previewId": str(exc.preview_id) if exc.preview_id else None,
                "linkedPipelineId": str(exc.linked_pipeline_id) if exc.linked_pipeline_id else None,
            },
        ) from exc
    if isinstance(exc, LookupError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if isinstance(exc, (OrchestrationConflictError, IdempotencyConflictError)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


def _parse_domains(value: str) -> list[str]:
    raw_value = (value or "").strip()
    if not raw_value:
        return ["functional", "performance", "security"]
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return [item.strip() for item in raw_value.split(",") if item.strip()]
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError("domains must be a JSON string array or comma-separated list")
    return parsed


def _parse_metadata(value: str | None) -> dict[str, object]:
    raw_value = (value or "{}").strip() or "{}"
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise ValueError("metadata must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("metadata must be a JSON object")
    return parsed


async def _read_bounded_upload(file: UploadFile, max_bytes: int) -> bytes:
    return await file.read(max_bytes + 1)


@router.post("/drafts")
def create_requirement_intake_draft(
    request: Request,
    payload: RequirementIntakeDraftCreateRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).create_draft(payload, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "created")


@router.get("/batches")
def list_requirement_intake_batches(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).list_batches(
            page=page,
            page_size=page_size,
            context=_context(request, user),
        )
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data)


@router.post("/batches")
def create_requirement_intake_batch(
    request: Request,
    payload: RequirementIntakeBatchCreateRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).create_batch(payload, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "created")


@router.post("/batches/uploads")
async def upload_requirement_intake_batch_sources(
    request: Request,
    files: list[UploadFile] = File(...),
    name: str = Form(...),
    sourceRef: str | None = Form(default=None),
    environment: str = Form(default="local"),
    projectId: UUID | None = Form(default=None),
    environmentId: UUID | None = Form(default=None),
    domains: str = Form(default='["functional","performance","security"]'),
    riskLevel: str = Form(default="medium"),
    metadata: str | None = Form(default="{}"),
    idempotencyKey: str | None = Form(default=None),
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        file_payloads = [
            {
                "fileName": file.filename or f"upload-{index}.txt",
                "contentType": file.content_type,
                "payload": await _read_bounded_upload(file, MAX_UPLOAD_BYTES),
            }
            for index, file in enumerate(files, start=1)
        ]
        data = RequirementIntakeService(db).create_upload_batch(
            name=name,
            files=file_payloads,
            source_ref=sourceRef,
            environment=environment,
            project_id=projectId,
            environment_id=environmentId,
            domains=_parse_domains(domains),
            risk_level=riskLevel,
            metadata=_parse_metadata(metadata),
            idempotency_key=idempotencyKey,
            context=_context(request, user),
        )
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "created")


@router.get("/batches/{batch_id}")
def get_requirement_intake_batch(
    request: Request,
    batch_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).get_batch(batch_id, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data)


@router.post("/batches/{batch_id}/confirm")
def confirm_requirement_intake_batch(
    request: Request,
    batch_id: UUID,
    payload: RequirementIntakeBatchConfirmRequest | None = None,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).confirm_batch(batch_id, _context(request, user), payload)
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "accepted")


@router.post("/batches/{batch_id}/sources/{source_id}/retry")
def retry_requirement_intake_batch_source(
    request: Request,
    batch_id: UUID,
    source_id: UUID,
    payload: RequirementIntakeBatchSourceRetryRequest | None = None,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).retry_batch_source(batch_id, source_id, _context(request, user), payload)
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "accepted")


@router.post("/uploads")
async def upload_requirement_intake_source(
    request: Request,
    file: UploadFile = File(...),
    name: str = Form(...),
    sourceRef: str | None = Form(default=None),
    environment: str = Form(default="local"),
    projectId: UUID | None = Form(default=None),
    environmentId: UUID | None = Form(default=None),
    domains: str = Form(default='["functional","performance","security"]'),
    riskLevel: str = Form(default="medium"),
    metadata: str | None = Form(default="{}"),
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).create_upload_draft_and_preview(
            file_name=file.filename or "upload.txt",
            content_type=file.content_type,
            payload=await _read_bounded_upload(file, MAX_UPLOAD_BYTES),
            name=name,
            source_ref=sourceRef,
            environment=environment,
            project_id=projectId,
            environment_id=environmentId,
            domains=_parse_domains(domains),
            risk_level=riskLevel,
            metadata=_parse_metadata(metadata),
            context=_context(request, user),
            allow_document_parsing=True,
        )
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "created")


@router.post("/ocr-uploads")
async def upload_requirement_intake_ocr_source(
    request: Request,
    file: UploadFile = File(...),
    name: str = Form(...),
    sourceRef: str | None = Form(default=None),
    environment: str = Form(default="local"),
    projectId: UUID | None = Form(default=None),
    environmentId: UUID | None = Form(default=None),
    domains: str = Form(default='["functional","performance","security"]'),
    riskLevel: str = Form(default="medium"),
    metadata: str | None = Form(default="{}"),
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).create_ocr_upload_draft_and_preview(
            file_name=file.filename or "ocr-source.pdf",
            content_type=file.content_type,
            payload=await _read_bounded_upload(file, MAX_OCR_UPLOAD_BYTES),
            name=name,
            source_ref=sourceRef,
            environment=environment,
            project_id=projectId,
            environment_id=environmentId,
            domains=_parse_domains(domains),
            risk_level=riskLevel,
            metadata=_parse_metadata(metadata),
            context=_context(request, user),
        )
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "created")


@router.get("/drafts/{draft_id}")
def get_requirement_intake_draft(
    request: Request,
    draft_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).get_draft(draft_id, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data)


@router.post("/drafts/{draft_id}/preview")
def create_requirement_intake_preview(
    request: Request,
    draft_id: UUID,
    payload: RequirementIntakePreviewCreateRequest | None = None,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).create_preview(
            draft_id,
            payload or RequirementIntakePreviewCreateRequest(),
            _context(request, user),
        )
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "created")


@router.get("/previews/{preview_id}")
def get_requirement_intake_preview(
    request: Request,
    preview_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).get_preview(preview_id, _context(request, user))
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data)


@router.post("/previews/{preview_id}/confirm")
def confirm_requirement_intake_preview(
    request: Request,
    preview_id: UUID,
    payload: RequirementIntakeConfirmRequest | None = None,
    db=Depends(get_db),
    user=Depends(capability_dependency("requirements.manage")),
) -> dict[str, object]:
    try:
        data = RequirementIntakeService(db).confirm_preview(preview_id, _context(request, user), payload)
    except Exception as exc:
        _raise_service_error(exc)
    return success_response(request, data, "accepted")

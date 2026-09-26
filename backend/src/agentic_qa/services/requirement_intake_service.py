# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit
from uuid import UUID, uuid4

import httpx
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from agentic_qa.connectors.contracts import ConnectorOperationRequest, ConnectorRuntime
from agentic_qa.connectors.requirement_docs import LarkRequirementDocsConnector, MockRequirementDocsConnector, ZentaoRequirementDocsConnector
from agentic_qa.domain.enums import GuardrailDecisionType, RiskLevel, TestDomain
from agentic_qa.domain.models import (
    GuardrailEvent,
    Project,
    ProjectEnvironment,
    RequirementIntakeBatch,
    RequirementIntakeBatchSource,
    RequirementIntakeDraft,
    RequirementIntakePreview,
    SkillConnectorBinding,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.artifact_storage import artifact_storage_adapter
from agentic_qa.infra.credentials import CredentialResolver
from agentic_qa.infra.redaction import (
    contains_unsafe_control_characters,
    redact_sensitive_data,
    redact_sensitive_text,
)
from agentic_qa.infra.safe_projection import ConnectorBindingSafeProjectionBuilder
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.core_loop import RequirementPipelineRequest
from agentic_qa.schemas.requirement_intake import (
    RequirementIntakeBatchConfirmRequest,
    RequirementIntakeBatchCreateRequest,
    RequirementIntakeBatchSourceCreateRequest,
    RequirementIntakeBatchSourceRetryRequest,
    RequirementIntakeConfirmRequest,
    RequirementIntakeDraftCreateRequest,
    RequirementIntakePreviewCreateRequest,
)
from agentic_qa.services.common import (
    IdempotencyConflictError,
    ServiceContext,
    acquire_transaction_advisory_lock,
    session_advisory_lock,
)
from agentic_qa.services.orchestrator_service import OrchestratorService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService
from agentic_qa.services.skill_service import SkillService
from agentic_qa.skills.integrations import IntegrationSkillInput
from agentic_qa.tools.document_parser import (
    DOCX_MIME_TYPE,
    MAX_DOCUMENT_BYTES,
    PDF_MIME_TYPE,
    DocumentTextParserAdapter,
    document_resource_limit_snapshot,
    document_text_parser_adapter,
)
from agentic_qa.tools.ocr_adapter import (
    MAX_OCR_INPUT_BYTES,
    OCR_IMAGE_MIME_TYPES,
    OCR_PDF_MIME_TYPE,
    OcrDocumentAdapter,
    ocr_document_adapter,
    ocr_resource_limit_snapshot,
)


PREFIX_PATTERN = re.compile(r"^\s*(?:[-*]\s*)?(?P<prefix>[A-Za-z][A-Za-z\s_-]{0,40}|需求|验收|验收标准)\s*[:：-]\s*(?P<value>.+?)\s*$")
SECTION_REQUIREMENT_MARKERS = ("requirement", "requirements", "req", "需求")
SECTION_ACCEPTANCE_MARKERS = ("acceptance", "acceptance criteria", "criteria", "ac", "验收", "验收标准")
MARKDOWN_HEADING_PATTERN = re.compile(r"^(?P<level>#{1,6})\s+(?P<title>.+?)\s*#*\s*$")
REQUIREMENT_HEADING_PATTERN = re.compile(
    r"^(?P<id>[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-[0-9]+)(?:\s+.+)?$",
    re.IGNORECASE,
)
ACCEPTANCE_HEADING_PATTERN = re.compile(r"^AC-(?:[A-Z0-9]+-)*[0-9]+(?:\s+.+)?$", re.IGNORECASE)
PREVIEW_PARSER_VERSION = "requirement-preview-markdown-v2"
SUPPORTED_SOURCE_TYPES = {"paste", "upload", "ocr_upload", "external_link", "connector"}
SUPPORTED_INTAKE_SOURCE_TYPES = ["paste", "upload", "ocr_upload", "external_link", "connector"]
SUPPORTED_REQUIREMENT_DOCUMENT_CONNECTORS = {"mock-requirement-docs", "lark-requirement-docs", "zentao-requirement-docs"}
SUPPORTED_UPLOAD_EXTENSIONS = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".csv": "text/csv",
}
SUPPORTED_DOCUMENT_UPLOAD_EXTENSIONS = {
    ".pdf": PDF_MIME_TYPE,
    ".docx": DOCX_MIME_TYPE,
}
SUPPORTED_SINGLE_UPLOAD_EXTENSIONS = {
    **SUPPORTED_UPLOAD_EXTENSIONS,
    **SUPPORTED_DOCUMENT_UPLOAD_EXTENSIONS,
}
SUPPORTED_UPLOAD_MIME_TYPES = {
    "",
    "application/csv",
    "application/json",
    "application/octet-stream",
    "text/csv",
    "text/markdown",
    "text/plain",
    "text/x-markdown",
}
SUPPORTED_SINGLE_UPLOAD_MIME_TYPES = {
    *SUPPORTED_UPLOAD_MIME_TYPES,
    PDF_MIME_TYPE,
    DOCX_MIME_TYPE,
}
MAX_UPLOAD_BYTES = MAX_DOCUMENT_BYTES
MAX_OCR_UPLOAD_BYTES = MAX_OCR_INPUT_BYTES
OCR_READY_CONFIDENCE = 0.85
OCR_BLOCK_CONFIDENCE = 0.50
SUPPORTED_OCR_UPLOAD_EXTENSIONS = {
    ".pdf": OCR_PDF_MIME_TYPE,
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".bmp": "image/bmp",
    ".webp": "image/webp",
}
SUPPORTED_OCR_UPLOAD_MIME_TYPES = {"", "application/octet-stream", OCR_PDF_MIME_TYPE, *OCR_IMAGE_MIME_TYPES}
MAX_EXTERNAL_LINK_BYTES = 1024 * 1024
MAX_CONNECTOR_DOCUMENT_BYTES = 1024 * 1024
EXTERNAL_LINK_TIMEOUT_SECONDS = 5.0
MAX_EXTERNAL_LINK_REDIRECTS = 3
SUPPORTED_EXTERNAL_LINK_EXTENSIONS = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".csv": "text/csv",
}
SUPPORTED_EXTERNAL_LINK_MIME_TYPES = {
    "",
    "application/csv",
    "application/json",
    "application/octet-stream",
    "application/xml",
    "application/x-ndjson",
    "application/x-yaml",
    "text/csv",
    "text/markdown",
    "text/plain",
    "text/x-markdown",
    "text/xml",
    "text/yaml",
}
SENSITIVE_URL_QUERY_KEY_FRAGMENTS = (
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "cookie",
    "credential",
    "key",
    "password",
    "secret",
    "session",
    "token",
)
SENSITIVE_URL_VALUE_PREFIXES = ("ghp_", "github_pat_", "sk-", "xoxb-", "xoxp-", "glpat-", "eyJ")


@dataclass(frozen=True, slots=True)
class ExternalLinkLocation:
    fetch_uri: str
    source_uri: str
    scheme: str
    host: str


@dataclass(frozen=True, slots=True)
class ExternalLinkDocument:
    document: str
    source_uri: str
    mime_type: str
    byte_size: int
    redaction_applied: bool
    extension: str


@dataclass(frozen=True, slots=True)
class ConnectorRequirementDocument:
    document: str
    external_document_id: str
    title: str
    source_uri: str
    mime_type: str
    content_version: str | None
    extension: str


@dataclass(frozen=True, slots=True)
class PreviewExtraction:
    requirements: list[str]
    acceptance_criteria: list[str]
    warnings: list[str]
    acceptance_by_requirement: list[list[str]] | None = None
    source_line_spans: list[tuple[int, int]] | None = None


class RequirementIntakeDuplicateError(ValueError):
    code = "REQUIREMENT_INTAKE_DUPLICATE"

    def __init__(
        self,
        *,
        draft_id: UUID,
        preview_id: UUID | None,
        linked_pipeline_id: UUID | None,
    ) -> None:
        super().__init__("the same requirement content already exists in this project and environment")
        self.draft_id = draft_id
        self.preview_id = preview_id
        self.linked_pipeline_id = linked_pipeline_id


class RequirementIntakeService:
    """Service-owned Draft/Preview intake for paste, upload, external link, and connector sources."""

    def __init__(
        self,
        db: Session,
        credential_resolver: CredentialResolver | None = None,
        document_parser: DocumentTextParserAdapter | None = None,
        ocr_adapter: OcrDocumentAdapter | None = None,
        connector_snapshot_builder: ConnectorBindingSafeProjectionBuilder | None = None,
    ) -> None:
        self.db = db
        self.credential_resolver = credential_resolver or CredentialResolver()
        self.document_parser = document_parser or document_text_parser_adapter()
        self.ocr_adapter = ocr_adapter or ocr_document_adapter()
        self.connector_snapshot_builder = connector_snapshot_builder or ConnectorBindingSafeProjectionBuilder()

    def create_batch(self, payload: RequirementIntakeBatchCreateRequest, context: ServiceContext) -> dict[str, object]:
        request_hash = self._batch_request_hash(payload)
        idempotency_key = (payload.idempotencyKey or "").strip()
        lock_key = f"{context.user.id}:{idempotency_key}" if idempotency_key else str(uuid4())
        with session_advisory_lock(
            self.db,
            "requirement-intake-batch",
            lock_key,
        ):
            return self._create_batch_locked(payload, context, request_hash)

    def _create_batch_locked(
        self,
        payload: RequirementIntakeBatchCreateRequest,
        context: ServiceContext,
        request_hash: str,
    ) -> dict[str, object]:
        existing = self._batch_for_idempotency(payload.idempotencyKey, context)
        if existing is not None:
            self._authorize_project_environment(
                existing.project_id,
                existing.environment_id,
                context,
                write=True,
            )
            if existing.metadata_json.get("idempotencyRequestHash") != request_hash:
                raise IdempotencyConflictError(
                    "idempotency conflict for requirement intake batch"
                )
            return self.serialize_batch(existing)
        self._authorize_project_environment(
            payload.projectId,
            payload.environmentId,
            context,
            write=True,
        )
        self._authorize_community_risk(payload.riskLevel, context)
        self._validate_batch_source_keys(payload.sources)
        batch = RequirementIntakeBatch(
            id=uuid4(),
            name=self._safe_user_text(payload.name, field_name="batch name"),
            idempotency_key=(payload.idempotencyKey or "").strip() or None,
            status="pending",
            environment=payload.environment.strip() or "local",
            project_id=payload.projectId,
            environment_id=payload.environmentId,
            domains=[domain.value for domain in payload.domains],
            risk_level=payload.riskLevel,
            summary={},
            trace_id=UUID(str(context.trace_id)),
            metadata_json={
                **redact_sensitive_data(dict(payload.metadata or {})),
                "source": "requirement-intake-batch",
                "sourceCount": len(payload.sources),
                "supportedSourceTypes": SUPPORTED_INTAKE_SOURCE_TYPES,
                "idempotencyRequestHash": request_hash,
            },
            created_by=context.user.id,
            updated_by=context.user.id,
        )
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="requirement_intake_batch",
            span_name="requirement_intake.batch.create",
            service_name="orchestrator-service",
            attributes={"sourceCount": len(payload.sources), "projectId": str(payload.projectId) if payload.projectId else None},
            parent_span_id=context.parent_span_id,
        ):
            self.db.add(batch)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "requirement_intake.batch.create",
                "requirement_intake_batch",
                str(batch.id),
                context.request_id,
                context.trace_id,
                details={"sourceCount": len(payload.sources), "idempotencyKey": batch.idempotency_key},
            )
        self.db.commit()
        self.db.refresh(batch)

        for index, source_payload in enumerate(payload.sources, start=1):
            source = self._create_batch_source_row(batch, source_payload, index, context)
            self._process_batch_source(batch, source, source_payload, context)
        self._refresh_batch_status(batch.id, context)
        return self.serialize_batch(self._require_batch(batch.id))

    def _batch_request_hash(
        self,
        payload: RequirementIntakeBatchCreateRequest,
    ) -> str:
        normalized = redact_sensitive_data(
            payload.model_dump(mode="json", exclude_none=True)
        )
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def create_upload_batch(
        self,
        *,
        name: str,
        files: list[dict[str, object]],
        source_ref: str | None,
        environment: str,
        project_id: UUID | None,
        environment_id: UUID | None,
        domains: list[str],
        risk_level: str,
        metadata: dict[str, Any],
        idempotency_key: str | None,
        context: ServiceContext,
    ) -> dict[str, object]:
        if not files:
            raise ValueError("batch upload requires at least one file")
        existing = self._batch_for_idempotency(idempotency_key, context)
        if existing is not None:
            self._authorize_project_environment(
                existing.project_id,
                existing.environment_id,
                context,
                write=True,
            )
            return self.serialize_batch(existing)
        self._authorize_project_environment(project_id, environment_id, context, write=True)
        parsed_domains = self._parse_domains(domains)
        parsed_risk = self._parse_risk_level(risk_level)
        self._authorize_community_risk(parsed_risk, context)
        batch = RequirementIntakeBatch(
            id=uuid4(),
            name=self._safe_user_text(name, field_name="batch name"),
            idempotency_key=(idempotency_key or "").strip() or None,
            status="pending",
            environment=environment.strip() or "local",
            project_id=project_id,
            environment_id=environment_id,
            domains=[domain.value for domain in parsed_domains],
            risk_level=parsed_risk,
            summary={},
            trace_id=UUID(str(context.trace_id)),
            metadata_json={
                **redact_sensitive_data(dict(metadata or {})),
                "source": "requirement-intake-batch-upload",
                "sourceCount": len(files),
                "supportedSourceTypes": SUPPORTED_INTAKE_SOURCE_TYPES,
            },
            created_by=context.user.id,
            updated_by=context.user.id,
        )
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="requirement_intake_batch",
            span_name="requirement_intake.batch.upload.create",
            service_name="orchestrator-service",
            attributes={"sourceCount": len(files), "projectId": str(project_id) if project_id else None},
            parent_span_id=context.parent_span_id,
        ):
            self.db.add(batch)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "requirement_intake.batch.upload.create",
                "requirement_intake_batch",
                str(batch.id),
                context.request_id,
                context.trace_id,
                details={"sourceCount": len(files), "idempotencyKey": batch.idempotency_key},
            )
        self.db.commit()
        self.db.refresh(batch)

        for index, file_data in enumerate(files, start=1):
            file_name = str(file_data.get("fileName") or f"upload-{index}.txt")
            source_payload = RequirementIntakeBatchSourceCreateRequest(
                sourceType="paste",
                sourceKey=f"upload:{index}:{file_name}",
                name=file_name,
                rawContent="upload source placeholder",
                sourceRef=f"{source_ref.rstrip('/')}/{file_name}" if source_ref else None,
                metadata={
                    "sourceType": "upload",
                    "fileName": file_name,
                    "contentType": file_data.get("contentType"),
                    "batchUpload": True,
                },
            )
            source = self._create_batch_source_row(batch, source_payload, index, context, source_type="upload")
            self._process_upload_batch_source(
                batch=batch,
                source=source,
                file_name=file_name,
                content_type=str(file_data.get("contentType") or "") or None,
                payload=bytes(file_data.get("payload") or b""),
                source_ref=source_payload.sourceRef,
                context=context,
            )
        self._refresh_batch_status(batch.id, context)
        return self.serialize_batch(self._require_batch(batch.id))

    def list_batches(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        safe_page = max(1, page)
        safe_page_size = min(max(1, page_size), 100)
        statement = select(RequirementIntakeBatch).order_by(RequirementIntakeBatch.created_at.desc())
        count_statement = select(RequirementIntakeBatch.id)
        if context is not None and (
            context.user.edition == "community"
            or not {"admin", "system"}.intersection(context.user.roles)
        ):
            authorized_project_ids = ScopeAuthorizationService(self.db).authorized_project_ids(context)
            if not authorized_project_ids:
                return {
                    "items": [],
                    "page": safe_page,
                    "pageSize": safe_page_size,
                    "total": 0,
                }
            statement = statement.where(RequirementIntakeBatch.project_id.in_(authorized_project_ids))
            count_statement = count_statement.where(RequirementIntakeBatch.project_id.in_(authorized_project_ids))
        rows = list(
            self.db.scalars(
                statement
                .offset((safe_page - 1) * safe_page_size)
                .limit(safe_page_size)
            )
        )
        total = len(list(self.db.scalars(count_statement)))
        return {
            "items": [self.serialize_batch(row, include_sources=False) for row in rows],
            "page": safe_page,
            "pageSize": safe_page_size,
            "total": total,
        }

    def get_batch(
        self,
        batch_id: UUID,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        batch = self._require_batch(batch_id)
        if context is not None:
            self._authorize_project_environment(
                batch.project_id,
                batch.environment_id,
                context,
                write=False,
            )
        return self.serialize_batch(batch)

    def confirm_batch(
        self,
        batch_id: UUID,
        context: ServiceContext,
        payload: RequirementIntakeBatchConfirmRequest | None = None,
    ) -> dict[str, object]:
        batch = self._require_batch(batch_id)
        self._authorize_project_environment(
            batch.project_id,
            batch.environment_id,
            context,
            write=True,
        )
        source_ids = [UUID(str(item)) for item in (payload.sourceIds or [])] if payload and payload.sourceIds else []
        sources = self._batch_sources(batch.id)
        if source_ids:
            requested = set(source_ids)
            sources = [source for source in sources if source.id in requested]
            unknown = requested - {source.id for source in sources}
            if unknown:
                raise ValueError(f"batch source not found: {next(iter(unknown))}")
        else:
            sources = [source for source in sources if source.status == "pending_confirm"]
        if not sources:
            raise ValueError("no pending batch sources selected for confirm")

        selected_by_source = dict(payload.selectedRequirementItemsBySource or {}) if payload else {}
        request_metadata = redact_sensitive_data(dict(payload.metadata or {})) if payload else {}
        for source in sources:
            if source.status == "confirmed":
                continue
            if source.status != "pending_confirm" or source.preview_id is None:
                source.status = "failed"
                source.error_message = "batch source is not ready for confirm"
                source.updated_by = context.user.id
                continue
            selected_items = selected_by_source.get(str(source.id))
            confirm_payload = RequirementIntakeConfirmRequest(
                selectedRequirementItems=selected_items,
                metadata={
                    **request_metadata,
                    "source": "requirement-intake-batch-confirm",
                    "batchId": str(batch.id),
                    "batchSourceId": str(source.id),
                },
            )
            try:
                result = self.confirm_preview(source.preview_id, context, confirm_payload)
                preview_payload = dict(result.get("preview") or {})
                source = self._require_batch_source(batch.id, source.id)
                source.status = "confirmed"
                source.linked_requirement_version_id = self._optional_uuid(preview_payload.get("linkedRequirementVersionId"))
                source.linked_pipeline_id = self._optional_uuid(preview_payload.get("linkedPipelineId"))
                source.artifact_refs = list(preview_payload.get("artifactRefs") or [])
                source.evidence_refs = list(preview_payload.get("evidenceRefs") or [])
                source.error_message = None
                source.metadata_json = {
                    **dict(source.metadata_json or {}),
                    "confirmedBy": str(context.user.id),
                    "confirmedAt": datetime.now(timezone.utc).isoformat(),
                    "selectedRequirementItemIds": preview_payload.get("metadata", {}).get("selectedRequirementItemIds", []),
                    "pipeline": result.get("pipeline"),
                }
                source.updated_by = context.user.id
            except Exception as exc:
                source = self._require_batch_source(batch.id, source.id)
                source.status = "failed"
                source.error_message = f"{type(exc).__name__}: {exc}"
                source.updated_by = context.user.id
        self._refresh_batch_status(batch.id, context)
        return self.serialize_batch(self._require_batch(batch.id))

    def retry_batch_source(
        self,
        batch_id: UUID,
        source_id: UUID,
        context: ServiceContext,
        payload: RequirementIntakeBatchSourceRetryRequest | None = None,
    ) -> dict[str, object]:
        batch = self._require_batch(batch_id)
        self._authorize_project_environment(
            batch.project_id,
            batch.environment_id,
            context,
            write=True,
        )
        source = self._require_batch_source(batch.id, source_id)
        if source.status == "confirmed":
            raise ValueError("confirmed batch source cannot be retried")
        source_request = payload.source if payload and payload.source else self._source_payload_from_metadata(source)
        source.retry_count = int(source.retry_count or 0) + 1
        source.status = "pending"
        source.error_message = None
        source.metadata_json = {
            **dict(source.metadata_json or {}),
            **(redact_sensitive_data(dict(payload.metadata or {})) if payload else {}),
            "retryRequestedAt": datetime.now(timezone.utc).isoformat(),
        }
        source.updated_by = context.user.id
        self.db.commit()
        self._process_batch_source(batch, source, source_request, context)
        self._refresh_batch_status(batch.id, context)
        return self.serialize_batch(self._require_batch(batch.id))

    def _create_batch_source_row(
        self,
        batch: RequirementIntakeBatch,
        payload: RequirementIntakeBatchSourceCreateRequest,
        ordinal: int,
        context: ServiceContext,
        *,
        source_type: str | None = None,
    ) -> RequirementIntakeBatchSource:
        effective_source_type = source_type or payload.sourceType
        source_key = (payload.sourceKey or f"{effective_source_type}:{ordinal}").strip()
        source = RequirementIntakeBatchSource(
            id=uuid4(),
            batch_id=batch.id,
            ordinal=ordinal,
            source_type=effective_source_type,
            source_key=source_key,
            status="pending",
            artifact_refs=[],
            evidence_refs=[],
            retry_count=0,
            metadata_json={
                "request": self._safe_source_request(payload),
                "batchId": str(batch.id),
                "sourceType": effective_source_type,
            },
            created_by=context.user.id,
            updated_by=context.user.id,
        )
        self.db.add(source)
        self.db.commit()
        self.db.refresh(source)
        return source

    def _process_batch_source(
        self,
        batch: RequirementIntakeBatch,
        source: RequirementIntakeBatchSource,
        payload: RequirementIntakeBatchSourceCreateRequest,
        context: ServiceContext,
    ) -> None:
        try:
            draft_payload = RequirementIntakeDraftCreateRequest(
                sourceType=payload.sourceType,
                name=(payload.name or f"{batch.name} source {source.ordinal}").strip(),
                rawContent=payload.rawContent,
                sourceUri=payload.sourceUri,
                connectorBindingId=payload.connectorBindingId,
                externalDocumentId=payload.externalDocumentId,
                sourceRef=payload.sourceRef,
                environment=batch.environment,
                projectId=batch.project_id,
                environmentId=batch.environment_id,
                domains=[TestDomain(value) for value in batch.domains],
                riskLevel=batch.risk_level,
                metadata={
                    **dict(payload.metadata or {}),
                    "source": "requirement-intake-batch",
                    "batchId": str(batch.id),
                    "batchSourceId": str(source.id),
                    "sourceKey": source.source_key,
                },
            )
            draft = self.create_draft(draft_payload, context)
            preview = self.create_preview(
                UUID(str(draft["draftId"])),
                RequirementIntakePreviewCreateRequest(
                    metadata={
                        "source": "requirement-intake-batch",
                        "batchId": str(batch.id),
                        "batchSourceId": str(source.id),
                    }
                ),
                context,
            )
            source = self._require_batch_source(batch.id, source.id)
            source.draft_id = UUID(str(draft["draftId"]))
            source.preview_id = UUID(str(preview["previewId"]))
            source.status = "pending_confirm"
            source.error_message = None
            source.artifact_refs = list(preview.get("artifactRefs") or draft.get("artifactRefs") or [])
            source.evidence_refs = list(preview.get("evidenceRefs") or draft.get("evidenceRefs") or [])
            source.metadata_json = {
                **dict(source.metadata_json or {}),
                "request": self._safe_source_request(payload),
                "draftId": str(draft["draftId"]),
                "previewId": str(preview["previewId"]),
                "requirementItemCount": len(list(preview.get("requirementItems") or [])),
                "processedAt": datetime.now(timezone.utc).isoformat(),
            }
            source.updated_by = context.user.id
            self.db.commit()
        except Exception as exc:
            source = self._require_batch_source(batch.id, source.id)
            source.status = "failed"
            source.error_message = str(exc)
            source.metadata_json = {
                **dict(source.metadata_json or {}),
                "request": self._safe_source_request(payload),
                "failedAt": datetime.now(timezone.utc).isoformat(),
            }
            source.updated_by = context.user.id
            self.db.commit()

    def _process_upload_batch_source(
        self,
        *,
        batch: RequirementIntakeBatch,
        source: RequirementIntakeBatchSource,
        file_name: str,
        content_type: str | None,
        payload: bytes,
        source_ref: str | None,
        context: ServiceContext,
    ) -> None:
        try:
            result = self.create_upload_draft_and_preview(
                file_name=file_name,
                content_type=content_type,
                payload=payload,
                name=file_name,
                source_ref=source_ref,
                environment=batch.environment,
                project_id=batch.project_id,
                environment_id=batch.environment_id,
                domains=list(batch.domains),
                risk_level=batch.risk_level.value,
                metadata={
                    "source": "requirement-intake-batch-upload",
                    "batchId": str(batch.id),
                    "batchSourceId": str(source.id),
                    "sourceKey": source.source_key,
                    "fileName": file_name,
                },
                context=context,
            )
            draft = dict(result.get("draft") or {})
            preview = dict(result.get("preview") or {})
            source = self._require_batch_source(batch.id, source.id)
            source.draft_id = UUID(str(draft["draftId"]))
            source.preview_id = UUID(str(preview["previewId"]))
            source.status = "pending_confirm"
            source.error_message = None
            source.artifact_refs = list(preview.get("artifactRefs") or draft.get("artifactRefs") or [])
            source.evidence_refs = list(preview.get("evidenceRefs") or draft.get("evidenceRefs") or [])
            source.metadata_json = {
                **dict(source.metadata_json or {}),
                "draftId": str(draft["draftId"]),
                "previewId": str(preview["previewId"]),
                "fileName": file_name,
                "contentType": content_type,
                "requirementItemCount": len(list(preview.get("requirementItems") or [])),
                "processedAt": datetime.now(timezone.utc).isoformat(),
            }
            source.updated_by = context.user.id
            self.db.commit()
        except Exception as exc:
            source = self._require_batch_source(batch.id, source.id)
            source.status = "failed"
            source.error_message = str(exc)
            source.metadata_json = {
                **dict(source.metadata_json or {}),
                "fileName": file_name,
                "contentType": content_type,
                "failedAt": datetime.now(timezone.utc).isoformat(),
                "retryPolicy": "upload retry requires resubmitting a valid file",
            }
            source.updated_by = context.user.id
            self.db.commit()

    def _refresh_batch_status(self, batch_id: UUID, context: ServiceContext | None = None) -> None:
        batch = self._require_batch(batch_id)
        sources = self._batch_sources(batch.id)
        total = len(sources)
        failed = sum(1 for source in sources if source.status == "failed")
        pending_confirm = sum(1 for source in sources if source.status == "pending_confirm")
        confirmed = sum(1 for source in sources if source.status == "confirmed")
        pending = sum(1 for source in sources if source.status == "pending")
        if total == 0 or pending:
            status = "pending"
        elif confirmed == total:
            status = "confirmed"
        elif confirmed > 0:
            status = "partially_confirmed"
        elif failed == total:
            status = "failed"
        elif failed > 0:
            status = "partially_failed"
        else:
            status = "ready"
        batch.status = status
        batch.summary = {
            "totalSources": total,
            "pendingSources": pending,
            "pendingConfirmSources": pending_confirm,
            "failedSources": failed,
            "confirmedSources": confirmed,
            "successfulSources": pending_confirm + confirmed,
        }
        if context is not None:
            batch.updated_by = context.user.id
        self.db.commit()

    def _batch_for_idempotency(self, idempotency_key: str | None, context: ServiceContext) -> RequirementIntakeBatch | None:
        key = (idempotency_key or "").strip()
        if not key:
            return None
        return self.db.scalar(
            select(RequirementIntakeBatch).where(
                RequirementIntakeBatch.created_by == context.user.id,
                RequirementIntakeBatch.idempotency_key == key,
            )
        )

    def _validate_batch_source_keys(self, sources: list[RequirementIntakeBatchSourceCreateRequest]) -> None:
        seen: set[str] = set()
        for index, source in enumerate(sources, start=1):
            key = (source.sourceKey or f"{source.sourceType}:{index}").strip()
            if key in seen:
                raise ValueError(f"duplicate batch sourceKey: {key}")
            seen.add(key)

    def _safe_source_request(self, payload: RequirementIntakeBatchSourceCreateRequest) -> dict[str, Any]:
        snapshot = redact_sensitive_data(payload.model_dump(mode="json", exclude_none=True))
        raw_content = snapshot.get("rawContent")
        if isinstance(raw_content, str):
            snapshot["rawContent"] = self._normalize_paste_content(raw_content)[0]
        source_uri = snapshot.get("sourceUri")
        if isinstance(source_uri, str):
            snapshot["sourceUri"] = self._safe_source_uri_for_error(source_uri)
        return snapshot

    def _optional_uuid(self, value: Any) -> UUID | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text.lower() == "none":
            return None
        try:
            return UUID(text)
        except (TypeError, ValueError, AttributeError):
            return None

    def _source_payload_from_metadata(self, source: RequirementIntakeBatchSource) -> RequirementIntakeBatchSourceCreateRequest:
        if source.source_type == "upload":
            raise ValueError("upload batch source retry requires resubmitting the file in a new batch")
        request_payload = dict((source.metadata_json or {}).get("request") or {})
        if not request_payload:
            raise ValueError("batch source retry request snapshot is unavailable")
        return RequirementIntakeBatchSourceCreateRequest(**request_payload)

    def _batch_sources(self, batch_id: UUID) -> list[RequirementIntakeBatchSource]:
        return list(
            self.db.scalars(
                select(RequirementIntakeBatchSource)
                .where(RequirementIntakeBatchSource.batch_id == UUID(str(batch_id)))
                .order_by(RequirementIntakeBatchSource.ordinal.asc())
            )
        )

    def _require_batch(self, batch_id: UUID) -> RequirementIntakeBatch:
        batch = self.db.get(RequirementIntakeBatch, UUID(str(batch_id)))
        if batch is None:
            raise LookupError("requirement intake batch not found")
        return batch

    def _require_batch_source(self, batch_id: UUID, source_id: UUID) -> RequirementIntakeBatchSource:
        normalized_batch_id = UUID(str(batch_id))
        source = self.db.get(RequirementIntakeBatchSource, UUID(str(source_id)))
        if source is None or UUID(str(source.batch_id)) != normalized_batch_id:
            raise LookupError("requirement intake batch source not found")
        return source

    def create_draft(self, payload: RequirementIntakeDraftCreateRequest, context: ServiceContext) -> dict[str, object]:
        if payload.sourceType == "connector":
            return self._create_connector_draft(payload, context)
        if payload.sourceType == "external_link":
            return self._create_external_link_draft(payload, context)
        if payload.sourceType != "paste":
            raise ValueError("only paste, external_link, and connector sourceType are supported")
        self._authorize_project_environment(
            payload.projectId,
            payload.environmentId,
            context,
            write=True,
        )
        self._authorize_community_risk(payload.riskLevel, context)
        draft_id = uuid4()
        raw_content = payload.rawContent or ""
        try:
            normalized_document, redaction_applied = self._normalize_paste_content(raw_content)
        except ValueError as exc:
            self._record_paste_guardrail(
                context=context,
                decision=GuardrailDecisionType.BLOCK,
                message=str(exc),
                draft_id=None,
                redaction_status="blocked",
                byte_size=len(raw_content.encode("utf-8")),
            )
            self.db.commit()
            raise
        content_bytes = normalized_document.encode("utf-8")
        content_hash = self._content_hash(content_bytes)
        self._raise_if_duplicate_content(
            content_hash=content_hash,
            normalized_document=normalized_document,
            project_id=payload.projectId,
            environment_id=payload.environmentId,
            created_by=context.user.id,
        )
        metadata = {
            **redact_sensitive_data(dict(payload.metadata or {})),
            "sourceType": payload.sourceType,
            "redactionApplied": redaction_applied,
            "supportedSourceTypes": SUPPORTED_INTAKE_SOURCE_TYPES,
        }
        source_ref = self._safe_user_text(
            payload.sourceRef or f"requirement-intake/paste/{draft_id}",
            field_name="sourceRef",
        )
        if not source_ref:
            source_ref = f"requirement-intake/paste/{draft_id}"

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="requirement_intake",
            span_name="requirement_intake.draft.create",
            service_name="orchestrator-service",
            attributes={"sourceType": payload.sourceType, "projectId": str(payload.projectId) if payload.projectId else None},
            parent_span_id=context.parent_span_id,
        ):
            self._record_paste_guardrail(
                context=context,
                decision=GuardrailDecisionType.ALLOW,
                message="pasted requirement intake normalization and redaction preflight allowed",
                draft_id=draft_id,
                redaction_status="redacted" if redaction_applied else "not_required",
                byte_size=len(raw_content.encode("utf-8")),
            )
            draft = RequirementIntakeDraft(
                id=draft_id,
                source_type=payload.sourceType,
                source_ref=source_ref,
                name=self._safe_user_text(payload.name, field_name="draft name"),
                raw_content=normalized_document,
                normalized_document=normalized_document,
                content_hash=content_hash,
                mime_type="text/plain",
                byte_size=len(content_bytes),
                artifact_refs=[],
                redaction_status="redacted" if redaction_applied else "not_required",
                project_id=payload.projectId,
                environment_id=payload.environmentId,
                environment=payload.environment.strip() or "local",
                domains=[domain.value for domain in payload.domains],
                risk_level=payload.riskLevel,
                status="draft",
                trace_id=UUID(str(context.trace_id)),
                metadata_json=metadata,
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(draft)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "requirement_intake.draft.create",
                "requirement_intake_draft",
                str(draft.id),
                context.request_id,
                context.trace_id,
                details={"sourceType": payload.sourceType, "redactionApplied": redaction_applied},
            )
        self.db.commit()
        self.db.refresh(draft)
        return self.serialize_draft(draft)

    def _create_external_link_draft(
        self,
        payload: RequirementIntakeDraftCreateRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._authorize_project_environment(
            payload.projectId,
            payload.environmentId,
            context,
            write=True,
        )
        self._authorize_community_risk(payload.riskLevel, context)
        draft_id = uuid4()
        source_ref = self._safe_user_text(
            payload.sourceRef or f"requirement-intake/external_link/{draft_id}",
            field_name="sourceRef",
        )
        if not source_ref:
            source_ref = f"requirement-intake/external_link/{draft_id}"
        document = self._fetch_external_link_document(payload.sourceUri or "", context)
        redaction_status = "redacted" if document.redaction_applied else "not_required"
        self._raise_if_duplicate_content(
            content_hash=self._content_hash(document.document.encode("utf-8")),
            normalized_document=document.document,
            project_id=payload.projectId,
            environment_id=payload.environmentId,
            created_by=context.user.id,
        )
        safe_metadata = redact_sensitive_data(dict(payload.metadata or {}))
        safe_metadata = {
            **safe_metadata,
            "sourceType": "external_link",
            "sourceUri": document.source_uri,
            "sourceHost": urlsplit(document.source_uri).hostname,
            "redactionApplied": document.redaction_applied,
            "redactionStatus": redaction_status,
            "mimeType": document.mime_type,
            "externalLinkByteSize": document.byte_size,
            "fetchTimeoutSeconds": EXTERNAL_LINK_TIMEOUT_SECONDS,
            "maxBytes": MAX_EXTERNAL_LINK_BYTES,
            "supportedSourceTypes": SUPPORTED_INTAKE_SOURCE_TYPES,
        }

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="requirement_intake",
            span_name="requirement_intake.external_link.create",
            service_name="orchestrator-service",
            attributes={
                "sourceType": "external_link",
                "projectId": str(payload.projectId) if payload.projectId else None,
                "sourceHost": urlsplit(document.source_uri).hostname,
                "mimeType": document.mime_type,
                "byteSize": document.byte_size,
            },
            parent_span_id=context.parent_span_id,
        ):
            self._record_external_link_guardrail(
                context=context,
                decision=GuardrailDecisionType.ALLOW,
                message="external_link requirement intake preflight allowed",
                source_uri=document.source_uri,
                draft_id=draft_id,
                evidence=[
                    {"type": "source_uri", "ref": document.source_uri},
                    {"type": "redaction_status", "ref": redaction_status},
                ],
                payload={
                    "sourceType": "external_link",
                    "mimeType": document.mime_type,
                    "byteSize": document.byte_size,
                    "timeoutSeconds": EXTERNAL_LINK_TIMEOUT_SECONDS,
                    "maxBytes": MAX_EXTERNAL_LINK_BYTES,
                    "redactionStatus": redaction_status,
                },
            )
            storage = artifact_storage_adapter().write_artifact(
                namespace="requirement-intake",
                artifact_id=str(draft_id),
                filename=f"external_link{document.extension}",
                payload=document.document.encode("utf-8"),
            )
            artifact_ref = {
                "artifactRef": f"artifact://requirement-intake/{draft_id}",
                "storageRef": storage["storageRef"],
                "contentHash": storage["contentHash"],
                "mimeType": document.mime_type,
                "byteSize": storage["byteSize"],
                "redactionStatus": redaction_status,
                "sourceType": "external_link",
                "sourceUri": document.source_uri,
            }
            evidence_ref = {
                "type": "external_link_source",
                "ref": f"evidence://requirement-intake/external_link/{draft_id}",
                "sourceRef": source_ref,
                "sourceUri": document.source_uri,
                "contentHash": storage["contentHash"],
                "mimeType": document.mime_type,
                "byteSize": storage["byteSize"],
                "redactionStatus": redaction_status,
            }
            safe_metadata = {
                **safe_metadata,
                "contentHash": storage["contentHash"],
                "byteSize": storage["byteSize"],
                "evidenceRefs": [evidence_ref],
            }
            draft = RequirementIntakeDraft(
                id=draft_id,
                source_type="external_link",
                source_ref=source_ref,
                source_uri=document.source_uri,
                name=self._safe_user_text(payload.name, field_name="draft name"),
                raw_content="",
                normalized_document="",
                storage_ref=str(storage["storageRef"]),
                content_hash=str(storage["contentHash"]),
                mime_type=document.mime_type,
                byte_size=int(storage["byteSize"]),
                artifact_refs=[artifact_ref],
                evidence_refs=[evidence_ref],
                redaction_status=redaction_status,
                project_id=payload.projectId,
                environment_id=payload.environmentId,
                environment=payload.environment.strip() or "local",
                domains=[domain.value for domain in payload.domains],
                risk_level=payload.riskLevel,
                status="draft",
                trace_id=UUID(str(context.trace_id)),
                metadata_json=safe_metadata,
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(draft)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "requirement_intake.external_link.create",
                "requirement_intake_draft",
                str(draft.id),
                context.request_id,
                context.trace_id,
                details={
                    "sourceType": "external_link",
                    "sourceUri": document.source_uri,
                    "mimeType": document.mime_type,
                    "byteSize": storage["byteSize"],
                    "contentHash": storage["contentHash"],
                    "redactionStatus": redaction_status,
                },
            )
        self.db.commit()
        self.db.refresh(draft)
        return self.serialize_draft(draft)

    def _create_connector_draft(
        self,
        payload: RequirementIntakeDraftCreateRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._authorize_project_environment(
            payload.projectId,
            payload.environmentId,
            context,
            write=True,
        )
        self._authorize_community_risk(payload.riskLevel, context)
        binding = self._require_requirement_document_binding(payload.connectorBindingId)
        self._authorize_requirement_document_binding_scope(
            binding,
            project_id=payload.projectId,
            environment_id=payload.environmentId,
            context=context,
        )
        draft_id = uuid4()
        external_document_id = (payload.externalDocumentId or payload.sourceRef or "").strip()
        source_ref = self._safe_user_text(
            payload.sourceRef or f"requirement-intake/connector/{binding.connector_name}/{external_document_id}",
            field_name="sourceRef",
        )
        if not source_ref:
            source_ref = f"requirement-intake/connector/{binding.connector_name}/{external_document_id}"

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="requirement_intake",
            span_name="requirement_intake.connector.create",
            service_name="orchestrator-service",
            attributes={
                "sourceType": "connector",
                "projectId": str(payload.projectId) if payload.projectId else None,
                "connectorBindingId": str(binding.id),
                "connectorName": binding.connector_name,
                "externalDocumentId": external_document_id,
            },
            parent_span_id=context.parent_span_id,
        ):
            binding_snapshot = self.credential_resolver.validate_binding(
                connector_name=binding.connector_name,
                secret_ref=binding.secret_ref,
                credential_ref=binding.credential_ref,
                scope=binding.scope,
            )
            connector_binding_snapshot = self._redacted_binding_snapshot(
                binding_snapshot,
                connector_binding_id=binding.id,
            )
            skill_service = SkillService(self.db, credential_resolver=self.credential_resolver)
            initial_skill_request = IntegrationSkillInput(
                skill="integration-intake",
                operation="normalize_requirement_document",
                provider=binding.connector_name,
                payload={
                    "connectorBindingId": str(binding.id),
                    "connectorName": binding.connector_name,
                    "externalDocumentId": external_document_id,
                },
                metadata={
                    "sourceWorkflow": "requirement-intake",
                    "sourceType": "connector",
                    "requestId": context.request_id,
                    "traceId": context.trace_id,
                },
            )
            invocation = skill_service.start_managed_invocation(
                skill_id="integration-intake",
                context=context,
                request=initial_skill_request.model_dump(mode="json"),
                source_workflow="requirement_intake.connector",
                policy_snapshot={
                    "sourceType": "connector",
                    "operation": "normalize_requirement_document",
                    "connectorName": binding.connector_name,
                    "connectorBindingId": str(binding.id),
                    "externalDocumentId": external_document_id,
                },
                connector_binding_snapshot=connector_binding_snapshot,
            )
            self._record_connector_requirement_guardrail(
                context=context,
                binding=binding,
                binding_snapshot=binding_snapshot,
                skill_invocation_id=invocation.id,
                draft_id=draft_id,
                external_document_id=external_document_id,
            )

            connector = self._runtime_for_requirement_document_binding(binding)
            connector_result = connector.invoke(
                ConnectorOperationRequest(
                    connector_name=binding.connector_name,
                    operation="fetch_requirement_document",
                    payload={"externalDocumentId": external_document_id, "sourceRef": source_ref},
                    binding_snapshot=connector_binding_snapshot,
                    runtime_credentials=self.credential_resolver.runtime_credentials_for_binding(
                        binding_snapshot
                    ),
                    trace_id=context.trace_id,
                    skill_invocation_id=str(invocation.id),
                )
            )
            if not connector_result.succeeded:
                error = "; ".join(connector_result.errors) or "requirement document connector fetch failed"
                skill_service.fail_managed_invocation(invocation, error)
                self.db.commit()
                raise ValueError(error)

            connector_document = self._connector_document_from_result(connector_result.data, external_document_id)
            normalized_document, redaction_applied = self._normalize_connector_content(
                connector_document.document,
                mime_type=connector_document.mime_type,
                extension=connector_document.extension,
            )
            redaction_status = "redacted" if redaction_applied else "not_required"
            self._raise_if_duplicate_content(
                content_hash=self._content_hash(normalized_document.encode("utf-8")),
                normalized_document=normalized_document,
                project_id=payload.projectId,
                environment_id=payload.environmentId,
                created_by=context.user.id,
            )
            storage = artifact_storage_adapter().write_artifact(
                namespace="requirement-intake",
                artifact_id=str(draft_id),
                filename=f"connector{connector_document.extension}",
                payload=normalized_document.encode("utf-8"),
            )
            artifact_ref = {
                "artifactRef": f"artifact://requirement-intake/{draft_id}",
                "storageRef": storage["storageRef"],
                "contentHash": storage["contentHash"],
                "mimeType": connector_document.mime_type,
                "byteSize": storage["byteSize"],
                "redactionStatus": redaction_status,
                "sourceType": "connector",
                "connectorName": binding.connector_name,
                "externalDocumentId": external_document_id,
                "sourceUri": connector_document.source_uri,
            }
            connector_call_refs = [
                {
                    "type": "connector_call",
                    "ref": connector_result.connector_call_ref,
                    "operation": "fetch_requirement_document",
                    "connector": binding.connector_name,
                    "connectorBindingId": str(binding.id),
                    "skillInvocationId": str(invocation.id),
                }
            ] if connector_result.connector_call_ref else []
            skill_request = IntegrationSkillInput(
                skill="integration-intake",
                operation="normalize_requirement_document",
                provider=binding.connector_name,
                payload={
                    "provider": binding.connector_name,
                    "connectorBindingId": str(binding.id),
                    "externalDocumentId": connector_document.external_document_id,
                    "title": connector_document.title,
                    "document": normalized_document,
                    "mimeType": connector_document.mime_type,
                    "sourceUri": connector_document.source_uri,
                    "contentVersion": connector_document.content_version,
                    "contentHash": storage["contentHash"],
                },
                metadata={
                    "sourceWorkflow": "requirement-intake",
                    "sourceType": "connector",
                    "requestId": context.request_id,
                    "traceId": context.trace_id,
                    "artifactRefs": [artifact_ref],
                    "connectorCallRefs": connector_call_refs,
                    "redactionStatus": redaction_status,
                },
            )
            invocation.input_snapshot = skill_request.model_dump(mode="json")
            skill_invocation = skill_service.run_integration_skill_for_invocation(
                invocation,
                skill_request,
                context,
                artifact_refs=[artifact_ref],
                connector_call_refs=connector_call_refs,
            )
            if skill_invocation.get("status") != "completed":
                self.db.commit()
                raise ValueError("integration-intake requirement document normalization failed")

            skill_output = dict(invocation.output_snapshot or {})
            skill_result = dict(skill_output.get("result") or {})
            source_uri = str(skill_result.get("sourceUri") or connector_document.source_uri)
            evidence_ref = {
                "type": "requirement_document_connector_source",
                "ref": f"evidence://requirement-intake/connector/{draft_id}",
                "sourceRef": source_ref,
                "sourceUri": source_uri,
                "connectorName": binding.connector_name,
                "connectorBindingId": str(binding.id),
                "externalDocumentId": external_document_id,
                "skillInvocationId": str(invocation.id),
                "contentHash": storage["contentHash"],
                "mimeType": connector_document.mime_type,
                "byteSize": storage["byteSize"],
                "redactionStatus": redaction_status,
            }
            evidence_refs = self._dedupe_refs(
                [
                    *connector_result.evidence_refs,
                    *list(skill_output.get("evidence") or []),
                    evidence_ref,
                ]
            )
            safe_metadata = redact_sensitive_data(dict(payload.metadata or {}))
            safe_metadata = {
                **safe_metadata,
                "sourceType": "connector",
                "connectorName": binding.connector_name,
                "connectorBindingId": str(binding.id),
                "externalDocumentId": external_document_id,
                "sourceUri": source_uri,
                "redactionApplied": redaction_applied,
                "redactionStatus": redaction_status,
                "mimeType": connector_document.mime_type,
                "byteSize": storage["byteSize"],
                "contentHash": storage["contentHash"],
                "skillInvocationId": str(invocation.id),
                "connectorCallRefs": connector_call_refs,
                "evidenceRefs": evidence_refs,
                "supportedSourceTypes": SUPPORTED_INTAKE_SOURCE_TYPES,
            }
            draft = RequirementIntakeDraft(
                id=draft_id,
                source_type="connector",
                source_ref=source_ref,
                source_uri=source_uri,
                name=self._safe_user_text(payload.name, field_name="draft name"),
                raw_content="",
                normalized_document="",
                storage_ref=str(storage["storageRef"]),
                content_hash=str(storage["contentHash"]),
                mime_type=connector_document.mime_type,
                byte_size=int(storage["byteSize"]),
                artifact_refs=[artifact_ref],
                evidence_refs=evidence_refs,
                redaction_status=redaction_status,
                project_id=payload.projectId,
                environment_id=payload.environmentId,
                environment=payload.environment.strip() or "local",
                domains=[domain.value for domain in payload.domains],
                risk_level=payload.riskLevel,
                status="draft",
                trace_id=UUID(str(context.trace_id)),
                skill_invocation_id=invocation.id,
                connector_binding_snapshot=connector_binding_snapshot,
                connector_call_refs=connector_call_refs,
                metadata_json=safe_metadata,
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(draft)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "requirement_intake.connector.create",
                "requirement_intake_draft",
                str(draft.id),
                context.request_id,
                context.trace_id,
                details={
                    "sourceType": "connector",
                    "connectorName": binding.connector_name,
                    "connectorBindingId": str(binding.id),
                    "externalDocumentId": external_document_id,
                    "skillInvocationId": str(invocation.id),
                    "mimeType": connector_document.mime_type,
                    "byteSize": storage["byteSize"],
                    "contentHash": storage["contentHash"],
                    "redactionStatus": redaction_status,
                },
            )
        self.db.commit()
        self.db.refresh(draft)
        return self.serialize_draft(draft)

    def create_upload_draft_and_preview(
        self,
        *,
        file_name: str,
        content_type: str | None,
        payload: bytes,
        name: str,
        source_ref: str | None,
        environment: str,
        project_id: UUID | None,
        environment_id: UUID | None,
        domains: list[str],
        risk_level: str,
        metadata: dict[str, Any],
        context: ServiceContext,
        allow_document_parsing: bool = False,
    ) -> dict[str, object]:
        self._authorize_project_environment(project_id, environment_id, context, write=True)
        parsed_domains = self._parse_domains(domains)
        parsed_risk = self._parse_risk_level(risk_level)
        self._authorize_community_risk(parsed_risk, context)
        try:
            document, redaction_applied, canonical_mime_type, extension = self._normalize_upload_content(
                file_name,
                content_type,
                payload,
                allow_document_parsing=allow_document_parsing,
            )
        except ValueError as exc:
            self._record_upload_guardrail(
                context=context,
                decision=GuardrailDecisionType.BLOCK,
                message=str(exc),
                draft_id=None,
                mime_type=(content_type or "").split(";")[0].strip().lower(),
                byte_size=len(payload),
                redaction_status="blocked",
            )
            self.db.commit()
            raise
        draft_id = uuid4()
        source_ref_value = self._safe_user_text(
            source_ref or f"requirement-intake/upload/{draft_id}",
            field_name="sourceRef",
        )
        if not source_ref_value:
            source_ref_value = f"requirement-intake/upload/{draft_id}"
        redaction_status = "redacted" if redaction_applied else "not_required"
        storage_payload = payload if extension in SUPPORTED_DOCUMENT_UPLOAD_EXTENSIONS else document.encode("utf-8")
        self._raise_if_duplicate_content(
            content_hash=self._content_hash(storage_payload),
            normalized_document=document,
            project_id=project_id,
            environment_id=environment_id,
            created_by=context.user.id,
        )
        self._record_upload_guardrail(
            context=context,
            decision=GuardrailDecisionType.ALLOW,
            message="requirement upload parsing and redaction preflight allowed",
            draft_id=draft_id,
            mime_type=canonical_mime_type,
            byte_size=len(payload),
            redaction_status=redaction_status,
        )
        storage = artifact_storage_adapter().write_artifact(
            namespace="requirement-intake",
            artifact_id=str(draft_id),
            filename=f"upload{extension}",
            payload=storage_payload,
        )
        artifact_ref = {
            "artifactRef": f"artifact://requirement-intake/{draft_id}",
            "storageRef": storage["storageRef"],
            "contentHash": storage["contentHash"],
            "mimeType": canonical_mime_type,
            "byteSize": storage["byteSize"],
            "redactionStatus": redaction_status,
            "sourceType": "upload",
        }
        safe_metadata = {
            **redact_sensitive_data(dict(metadata or {})),
            "sourceType": "upload",
            "redactionApplied": redaction_applied,
            "redactionStatus": redaction_status,
            "mimeType": canonical_mime_type,
            "byteSize": storage["byteSize"],
            "contentHash": storage["contentHash"],
            "fileExtension": extension.removeprefix("."),
            "supportedSourceTypes": SUPPORTED_INTAKE_SOURCE_TYPES,
        }

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="requirement_intake",
            span_name="requirement_intake.upload.create",
            service_name="orchestrator-service",
            attributes={
                "sourceType": "upload",
                "projectId": str(project_id) if project_id else None,
                "mimeType": canonical_mime_type,
                "byteSize": storage["byteSize"],
            },
            parent_span_id=context.parent_span_id,
        ):
            draft = RequirementIntakeDraft(
                id=draft_id,
                source_type="upload",
                source_ref=source_ref_value,
                name=self._safe_user_text(name, field_name="draft name"),
                raw_content="",
                normalized_document="",
                storage_ref=str(storage["storageRef"]),
                content_hash=str(storage["contentHash"]),
                mime_type=canonical_mime_type,
                byte_size=int(storage["byteSize"]),
                artifact_refs=[artifact_ref],
                evidence_refs=[],
                redaction_status=redaction_status,
                project_id=project_id,
                environment_id=environment_id,
                environment=environment.strip() or "local",
                domains=[domain.value for domain in parsed_domains],
                risk_level=parsed_risk,
                status="draft",
                trace_id=UUID(str(context.trace_id)),
                metadata_json=safe_metadata,
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(draft)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "requirement_intake.upload.create",
                "requirement_intake_draft",
                str(draft.id),
                context.request_id,
                context.trace_id,
                details={
                    "sourceType": "upload",
                    "mimeType": canonical_mime_type,
                    "byteSize": storage["byteSize"],
                    "contentHash": storage["contentHash"],
                    "redactionStatus": redaction_status,
                },
            )
        self.db.commit()
        self.db.refresh(draft)
        preview = self.create_preview(
            draft.id,
            RequirementIntakePreviewCreateRequest(metadata={"source": "requirement-intake-upload"}),
            context,
        )
        return {"draft": self.get_draft(draft.id), "preview": preview}

    def create_ocr_upload_draft_and_preview(
        self,
        *,
        file_name: str,
        content_type: str | None,
        payload: bytes,
        name: str,
        source_ref: str | None,
        environment: str,
        project_id: UUID | None,
        environment_id: UUID | None,
        domains: list[str],
        risk_level: str,
        metadata: dict[str, Any],
        context: ServiceContext,
    ) -> dict[str, object]:
        self._authorize_project_environment(project_id, environment_id, context, write=True)
        parsed_domains = self._parse_domains(domains)
        parsed_risk = self._parse_risk_level(risk_level)
        self._authorize_community_risk(parsed_risk, context)
        draft_id = uuid4()
        trace_ref = f"trace://{context.trace_id}"
        try:
            canonical_mime_type, extension = self._canonical_ocr_upload(file_name, content_type, payload)
        except ValueError as exc:
            self._record_ocr_guardrail(
                context=context,
                decision=GuardrailDecisionType.BLOCK,
                message=str(exc),
                draft_id=None,
                confidence=None,
                status="blocked",
                mime_type=(content_type or "").split(";")[0].strip().lower(),
                byte_size=len(payload),
                redaction_status="blocked",
                trace_ref=trace_ref,
            )
            self.db.commit()
            raise
        source_ref_value = self._safe_user_text(
            source_ref or f"requirement-intake/ocr/{draft_id}",
            field_name="sourceRef",
        )
        if not source_ref_value:
            source_ref_value = f"requirement-intake/ocr/{draft_id}"
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="requirement_intake",
            span_name="requirement_intake.ocr.create",
            service_name="orchestrator-service",
            attributes={
                "sourceType": "ocr_upload",
                "projectId": str(project_id) if project_id else None,
                "mimeType": canonical_mime_type,
                "byteSize": len(payload),
            },
            parent_span_id=context.parent_span_id,
        ):
            try:
                ocr_result = self.ocr_adapter.extract_text(payload, mime_type=canonical_mime_type)
            except ValueError as exc:
                self._record_ocr_guardrail(
                    context=context,
                    decision=GuardrailDecisionType.BLOCK,
                    message=str(exc),
                    draft_id=None,
                    confidence=None,
                    status="blocked",
                    mime_type=canonical_mime_type,
                    byte_size=len(payload),
                    redaction_status="blocked",
                    trace_ref=trace_ref,
                )
                self.db.commit()
                raise

            redacted_document, redaction_applied = self._normalize_paste_content(ocr_result.text)
            redaction_status = "redacted" if redaction_applied else "not_required"
            self._raise_if_duplicate_content(
                content_hash=self._content_hash(payload),
                normalized_document=redacted_document,
                project_id=project_id,
                environment_id=environment_id,
                created_by=context.user.id,
            )
            ocr_status, review_reasons = self._ocr_review_status(ocr_result.confidence, parsed_risk)
            decision = {
                "ready": GuardrailDecisionType.ALLOW,
                "review_required": GuardrailDecisionType.WARN,
                "blocked": GuardrailDecisionType.BLOCK,
            }[ocr_status]
            storage = artifact_storage_adapter().write_artifact(
                namespace="requirement-intake",
                artifact_id=str(draft_id),
                filename=f"ocr_source{extension}",
                payload=payload,
            )
            artifact_ref = {
                "artifactRef": f"artifact://requirement-intake/ocr/{draft_id}",
                "storageRef": storage["storageRef"],
                "contentHash": storage["contentHash"],
                "mimeType": canonical_mime_type,
                "byteSize": storage["byteSize"],
                "redactionStatus": redaction_status,
                "sourceType": "ocr_upload",
            }
            evidence_ref = {
                "type": "ocr_extraction",
                "ref": f"evidence://requirement-intake/ocr/{draft_id}",
                "artifactRef": artifact_ref["artifactRef"],
                "confidence": ocr_result.confidence,
                "pageCount": ocr_result.page_count,
                "lineCount": ocr_result.line_count,
                "adapter": ocr_result.adapter,
                "redactionStatus": redaction_status,
                "traceRef": trace_ref,
            }
            ocr_projection = {
                "status": ocr_status,
                "confidence": ocr_result.confidence,
                "reviewRequired": ocr_status == "review_required",
                "blocked": ocr_status == "blocked",
                "reviewReasons": review_reasons,
                "adapter": ocr_result.adapter,
                "pageCount": ocr_result.page_count,
                "lineCount": ocr_result.line_count,
                "readyConfidenceThreshold": OCR_READY_CONFIDENCE,
                "blockConfidenceThreshold": OCR_BLOCK_CONFIDENCE,
                "traceRefs": [trace_ref],
                "pages": [
                    {
                        "pageNumber": page.page_number,
                        "confidence": page.confidence,
                        "lineCount": page.line_count,
                    }
                    for page in ocr_result.pages
                ],
            }
            safe_metadata = {
                **redact_sensitive_data(dict(metadata or {})),
                "sourceType": "ocr_upload",
                "mimeType": canonical_mime_type,
                "byteSize": storage["byteSize"],
                "contentHash": storage["contentHash"],
                "redactionStatus": redaction_status,
                "ocr": ocr_projection,
                "supportedSourceTypes": SUPPORTED_INTAKE_SOURCE_TYPES,
            }
            self._record_ocr_guardrail(
                context=context,
                decision=decision,
                message=f"OCR intake preflight completed with status {ocr_status}",
                draft_id=draft_id,
                confidence=ocr_result.confidence,
                status=ocr_status,
                mime_type=canonical_mime_type,
                byte_size=int(storage["byteSize"]),
                redaction_status=redaction_status,
                trace_ref=trace_ref,
            )
            draft = RequirementIntakeDraft(
                id=draft_id,
                source_type="ocr_upload",
                source_ref=source_ref_value,
                name=self._safe_user_text(name, field_name="draft name"),
                raw_content="",
                normalized_document=redacted_document,
                storage_ref=str(storage["storageRef"]),
                content_hash=str(storage["contentHash"]),
                mime_type=canonical_mime_type,
                byte_size=int(storage["byteSize"]),
                artifact_refs=[artifact_ref],
                evidence_refs=[evidence_ref],
                redaction_status=redaction_status,
                project_id=project_id,
                environment_id=environment_id,
                environment=environment.strip() or "local",
                domains=[domain.value for domain in parsed_domains],
                risk_level=parsed_risk,
                status="draft",
                trace_id=UUID(str(context.trace_id)),
                metadata_json=safe_metadata,
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(draft)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "requirement_intake.ocr.create",
                "requirement_intake_draft",
                str(draft.id),
                context.request_id,
                context.trace_id,
                details={
                    "sourceType": "ocr_upload",
                    "mimeType": canonical_mime_type,
                    "byteSize": storage["byteSize"],
                    "contentHash": storage["contentHash"],
                    "ocrConfidence": ocr_result.confidence,
                    "ocrStatus": ocr_status,
                    "redactionStatus": redaction_status,
                    "traceRef": trace_ref,
                },
            )
        self.db.commit()
        self.db.refresh(draft)
        preview = self.create_preview(
            draft.id,
            RequirementIntakePreviewCreateRequest(metadata={"source": "requirement-intake-ocr"}),
            context,
        )
        return {"draft": self.get_draft(draft.id), "preview": preview}

    def get_draft(
        self,
        draft_id: UUID,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        draft = self._require_draft(draft_id)
        if context is not None:
            self._authorize_project_environment(
                draft.project_id,
                draft.environment_id,
                context,
                write=False,
            )
        return self.serialize_draft(draft)

    def create_preview(
        self,
        draft_id: UUID,
        payload: RequirementIntakePreviewCreateRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        draft = self._require_draft(draft_id)
        self._authorize_project_environment(
            draft.project_id,
            draft.environment_id,
            context,
            write=True,
        )
        if draft.source_type not in SUPPORTED_SOURCE_TYPES:
            raise ValueError("unsupported requirement intake sourceType")
        if draft.status == "confirmed":
            raise ValueError("confirmed draft cannot create a new preview")

        existing_preview = self.db.scalar(
            select(RequirementIntakePreview)
            .where(
                RequirementIntakePreview.draft_id == draft.id,
                RequirementIntakePreview.status.in_(("generated", "review_required", "blocked")),
            )
            .order_by(RequirementIntakePreview.created_at.desc(), RequirementIntakePreview.id.desc())
            .limit(1)
        )
        if existing_preview is not None and existing_preview.metadata_json.get("previewParserVersion") == PREVIEW_PARSER_VERSION:
            return self.serialize_preview(existing_preview)

        document = self._document_for_preview(draft)
        extraction = self._extract_preview_structure(document)
        if existing_preview is not None and extraction.acceptance_by_requirement is None:
            return self.serialize_preview(existing_preview)
        requirements = extraction.requirements
        acceptance_criteria = extraction.acceptance_criteria
        warnings = extraction.warnings
        if draft.redaction_status == "redacted" or draft.metadata_json.get("redactionApplied"):
            warnings.append("sensitive_content_redacted")
        ocr_projection = self._ocr_projection(draft.metadata_json)
        preview_status = "generated"
        draft_status = "previewed"
        if ocr_projection is not None:
            warnings.append("ocr_text_extracted")
            if ocr_projection["status"] == "review_required":
                warnings.append("ocr_review_required")
                preview_status = "review_required"
                draft_status = "review_required"
            elif ocr_projection["status"] == "blocked":
                warnings.append("ocr_low_confidence_blocked")
                preview_status = "blocked"
                draft_status = "blocked"
        warnings = self._dedupe(warnings)

        preview_id = uuid4()
        requirement_items = self._build_selectable_requirement_items(
            draft,
            preview_id=preview_id,
            requirements=requirements,
            acceptance_criteria=acceptance_criteria,
            acceptance_by_requirement=extraction.acceptance_by_requirement,
            source_line_spans=extraction.source_line_spans,
        )
        safe_preview_metadata = redact_sensitive_data(dict(payload.metadata or {}))
        pipeline_payload = self._build_pipeline_payload(
            draft,
            preview_id=preview_id,
            document=document,
            requirements=requirements,
            acceptance_criteria=acceptance_criteria,
            requirement_items=requirement_items,
            metadata=safe_preview_metadata,
        )

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="requirement_intake",
            span_name="requirement_intake.preview.create",
            service_name="orchestrator-service",
            attributes={"draftId": str(draft.id), "sourceType": draft.source_type},
            parent_span_id=context.parent_span_id,
        ):
            existing_active = list(
                self.db.scalars(
                    select(RequirementIntakePreview).where(
                        RequirementIntakePreview.draft_id == draft.id,
                        RequirementIntakePreview.status.in_(("generated", "review_required", "blocked")),
                    )
                )
            )
            for existing in existing_active:
                existing.status = "superseded"
            preview = RequirementIntakePreview(
                id=preview_id,
                draft_id=draft.id,
                source_type=draft.source_type,
                source_ref=draft.source_ref,
                source_uri=draft.source_uri,
                document=document,
                storage_ref=draft.storage_ref,
                content_hash=draft.content_hash,
                mime_type=draft.mime_type,
                byte_size=draft.byte_size,
                artifact_refs=list(draft.artifact_refs),
                evidence_refs=list(draft.evidence_refs),
                redaction_status=draft.redaction_status,
                requirements=requirements,
                acceptance_criteria=acceptance_criteria,
                pipeline_payload=pipeline_payload,
                warnings=warnings,
                status=preview_status,
                trace_id=UUID(str(context.trace_id)),
                skill_invocation_id=draft.skill_invocation_id,
                connector_binding_snapshot=self.connector_snapshot_builder.build(
                    draft.connector_binding_snapshot
                ),
                connector_call_refs=list(draft.connector_call_refs or []),
                metadata_json={
                    **safe_preview_metadata,
                    "source": "requirement-intake-preview",
                    "previewParserVersion": PREVIEW_PARSER_VERSION,
                    "requirementItems": requirement_items,
                    "selectionDefault": "all",
                    "ocr": ocr_projection,
                },
                created_by=context.user.id,
            )
            draft.status = draft_status
            draft.updated_by = context.user.id
            self.db.add(preview)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "requirement_intake.preview.create",
                "requirement_intake_preview",
                str(preview.id),
                context.request_id,
                context.trace_id,
                details={
                    "draftId": str(draft.id),
                    "requirementCount": len(requirements),
                    "acceptanceCriteriaCount": len(acceptance_criteria),
                    "ocrConfidence": ocr_projection.get("confidence") if ocr_projection else None,
                    "ocrStatus": ocr_projection.get("status") if ocr_projection else None,
                },
            )
        self.db.commit()
        self.db.refresh(preview)
        return self.serialize_preview(preview)

    def get_preview(
        self,
        preview_id: UUID,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        preview = self._require_preview(preview_id)
        if context is not None:
            draft = self._require_draft(preview.draft_id)
            self._authorize_project_environment(
                draft.project_id,
                draft.environment_id,
                context,
                write=False,
            )
        return self.serialize_preview(preview)

    def confirm_preview(
        self,
        preview_id: UUID,
        context: ServiceContext,
        payload: RequirementIntakeConfirmRequest | None = None,
    ) -> dict[str, object]:
        preview = self._require_preview(preview_id)
        draft = self._require_draft(preview.draft_id)
        self._authorize_project_environment(
            draft.project_id,
            draft.environment_id,
            context,
            write=True,
        )
        if preview.status == "confirmed" and preview.linked_pipeline_id is not None:
            pipeline = self._serialize_confirm_pipeline(OrchestratorService(self.db).get_pipeline(preview.linked_pipeline_id))
            return {"draft": self.serialize_draft(draft), "preview": self.serialize_preview(preview), "pipeline": pipeline}
        if preview.source_type == "ocr_upload" and preview.status == "review_required":
            raise ValueError("OCR_REVIEW_REQUIRED: OCR preview requires review before confirm")
        if preview.source_type == "ocr_upload" and preview.status == "blocked":
            raise ValueError("OCR_CONFIDENCE_BLOCKED: OCR preview confidence is below the confirm threshold")
        if preview.status != "generated":
            raise ValueError("only generated previews can be confirmed")
        if draft.source_type != preview.source_type or draft.source_type not in SUPPORTED_SOURCE_TYPES:
            raise ValueError("unsupported requirement intake sourceType")

        selected_items, selection_mode = self._resolve_selected_requirement_items(preview, payload)
        safe_confirm_metadata = redact_sensitive_data(dict(payload.metadata or {})) if payload else {}
        pipeline_payload_dict = self._build_selected_pipeline_payload(
            preview,
            selected_items=selected_items,
            selection_mode=selection_mode,
            request_metadata=safe_confirm_metadata,
        )
        pipeline_payload = RequirementPipelineRequest(**pipeline_payload_dict)
        pipeline = OrchestratorService(self.db).run_requirement_pipeline(pipeline_payload, context)
        preview = self._require_preview(preview.id)
        draft = self._require_draft(draft.id)
        preview.status = "confirmed"
        preview.confirmed_at = datetime.now(timezone.utc)
        preview.linked_requirement_version_id = self._optional_uuid(pipeline.get("requirementVersionId"))
        preview.linked_pipeline_id = self._optional_uuid(pipeline.get("orchestrationId"))
        preview.pipeline_payload = pipeline_payload_dict
        preview.metadata_json = {
            **preview.metadata_json,
            "confirmedBy": str(context.user.id),
            "pipelineCreatedThrough": "OrchestratorService.run_requirement_pipeline",
            "selectedRequirementItems": selected_items,
            "selectedRequirementItemIds": [str(item["itemId"]) for item in selected_items],
            "selectionMode": selection_mode,
            "selectionCount": len(selected_items),
        }
        draft.status = "confirmed"
        draft.updated_by = context.user.id
        write_audit_log(
            self.db,
            str(context.user.id),
            "requirement_intake.preview.confirm",
            "requirement_intake_preview",
            str(preview.id),
            context.request_id,
            context.trace_id,
            details={
                "draftId": str(draft.id),
                "orchestrationId": pipeline["orchestrationId"],
                "requirementVersionId": pipeline.get("requirementVersionId"),
                "selectedRequirementItemIds": [str(item["itemId"]) for item in selected_items],
                "selectionMode": selection_mode,
            },
        )
        self.db.commit()
        self.db.refresh(preview)
        self.db.refresh(draft)
        return {"draft": self.serialize_draft(draft), "preview": self.serialize_preview(preview), "pipeline": pipeline}

    def _serialize_confirm_pipeline(self, pipeline: dict[str, object]) -> dict[str, object]:
        if "orchestrationId" in pipeline:
            return pipeline
        return {
            **pipeline,
            "orchestrationId": pipeline.get("id"),
        }

    def serialize_draft(self, draft: RequirementIntakeDraft) -> dict[str, object]:
        return {
            "draftId": str(draft.id),
            "sourceType": draft.source_type,
            "sourceRef": draft.source_ref,
            "sourceUri": draft.source_uri,
            "name": draft.name,
            "rawContent": draft.raw_content,
            "normalizedDocument": draft.normalized_document,
            "storageRef": draft.storage_ref,
            "contentHash": draft.content_hash,
            "mimeType": draft.mime_type,
            "byteSize": draft.byte_size,
            "artifactRefs": list(draft.artifact_refs),
            "evidenceRefs": list(draft.evidence_refs),
            "redactionStatus": draft.redaction_status,
            "environment": draft.environment,
            "projectId": str(draft.project_id) if draft.project_id else None,
            "environmentId": str(draft.environment_id) if draft.environment_id else None,
            "domains": list(draft.domains),
            "riskLevel": draft.risk_level.value,
            "status": draft.status,
            "traceId": str(draft.trace_id) if draft.trace_id else None,
            "skillInvocationId": str(draft.skill_invocation_id) if draft.skill_invocation_id else None,
            "connectorBindingSnapshot": self.connector_snapshot_builder.build(
                draft.connector_binding_snapshot
            ),
            "connectorCallRefs": list(draft.connector_call_refs or []),
            "ocr": self._ocr_projection(draft.metadata_json),
            "metadata": draft.metadata_json,
            "createdAt": draft.created_at.isoformat(),
            "updatedAt": draft.updated_at.isoformat(),
        }

    def serialize_preview(self, preview: RequirementIntakePreview) -> dict[str, object]:
        return {
            "previewId": str(preview.id),
            "draftId": str(preview.draft_id),
            "sourceType": preview.source_type,
            "sourceRef": preview.source_ref,
            "sourceUri": preview.source_uri,
            "document": preview.document,
            "storageRef": preview.storage_ref,
            "contentHash": preview.content_hash,
            "mimeType": preview.mime_type,
            "byteSize": preview.byte_size,
            "artifactRefs": list(preview.artifact_refs),
            "evidenceRefs": list(preview.evidence_refs),
            "redactionStatus": preview.redaction_status,
            "requirements": list(preview.requirements),
            "acceptanceCriteria": list(preview.acceptance_criteria),
            "requirementItems": self._requirement_items_for_preview(preview),
            "pipelinePayload": preview.pipeline_payload,
            "warnings": list(preview.warnings),
            "status": preview.status,
            "linkedRequirementVersionId": str(preview.linked_requirement_version_id) if preview.linked_requirement_version_id else None,
            "linkedPipelineId": str(preview.linked_pipeline_id) if preview.linked_pipeline_id else None,
            "confirmedAt": preview.confirmed_at.isoformat() if preview.confirmed_at else None,
            "traceId": str(preview.trace_id) if preview.trace_id else None,
            "skillInvocationId": str(preview.skill_invocation_id) if preview.skill_invocation_id else None,
            "connectorBindingSnapshot": self.connector_snapshot_builder.build(
                preview.connector_binding_snapshot
            ),
            "connectorCallRefs": list(preview.connector_call_refs or []),
            "ocr": self._ocr_projection(preview.metadata_json),
            "metadata": preview.metadata_json,
            "createdAt": preview.created_at.isoformat(),
            "updatedAt": preview.updated_at.isoformat(),
        }

    def serialize_batch(self, batch: RequirementIntakeBatch, *, include_sources: bool = True) -> dict[str, object]:
        sources = self._batch_sources(batch.id) if include_sources else []
        return {
            "batchId": str(batch.id),
            "name": batch.name,
            "idempotencyKey": batch.idempotency_key,
            "status": batch.status,
            "environment": batch.environment,
            "projectId": str(batch.project_id) if batch.project_id else None,
            "environmentId": str(batch.environment_id) if batch.environment_id else None,
            "domains": list(batch.domains),
            "riskLevel": batch.risk_level.value,
            "summary": dict(batch.summary or {}),
            "traceId": str(batch.trace_id) if batch.trace_id else None,
            "metadata": dict(batch.metadata_json or {}),
            "sources": [self.serialize_batch_source(source) for source in sources],
            "createdAt": batch.created_at.isoformat(),
            "updatedAt": batch.updated_at.isoformat(),
        }

    def serialize_batch_source(self, source: RequirementIntakeBatchSource) -> dict[str, object]:
        draft = self.db.get(RequirementIntakeDraft, source.draft_id) if source.draft_id else None
        preview = self.db.get(RequirementIntakePreview, source.preview_id) if source.preview_id else None
        return {
            "batchSourceId": str(source.id),
            "batchId": str(source.batch_id),
            "ordinal": source.ordinal,
            "sourceType": source.source_type,
            "sourceKey": source.source_key,
            "status": source.status,
            "draftId": str(source.draft_id) if source.draft_id else None,
            "previewId": str(source.preview_id) if source.preview_id else None,
            "linkedRequirementVersionId": (
                str(source.linked_requirement_version_id) if source.linked_requirement_version_id else None
            ),
            "linkedPipelineId": str(source.linked_pipeline_id) if source.linked_pipeline_id else None,
            "errorMessage": source.error_message,
            "artifactRefs": list(source.artifact_refs or []),
            "evidenceRefs": list(source.evidence_refs or []),
            "retryCount": int(source.retry_count or 0),
            "draft": self.serialize_draft(draft) if draft else None,
            "preview": self.serialize_preview(preview) if preview else None,
            "metadata": dict(source.metadata_json or {}),
            "createdAt": source.created_at.isoformat(),
            "updatedAt": source.updated_at.isoformat(),
        }

    def _build_pipeline_payload(
        self,
        draft: RequirementIntakeDraft,
        *,
        preview_id: UUID,
        document: str,
        requirements: list[str],
        acceptance_criteria: list[str],
        requirement_items: list[dict[str, Any]],
        metadata: dict[str, object],
    ) -> dict[str, object]:
        return {
            "name": draft.name,
            "sourceRef": draft.source_ref,
            "document": document,
            "requirements": requirements,
            "acceptanceCriteria": acceptance_criteria,
            "environment": draft.environment,
            "projectId": str(draft.project_id) if draft.project_id else None,
            "environmentId": str(draft.environment_id) if draft.environment_id else None,
            "domains": list(draft.domains),
            "riskLevel": draft.risk_level.value,
            "metadata": {
                **draft.metadata_json,
                **metadata,
                "source": "requirement-intake",
                "intakeDraftId": str(draft.id),
                "intakePreviewId": str(preview_id),
                "intakeSourceType": draft.source_type,
                "intakeSourceUri": draft.source_uri,
                "intakeEvidenceRefs": list(draft.evidence_refs),
                "intakeArtifactRefs": list(draft.artifact_refs),
                "intakeRequirementItems": requirement_items,
                "selectionDefault": "all",
                "intakeSkillInvocationId": str(draft.skill_invocation_id) if draft.skill_invocation_id else None,
                "intakeConnectorBindingSnapshot": self.connector_snapshot_builder.build(
                    draft.connector_binding_snapshot
                ),
                "intakeConnectorCallRefs": list(draft.connector_call_refs or []),
                "intakeRedactionStatus": draft.redaction_status,
                "intakeContentHash": draft.content_hash,
                "intakeMimeType": draft.mime_type,
                "intakeByteSize": draft.byte_size,
            },
        }

    def _build_selectable_requirement_items(
        self,
        draft: RequirementIntakeDraft,
        *,
        preview_id: UUID,
        requirements: list[str],
        acceptance_criteria: list[str],
        acceptance_by_requirement: list[list[str]] | None = None,
        source_line_spans: list[tuple[int, int]] | None = None,
    ) -> list[dict[str, Any]]:
        if acceptance_by_requirement is not None and len(acceptance_by_requirement) != len(requirements):
            raise ValueError("acceptance mapping must match requirement count")
        if source_line_spans is not None and len(source_line_spans) != len(requirements):
            raise ValueError("source spans must match requirement count")
        items: list[dict[str, Any]] = []
        for index, requirement in enumerate(requirements, start=1):
            if acceptance_by_requirement is not None:
                item_acceptance_criteria = list(acceptance_by_requirement[index - 1])
            elif len(requirements) == 1:
                item_acceptance_criteria = list(acceptance_criteria)
            elif len(acceptance_criteria) == len(requirements):
                item_acceptance_criteria = [acceptance_criteria[index - 1]]
            elif index <= len(acceptance_criteria):
                item_acceptance_criteria = [acceptance_criteria[index - 1]]
            else:
                item_acceptance_criteria = []
            item_id = f"req-{index:03d}"
            items.append(
                {
                    "itemId": item_id,
                    "ordinal": index,
                    "requirement": requirement,
                    "acceptanceCriteria": item_acceptance_criteria,
                    "sourceRef": draft.source_ref,
                    "sourceUri": draft.source_uri,
                    "evidenceRefs": list(draft.evidence_refs or []),
                    "artifactRefs": list(draft.artifact_refs or []),
                    "selectedByDefault": True,
                    "metadata": {
                        "intakeDraftId": str(draft.id),
                        "intakePreviewId": str(preview_id),
                        "sourceType": draft.source_type,
                        "contentHash": draft.content_hash,
                        "redactionStatus": draft.redaction_status,
                        **(
                            {"sourceLineSpan": list(source_line_spans[index - 1])}
                            if source_line_spans is not None
                            else {}
                        ),
                    },
                }
            )
        return items

    def _requirement_items_for_preview(self, preview: RequirementIntakePreview) -> list[dict[str, Any]]:
        metadata_items = preview.metadata_json.get("requirementItems")
        if isinstance(metadata_items, list):
            return [self._normalize_requirement_item(item, preview) for item in metadata_items if isinstance(item, dict)]
        payload_metadata = dict(preview.pipeline_payload.get("metadata") or {})
        payload_items = payload_metadata.get("intakeRequirementItems")
        if isinstance(payload_items, list):
            return [self._normalize_requirement_item(item, preview) for item in payload_items if isinstance(item, dict)]
        draft = self._require_draft(preview.draft_id)
        return self._build_selectable_requirement_items(
            draft,
            preview_id=preview.id,
            requirements=list(preview.requirements),
            acceptance_criteria=list(preview.acceptance_criteria),
        )

    def _normalize_requirement_item(self, item: dict[str, Any], preview: RequirementIntakePreview) -> dict[str, Any]:
        item_id = str(item.get("itemId") or "").strip()
        ordinal = int(item.get("ordinal") or 0)
        requirement = str(item.get("requirement") or "").strip()
        acceptance_criteria = [str(value).strip() for value in list(item.get("acceptanceCriteria") or []) if str(value).strip()]
        source_ref = str(item.get("sourceRef") or preview.source_ref)
        source_uri = item.get("sourceUri", preview.source_uri)
        return {
            "itemId": item_id or f"req-{ordinal:03d}" if ordinal else item_id,
            "ordinal": ordinal,
            "requirement": requirement,
            "acceptanceCriteria": acceptance_criteria,
            "sourceRef": source_ref,
            "sourceUri": str(source_uri) if source_uri else None,
            "evidenceRefs": list(item.get("evidenceRefs") or preview.evidence_refs or []),
            "artifactRefs": list(item.get("artifactRefs") or preview.artifact_refs or []),
            "selectedByDefault": bool(item.get("selectedByDefault", True)),
            "metadata": dict(item.get("metadata") or {}),
        }

    def _resolve_selected_requirement_items(
        self,
        preview: RequirementIntakePreview,
        payload: RequirementIntakeConfirmRequest | None,
    ) -> tuple[list[dict[str, Any]], str]:
        requirement_items = self._requirement_items_for_preview(preview)
        item_by_id = {str(item["itemId"]): item for item in requirement_items if item.get("itemId")}
        if payload is None or payload.selectedRequirementItems is None:
            selected_ids = [str(item["itemId"]) for item in requirement_items if item.get("itemId")]
            selection_mode = "default_all"
        else:
            selected_ids = [str(item_id).strip() for item_id in payload.selectedRequirementItems if str(item_id).strip()]
            selection_mode = "explicit"

        deduped_ids: list[str] = []
        for item_id in selected_ids:
            if item_id not in deduped_ids:
                deduped_ids.append(item_id)
        if not deduped_ids:
            raise ValueError("selectedRequirementItems must include at least one requirement item")

        unknown_ids = [item_id for item_id in deduped_ids if item_id not in item_by_id]
        if unknown_ids:
            raise ValueError(f"selectedRequirementItems contains unknown requirement item id: {unknown_ids[0]}")
        return [item_by_id[item_id] for item_id in deduped_ids], selection_mode

    def _build_selected_pipeline_payload(
        self,
        preview: RequirementIntakePreview,
        *,
        selected_items: list[dict[str, Any]],
        selection_mode: str,
        request_metadata: dict[str, Any],
    ) -> dict[str, object]:
        base_payload = dict(preview.pipeline_payload or {})
        all_items = self._requirement_items_for_preview(preview)
        selected_ids = [str(item["itemId"]) for item in selected_items]
        all_ids = [str(item["itemId"]) for item in all_items]
        selected_requirements = [str(item["requirement"]).strip() for item in selected_items if str(item.get("requirement") or "").strip()]
        selected_acceptance_criteria = self._dedupe(
            [
                str(criteria).strip()
                for item in selected_items
                for criteria in list(item.get("acceptanceCriteria") or [])
                if str(criteria).strip()
            ]
        )
        document = (
            str(base_payload.get("document") or preview.document)
            if selected_ids == all_ids
            else self._document_for_selected_requirement_items(preview, selected_items)
        )
        metadata = {
            **dict(base_payload.get("metadata") or {}),
            **request_metadata,
            "selectionMode": selection_mode,
            "selectedRequirementItemIds": selected_ids,
            "selectedRequirementItems": selected_items,
            "selectableRequirementItemCount": len(all_items),
            "selectedRequirementItemCount": len(selected_items),
        }
        return {
            **base_payload,
            "document": document,
            "requirements": selected_requirements,
            "acceptanceCriteria": selected_acceptance_criteria,
            "metadata": metadata,
        }

    def _document_for_selected_requirement_items(
        self,
        preview: RequirementIntakePreview,
        selected_items: list[dict[str, Any]],
    ) -> str:
        lines = [
            f"Selected requirement items from preview {preview.id}",
            f"Source ref: {preview.source_ref}",
        ]
        if preview.source_uri:
            lines.append(f"Source URI: {preview.source_uri}")
        source_lines = preview.document.splitlines()
        for item in selected_items:
            lines.append("")
            lines.append(f"Requirement item: {item['itemId']}")
            span = dict(item.get("metadata") or {}).get("sourceLineSpan")
            if (
                isinstance(span, list)
                and len(span) == 2
                and all(type(value) is int for value in span)
                and 0 <= span[0] < span[1] <= len(source_lines)
            ):
                source_section = "\n".join(source_lines[span[0]:span[1]]).strip()
                source_heading = MARKDOWN_HEADING_PATTERN.match(source_section.splitlines()[0])
                if source_heading and source_heading.group("title").strip() == item["requirement"]:
                    lines.append(source_section)
                    continue
            lines.append(f"Requirement: {item['requirement']}")
            for criteria in list(item.get("acceptanceCriteria") or []):
                lines.append(f"Acceptance: {criteria}")
            lines.append(f"Evidence refs: {len(list(item.get('evidenceRefs') or []))}")
            lines.append(f"Artifact refs: {len(list(item.get('artifactRefs') or []))}")
        return "\n".join(lines).strip()

    def _extract_preview_items(self, document: str) -> tuple[list[str], list[str], list[str]]:
        extraction = self._extract_preview_structure(document)
        return extraction.requirements, extraction.acceptance_criteria, extraction.warnings

    def _extract_preview_structure(self, document: str) -> PreviewExtraction:
        markdown = self._extract_markdown_preview_structure(document)
        if markdown.requirements:
            return markdown

        requirements: list[str] = []
        acceptance_criteria: list[str] = []
        current_section: str | None = None
        code_fence: str | None = None
        for raw_line in document.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith(("```", "~~~")):
                marker = line[:3]
                if code_fence is None:
                    code_fence = marker
                elif code_fence == marker:
                    code_fence = None
                continue
            if code_fence is not None:
                continue
            heading = MARKDOWN_HEADING_PATTERN.match(line)
            content = heading.group("title").strip() if heading else line
            lower = content.lower().rstrip(":：")
            if lower in SECTION_REQUIREMENT_MARKERS:
                current_section = "requirements"
                continue
            if lower in SECTION_ACCEPTANCE_MARKERS:
                current_section = "acceptance"
                continue
            if heading:
                current_section = None
            prefixed = PREFIX_PATTERN.match(content)
            if prefixed:
                prefix = prefixed.group("prefix").strip().lower()
                value = prefixed.group("value").strip()
                if self._is_requirement_prefix(prefix):
                    requirements.append(value)
                    current_section = "requirements"
                    continue
                if self._is_acceptance_prefix(prefix):
                    acceptance_criteria.append(value)
                    current_section = "acceptance"
                    continue
            if line.startswith(("-", "*")):
                value = line[1:].strip()
                if current_section == "requirements":
                    requirements.append(value)
                elif current_section == "acceptance":
                    acceptance_criteria.append(value)
                continue
        if not requirements:
            fallback = self._first_meaningful_line(document)
            if fallback:
                requirements.append(fallback)
        warnings: list[str] = []
        if not requirements:
            warnings.append("missing_requirements")
        if not acceptance_criteria:
            warnings.append("missing_acceptance_criteria")
        return PreviewExtraction(self._dedupe(requirements), self._dedupe(acceptance_criteria), warnings)

    def _extract_markdown_preview_structure(self, document: str) -> PreviewExtraction:
        requirements: list[str] = []
        acceptance_by_requirement: list[list[str]] = []
        source_line_spans: list[tuple[int, int]] = []
        current_requirement: int | None = None
        current_section: str | None = None
        case_lines: list[str] = []
        code_fence: str | None = None

        def finish_case() -> None:
            if case_lines and current_requirement is not None:
                acceptance_by_requirement[current_requirement].append(" ".join(case_lines))
            case_lines.clear()

        document_lines = document.splitlines()
        for line_number, raw_line in enumerate(document_lines):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith(("```", "~~~")):
                marker = line[:3]
                if code_fence is None:
                    code_fence = marker
                elif code_fence == marker:
                    code_fence = None
                if case_lines:
                    case_lines.append(line)
                continue
            if code_fence is not None:
                if case_lines:
                    case_lines.append(line)
                continue
            if line in ("---", "***", "___"):
                finish_case()
                continue
            heading = MARKDOWN_HEADING_PATTERN.match(line)
            if heading:
                title = heading.group("title").strip()
                if self._requirement_heading(title):
                    finish_case()
                    if current_requirement is not None:
                        start, _ = source_line_spans[current_requirement]
                        source_line_spans[current_requirement] = (start, line_number)
                    current_requirement = len(requirements)
                    requirements.append(title)
                    acceptance_by_requirement.append([])
                    source_line_spans.append((line_number, len(document_lines)))
                    current_section = None
                elif title.lower().rstrip(":：") in SECTION_ACCEPTANCE_MARKERS:
                    finish_case()
                    current_section = "acceptance" if current_requirement is not None else None
                elif (
                    current_section == "acceptance"
                    and current_requirement is not None
                    and ACCEPTANCE_HEADING_PATTERN.fullmatch(title)
                ):
                    finish_case()
                    case_lines.append(title)
                else:
                    finish_case()
                    current_section = None
                    if heading.group("level") == "#":
                        if current_requirement is not None:
                            start, _ = source_line_spans[current_requirement]
                            source_line_spans[current_requirement] = (start, line_number)
                        current_requirement = None
                continue
            if current_section != "acceptance" or current_requirement is None:
                continue
            if case_lines:
                case_lines.append(line)
            elif line.startswith(("- ", "* ")):
                acceptance_by_requirement[current_requirement].append(line[2:].strip())

        finish_case()
        acceptance_criteria = self._dedupe(
            [criterion for group in acceptance_by_requirement for criterion in group]
        )
        warnings = []
        if not acceptance_criteria:
            warnings.append("missing_acceptance_criteria")
        return PreviewExtraction(
            requirements,
            acceptance_criteria,
            warnings,
            acceptance_by_requirement,
            source_line_spans,
        )

    def _requirement_heading(self, title: str) -> bool:
        match = REQUIREMENT_HEADING_PATTERN.fullmatch(title.strip())
        return match is not None and match.group("id").split("-", 1)[0].upper() not in {"AC", "BR"}

    def _document_for_preview(self, draft: RequirementIntakeDraft) -> str:
        if draft.source_type == "paste":
            return draft.normalized_document
        if draft.source_type == "ocr_upload":
            if not draft.normalized_document.strip():
                raise ValueError("OCR_NO_TEXT: OCR draft is missing redacted extracted text")
            return draft.normalized_document
        if draft.source_type in {"upload", "external_link", "connector"}:
            if not draft.storage_ref:
                raise ValueError("storage-backed draft is missing storageRef")
            payload = artifact_storage_adapter().read_artifact(draft.storage_ref)
            if draft.source_type == "upload" and draft.mime_type in SUPPORTED_DOCUMENT_UPLOAD_EXTENSIONS.values():
                parsed = self.document_parser.extract_text(payload, mime_type=str(draft.mime_type))
                redacted, _ = self._normalize_paste_content(parsed.text)
                return redacted
            return payload.decode("utf-8")
        raise ValueError("unsupported requirement intake sourceType")

    def _connector_document_from_result(
        self,
        data: dict[str, Any],
        requested_external_document_id: str,
    ) -> ConnectorRequirementDocument:
        external_document_id = str(data.get("externalDocumentId") or requested_external_document_id).strip()
        if not external_document_id:
            raise ValueError("connector externalDocumentId is required")
        document = str(data.get("document") or "").strip()
        if not document:
            raise ValueError("connector requirement document is empty")
        if "\x00" in document:
            raise ValueError("connector requirement document appears to be binary")
        byte_size = len(document.encode("utf-8"))
        if byte_size > MAX_CONNECTOR_DOCUMENT_BYTES:
            raise ValueError("connector requirement document exceeds max supported size")
        mime_type = str(data.get("mimeType") or "text/plain").split(";")[0].strip().lower()
        extension = self._connector_extension_for_mime_type(mime_type)
        return ConnectorRequirementDocument(
            document=document,
            external_document_id=external_document_id,
            title=str(data.get("title") or external_document_id).strip(),
            source_uri=str(data.get("sourceUri") or f"mock-requirement-docs://requirement-documents/{external_document_id}").strip(),
            mime_type=mime_type,
            content_version=str(data.get("contentVersion") or "").strip() or None,
            extension=extension,
        )

    def _normalize_connector_content(self, document: str, *, mime_type: str, extension: str) -> tuple[str, bool]:
        normalized = document.strip()
        if mime_type == "application/json" or extension == ".json":
            try:
                parsed = json.loads(normalized)
            except json.JSONDecodeError as exc:
                raise ValueError("connector requirement document JSON is invalid") from exc
            normalized = json.dumps(parsed, ensure_ascii=False, indent=2)
        redacted, redaction_applied = self._normalize_paste_content(normalized)
        if not redacted:
            raise ValueError("connector requirement document is empty")
        if len(redacted.encode("utf-8")) > MAX_CONNECTOR_DOCUMENT_BYTES:
            raise ValueError("connector requirement document exceeds max supported size")
        return redacted, redaction_applied

    def _connector_extension_for_mime_type(self, mime_type: str) -> str:
        if mime_type.startswith("text/markdown") or mime_type == "text/x-markdown":
            return ".md"
        if mime_type in {"text/csv", "application/csv"}:
            return ".csv"
        if mime_type == "application/json":
            return ".json"
        if mime_type.startswith("text/") or mime_type in {"", "application/octet-stream"}:
            return ".txt"
        raise ValueError("connector requirement document must be a supported text document")

    def _require_requirement_document_binding(self, binding_id: UUID | None) -> SkillConnectorBinding:
        if binding_id is None:
            raise ValueError("connectorBindingId is required")
        binding = self.db.get(SkillConnectorBinding, binding_id)
        if binding is None:
            raise LookupError("connector binding not found")
        if binding.status != "active":
            raise ValueError("connector binding is not active")
        if binding.connector_name not in SUPPORTED_REQUIREMENT_DOCUMENT_CONNECTORS:
            raise ValueError("connector binding is not a supported requirement document connector")
        return binding

    def _authorize_requirement_document_binding_scope(
        self,
        binding: SkillConnectorBinding,
        *,
        project_id: UUID | None,
        environment_id: UUID | None,
        context: ServiceContext,
    ) -> None:
        binding_project_id = self._uuid_from_scope(binding.scope, "projectId", "project_id")
        binding_environment_id = self._uuid_from_scope(binding.scope, "environmentId", "environment_id")
        if context.user.edition == "community" and binding_project_id is None:
            raise ScopeAuthorizationError("COMMUNITY_CONNECTOR_PROJECT_SCOPE_REQUIRED")
        if binding_project_id is not None and binding_project_id != project_id:
            raise ScopeAuthorizationError("SCOPE_PROJECT_NOT_FOUND")
        if binding_environment_id is not None and binding_environment_id != environment_id:
            raise ScopeAuthorizationError("SCOPE_ENVIRONMENT_NOT_FOUND")

    @staticmethod
    def _uuid_from_scope(scope: dict[str, Any], *keys: str) -> UUID | None:
        for key in keys:
            value = scope.get(key)
            if value in {None, ""}:
                continue
            try:
                return UUID(str(value))
            except ValueError as exc:
                raise ScopeAuthorizationError("COMMUNITY_CONNECTOR_SCOPE_INVALID", status_code=409) from exc
        return None

    def _runtime_for_requirement_document_binding(self, binding: SkillConnectorBinding) -> ConnectorRuntime:
        if binding.connector_name == "mock-requirement-docs":
            return MockRequirementDocsConnector()
        if binding.connector_name == "lark-requirement-docs":
            return LarkRequirementDocsConnector(base_url=str(binding.scope.get("baseUrl") or "https://open.feishu.cn"))
        if binding.connector_name == "zentao-requirement-docs":
            return ZentaoRequirementDocsConnector(base_url=str(binding.scope.get("baseUrl") or ""))
        raise ValueError("connector binding is not a supported requirement document connector")

    def _record_connector_requirement_guardrail(
        self,
        *,
        context: ServiceContext,
        binding: SkillConnectorBinding,
        binding_snapshot: dict[str, object],
        skill_invocation_id: UUID,
        draft_id: UUID,
        external_document_id: str,
    ) -> None:
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                rule_id="connector.requirement_document_fetch_preflight",
                decision=GuardrailDecisionType.ALLOW,
                trace_id=UUID(str(context.trace_id)),
                skill_invocation_id=skill_invocation_id,
                connector_binding_id=binding.id,
                request_id=context.request_id,
                severity="info",
                message="requirement document connector fetch preflight allowed",
                evidence=[
                    {"type": "connector_binding", "ref": str(binding.id)},
                    {"type": "skill_invocation", "ref": str(skill_invocation_id)},
                ],
                payload={
                    "resourceType": "connector",
                    "resourceId": binding.connector_name,
                    "draftId": str(draft_id),
                    "externalDocumentId": external_document_id,
                    "connectorBindingId": str(binding.id),
                    "skillInvocationId": str(skill_invocation_id),
                    "secretScheme": binding_snapshot.get("secretScheme"),
                    "credentialScheme": binding_snapshot.get("credentialScheme"),
                    "operation": "fetch_requirement_document",
                    "readOnly": True,
                },
                metadata_json={
                    "connectorBindingSnapshot": self.connector_snapshot_builder.build(
                        {
                            "connectorBindingId": str(binding.id),
                            "connectorType": binding.connector_name,
                            "scope": binding.scope,
                            "bindingRevision": 1,
                        }
                    )
                },
            )
        )

    def _redacted_binding_snapshot(
        self,
        binding_snapshot: dict[str, object],
        *,
        connector_binding_id: UUID,
    ) -> dict[str, object]:
        return self.connector_snapshot_builder.build(
            {
                "connectorBindingId": str(connector_binding_id),
                "connectorType": binding_snapshot.get("connectorName"),
                "scope": dict(binding_snapshot.get("scope") or {}),
                "bindingRevision": 1,
                # The source refs are deliberately supplied only to the
                # allowlist builder, which drops them before persistence.
                "secretRef": binding_snapshot.get("secretRef"),
                "credentialRef": binding_snapshot.get("credentialRef"),
            }
        )

    def _dedupe_refs(self, refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for ref in refs:
            key = json.dumps(ref, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(ref)
        return deduped

    def _fetch_external_link_document(self, source_uri: str, context: ServiceContext) -> ExternalLinkDocument:
        try:
            location = self._validate_external_link_uri(source_uri)
            response = self._http_get_external_link(location.fetch_uri)
            final_location = self._validate_external_link_uri(str(response.url))
            raw_payload = bytes(response.content)
            self._validate_external_link_response(response, raw_payload)
            mime_type, extension = self._canonical_external_link_mime_type(
                response.headers.get("content-type"),
                final_location.source_uri,
            )
            document, redaction_applied = self._normalize_external_link_content(
                raw_payload,
                mime_type=mime_type,
                extension=extension,
            )
        except ValueError as exc:
            safe_uri = self._safe_source_uri_for_error(source_uri)
            self._record_external_link_guardrail(
                context=context,
                decision=GuardrailDecisionType.BLOCK,
                message=str(exc),
                source_uri=safe_uri,
                draft_id=None,
                evidence=[{"type": "source_uri", "ref": safe_uri}] if safe_uri else [],
                payload={"sourceType": "external_link"},
            )
            self.db.commit()
            raise
        return ExternalLinkDocument(
            document=document,
            source_uri=final_location.source_uri,
            mime_type=mime_type,
            byte_size=len(raw_payload),
            redaction_applied=redaction_applied,
            extension=extension,
        )

    def _http_get_external_link(self, source_uri: str) -> httpx.Response:
        current_uri = source_uri
        try:
            for _ in range(MAX_EXTERNAL_LINK_REDIRECTS + 1):
                location = self._validate_external_link_uri(current_uri)
                resolved_addresses = self._resolve_external_link_addresses(location)
                response = self._request_external_link_once(location, resolved_addresses[0])
                if response.status_code not in {301, 302, 303, 307, 308}:
                    return response
                redirect_location = response.headers.get("location")
                if not redirect_location:
                    raise ValueError("external_link redirect missing location")
                current_uri = urljoin(str(response.url), redirect_location)
        except (socket.timeout, TimeoutError) as exc:
            raise ValueError("external_link fetch timed out") from exc
        except ValueError:
            raise
        except (http.client.HTTPException, OSError) as exc:
            raise ValueError("external_link fetch failed") from exc
        raise ValueError("external_link redirect limit exceeded")

    def _resolve_external_link_addresses(self, location: ExternalLinkLocation) -> tuple[str, ...]:
        parsed = urlsplit(location.fetch_uri)
        port = parsed.port or (443 if location.scheme == "https" else 80)
        try:
            records = socket.getaddrinfo(
                location.host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise ValueError("external_link host could not be resolved") from exc
        addresses = tuple(
            sorted(
                {
                    str(record[4][0]).split("%", 1)[0]
                    for record in records
                    if record[4]
                }
            )
        )
        if not addresses:
            raise ValueError("external_link host could not be resolved")
        for address in addresses:
            try:
                resolved_ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ValueError("external_link host resolved to an invalid address") from exc
            if (
                not resolved_ip.is_global
                or resolved_ip.is_multicast
                or resolved_ip.is_reserved
                or resolved_ip.is_unspecified
            ):
                raise ValueError("external_link host resolved to a non-public address")
        return addresses

    def _request_external_link_once(
        self,
        location: ExternalLinkLocation,
        resolved_address: str,
    ) -> httpx.Response:
        parsed = urlsplit(location.fetch_uri)
        port = parsed.port or (443 if location.scheme == "https" else 80)
        connection_type = (
            http.client.HTTPSConnection
            if location.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_type(
            location.host,
            port,
            timeout=EXTERNAL_LINK_TIMEOUT_SECONDS,
        )

        def pinned_connection(
            _address: tuple[str, int],
            timeout: float | None = None,
            source_address: tuple[str, int] | None = None,
        ) -> socket.socket:
            return socket.create_connection(
                (resolved_address, port),
                timeout,
                source_address,
            )

        connection._create_connection = pinned_connection  # type: ignore[attr-defined,method-assign]
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        host_header = f"[{location.host}]" if ":" in location.host else location.host
        default_port = 443 if location.scheme == "https" else 80
        if port != default_port:
            host_header = f"{host_header}:{port}"
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Accept": "text/plain,text/markdown,text/csv,application/json,text/*;q=0.8",
                    "Accept-Encoding": "identity",
                    "Host": host_header,
                    "User-Agent": "agentic-qa-requirement-intake/1.0",
                },
            )
            raw_response = connection.getresponse()
            content_length = raw_response.getheader("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_EXTERNAL_LINK_BYTES:
                        raise ValueError("external_link document exceeds max supported size")
                except ValueError as exc:
                    if str(exc) == "external_link document exceeds max supported size":
                        raise
                    raise ValueError("external_link content-length is invalid") from exc
            payload = raw_response.read(MAX_EXTERNAL_LINK_BYTES + 1)
            if len(payload) > MAX_EXTERNAL_LINK_BYTES:
                raise ValueError("external_link document exceeds max supported size")
            request = httpx.Request("GET", location.fetch_uri)
            return httpx.Response(
                raw_response.status,
                headers=raw_response.getheaders(),
                content=payload,
                request=request,
            )
        finally:
            connection.close()

    def _validate_external_link_response(self, response: httpx.Response, payload: bytes) -> None:
        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError("external_link fetch returned a non-success status")
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_EXTERNAL_LINK_BYTES:
                    raise ValueError("external_link document exceeds max supported size")
            except ValueError as exc:
                if str(exc) == "external_link document exceeds max supported size":
                    raise
                raise ValueError("external_link content-length is invalid") from exc
        if not payload:
            raise ValueError("external_link document is empty")
        if len(payload) > MAX_EXTERNAL_LINK_BYTES:
            raise ValueError("external_link document exceeds max supported size")

    def _validate_external_link_uri(self, source_uri: str) -> ExternalLinkLocation:
        raw_uri = source_uri.strip()
        if not raw_uri:
            raise ValueError("external_link sourceUri is required")
        if len(raw_uri) > 2048:
            raise ValueError("external_link sourceUri exceeds max length")
        if contains_unsafe_control_characters(raw_uri):
            raise ValueError("external_link sourceUri contains unsafe control characters")
        parsed = urlsplit(raw_uri)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("external_link sourceUri must use http or https")
        if parsed.username or parsed.password:
            raise ValueError("external_link sourceUri must not include credentials")
        host = (parsed.hostname or "").lower().strip().rstrip(".")
        if not host:
            raise ValueError("external_link sourceUri host is required")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("external_link sourceUri port is invalid") from exc
        self._validate_external_link_host(host)
        netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
        if port is not None:
            netloc = f"{netloc}:{port}"
        path = parsed.path or "/"
        safe_query = self._sanitize_url_query(parsed.query)
        source_uri_value = urlunsplit((scheme, netloc, path, safe_query, ""))
        fetch_uri = urlunsplit((scheme, netloc, path, parsed.query, ""))
        return ExternalLinkLocation(fetch_uri=fetch_uri, source_uri=source_uri_value, scheme=scheme, host=host)

    def _validate_external_link_host(self, host: str) -> None:
        if host in {"localhost", "0.0.0.0"} or host.endswith(".localhost"):
            raise ValueError("external_link host is not allowed")
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            if re.fullmatch(
                r"(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+))*",
                host,
            ):
                raise ValueError("external_link host is not allowed")
            labels = host.rstrip(".").split(".")
            if any(not label or len(label) > 63 for label in labels):
                raise ValueError("external_link host is invalid")
            if any(not re.fullmatch(r"[a-z0-9-]+", label) or label.startswith("-") or label.endswith("-") for label in labels):
                raise ValueError("external_link host is invalid")
            return
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError("external_link host is not allowed")

    def _canonical_external_link_mime_type(self, content_type: str | None, source_uri: str) -> tuple[str, str]:
        supplied_mime = (content_type or "").split(";")[0].strip().lower()
        extension = Path(urlsplit(source_uri).path or "").suffix.lower()
        if supplied_mime.startswith("text/"):
            return supplied_mime, extension if extension in SUPPORTED_EXTERNAL_LINK_EXTENSIONS else ".txt"
        if supplied_mime in SUPPORTED_EXTERNAL_LINK_MIME_TYPES:
            if supplied_mime == "application/octet-stream" and extension not in SUPPORTED_EXTERNAL_LINK_EXTENSIONS:
                raise ValueError("external_link content must be a supported text document")
            canonical = supplied_mime or SUPPORTED_EXTERNAL_LINK_EXTENSIONS.get(extension, "text/plain")
            return canonical, extension if extension in SUPPORTED_EXTERNAL_LINK_EXTENSIONS else ".txt"
        if extension in SUPPORTED_EXTERNAL_LINK_EXTENSIONS and supplied_mime in {"", "application/octet-stream"}:
            return SUPPORTED_EXTERNAL_LINK_EXTENSIONS[extension], extension
        raise ValueError("external_link content must be a supported text document")

    def _normalize_external_link_content(self, payload: bytes, *, mime_type: str, extension: str) -> tuple[str, bool]:
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("external_link document must be UTF-8 text") from exc
        if "\x00" in text:
            raise ValueError("external_link document appears to be binary")
        normalized = text.strip()
        if mime_type == "application/json" or extension == ".json":
            try:
                parsed = json.loads(normalized)
            except json.JSONDecodeError as exc:
                raise ValueError("external_link JSON is invalid") from exc
            normalized = json.dumps(parsed, ensure_ascii=False, indent=2)
        redacted, redaction_applied = self._normalize_paste_content(normalized)
        return redacted, redaction_applied

    def _sanitize_url_query(self, query: str) -> str:
        if not query:
            return ""
        sanitized: list[tuple[str, str]] = []
        for key, value in parse_qsl(query, keep_blank_values=True):
            key_lower = key.lower()
            if any(fragment in key_lower for fragment in SENSITIVE_URL_QUERY_KEY_FRAGMENTS) or self._looks_like_url_secret(value):
                sanitized.append((key, "[REDACTED]"))
            else:
                sanitized.append((key, value))
        return urlencode(sanitized, doseq=True, safe="[]")

    def _looks_like_url_secret(self, value: str) -> bool:
        return value.startswith(SENSITIVE_URL_VALUE_PREFIXES)

    def _safe_source_uri_for_error(self, source_uri: str) -> str | None:
        try:
            return self._validate_external_link_uri(source_uri).source_uri
        except ValueError:
            parsed = urlsplit(source_uri.strip())
            if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
                host = parsed.hostname.lower()
                netloc = host
                try:
                    if parsed.port is not None:
                        netloc = f"{netloc}:{parsed.port}"
                except ValueError:
                    pass
                safe_path = parsed.path or "/"
                if contains_unsafe_control_characters(safe_path):
                    safe_path = "/"
                return urlunsplit(
                    (
                        parsed.scheme.lower(),
                        netloc,
                        redact_sensitive_text(safe_path),
                        self._sanitize_url_query(parsed.query),
                        "",
                    )
                )
        return None

    def _record_external_link_guardrail(
        self,
        *,
        context: ServiceContext,
        decision: GuardrailDecisionType,
        message: str,
        source_uri: str | None,
        draft_id: UUID | None,
        evidence: list[dict[str, Any]],
        payload: dict[str, Any],
    ) -> None:
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                rule_id="requirement_intake.external_link_preflight",
                decision=decision,
                trace_id=UUID(str(context.trace_id)),
                request_id=context.request_id,
                severity="info" if decision == GuardrailDecisionType.ALLOW else "block",
                message=message,
                evidence=evidence,
                payload={
                    "resourceType": "requirement_intake_draft",
                    "resourceId": str(draft_id) if draft_id else None,
                    "sourceUri": source_uri,
                    **payload,
                },
                metadata_json={"guardrail": "requirement_intake.external_link_preflight"},
            )
        )

    def _record_upload_guardrail(
        self,
        *,
        context: ServiceContext,
        decision: GuardrailDecisionType,
        message: str,
        draft_id: UUID | None,
        mime_type: str,
        byte_size: int,
        redaction_status: str,
    ) -> None:
        resource_limits = document_resource_limit_snapshot()
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                rule_id="requirement_intake.upload_preflight",
                decision=decision,
                trace_id=UUID(str(context.trace_id)),
                request_id=context.request_id,
                severity="info" if decision == GuardrailDecisionType.ALLOW else "block",
                message=message,
                evidence=[
                    {"type": "redaction_status", "ref": redaction_status},
                    {"type": "resource_limit_profile", "ref": resource_limits["profile"]},
                ],
                payload={
                    "resourceType": "requirement_intake_draft",
                    "resourceId": str(draft_id) if draft_id else None,
                    "sourceType": "upload",
                    "mimeType": mime_type,
                    "byteSize": byte_size,
                    "redactionStatus": redaction_status,
                    "errorCode": self._stable_error_code(message),
                    "resourceLimits": resource_limits,
                },
                metadata_json={"guardrail": "requirement_intake.upload_preflight"},
            )
        )

    def _record_paste_guardrail(
        self,
        *,
        context: ServiceContext,
        decision: GuardrailDecisionType,
        message: str,
        draft_id: UUID | None,
        redaction_status: str,
        byte_size: int,
    ) -> None:
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                rule_id="requirement_intake.paste_preflight",
                decision=decision,
                trace_id=UUID(str(context.trace_id)),
                request_id=context.request_id,
                severity="info" if decision == GuardrailDecisionType.ALLOW else "block",
                message=message,
                evidence=[{"type": "redaction_status", "ref": redaction_status}],
                payload={
                    "resourceType": "requirement_intake_draft",
                    "resourceId": str(draft_id) if draft_id else None,
                    "sourceType": "paste",
                    "byteSize": byte_size,
                    "redactionStatus": redaction_status,
                    "errorCode": self._stable_error_code(message),
                },
                metadata_json={"guardrail": "requirement_intake.paste_preflight"},
            )
        )

    def _record_ocr_guardrail(
        self,
        *,
        context: ServiceContext,
        decision: GuardrailDecisionType,
        message: str,
        draft_id: UUID | None,
        confidence: float | None,
        status: str,
        mime_type: str,
        byte_size: int,
        redaction_status: str,
        trace_ref: str,
    ) -> None:
        resource_limits = ocr_resource_limit_snapshot()
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                rule_id="requirement_intake.ocr_preflight",
                decision=decision,
                trace_id=UUID(str(context.trace_id)),
                request_id=context.request_id,
                severity={
                    GuardrailDecisionType.ALLOW: "info",
                    GuardrailDecisionType.WARN: "medium",
                    GuardrailDecisionType.BLOCK: "block",
                }[decision],
                message=message,
                evidence=[
                    {"type": "trace_ref", "ref": trace_ref},
                    {"type": "resource_limit_profile", "ref": resource_limits["profile"]},
                ],
                payload={
                    "resourceType": "requirement_intake_draft",
                    "resourceId": str(draft_id) if draft_id else None,
                    "sourceType": "ocr_upload",
                    "mimeType": mime_type,
                    "byteSize": byte_size,
                    "ocrConfidence": confidence,
                    "ocrStatus": status,
                    "redactionStatus": redaction_status,
                    "traceRef": trace_ref,
                    "errorCode": self._stable_error_code(message),
                    "resourceLimits": resource_limits,
                },
                metadata_json={"guardrail": "requirement_intake.ocr_preflight"},
            )
        )

    def _canonical_ocr_upload(self, file_name: str, content_type: str | None, payload: bytes) -> tuple[str, str]:
        if not payload:
            raise ValueError("OCR_INPUT_INVALID: OCR source is empty")
        if len(payload) > MAX_OCR_UPLOAD_BYTES:
            raise ValueError("OCR_INPUT_TOO_LARGE: OCR source exceeds max supported size")
        self._validate_upload_filename(file_name)
        extension = Path(file_name or "").suffix.lower()
        if extension not in SUPPORTED_OCR_UPLOAD_EXTENSIONS:
            raise ValueError("OCR_INPUT_UNSUPPORTED: unsupported OCR upload file type")
        supplied_mime = (content_type or "").split(";")[0].strip().lower()
        if supplied_mime not in SUPPORTED_OCR_UPLOAD_MIME_TYPES:
            raise ValueError("OCR_INPUT_UNSUPPORTED: unsupported OCR upload mimeType")
        canonical_mime = SUPPORTED_OCR_UPLOAD_EXTENSIONS[extension]
        if supplied_mime not in {"", "application/octet-stream", canonical_mime}:
            raise ValueError("OCR_INPUT_INVALID: OCR upload extension and mimeType do not match")
        return canonical_mime, extension

    def _ocr_review_status(self, confidence: float, risk_level: RiskLevel) -> tuple[str, list[str]]:
        normalized_confidence = max(0.0, min(1.0, float(confidence)))
        if normalized_confidence < OCR_BLOCK_CONFIDENCE:
            return "blocked", ["confidence_below_block_threshold"]
        reasons: list[str] = []
        if normalized_confidence < OCR_READY_CONFIDENCE:
            reasons.append("confidence_below_ready_threshold")
        if risk_level == RiskLevel.HIGH:
            reasons.append("high_risk_content_requires_review")
        return ("review_required", reasons) if reasons else ("ready", [])

    def _ocr_projection(self, metadata: dict[str, Any] | None) -> dict[str, Any] | None:
        value = dict((metadata or {}).get("ocr") or {})
        if not value:
            return None
        return {
            "status": str(value.get("status") or "blocked"),
            "confidence": float(value.get("confidence") or 0.0),
            "reviewRequired": bool(value.get("reviewRequired")),
            "blocked": bool(value.get("blocked")),
            "reviewReasons": [str(item) for item in list(value.get("reviewReasons") or [])],
            "adapter": str(value.get("adapter") or ""),
            "pageCount": int(value.get("pageCount") or 0),
            "lineCount": int(value.get("lineCount") or 0),
            "readyConfidenceThreshold": float(value.get("readyConfidenceThreshold") or OCR_READY_CONFIDENCE),
            "blockConfidenceThreshold": float(value.get("blockConfidenceThreshold") or OCR_BLOCK_CONFIDENCE),
            "traceRefs": [str(item) for item in list(value.get("traceRefs") or [])],
            "pages": [dict(item) for item in list(value.get("pages") or []) if isinstance(item, dict)],
        }

    @staticmethod
    def _stable_error_code(message: str) -> str | None:
        candidate = message.partition(":")[0].strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", candidate):
            return candidate
        return None

    def _normalize_upload_content(
        self,
        file_name: str,
        content_type: str | None,
        payload: bytes,
        *,
        allow_document_parsing: bool = False,
    ) -> tuple[str, bool, str, str]:
        if not payload:
            raise ValueError("uploaded file is empty")
        if len(payload) > MAX_UPLOAD_BYTES:
            raise ValueError("uploaded file exceeds max supported size")
        self._validate_upload_filename(file_name)
        extension = Path(file_name or "").suffix.lower()
        supported_extensions = SUPPORTED_SINGLE_UPLOAD_EXTENSIONS if allow_document_parsing else SUPPORTED_UPLOAD_EXTENSIONS
        if extension not in supported_extensions:
            raise ValueError("unsupported upload file type")
        supplied_mime = (content_type or "").split(";")[0].strip().lower()
        supported_mime_types = SUPPORTED_SINGLE_UPLOAD_MIME_TYPES if allow_document_parsing else SUPPORTED_UPLOAD_MIME_TYPES
        if supplied_mime not in supported_mime_types:
            raise ValueError("unsupported upload mimeType")
        canonical_mime_type = supported_extensions[extension]
        if extension not in SUPPORTED_DOCUMENT_UPLOAD_EXTENSIONS and supplied_mime in SUPPORTED_DOCUMENT_UPLOAD_EXTENSIONS.values():
            raise ValueError("upload extension and mimeType do not match")
        if extension in SUPPORTED_DOCUMENT_UPLOAD_EXTENSIONS:
            if supplied_mime not in {"", "application/octet-stream", canonical_mime_type}:
                raise ValueError("upload extension and mimeType do not match")
            parsed = self.document_parser.extract_text(payload, mime_type=canonical_mime_type)
            redacted, redaction_applied = self._normalize_paste_content(parsed.text)
            return redacted, redaction_applied, canonical_mime_type, extension
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("uploaded text must be UTF-8") from exc
        if "\x00" in text:
            raise ValueError("uploaded file appears to be binary")
        normalized = text.strip()
        if extension == ".json":
            try:
                parsed = json.loads(normalized)
            except json.JSONDecodeError as exc:
                raise ValueError("uploaded JSON is invalid") from exc
            normalized = json.dumps(parsed, ensure_ascii=False, indent=2)
        redacted, redaction_applied = self._normalize_paste_content(normalized)
        return redacted, redaction_applied, canonical_mime_type, extension

    def _normalize_paste_content(self, raw_content: str) -> tuple[str, bool]:
        if len(raw_content.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise ValueError("REQUIREMENT_CONTENT_TOO_LARGE: requirement content exceeds max supported size")
        if contains_unsafe_control_characters(raw_content):
            raise ValueError("REQUIREMENT_CONTENT_INVALID: requirement content contains unsafe control characters")
        normalized = raw_content.strip()
        redacted = redact_sensitive_text(normalized)
        return redacted, redacted != normalized

    def _validate_upload_filename(self, file_name: str) -> None:
        value = (file_name or "").strip()
        if not value or len(value) > 255:
            raise ValueError("UPLOAD_FILENAME_INVALID: upload filename is invalid")
        decoded = value
        for _ in range(3):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        if (
            decoded != value
            or "/" in decoded
            or "\\" in decoded
            or Path(decoded).is_absolute()
            or Path(decoded).drive
            or decoded in {".", ".."}
            or contains_unsafe_control_characters(decoded)
        ):
            raise ValueError("UPLOAD_FILENAME_INVALID: upload filename contains an unsafe path")

    def _safe_user_text(self, value: str, *, field_name: str) -> str:
        normalized = value.strip()
        if contains_unsafe_control_characters(normalized):
            raise ValueError(f"{field_name} contains unsafe control characters")
        return redact_sensitive_text(normalized)

    def _parse_domains(self, domains: list[str]) -> list[TestDomain]:
        parsed: list[TestDomain] = []
        for domain in domains:
            if not domain:
                continue
            parsed.append(TestDomain(domain))
        return parsed or [TestDomain.FUNCTIONAL, TestDomain.PERFORMANCE, TestDomain.SECURITY]

    def _parse_risk_level(self, risk_level: str) -> RiskLevel:
        return RiskLevel(risk_level or RiskLevel.MEDIUM.value)

    def _validate_project_environment(self, project_id: UUID | None, environment_id: UUID | None) -> None:
        project = self.db.get(Project, project_id) if project_id else None
        if project_id is not None and project is None:
            raise LookupError("project not found")
        environment = self.db.get(ProjectEnvironment, environment_id) if environment_id else None
        if environment_id is not None and environment is None:
            raise LookupError("environment not found")
        if project is not None and environment is not None and environment.project_id != project.id:
            raise ValueError("environment does not belong to project")

    def _authorize_project_environment(
        self,
        project_id: UUID | None,
        environment_id: UUID | None,
        context: ServiceContext,
        *,
        write: bool,
    ) -> None:
        self._validate_project_environment(project_id, environment_id)
        resolved_project_id = project_id
        if resolved_project_id is None and environment_id is not None:
            environment = self.db.get(ProjectEnvironment, environment_id)
            resolved_project_id = environment.project_id if environment is not None else None
        if resolved_project_id is None:
            if context.user.edition == "community":
                raise ScopeAuthorizationError(
                    "COMMUNITY_REQUIREMENT_PROJECT_SCOPE_REQUIRED",
                    status_code=400,
                    field="projectId",
                )
            return
        ScopeAuthorizationService(self.db).resolve_project(
            resolved_project_id,
            context,
            environment_id=environment_id,
            write=write,
        )

    @staticmethod
    def _authorize_community_risk(risk_level: RiskLevel, context: ServiceContext) -> None:
        if context.user.edition == "community" and risk_level == RiskLevel.HIGH:
            raise ScopeAuthorizationError(
                "COMMUNITY_REQUIREMENT_HIGH_RISK_APPROVAL_UNAVAILABLE",
                status_code=409,
                field="riskLevel",
            )

    def _require_draft(self, draft_id: UUID) -> RequirementIntakeDraft:
        draft = self.db.get(RequirementIntakeDraft, UUID(str(draft_id)))
        if draft is None:
            raise LookupError("requirement intake draft not found")
        return draft

    @staticmethod
    def _content_hash(payload: bytes) -> str:
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _raise_if_duplicate_content(
        self,
        *,
        content_hash: str,
        normalized_document: str,
        project_id: UUID | None,
        environment_id: UUID | None,
        created_by: UUID,
    ) -> None:
        scope_identity = str(project_id) if project_id is not None else f"user:{created_by}"
        acquire_transaction_advisory_lock(
            self.db,
            "requirement-intake-content",
            f"{scope_identity}:{environment_id or 'none'}:{content_hash}",
        )
        scope_filters = [
            RequirementIntakeDraft.status != "discarded",
            RequirementIntakeDraft.project_id == project_id
            if project_id is not None
            else RequirementIntakeDraft.project_id.is_(None),
            RequirementIntakeDraft.environment_id == environment_id
            if environment_id is not None
            else RequirementIntakeDraft.environment_id.is_(None),
        ]
        if project_id is None:
            scope_filters.append(RequirementIntakeDraft.created_by == created_by)
        content_filter = RequirementIntakeDraft.content_hash == content_hash
        if normalized_document:
            content_filter = or_(
                content_filter,
                and_(
                    RequirementIntakeDraft.content_hash.is_(None),
                    RequirementIntakeDraft.normalized_document == normalized_document,
                ),
            )
        duplicate = self.db.scalar(
            select(RequirementIntakeDraft)
            .where(*scope_filters, content_filter)
            .order_by(RequirementIntakeDraft.created_at.desc(), RequirementIntakeDraft.id.desc())
            .limit(1)
        )
        if duplicate is None:
            return
        preview = self.db.scalar(
            select(RequirementIntakePreview)
            .where(
                RequirementIntakePreview.draft_id == duplicate.id,
                RequirementIntakePreview.status != "superseded",
            )
            .order_by(RequirementIntakePreview.created_at.desc(), RequirementIntakePreview.id.desc())
            .limit(1)
        )
        raise RequirementIntakeDuplicateError(
            draft_id=duplicate.id,
            preview_id=preview.id if preview is not None else None,
            linked_pipeline_id=preview.linked_pipeline_id if preview is not None else None,
        )

    def _require_preview(self, preview_id: UUID) -> RequirementIntakePreview:
        preview = self.db.get(RequirementIntakePreview, UUID(str(preview_id)))
        if preview is None:
            raise LookupError("requirement intake preview not found")
        return preview

    def _first_meaningful_line(self, document: str) -> str | None:
        for raw_line in document.splitlines():
            line = raw_line.strip(" -*\t")
            if len(line) >= 10 and not self._is_section_header(line):
                return line
        return None

    def _is_section_header(self, line: str) -> bool:
        lower = line.lower().rstrip(":：")
        return lower in SECTION_REQUIREMENT_MARKERS or lower in SECTION_ACCEPTANCE_MARKERS

    def _is_requirement_prefix(self, prefix: str) -> bool:
        return prefix in SECTION_REQUIREMENT_MARKERS or prefix.startswith("req") or prefix.startswith("requirement")

    def _is_acceptance_prefix(self, prefix: str) -> bool:
        return (
            prefix in SECTION_ACCEPTANCE_MARKERS
            or prefix.startswith("ac")
            or "acceptance" in prefix
            or "criteria" in prefix
        )

    def _dedupe(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            cleaned = value.strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            deduped.append(cleaned)
        return deduped

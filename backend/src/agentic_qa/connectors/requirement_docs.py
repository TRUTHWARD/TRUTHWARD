# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from agentic_qa.connectors.contracts import (
    ConnectorCapability,
    ConnectorOperationRequest,
    ConnectorOperationResult,
    ConnectorRuntimeContract,
)
from agentic_qa.infra.managed_http import ManagedHttpRequestError, managed_http_request


REQUIREMENT_DOCUMENT_CAPABILITIES = [
    ConnectorCapability(name="fetch_requirement_document", read_only=True, risk_level="low"),
]

MOCK_REQUIREMENT_DOCS_CONTRACT = ConnectorRuntimeContract(
    connector_name="mock-requirement-docs",
    protocol="mock",
    capabilities=REQUIREMENT_DOCUMENT_CAPABILITIES,
    credential_schemes=["vault", "credential", "env", "mcp-secret"],
)

LARK_REQUIREMENT_DOCS_CONTRACT = ConnectorRuntimeContract(
    connector_name="lark-requirement-docs",
    protocol="https",
    capabilities=REQUIREMENT_DOCUMENT_CAPABILITIES,
    credential_schemes=["vault", "credential", "env", "mcp-secret"],
)

ZENTAO_REQUIREMENT_DOCS_CONTRACT = ConnectorRuntimeContract(
    connector_name="zentao-requirement-docs",
    protocol="https",
    capabilities=REQUIREMENT_DOCUMENT_CAPABILITIES,
    credential_schemes=["vault", "credential", "env", "mcp-secret"],
)

TAG_PATTERN = re.compile(r"<[^>]+>")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _document_ref(request: ConnectorOperationRequest) -> str:
    return str(request.payload.get("externalDocumentId") or request.payload.get("sourceRef") or "").strip()


def _first_string(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value is not None and not isinstance(value, (dict, list)):
            return str(value).strip()
    return None


def _nested_payload(payload: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    return payload


def _plain_text(value: str) -> str:
    return TAG_PATTERN.sub("", html.unescape(value)).strip()


class HttpRequirementDocsConnector:
    """Base class for read-only external requirement document adapters."""

    contract: ConnectorRuntimeContract

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._attempts = 0

    def _token(self, request: ConnectorOperationRequest) -> str:
        token = str(
            request.runtime_credentials.get("token")
            or request.runtime_credentials.get("accessToken")
            or request.runtime_credentials.get("apiToken")
            or ""
        ).strip()
        if not token:
            raise ValueError("runtime credential token is required for requirement document fetch")
        return token

    def _headers(self, request: ConnectorOperationRequest, *, accept: str = "application/json") -> dict[str, str]:
        token = self._token(request)
        return {
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "User-Agent": "agentic-qa-requirement-docs/1.0",
        }

    def _get_json(self, path: str, request: ConnectorOperationRequest) -> dict[str, Any]:
        response = managed_http_request(
            "GET",
            f"{self.base_url}{path}",
            headers=self._headers(request),
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
        )
        self._attempts += response.attempts
        parsed = json.loads(response.text)
        return parsed if isinstance(parsed, dict) else {"items": parsed}

    def _error_result(self, error: Exception) -> ConnectorOperationResult:
        if isinstance(error, ManagedHttpRequestError):
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"{self.contract.connector_name} {error.summary}"],
            )
        if isinstance(error, json.JSONDecodeError):
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"{self.contract.connector_name} malformed json response"],
            )
        return ConnectorOperationResult(succeeded=False, errors=[str(error)])

    def _evidence_metadata(self, request: ConnectorOperationRequest) -> dict[str, Any]:
        return {
            "operation": request.operation,
            "connector": self.contract.connector_name,
            "attempts": max(self._attempts, 1),
            "traceId": request.trace_id,
            "skillInvocationId": request.skill_invocation_id,
        }


class LarkRequirementDocsConnector(HttpRequirementDocsConnector):
    """Read-only Lark document adapter for requirement import."""

    contract = LARK_REQUIREMENT_DOCS_CONTRACT

    def __init__(
        self,
        *,
        base_url: str = "https://open.feishu.cn",
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        super().__init__(
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        self._attempts = 0
        if request.operation != "fetch_requirement_document":
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"unsupported requirement document operation '{request.operation}'"],
            )
        external_document_id = _document_ref(request)
        if not external_document_id:
            return ConnectorOperationResult(succeeded=False, errors=["externalDocumentId or sourceRef is required"])
        try:
            payload = self._get_json(f"/open-apis/docx/v1/documents/{quote(external_document_id, safe='')}/raw_content", request)
            if "code" in payload and payload.get("code") not in (0, "0", None):
                return ConnectorOperationResult(succeeded=False, errors=["lark requirement document fetch returned provider error"])
            data = _nested_payload(payload, "data", "document")
            document = _first_string(data, "content", "rawContent", "markdown", "text", "document")
            if not document:
                return ConnectorOperationResult(succeeded=False, errors=["lark requirement document response did not include text content"])
            title = _first_string(data, "title", "name") or f"Lark Requirement Document {external_document_id}"
            source_uri = _first_string(data, "url", "sourceUri") or f"lark://docx/{external_document_id}"
            content_version = _first_string(data, "revision_id", "revisionId", "version")
            provider_native_refs = [{"type": "lark_docx_document", "documentId": external_document_id}]
            result = {
                "provider": self.contract.connector_name,
                "operation": request.operation,
                "externalDocumentId": external_document_id,
                "sourceRef": request.payload.get("sourceRef"),
                "title": title,
                "document": document.strip(),
                "mimeType": "text/markdown",
                "sourceUri": source_uri,
                "contentVersion": content_version,
                "providerNativeRefs": provider_native_refs,
                "fetchedAt": _now(),
                "readOnly": True,
            }
            return self._result(request, result, source_uri, provider_native_refs)
        except Exception as exc:
            return self._error_result(exc)

    def _result(
        self,
        request: ConnectorOperationRequest,
        data: dict[str, Any],
        ref: str,
        provider_native_refs: list[dict[str, Any]],
    ) -> ConnectorOperationResult:
        metadata = {
            **self._evidence_metadata(request),
            "providerNativeRefs": provider_native_refs,
            "readOnly": True,
        }
        return ConnectorOperationResult(
            succeeded=True,
            data=data,
            evidence_refs=[
                {
                    "type": "connector",
                    "ref": ref,
                    "metadata": metadata,
                }
            ],
            connector_call_ref=ref,
        )


class ZentaoRequirementDocsConnector(HttpRequirementDocsConnector):
    """Read-only ZenTao story/document adapter for requirement import.

    This connector is intentionally separate from the `zentao` issue-tracker
    adapter. It reads requirement/story content only and never syncs defects.
    """

    contract = ZENTAO_REQUIREMENT_DOCS_CONTRACT

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        if not base_url:
            raise ValueError("baseUrl is required for zentao requirement document connector")
        super().__init__(
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        self._attempts = 0
        if request.operation != "fetch_requirement_document":
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"unsupported requirement document operation '{request.operation}'"],
            )
        external_document_id = _document_ref(request)
        if not external_document_id:
            return ConnectorOperationResult(succeeded=False, errors=["externalDocumentId or sourceRef is required"])
        try:
            payload = self._get_json(f"/api.php/v1/stories/{quote(external_document_id, safe='')}", request)
            data = _nested_payload(payload, "data", "story")
            title = _first_string(data, "title", "name") or f"ZenTao Requirement Document {external_document_id}"
            document = self._document_from_story(data, title)
            if not document:
                return ConnectorOperationResult(succeeded=False, errors=["zentao requirement document response did not include text content"])
            source_uri = _first_string(data, "url", "sourceUri", "webUrl") or f"zentao://story/{external_document_id}"
            content_version = _first_string(data, "version", "openedDate", "lastEditedDate", "updatedAt")
            provider_native_refs = [{"type": "zentao_story", "storyId": external_document_id}]
            result = {
                "provider": self.contract.connector_name,
                "operation": request.operation,
                "externalDocumentId": external_document_id,
                "sourceRef": request.payload.get("sourceRef"),
                "title": title,
                "document": document.strip(),
                "mimeType": "text/markdown",
                "sourceUri": source_uri,
                "contentVersion": content_version,
                "providerNativeRefs": provider_native_refs,
                "fetchedAt": _now(),
                "readOnly": True,
            }
            return self._result(request, result, source_uri, provider_native_refs)
        except Exception as exc:
            return self._error_result(exc)

    def _headers(self, request: ConnectorOperationRequest, *, accept: str = "application/json") -> dict[str, str]:
        headers = super()._headers(request, accept=accept)
        headers["Token"] = self._token(request)
        return headers

    def _document_from_story(self, data: dict[str, Any], title: str) -> str:
        direct = _first_string(data, "document", "content", "rawContent", "markdown")
        if direct:
            return _plain_text(direct)
        spec = _plain_text(_first_string(data, "spec", "description", "requirements") or "")
        verify = _plain_text(_first_string(data, "verify", "acceptanceCriteria", "acceptance") or "")
        lines = [f"# {title}"]
        if spec:
            lines.extend(["", f"Requirement: {spec}"])
        if verify:
            lines.extend(["", f"Acceptance: {verify}"])
        return "\n".join(lines).strip()

    def _result(
        self,
        request: ConnectorOperationRequest,
        data: dict[str, Any],
        ref: str,
        provider_native_refs: list[dict[str, Any]],
    ) -> ConnectorOperationResult:
        metadata = {
            **self._evidence_metadata(request),
            "providerNativeRefs": provider_native_refs,
            "readOnly": True,
        }
        return ConnectorOperationResult(
            succeeded=True,
            data=data,
            evidence_refs=[
                {
                    "type": "connector",
                    "ref": ref,
                    "metadata": metadata,
                }
            ],
            connector_call_ref=ref,
        )


class MockRequirementDocsConnector:
    """Read-only mock adapter for requirement document imports.

    The adapter returns connector-native document data and evidence refs only.
    It does not create RequirementVersion records, write Gate or Memory, or make
    any product decision about whether the document should enter the pipeline.
    """

    contract = MOCK_REQUIREMENT_DOCS_CONTRACT

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        if request.operation != "fetch_requirement_document":
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"unsupported requirement document operation '{request.operation}'"],
            )

        external_document_id = str(request.payload.get("externalDocumentId") or "").strip()
        if not external_document_id:
            return ConnectorOperationResult(
                succeeded=False,
                errors=["externalDocumentId is required"],
            )

        title = str(request.payload.get("title") or self._title_for(external_document_id)).strip()
        document = str(request.payload.get("document") or self._document_for(external_document_id, title)).strip()
        ref = f"mock-requirement-docs://requirement-documents/{self._safe_ref(external_document_id)}"
        provider_native_refs = [{"type": "mock_requirement_document", "documentId": external_document_id}]
        data: dict[str, Any] = {
            "provider": self.contract.connector_name,
            "operation": request.operation,
            "externalDocumentId": external_document_id,
            "title": title,
            "document": document,
            "mimeType": "text/markdown",
            "sourceUri": ref,
            "contentVersion": "mock-v1",
            "providerNativeRefs": provider_native_refs,
            "fetchedAt": datetime.now(timezone.utc).isoformat(),
            "readOnly": True,
        }
        return ConnectorOperationResult(
            succeeded=True,
            data=data,
            evidence_refs=[
                {
                    "type": "connector",
                    "ref": ref,
                    "metadata": {
                        "operation": request.operation,
                        "connector": self.contract.connector_name,
                        "externalDocumentId": external_document_id,
                        "providerNativeRefs": provider_native_refs,
                        "readOnly": True,
                    },
                }
            ],
            connector_call_ref=ref,
        )

    def _title_for(self, external_document_id: str) -> str:
        normalized = external_document_id.replace("_", " ").replace("-", " ").strip()
        return f"Mock Requirement Document {normalized or 'default'}"

    def _document_for(self, external_document_id: str, title: str) -> str:
        return "\n".join(
            [
                f"# {title}",
                "",
                f"Requirement: Imported document {external_document_id} can enter the requirement intake preview.",
                "Acceptance: The imported document produces a structured preview.",
            ]
        )

    def _safe_ref(self, external_document_id: str) -> str:
        return "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in external_document_id).strip("-") or "document"

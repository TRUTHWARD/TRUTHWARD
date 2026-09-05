# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from urllib.parse import quote
from urllib.parse import urlencode

from agentic_qa.connectors.contracts import (
    ConnectorCapability,
    ConnectorOperationRequest,
    ConnectorOperationResult,
    ConnectorRuntimeContract,
)
from agentic_qa.infra.managed_http import ManagedHttpRequestError, managed_http_request


GITLAB_CONNECTOR_CONTRACT = ConnectorRuntimeContract(
    connector_name="gitlab",
    protocol="https",
    capabilities=[
        ConnectorCapability(name="receive_merge_request_webhook", read_only=True, risk_level="low"),
        ConnectorCapability(name="fetch_merge_request", read_only=True, risk_level="low"),
        ConnectorCapability(name="fetch_diff", read_only=True, risk_level="low"),
        ConnectorCapability(name="write_check", read_only=False, risk_level="high"),
    ],
    credential_schemes=["vault", "credential", "env", "mcp-secret"],
)


class GitLabReadOnlyConnector:
    """Provider-native GitLab protocol adapter with no workflow decisions."""

    contract = GITLAB_CONNECTOR_CONTRACT

    def __init__(self, base_url: str = "https://gitlab.com/api/v4", *, timeout_seconds: float = 20.0, max_retries: int = 2) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        try:
            project = quote(str(request.payload["repository"]), safe="")
            number = quote(str(request.payload.get("pullNumber") or ""), safe="")
            if request.operation == "fetch_merge_request":
                path = f"/projects/{project}/merge_requests/{number}"
            elif request.operation == "fetch_diff":
                path = f"/projects/{project}/merge_requests/{number}/changes"
            elif request.operation == "write_check":
                return self._write_check(project, request)
            else:
                return ConnectorOperationResult(succeeded=False, errors=[f"unsupported GitLab connector operation '{request.operation}'"])
            response = managed_http_request(
                "GET",
                f"{self.base_url}{path}",
                headers=self._headers(request),
                timeout_seconds=self.timeout_seconds,
                max_retries=self.max_retries,
            )
            data = json.loads(response.text)
            native = data if isinstance(data, dict) else {"items": data}
            ref = f"gitlab://{request.payload['repository']}/merge_requests/{request.payload['pullNumber']}/{request.operation}"
            return ConnectorOperationResult(
                succeeded=True,
                data=native,
                evidence_refs=[{"type": "connector", "ref": ref, "metadata": {"operation": request.operation, "attempts": response.attempts}}],
                connector_call_ref=ref,
            )
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError, ManagedHttpRequestError) as exc:
            return ConnectorOperationResult(succeeded=False, errors=[f"gitlab {exc}"])

    def _write_check(self, project: str, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        status = str(request.payload["status"])
        if status == "stale":
            raise ValueError("GitLab connector refuses stale CI writeback")
        native_state = {
            "pending": "pending",
            "in_progress": "running",
            "success": "success",
            "failure": "failed",
            "neutral": "success",
            "cancelled": "canceled",
        }[status]
        query = urlencode(
            {
                "state": native_state,
                "name": str(request.payload["checkName"]),
                "description": str(request.payload["summary"])[:255],
                "target_url": str(request.payload.get("detailsUrl") or ""),
            }
        )
        sha = quote(str(request.payload["headSha"]), safe="")
        response = managed_http_request(
            "POST",
            f"{self.base_url}/projects/{project}/statuses/{sha}?{query}",
            headers=self._headers(request),
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
        )
        parsed = json.loads(response.text) if response.text else {}
        data = parsed if isinstance(parsed, dict) else {"items": parsed}
        ref = f"gitlab://{request.payload['repository']}/statuses/{sha}/{data.get('id', 'unknown')}"
        return ConnectorOperationResult(
            succeeded=True,
            data=data,
            evidence_refs=[{"type": "connector", "ref": ref, "metadata": {"operation": "write_check", "attempts": response.attempts}}],
            connector_call_ref=ref,
        )

    @staticmethod
    def _headers(request: ConnectorOperationRequest) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "agentic-qa-phase8"}
        token = request.runtime_credentials.get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers


__all__ = ["GITLAB_CONNECTOR_CONTRACT", "GitLabReadOnlyConnector"]

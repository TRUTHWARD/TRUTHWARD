# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from urllib.parse import quote

from agentic_qa.connectors.contracts import (
    ConnectorCapability,
    ConnectorOperationRequest,
    ConnectorOperationResult,
    ConnectorRuntimeContract,
)
from agentic_qa.infra.managed_http import ManagedHttpRequestError, ManagedHttpResponse, managed_http_request


GITHUB_CONNECTOR_CONTRACT = ConnectorRuntimeContract(
    connector_name="github",
    protocol="https",
    capabilities=[
        ConnectorCapability(name="receive_pull_request_webhook", read_only=True, risk_level="low"),
        ConnectorCapability(name="fetch_pull_request", read_only=True, risk_level="low"),
        ConnectorCapability(name="fetch_diff", read_only=True, risk_level="low"),
        ConnectorCapability(name="fetch_checks", read_only=True, risk_level="low"),
        ConnectorCapability(name="write_check", read_only=False, risk_level="high"),
    ],
    credential_schemes=["vault", "credential", "env", "mcp-secret"],
)


class GitHubReadOnlyConnector:
    """GitHub protocol adapter; write authorization remains Service-owned.

    This adapter intentionally returns provider-native data and evidence refs.
    It does not decide Gate outcome, generate Findings, or trigger executions.
    """

    contract = GITHUB_CONNECTOR_CONTRACT

    def __init__(
        self,
        base_url: str = "https://api.github.com",
        *,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._attempts = 0
        self._pages = 0

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        self._attempts = 0
        self._pages = 0
        try:
            if request.operation == "fetch_pull_request":
                return self._fetch_pull_request(request)
            if request.operation == "fetch_diff":
                return self._fetch_diff(request)
            if request.operation == "fetch_checks":
                return self._fetch_checks(request)
            if request.operation == "write_check":
                return self._write_check(request)
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"unsupported GitHub connector operation '{request.operation}'"],
            )
        except ManagedHttpRequestError as exc:
            return ConnectorOperationResult(succeeded=False, errors=[f"github {exc.summary}"])
        except json.JSONDecodeError:
            return ConnectorOperationResult(succeeded=False, errors=["github malformed json response"])
        except (OSError, TypeError, ValueError) as exc:
            return ConnectorOperationResult(succeeded=False, errors=[str(exc)])

    def _fetch_pull_request(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        owner, repo = self._owner_repo(request)
        pull_number = str(request.payload["pullNumber"])
        data = self._get_json(f"/repos/{owner}/{repo}/pulls/{quote(pull_number)}", request)
        return self._result(request, data, f"github://{owner}/{repo}/pull/{pull_number}")

    def _fetch_diff(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        owner, repo = self._owner_repo(request)
        pull_number = str(request.payload["pullNumber"])
        diff = self._get_text(
            f"/repos/{owner}/{repo}/pulls/{quote(pull_number)}",
            request,
            accept="application/vnd.github.v3.diff",
        )
        return self._result(
            request,
            {"diff": diff},
            f"github://{owner}/{repo}/pull/{pull_number}/diff",
        )

    def _fetch_checks(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        owner, repo = self._owner_repo(request)
        commit_sha = str(request.payload["commitSha"])
        data = self._get_paginated_json(
            f"/repos/{owner}/{repo}/commits/{quote(commit_sha)}/check-runs",
            request,
        )
        return self._result(request, data, f"github://{owner}/{repo}/commit/{commit_sha}/checks")

    def _write_check(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        owner, repo = self._owner_repo(request)
        status = str(request.payload["status"])
        if status == "stale":
            raise ValueError("GitHub connector refuses stale CI writeback")
        native_status = {
            "pending": "queued",
            "in_progress": "in_progress",
            "success": "completed",
            "failure": "completed",
            "neutral": "completed",
            "cancelled": "completed",
        }[status]
        body: dict[str, object] = {
            "name": str(request.payload["checkName"]),
            "head_sha": str(request.payload["headSha"]),
            "external_id": str(request.payload["idempotencyKey"]),
            "status": native_status,
            "details_url": request.payload.get("detailsUrl"),
            "output": {
                "title": str(request.payload.get("title") or request.payload["checkName"]),
                "summary": str(request.payload["summary"]),
            },
        }
        if native_status == "completed":
            body["conclusion"] = {
                "success": "success",
                "failure": "failure",
                "neutral": "neutral",
                "cancelled": "cancelled",
            }[status]
        response = managed_http_request(
            "POST",
            f"{self.base_url}/repos/{owner}/{repo}/check-runs",
            headers=self._headers(request),
            json_body=body,
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
        )
        self._attempts += response.attempts
        parsed = json.loads(response.text) if response.text else {}
        data = parsed if isinstance(parsed, dict) else {"items": parsed}
        return self._result(request, data, f"github://{owner}/{repo}/check-runs/{data.get('id', 'unknown')}")

    def _result(
        self,
        request: ConnectorOperationRequest,
        data: dict[str, object],
        evidence_ref: str,
    ) -> ConnectorOperationResult:
        metadata = {
            "operation": request.operation,
            "attempts": self._attempts,
            "pages": max(self._pages, 1),
            "traceId": request.trace_id,
            "skillInvocationId": request.skill_invocation_id,
        }
        return ConnectorOperationResult(
            succeeded=True,
            data=data,
            evidence_refs=[{"type": "connector", "ref": evidence_ref, "metadata": metadata}],
            connector_call_ref=evidence_ref,
        )

    def _owner_repo(self, request: ConnectorOperationRequest) -> tuple[str, str]:
        repository = str(request.payload.get("repository") or "")
        if "/" not in repository:
            raise ValueError("GitHub repository must use owner/repo format")
        owner, repo = repository.split("/", 1)
        return quote(owner), quote(repo)

    def _headers(self, request: ConnectorOperationRequest, accept: str = "application/vnd.github+json") -> dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": "agentic-qa-phase8",
        }
        token = request.runtime_credentials.get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _get_json(self, path: str, request: ConnectorOperationRequest) -> dict[str, object]:
        response = self._request(path, request)
        parsed = json.loads(response.text)
        return parsed if isinstance(parsed, dict) else {"items": parsed}

    def _get_paginated_json(self, path: str, request: ConnectorOperationRequest) -> dict[str, object]:
        next_url: str | None = path
        seen_urls: set[str] = set()
        pages: list[dict[str, object]] = []
        while next_url:
            absolute_url = next_url if next_url.startswith(("http://", "https://")) else f"{self.base_url}{next_url}"
            if absolute_url in seen_urls or len(seen_urls) >= 100:
                raise ValueError("github pagination did not terminate")
            seen_urls.add(absolute_url)
            response = self._request(absolute_url, request)
            parsed = json.loads(response.text)
            pages.append(parsed if isinstance(parsed, dict) else {"items": parsed})
            next_url = self._next_link(response.headers.get("link"))

        if len(pages) == 1:
            return pages[0]
        check_runs: list[object] = []
        items: list[object] = []
        for page in pages:
            page_check_runs = page.get("check_runs")
            if isinstance(page_check_runs, list):
                check_runs.extend(page_check_runs)
            page_items = page.get("items")
            if isinstance(page_items, list):
                items.extend(page_items)
        if check_runs:
            return {"total_count": len(check_runs), "check_runs": check_runs}
        return {"items": items or pages}

    def _next_link(self, link_header: str | None) -> str | None:
        for part in str(link_header or "").split(","):
            sections = [section.strip() for section in part.split(";")]
            if len(sections) < 2 or 'rel="next"' not in sections[1:]:
                continue
            if sections[0].startswith("<") and sections[0].endswith(">"):
                return sections[0][1:-1]
        return None

    def _get_text(
        self,
        path: str,
        request: ConnectorOperationRequest,
        *,
        accept: str = "application/vnd.github+json",
    ) -> str:
        return self._request(path, request, accept=accept).text

    def _request(
        self,
        path_or_url: str,
        request: ConnectorOperationRequest,
        *,
        accept: str = "application/vnd.github+json",
    ) -> ManagedHttpResponse:
        url = (
            path_or_url
            if path_or_url.startswith(("http://", "https://"))
            else f"{self.base_url}{path_or_url}"
        )
        response = managed_http_request(
            "GET",
            url,
            headers=self._headers(request, accept=accept),
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
        )
        self._attempts += response.attempts
        self._pages += 1
        return response

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from agentic_qa.connectors.contracts import (
    ConnectorCapability,
    ConnectorOperationRequest,
    ConnectorOperationResult,
    ConnectorRuntimeContract,
)
from agentic_qa.infra.managed_http import ManagedHttpRequestError, managed_http_request


ISSUE_TRACKER_CAPABILITIES = [
    ConnectorCapability(name="create_issue", read_only=False, risk_level="high"),
    ConnectorCapability(name="update_issue", read_only=False, risk_level="medium"),
    ConnectorCapability(name="fetch_issue_status", read_only=True, risk_level="low"),
]

JIRA_CONNECTOR_CONTRACT = ConnectorRuntimeContract(
    connector_name="jira",
    protocol="https",
    capabilities=ISSUE_TRACKER_CAPABILITIES,
    credential_schemes=["vault", "credential", "env", "mcp-secret"],
)

ZENTAO_CONNECTOR_CONTRACT = ConnectorRuntimeContract(
    connector_name="zentao",
    protocol="https",
    capabilities=ISSUE_TRACKER_CAPABILITIES,
    credential_schemes=["vault", "credential", "env", "mcp-secret"],
)

MOCK_ISSUE_TRACKER_CONTRACT = ConnectorRuntimeContract(
    connector_name="mock-issue-tracker",
    protocol="mock",
    capabilities=ISSUE_TRACKER_CAPABILITIES,
    credential_schemes=["vault", "credential", "env", "mcp-secret"],
)


class IssueTrackerConnector:
    """Provider adapter for issue-tracker operations.

    The adapter returns provider-native issue references and evidence refs only.
    It does not decide whether a Finding should sync, dedupe records, approve
    writes, or mutate platform state.
    """

    contract: ConnectorRuntimeContract

    def __init__(
        self,
        contract: ConnectorRuntimeContract,
        *,
        base_url: str | None = None,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        self.contract = contract
        self.base_url = (base_url or "").rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._attempts = 0

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        self._attempts = 0
        try:
            if self.base_url and self.contract.connector_name != "mock-issue-tracker":
                return self._invoke_http(request)
            if request.operation == "create_issue":
                return self._create_issue(request)
            if request.operation == "update_issue":
                return self._update_issue(request)
            if request.operation == "fetch_issue_status":
                return self._fetch_issue_status(request)
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"unsupported issue tracker operation '{request.operation}'"],
            )
        except ManagedHttpRequestError as exc:
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"{self.contract.connector_name} {exc.summary}"],
            )
        except json.JSONDecodeError:
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"{self.contract.connector_name} malformed json response"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            return ConnectorOperationResult(succeeded=False, errors=[str(exc)])

    def _create_issue(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        finding = self._finding_payload(request)
        issue_key = str(request.payload.get("externalIssueKey") or self._issue_key(finding))
        issue_id = str(request.payload.get("externalIssueId") or issue_key)
        issue_url = str(request.payload.get("externalIssueUrl") or self._issue_url(issue_key))
        status = str(request.payload.get("status") or "open")
        data = {
            "provider": self.contract.connector_name,
            "operation": request.operation,
            "externalIssueId": issue_id,
            "externalIssueKey": issue_key,
            "externalIssueUrl": issue_url,
            "status": status,
            "syncedAt": self._now(),
        }
        return self._result(request, data, issue_key)

    def _update_issue(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        issue_key = str(request.payload.get("externalIssueKey") or request.payload.get("externalIssueId") or self._issue_key(self._finding_payload(request)))
        issue_url = str(request.payload.get("externalIssueUrl") or self._issue_url(issue_key))
        status = str(request.payload.get("status") or request.payload.get("externalStatus") or "open")
        data = {
            "provider": self.contract.connector_name,
            "operation": request.operation,
            "externalIssueId": str(request.payload.get("externalIssueId") or issue_key),
            "externalIssueKey": issue_key,
            "externalIssueUrl": issue_url,
            "status": status,
            "syncedAt": self._now(),
        }
        return self._result(request, data, issue_key)

    def _fetch_issue_status(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        issue_key = str(request.payload.get("externalIssueKey") or request.payload.get("externalIssueId") or "")
        if not issue_key:
            return ConnectorOperationResult(succeeded=False, errors=["externalIssueKey is required"])
        data = {
            "provider": self.contract.connector_name,
            "operation": request.operation,
            "externalIssueId": str(request.payload.get("externalIssueId") or issue_key),
            "externalIssueKey": issue_key,
            "externalIssueUrl": str(request.payload.get("externalIssueUrl") or self._issue_url(issue_key)),
            "status": str(request.payload.get("status") or "open"),
            "syncedAt": self._now(),
        }
        return self._result(request, data, issue_key)

    def _result(self, request: ConnectorOperationRequest, data: dict[str, Any], issue_key: str) -> ConnectorOperationResult:
        ref = f"{self.contract.connector_name}://issue/{issue_key}"
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
                        "attempts": max(self._attempts, 1),
                        "traceId": request.trace_id,
                        "skillInvocationId": request.skill_invocation_id,
                    },
                }
            ],
            connector_call_ref=ref,
        )

    def _invoke_http(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        if request.operation == "create_issue":
            return self._http_create_issue(request)
        if request.operation == "update_issue":
            return self._http_update_issue(request)
        if request.operation == "fetch_issue_status":
            return self._http_fetch_issue_status(request)
        return ConnectorOperationResult(
            succeeded=False,
            errors=[f"unsupported issue tracker operation '{request.operation}'"],
        )

    def _http_create_issue(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        finding = self._finding_payload(request)
        title = str(finding.get("title") or "").strip()
        if not title:
            raise ValueError("finding.title is required for issue tracker operation")
        if self.contract.connector_name == "jira":
            project_key = str(request.payload.get("projectKey") or "").strip()
            if not project_key:
                raise ValueError("projectKey is required for Jira issue creation")
            issue_type = str(request.payload.get("issueType") or "Bug")
            fields = {
                "project": {"key": project_key},
                "summary": title,
                "description": str(finding.get("summary") or finding.get("description") or ""),
                "issuetype": {"name": issue_type},
                "labels": list(request.payload.get("labels") or []),
                **dict(request.payload.get("extraFields") or {}),
            }
            payload = self._request_json("POST", "/rest/api/3/issue", request, {"fields": fields})
            issue_key = str(payload.get("key") or payload.get("id") or "")
            issue_id = str(payload.get("id") or issue_key)
            issue_url = str(payload.get("self") or self._issue_url(issue_key))
        else:
            body = {
                "title": title,
                "steps": str(finding.get("summary") or finding.get("description") or ""),
                "severity": finding.get("severity"),
                "labels": list(request.payload.get("labels") or []),
                **dict(request.payload.get("extraFields") or {}),
            }
            payload = self._request_json("POST", "/api.php/v1/bugs", request, body)
            data = self._nested_issue_payload(payload)
            issue_key = str(data.get("key") or data.get("id") or "")
            issue_id = str(data.get("id") or issue_key)
            issue_url = str(data.get("url") or self._issue_url(issue_key))
        if not issue_key:
            raise ValueError(f"{self.contract.connector_name} issue response did not include an issue key")
        return self._result(
            request,
            {
                "provider": self.contract.connector_name,
                "operation": request.operation,
                "externalIssueId": issue_id,
                "externalIssueKey": issue_key,
                "externalIssueUrl": issue_url,
                "status": "open",
                "syncedAt": self._now(),
            },
            issue_key,
        )

    def _http_update_issue(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        issue_key = str(
            request.payload.get("externalIssueKey")
            or request.payload.get("externalIssueId")
            or ""
        ).strip()
        if not issue_key:
            raise ValueError("externalIssueKey is required")
        status = str(request.payload.get("status") or request.payload.get("externalStatus") or "open")
        if self.contract.connector_name == "jira":
            self._request_json(
                "PUT",
                f"/rest/api/3/issue/{quote(issue_key, safe='')}",
                request,
                {"fields": {"status": {"name": status}}},
            )
        else:
            self._request_json(
                "PUT",
                f"/api.php/v1/bugs/{quote(issue_key, safe='')}",
                request,
                {"status": status},
            )
        return self._result(
            request,
            {
                "provider": self.contract.connector_name,
                "operation": request.operation,
                "externalIssueId": str(request.payload.get("externalIssueId") or issue_key),
                "externalIssueKey": issue_key,
                "externalIssueUrl": str(request.payload.get("externalIssueUrl") or self._issue_url(issue_key)),
                "status": status,
                "syncedAt": self._now(),
            },
            issue_key,
        )

    def _http_fetch_issue_status(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        issue_key = str(
            request.payload.get("externalIssueKey")
            or request.payload.get("externalIssueId")
            or ""
        ).strip()
        if not issue_key:
            raise ValueError("externalIssueKey is required")
        if self.contract.connector_name == "jira":
            payload = self._request_json(
                "GET",
                f"/rest/api/3/issue/{quote(issue_key, safe='')}",
                request,
            )
            raw_fields = payload.get("fields")
            fields = raw_fields if isinstance(raw_fields, dict) else {}
            raw_status = fields.get("status")
            status_payload = raw_status if isinstance(raw_status, dict) else {}
            status = str(status_payload.get("name") or payload.get("status") or "open")
            issue_url = str(payload.get("self") or self._issue_url(issue_key))
            issue_id = str(payload.get("id") or issue_key)
        else:
            payload = self._request_json(
                "GET",
                f"/api.php/v1/bugs/{quote(issue_key, safe='')}",
                request,
            )
            data = self._nested_issue_payload(payload)
            status = str(data.get("status") or "open")
            issue_url = str(data.get("url") or self._issue_url(issue_key))
            issue_id = str(data.get("id") or issue_key)
        return self._result(
            request,
            {
                "provider": self.contract.connector_name,
                "operation": request.operation,
                "externalIssueId": issue_id,
                "externalIssueKey": issue_key,
                "externalIssueUrl": issue_url,
                "status": status,
                "syncedAt": self._now(),
            },
            issue_key,
        )

    def _request_json(
        self,
        method: str,
        path: str,
        request: ConnectorOperationRequest,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = managed_http_request(
            method,
            f"{self.base_url}{path}",
            headers=self._headers(request),
            json_body=body,
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries if method == "GET" else 0,
        )
        self._attempts += response.attempts
        if not response.text.strip():
            return {}
        payload = json.loads(response.text)
        if not isinstance(payload, dict):
            raise ValueError(f"{self.contract.connector_name} issue response must be a JSON object")
        return payload

    def _headers(self, request: ConnectorOperationRequest) -> dict[str, str]:
        token = str(
            request.runtime_credentials.get("token")
            or request.runtime_credentials.get("accessToken")
            or request.runtime_credentials.get("apiToken")
            or ""
        ).strip()
        if not token:
            raise ValueError("runtime credential token is required for issue tracker operation")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "agentic-qa-issue-tracker/1.0",
        }
        if self.contract.connector_name == "zentao":
            headers["Token"] = token
        return headers

    def _nested_issue_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        for key in ("data", "bug", "issue"):
            nested = payload.get(key)
            if isinstance(nested, dict):
                return nested
        return payload

    def _finding_payload(self, request: ConnectorOperationRequest) -> dict[str, Any]:
        finding = request.payload.get("finding")
        return dict(finding) if isinstance(finding, dict) else {}

    def _issue_key(self, finding: dict[str, Any]) -> str:
        seed = str(finding.get("id") or uuid4()).replace("-", "")[:10].upper()
        if self.contract.connector_name == "zentao":
            return f"ZT-{seed}"
        if self.contract.connector_name == "mock-issue-tracker":
            return f"MOCK-{seed}"
        return f"JIRA-{seed}"

    def _issue_url(self, issue_key: str) -> str:
        if self.base_url:
            return f"{self.base_url}/browse/{issue_key}"
        return f"{self.contract.connector_name}://issue/{issue_key}"

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


class JiraIssueTrackerConnector(IssueTrackerConnector):
    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        super().__init__(
            JIRA_CONNECTOR_CONTRACT,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )


class ZentaoIssueTrackerConnector(IssueTrackerConnector):
    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        super().__init__(
            ZENTAO_CONNECTOR_CONTRACT,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )


class MockIssueTrackerConnector(IssueTrackerConnector):
    def __init__(self, *, base_url: str | None = None) -> None:
        super().__init__(MOCK_ISSUE_TRACKER_CONTRACT, base_url=base_url)

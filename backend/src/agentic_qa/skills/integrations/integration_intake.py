# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

from agentic_qa.skills.integrations.contracts import (
    IntegrationEvidenceRef,
    IntegrationSkillInput,
    IntegrationSkillResult,
    completed_result,
    failed_result,
)


class IntegrationIntakeSkill:
    skill_name = "integration-intake"

    def run(self, request: IntegrationSkillInput) -> IntegrationSkillResult:
        if request.operation == "normalize_requirement_document":
            return self._normalize_requirement_document(request)
        if request.operation != "normalize_pr_trigger":
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error=f"unsupported operation: {request.operation}",
            )
        payload = dict(request.payload)
        required = ["repository", "pullRequestId", "branch", "commitSha"]
        missing = [field for field in required if not payload.get(field)]
        if missing:
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error=f"missing required PR trigger fields: {', '.join(missing)}",
                data={"missing": missing},
            )

        provider = str(request.provider or payload.get("provider") or "git")
        repository = str(payload["repository"])
        pull_request_id = str(payload["pullRequestId"])
        normalized: dict[str, Any] = {
            "source": provider,
            "eventType": "pr_trigger",
            "externalRef": pull_request_id,
            "repository": repository,
            "pullRequestId": pull_request_id,
            "branch": str(payload["branch"]),
            "commitSha": str(payload["commitSha"]),
            "payload": {
                "repository": repository,
                "pullRequestId": pull_request_id,
                "branch": str(payload["branch"]),
                "commitSha": str(payload["commitSha"]),
            },
            "dedupeKey": f"{provider}:pr:{repository}:{pull_request_id}:{payload['commitSha']}",
        }
        return completed_result(
            skill=self.skill_name,
            operation=request.operation,
            data=normalized,
            evidence=[
                IntegrationEvidenceRef(
                    type="integration_payload",
                    ref=f"{provider}:{repository}:pr:{pull_request_id}",
                    metadata={"branch": normalized["branch"], "commitSha": normalized["commitSha"]},
                )
            ],
            metadata={"provider": provider},
        )

    def _normalize_requirement_document(self, request: IntegrationSkillInput) -> IntegrationSkillResult:
        payload = dict(request.payload)
        document = str(payload.get("document") or "").strip()
        external_document_id = str(payload.get("externalDocumentId") or "").strip()
        if not external_document_id:
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error="externalDocumentId is required",
            )
        if not document:
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error="document is required",
                data={"externalDocumentId": external_document_id},
            )

        provider = str(request.provider or payload.get("provider") or "connector")
        title = str(payload.get("title") or external_document_id).strip()
        mime_type = str(payload.get("mimeType") or "text/plain").strip()
        source_uri = str(payload.get("sourceUri") or f"{provider}://requirement-documents/{external_document_id}").strip()
        content_version = str(payload.get("contentVersion") or "").strip() or None
        normalized: dict[str, Any] = {
            "source": provider,
            "eventType": "requirement_document",
            "externalRef": external_document_id,
            "externalDocumentId": external_document_id,
            "title": title,
            "document": document,
            "mimeType": mime_type,
            "sourceUri": source_uri,
            "contentVersion": content_version,
            "payload": {
                "externalDocumentId": external_document_id,
                "title": title,
                "mimeType": mime_type,
                "sourceUri": source_uri,
                "contentVersion": content_version,
            },
            "dedupeKey": f"{provider}:requirement-document:{external_document_id}:{content_version or 'latest'}",
        }
        return completed_result(
            skill=self.skill_name,
            operation=request.operation,
            data=normalized,
            evidence=[
                IntegrationEvidenceRef(
                    type="requirement_document",
                    ref=source_uri,
                    metadata={
                        "externalDocumentId": external_document_id,
                        "mimeType": mime_type,
                        "provider": provider,
                    },
                )
            ],
            metadata={"provider": provider},
        )

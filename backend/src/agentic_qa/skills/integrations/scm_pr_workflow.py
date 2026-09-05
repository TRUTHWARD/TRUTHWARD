# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.skills.integrations.contracts import (
    IntegrationEvidenceRef,
    IntegrationSkillInput,
    IntegrationSkillResult,
    completed_result,
    failed_result,
)


class ScmPrWorkflowSkill:
    skill_name = "scm-pr-workflow"

    def run(self, request: IntegrationSkillInput) -> IntegrationSkillResult:
        if request.operation != "build_pr_context":
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error=f"unsupported operation: {request.operation}",
            )
        payload = dict(request.payload)
        required = ["repository", "pullRequestId"]
        modern = isinstance(payload.get("revision"), dict)
        if not modern:
            required.extend(["branch", "commitSha"])
        missing = [field for field in required if not payload.get(field)]
        if missing:
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error=f"missing required PR context fields: {', '.join(missing)}",
                data={"missing": missing},
            )

        provider = str(request.provider or payload.get("source") or "git")
        repository = str(payload["repository"])
        pull_request_id = str(payload["pullRequestId"])
        source_ref = f"{repository}/pull/{pull_request_id}"
        revision = dict(payload.get("revision") or {})
        branch = str(payload.get("branch") or revision.get("headRef") or "")
        commit_sha = str(payload.get("commitSha") or revision.get("headSha") or "")
        if not branch or not commit_sha:
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error="missing required PR revision fields",
            )
        data = {
            "provider": provider,
            "repository": repository,
            "pullRequestId": pull_request_id,
            "branch": branch,
            "commitSha": commit_sha,
            "sourceRef": source_ref,
            "comparison": {
                "baseSha": payload.get("baseSha") or revision.get("baseSha"),
                "headSha": commit_sha,
                "changedFiles": list(payload.get("changedFiles", [])) if isinstance(payload.get("changedFiles", []), list) else [],
            },
            "revision": revision,
            "labels": list(payload.get("labels", [])) if isinstance(payload.get("labels"), list) else [],
            "draft": bool(payload.get("draft", False)),
            "state": str(payload.get("state") or "unknown"),
            "authorRef": str(payload.get("authorRef") or "unknown"),
            "explicitRequirementRefs": list(payload.get("explicitRequirementRefs", []))
            if isinstance(payload.get("explicitRequirementRefs"), list)
            else [],
        }
        return completed_result(
            skill=self.skill_name,
            operation=request.operation,
            data=data,
            evidence=[
                IntegrationEvidenceRef(
                    type="scm_pr_ref",
                    ref=source_ref,
                    metadata={"provider": provider, "commitSha": data["commitSha"]},
                )
            ],
            metadata={"provider": provider},
        )

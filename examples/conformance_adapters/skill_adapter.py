# SPDX-License-Identifier: Apache-2.0
"""Apache-2.0 reference IntegrationSkill for the public conformance kit."""

from __future__ import annotations

import hashlib
import json

from agentic_qa.skills.integrations.contracts import (
    IntegrationEvidenceRef,
    IntegrationSkillInput,
    IntegrationSkillResult,
    completed_result,
    failed_result,
)

_MANIFEST_BODY: dict[str, object] = {
    "skillId": "public-reference-skill",
    "version": "1.0.0",
    "capabilities": {
        "category": "integration",
        "operations": ["conformance.normalize"],
    },
    "inputSchema": {"operation": "str", "payload": "dict", "metadata": "dict"},
    "outputSchema": {
        "result": "dict",
        "confidence": "float",
        "evidence": "list",
        "artifactRefs": "list",
        "rawFindingRefs": "list",
        "findingCandidates": "list",
        "metadata": "dict",
    },
    "allowedTools": [],
    "allowedConnectors": [],
    "riskProfile": {"level": "low"},
    "approvalPolicy": {"required": False},
    "dataAccessPolicy": {"writeDb": False, "writeMemory": False, "writeGate": False},
    "replayPolicy": {"freezeManifest": True, "freezeInputOutput": True},
    "extensionPoints": [],
    "compatibility": {
        "input": "integration-skill-input.v1",
        "output": "skill-result.v1",
    },
}
_canonical_manifest = json.dumps(
    _MANIFEST_BODY,
    ensure_ascii=False,
    separators=(",", ":"),
    sort_keys=True,
).encode("utf-8")
SKILL_MANIFEST = {
    **_MANIFEST_BODY,
    "manifestHash": "sha256:" + hashlib.sha256(_canonical_manifest).hexdigest(),
}


class ReferenceIntegrationSkill:
    skill_name = "public-reference-skill"

    def run(self, request: IntegrationSkillInput) -> IntegrationSkillResult:
        if request.operation != "conformance.normalize":
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error=f"unsupported operation: {request.operation}",
            )
        value = str(request.payload.get("value") or "").strip()
        if not value:
            return failed_result(
                skill=self.skill_name,
                operation=request.operation,
                error="value is required",
            )
        return completed_result(
            skill=self.skill_name,
            operation=request.operation,
            data={"normalized": value.casefold()},
            evidence=[
                IntegrationEvidenceRef(
                    type="conformance_input",
                    ref="artifact://public-conformance/skill/input.json",
                )
            ],
            metadata={"adapterVersion": "1.0.0"},
        )


def create_skill() -> ReferenceIntegrationSkill:
    return ReferenceIntegrationSkill()


def get_manifest() -> dict[str, object]:
    return dict(SKILL_MANIFEST)

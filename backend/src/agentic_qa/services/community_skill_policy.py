# SPDX-License-Identifier: Apache-2.0
"""Pure data contract for the explicitly bounded Community presentation adapter."""
from __future__ import annotations

from copy import deepcopy
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict

COMMUNITY_REGRESSION_ADAPTER = "community.regression_projection.v1"
COMMUNITY_REGRESSION_EXTENSION = "PREPARE.regression_scope"
COMMUNITY_ENABLEMENT_POLICY = "community-presentation-enable.v1"


class CommunityRegressionProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    groupBy: Literal["domain", "priority"]
    includeCaseIds: bool


def validate_community_presentation_manifest(manifest: dict[str, object]) -> dict[str, object]:
    """No generic low-risk assertion may opt another implementation into this policy."""
    compatibility = manifest.get("compatibility")
    if not isinstance(compatibility, dict) or set(compatibility) != {
        "input", "output", "runtimeAdapter", "runtimeResultKind", "communityProfile",
    }:
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_CONTRACT_REQUIRED")
    expected = {
        "extensionPoints": [COMMUNITY_REGRESSION_EXTENSION],
        "allowedTools": [], "allowedConnectors": [],
        "riskProfile": {"level": "low"}, "approvalPolicy": {"required": False},
        "capabilities": {"category": "community-local", "operations": ["recommend_regression_scope"]},
        "dataAccessPolicy": {
            "writeDb": False, "writeMemory": False, "writeGate": False,
            "externalWrite": False, "scope": {"projectRequired": True},
        },
        "replayPolicy": {"freezeManifest": True, "freezeInputOutput": True, "freezeResolution": True},
    }
    for key, value in expected.items():
        # bool/int coercions must not weaken the data-only boundary.
        if json.dumps(manifest.get(key), sort_keys=True) != json.dumps(value, sort_keys=True):
            raise ValueError("COMMUNITY_SKILL_PRESENTATION_POLICY_MISMATCH:" + key)
    if (
        compatibility.get("input") != "skill-request.v1"
        or compatibility.get("output") != "skill-result.v1"
        or compatibility.get("runtimeAdapter") != COMMUNITY_REGRESSION_ADAPTER
        or compatibility.get("runtimeResultKind") != "skill_result"
    ):
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_ADAPTER_REQUIRED")
    try:
        return CommunityRegressionProfile.model_validate(compatibility["communityProfile"]).model_dump()
    except ValueError as exc:
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_PROFILE_INVALID") from exc


def project_regression_view(plan: dict[str, object], profile: dict[str, object]) -> dict[str, object]:
    """Group already-selected cases; never select, remove, reprioritize or execute."""
    settings = CommunityRegressionProfile.model_validate(profile)
    result = deepcopy(plan)
    cases = result.get("recommendedRegressionSuite")
    if not isinstance(cases, list) or len(cases) > 10000:
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_INPUT_INVALID")
    groups: dict[str, list[str]] = {}
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("COMMUNITY_SKILL_PRESENTATION_CASE_INVALID")
        label = str(case.get(settings.groupBy) or "unrecorded")
        groups.setdefault(label, []).append(str(case.get("caseId") or ""))
    view = {
        "schemaVersion": "community.regression-view.v1",
        "nonAuthoritative": True,
        "groupBy": settings.groupBy,
        "caseCount": len(cases),
        "groups": [
            {"label": label, "count": len(ids), **({"caseIds": ids} if settings.includeCaseIds else {})}
            for label, ids in sorted(groups.items())
        ],
    }
    current_metadata = result.get("metadata")
    if current_metadata is not None and not isinstance(current_metadata, dict):
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_METADATA_INVALID")
    result["metadata"] = {**(current_metadata or {}), "communityView": view}
    return result


def verify_presentation_preserves_plan(before: dict[str, object], after: dict[str, object]) -> None:
    normalized = deepcopy(after)
    current_metadata = normalized.get("metadata")
    if current_metadata is not None and not isinstance(current_metadata, dict):
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_METADATA_INVALID")
    metadata = dict(current_metadata or {})
    metadata.pop("communityView", None)
    normalized["metadata"] = metadata
    if normalized != before:
        raise ValueError("COMMUNITY_SKILL_AUTHORITATIVE_RESULT_CHANGED")


def presentation_conformance(profile: dict[str, object]) -> dict[str, object]:
    fixture: dict[str, object] = {
        "recommendedRegressionSuite": [
            {"caseId": "case-a", "domain": "functional", "priority": "high"},
            {"caseId": "case-b", "domain": "functional", "priority": "low"},
            {"caseId": "case-c", "domain": "security", "priority": "high"},
        ],
        "evidenceRefs": [{"type": "fixture", "id": "community-presentation-v1"}],
        "metadata": {},
    }
    output = project_regression_view(fixture, profile)
    verify_presentation_preserves_plan(fixture, output)
    return {"fixtureVersion": "community-presentation-v1", "passed": True, "output": output}

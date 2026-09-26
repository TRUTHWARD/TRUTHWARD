# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from agentic_qa.infra.redaction import contains_sensitive_material


SCHEMA_VERSION = "community.executable-scenarios.v1"
ALLOWED_ACTION_TYPES = frozenset(
    {"navigate", "fill", "click", "assert_visible", "assert_text"}
)
_SCENARIO_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_FORBIDDEN_INLINE_FIELDS = frozenset(
    {"value", "textValue", "secret", "password", "token", "credential"}
)
_TARGET_FIELDS = frozenset({"role", "name", "intent", "intentKey", "url"})
_HINT_FIELDS = frozenset({"selector", "css", "testId", "text", "url"})
_ASSERTION_FIELDS = frozenset({"expectedText", "text", "expected", "match"})
_VALIDATION_LIMITATIONS = frozenset(
    {
        "TARGET_URL_REQUIRED",
        "ACTIONS_REQUIRED",
        "ELEMENT_TARGET_REQUIRED",
        "EXPECTED_TEXT_REQUIRED",
        "FILL_REFERENCE_REQUIRED",
    }
)


class ExecutableScenarioError(ValueError):
    pass


def canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return f"sha256:{sha256(encoded).hexdigest()}"


def source_fingerprint(
    input_payload: dict[str, Any],
    requirement_version_id: object | None,
    requirement_scope: dict[str, Any] | None,
) -> str:
    return canonical_hash(
        {
            "requirementVersionId": (
                str(requirement_version_id) if requirement_version_id else None
            ),
            "requirementScope": requirement_scope or {},
            "input": input_payload,
            "requirements": _clean_strings(input_payload.get("requirements", []), 500),
            "acceptanceCriteria": _clean_strings(
                input_payload.get("acceptanceCriteria", []), 500
            ),
        }
    )


def generated_collection(
    generated_plan: dict[str, Any],
    *,
    input_payload: dict[str, Any],
    requirement_version_id: object | None,
    requirement_scope: dict[str, Any] | None,
    environment_base_url: str | None,
    previous: dict[str, Any] | None = None,
    risk_level: str = "low",
) -> dict[str, Any] | None:
    generated_cases = generated_plan.get("generatedCases")
    functional = (
        generated_cases.get("functional", [])
        if isinstance(generated_cases, dict)
        else []
    )
    if not isinstance(functional, list) or not functional:
        return None

    acceptance = _clean_strings(input_payload.get("acceptanceCriteria", []), 500)
    requirement_ref = (
        f"requirement-version://{requirement_version_id}"
        if requirement_version_id
        else "test-plan-input://requirements"
    )
    scenarios: list[dict[str, Any]] = []
    for index, raw_case in enumerate(functional[:100]):
        if not isinstance(raw_case, dict):
            continue
        name = _bounded_text(raw_case.get("name"), 255) or f"Functional case {index + 1}"
        goal = _bounded_text(raw_case.get("goal"), 4000) or name
        scenario_id = _stable_id(
            "generated",
            str(raw_case.get("caseId") or ""),
            name,
            str(index),
        )
        case_source_refs = _source_refs(raw_case.get("sourceRefs"))
        criterion = acceptance[index] if index < len(acceptance) else (
            acceptance[0] if len(acceptance) == 1 else goal
        )
        if not case_source_refs:
            criterion_index = index if index < len(acceptance) else 0
            case_source_refs = [
                {
                    "type": "acceptance_criterion",
                    "ref": f"{requirement_ref}#acceptance-criteria/{criterion_index}",
                }
            ]
        raw_actions = raw_case.get("steps")
        if not isinstance(raw_actions, list) or not raw_actions:
            raw_actions = [
                {
                    "actionId": f"{scenario_id}-assertion-1",
                    "actionType": "assert_text",
                    "semanticTarget": {},
                    "targetHints": {},
                    "assertionIntent": {
                        "expectedText": criterion,
                        "match": "contains",
                    },
                    "sourceRefs": case_source_refs,
                    "confidence": float(raw_case.get("confidence") or 0.5),
                    "limitations": ["ELEMENT_TARGET_REQUIRED"],
                    "origin": "generated",
                }
            ]
        scenarios.append(
            {
                "scenarioId": scenario_id,
                "name": name,
                "goal": goal,
                "targetUrl": _bounded_text(
                    raw_case.get("targetUrl") or environment_base_url, 2000
                ),
                "preconditions": _clean_strings(raw_case.get("preconditions", []), 50),
                "actions": raw_actions,
                "sourceRefs": case_source_refs,
                "confidence": _confidence(raw_case.get("confidence"), 0.5),
                "limitations": _clean_strings(raw_case.get("limitations", []), 50),
                "status": "needs_input",
                "selected": True,
                "origin": "generated",
            }
        )

    current_fingerprint = source_fingerprint(
        input_payload, requirement_version_id, requirement_scope
    )
    previous_fingerprint = (
        str(previous.get("sourceFingerprint") or "")
        if isinstance(previous, dict)
        else ""
    )
    raw_collection = {
        "schemaVersion": SCHEMA_VERSION,
        "revision": (
            _revision(previous.get("revision")) + 1
            if isinstance(previous, dict)
            else 1
        ),
        "sourceFingerprint": current_fingerprint,
        "sourceChanged": False,
        "changeSummary": {
            "previousSourceFingerprint": previous_fingerprint or None,
            "currentSourceFingerprint": current_fingerprint,
            "regenerated": bool(previous_fingerprint),
            "previousScenarioCount": len((previous or {}).get("scenarios") or []),
            "currentScenarioCount": len(scenarios),
        },
        "scenarios": scenarios,
    }
    return normalize_collection(
        raw_collection,
        risk_level=risk_level,
        current_source_fingerprint=current_fingerprint,
        environment_base_url=environment_base_url,
        allow_confirm=False,
    )


def normalize_functional_config(
    raw_config: dict[str, Any] | None,
    *,
    risk_level: str,
    current_source_fingerprint: str | None = None,
    environment_base_url: str | None = None,
    allow_confirm: bool = True,
) -> dict[str, Any]:
    config = deepcopy(raw_config or {})
    raw_collection = config.get("executableScenarios")
    if isinstance(raw_collection, dict):
        collection = normalize_collection(
            raw_collection,
            risk_level=risk_level,
            current_source_fingerprint=current_source_fingerprint,
            environment_base_url=environment_base_url,
            allow_confirm=allow_confirm,
        )
        config["executableScenarios"] = collection
        config["actualExecution"] = bool(collection["reviewSummary"]["confirmedCount"])
        config.pop("semanticAction", None)
        config.pop("semanticActions", None)
        return config

    legacy_actions = config.get("semanticActions")
    if not isinstance(legacy_actions, list):
        legacy_action = config.get("semanticAction")
        legacy_actions = [legacy_action] if isinstance(legacy_action, dict) else []
    if legacy_actions and config.get("actualExecution") is True:
        target_url = _bounded_text(
            config.get("targetUrl") or config.get("url") or environment_base_url,
            2000,
        )
        raw_collection = {
            "schemaVersion": SCHEMA_VERSION,
            "revision": 1,
            "sourceFingerprint": current_source_fingerprint or "",
            "sourceChanged": False,
            "scenarios": [
                {
                    "scenarioId": "legacy-browser-scenario",
                    "name": "Legacy browser scenario",
                    "goal": "Preserved browser execution configuration",
                    "targetUrl": target_url,
                    "preconditions": [],
                    "actions": legacy_actions,
                    "sourceRefs": [],
                    "confidence": 1.0,
                    "limitations": [],
                    "status": "confirmed",
                    "selected": True,
                    "origin": "legacy",
                }
            ],
        }
        config["executableScenarios"] = normalize_collection(
            raw_collection,
            risk_level=risk_level,
            current_source_fingerprint=current_source_fingerprint,
            environment_base_url=environment_base_url,
            allow_confirm=True,
        )
    return config


def normalize_collection(
    raw: dict[str, Any],
    *,
    risk_level: str,
    current_source_fingerprint: str | None,
    environment_base_url: str | None,
    allow_confirm: bool,
) -> dict[str, Any]:
    raw_scenarios = raw.get("scenarios")
    if not isinstance(raw_scenarios, list):
        raise ExecutableScenarioError("EXECUTABLE_SCENARIOS_INVALID")
    if len(raw_scenarios) > 100:
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_LIMIT_EXCEEDED")

    accept_current_source = bool(raw.get("acceptCurrentSource", False))
    stored_fingerprint = str(raw.get("sourceFingerprint") or "")
    if accept_current_source and current_source_fingerprint:
        stored_fingerprint = current_source_fingerprint
    source_changed = bool(
        stored_fingerprint
        and current_source_fingerprint
        and stored_fingerprint != current_source_fingerprint
    )
    seen_ids: set[str] = set()
    scenarios: list[dict[str, Any]] = []
    for index, item in enumerate(raw_scenarios):
        if not isinstance(item, dict):
            raise ExecutableScenarioError("EXECUTABLE_SCENARIO_INVALID")
        scenario = _normalize_scenario(
            item,
            index=index,
            risk_level=risk_level,
            environment_base_url=environment_base_url,
            source_changed=source_changed,
            allow_confirm=allow_confirm and not accept_current_source,
        )
        if scenario["scenarioId"] in seen_ids:
            raise ExecutableScenarioError("EXECUTABLE_SCENARIO_ID_CONFLICT")
        seen_ids.add(scenario["scenarioId"])
        scenarios.append(scenario)

    selected = [item for item in scenarios if item["selected"]]
    confirmed = [item for item in selected if item["status"] == "confirmed"]
    stale = [item for item in selected if item["status"] == "stale"]
    needs_input = [item for item in selected if item["status"] == "needs_input"]
    draft = [item for item in selected if item["status"] == "draft"]
    normalized = {
        "schemaVersion": SCHEMA_VERSION,
        "revision": _revision(raw.get("revision")),
        "sourceFingerprint": stored_fingerprint
        or current_source_fingerprint
        or canonical_hash({"source": "manual"}),
        "sourceChanged": source_changed,
        "changeSummary": {
            **_json_object(raw.get("changeSummary")),
            **(
                {"acceptedCurrentSource": True}
                if accept_current_source and current_source_fingerprint
                else {}
            ),
        },
        "scenarios": scenarios,
        "reviewSummary": {
            "scenarioCount": len(scenarios),
            "selectedCount": len(selected),
            "confirmedCount": len(confirmed),
            "needsInputCount": len(needs_input),
            "draftCount": len(draft),
            "staleCount": len(stale),
            "ready": bool(selected)
            and len(confirmed) == len(selected)
            and not source_changed,
        },
    }
    normalized["contentHash"] = canonical_hash(
        {
            "schemaVersion": normalized["schemaVersion"],
            "revision": normalized["revision"],
            "sourceFingerprint": normalized["sourceFingerprint"],
            "scenarios": scenarios,
        }
    )
    return normalized


def compile_confirmed_scenarios(
    config: dict[str, Any],
    *,
    risk_level: str,
    selected_scenario_ids: Iterable[str] | None = None,
    current_source_fingerprint: str | None = None,
    environment_base_url: str | None = None,
) -> list[dict[str, Any]]:
    normalized = normalize_functional_config(
        config,
        risk_level=risk_level,
        current_source_fingerprint=current_source_fingerprint,
        environment_base_url=environment_base_url,
        allow_confirm=True,
    )
    collection = normalized.get("executableScenarios")
    if not isinstance(collection, dict):
        return []
    requested = {str(item) for item in selected_scenario_ids or [] if str(item)}
    available = {
        str(item["scenarioId"]): item
        for item in collection.get("scenarios", [])
        if isinstance(item, dict)
    }
    unknown = requested - set(available)
    if unknown:
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_SELECTION_INVALID")
    candidates = [
        item
        for scenario_id, item in available.items()
        if (scenario_id in requested if requested else bool(item.get("selected", True)))
    ]
    if not candidates:
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_SELECTION_EMPTY")
    if any(item.get("status") != "confirmed" for item in candidates):
        raise ExecutableScenarioError("EXECUTABLE_SCENARIOS_CONFIRMATION_REQUIRED")
    if collection.get("sourceChanged"):
        raise ExecutableScenarioError("EXECUTABLE_SCENARIOS_SOURCE_CHANGED")

    return [
        {
            "scenarioId": item["scenarioId"],
            "name": item["name"],
            "goal": item["goal"],
            "targetUrl": item["targetUrl"],
            "semanticActions": deepcopy(item["actions"]),
            "sourceRefs": deepcopy(item["sourceRefs"]),
            "sourceFingerprint": collection["sourceFingerprint"],
            "scenarioContentHash": item["contentHash"],
            "collectionContentHash": collection["contentHash"],
            "revision": collection["revision"],
            "confidence": item["confidence"],
            "limitations": deepcopy(item["limitations"]),
        }
        for item in candidates
    ]


def _normalize_scenario(
    raw: dict[str, Any],
    *,
    index: int,
    risk_level: str,
    environment_base_url: str | None,
    source_changed: bool,
    allow_confirm: bool,
) -> dict[str, Any]:
    scenario_id = str(raw.get("scenarioId") or f"scenario-{index + 1}")
    if not _SCENARIO_ID.fullmatch(scenario_id):
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_ID_INVALID")
    actions_raw = raw.get("actions")
    if not isinstance(actions_raw, list):
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_ACTIONS_INVALID")
    if len(actions_raw) > 100:
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_ACTION_LIMIT_EXCEEDED")

    actions: list[dict[str, Any]] = []
    action_issues: list[str] = []
    action_ids: set[str] = set()
    for action_index, raw_action in enumerate(actions_raw):
        if not isinstance(raw_action, dict):
            raise ExecutableScenarioError("EXECUTABLE_ACTION_INVALID")
        action, issues = _normalize_action(
            raw_action,
            action_index=action_index,
            scenario_id=scenario_id,
            risk_level=risk_level,
        )
        if action["actionId"] in action_ids:
            raise ExecutableScenarioError("EXECUTABLE_ACTION_ID_CONFLICT")
        action_ids.add(action["actionId"])
        actions.append(action)
        action_issues.extend(issues)

    target_url = _bounded_text(raw.get("targetUrl") or environment_base_url, 2000)
    if target_url:
        _validate_url(target_url)
    elif any(
        item["actionType"] != "navigate"
        or not (
            item["semanticTarget"].get("url")
            or item["targetHints"].get("url")
        )
        for item in actions
    ):
        action_issues.append("TARGET_URL_REQUIRED")
    if not actions:
        action_issues.append("ACTIONS_REQUIRED")

    requested_status = str(raw.get("status") or "draft")
    if requested_status not in {"draft", "needs_input", "confirmed", "stale"}:
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_STATUS_INVALID")
    if source_changed:
        status = "stale"
    elif action_issues:
        if requested_status == "confirmed" and allow_confirm:
            raise ExecutableScenarioError(action_issues[0])
        status = "needs_input"
    elif requested_status == "confirmed" and allow_confirm:
        status = "confirmed"
    else:
        status = "draft" if requested_status == "confirmed" else requested_status

    limitations = _dedupe(
        [
            *[
                item
                for item in _clean_strings(raw.get("limitations", []), 50)
                if item not in _VALIDATION_LIMITATIONS
            ],
            *action_issues,
        ]
    )
    scenario = {
        "scenarioId": scenario_id,
        "name": _bounded_text(raw.get("name"), 255) or f"Scenario {index + 1}",
        "goal": _bounded_text(raw.get("goal"), 4000),
        "targetUrl": target_url,
        "preconditions": _clean_strings(raw.get("preconditions", []), 50),
        "actions": actions,
        "sourceRefs": _source_refs(raw.get("sourceRefs")),
        "confidence": _confidence(raw.get("confidence"), 1.0),
        "limitations": limitations,
        "status": status,
        "selected": bool(raw.get("selected", True)),
        "origin": (
            str(raw.get("origin"))
            if str(raw.get("origin")) in {"generated", "manual", "legacy"}
            else "manual"
        ),
    }
    scenario["contentHash"] = canonical_hash(
        {key: value for key, value in scenario.items() if key != "contentHash"}
    )
    return scenario


def _normalize_action(
    raw: dict[str, Any],
    *,
    action_index: int,
    scenario_id: str,
    risk_level: str,
) -> tuple[dict[str, Any], list[str]]:
    forbidden = sorted(_FORBIDDEN_INLINE_FIELDS.intersection(raw))
    if forbidden:
        raise ExecutableScenarioError("EXECUTABLE_ACTION_INLINE_SECRET_FORBIDDEN")
    action_type = str(raw.get("actionType") or "")
    if action_type not in ALLOWED_ACTION_TYPES:
        raise ExecutableScenarioError("EXECUTABLE_ACTION_TYPE_INVALID")
    action_id = str(raw.get("actionId") or f"{scenario_id}-action-{action_index + 1}")
    if not _SCENARIO_ID.fullmatch(action_id):
        raise ExecutableScenarioError("EXECUTABLE_ACTION_ID_INVALID")

    target = _allowlisted_object(raw.get("semanticTarget"), _TARGET_FIELDS)
    hints = _allowlisted_object(raw.get("targetHints"), _HINT_FIELDS)
    assertion = _allowlisted_object(raw.get("assertionIntent"), _ASSERTION_FIELDS)
    if assertion.get("match") not in {None, "contains", "exact"}:
        raise ExecutableScenarioError("EXECUTABLE_ASSERTION_MATCH_INVALID")
    issues: list[str] = []
    has_target = bool(
        hints.get("selector")
        or hints.get("css")
        or hints.get("testId")
        or (target.get("role") and target.get("name"))
        or hints.get("text")
        or target.get("name")
    )
    if action_type == "navigate":
        navigation_url = target.get("url") or hints.get("url")
        if navigation_url:
            _validate_url(str(navigation_url))
    elif not has_target:
        issues.append("ELEMENT_TARGET_REQUIRED")
    if action_type == "assert_text" and not str(
        assertion.get("expectedText")
        or assertion.get("text")
        or assertion.get("expected")
        or ""
    ).strip():
        issues.append("EXPECTED_TEXT_REQUIRED")
    if action_type == "fill":
        value_ref = _bounded_text(raw.get("valueRef"), 500)
        secret_ref = _bounded_text(raw.get("secretRef"), 500)
        if bool(value_ref) == bool(secret_ref):
            issues.append("FILL_REFERENCE_REQUIRED")
    else:
        value_ref = ""
        secret_ref = ""

    action: dict[str, Any] = {
        "schemaVersion": "phase7.v1",
        "actionId": action_id,
        "actionType": action_type,
        "semanticTarget": target,
        "targetHints": hints,
        "locatorStrategy": {
            "primary": "dom",
            "fallback": ["accessibility"],
        },
        "fallbackPolicy": {"allowCoordinateClick": False},
        "assertionIntent": assertion,
        "riskLevel": risk_level,
        "policyRefs": [],
        "sourceRefs": _source_refs(raw.get("sourceRefs")),
        "confidence": _confidence(raw.get("confidence"), 1.0),
        "limitations": _dedupe(
            [
                *[
                    item
                    for item in _clean_strings(raw.get("limitations", []), 50)
                    if item not in _VALIDATION_LIMITATIONS
                ],
                *issues,
            ]
        ),
        "origin": (
            str(raw.get("origin"))
            if str(raw.get("origin")) in {"generated", "manual", "legacy"}
            else "manual"
        ),
    }
    if value_ref:
        action["valueRef"] = value_ref
    if secret_ref:
        action["secretRef"] = secret_ref
    return action, issues


def _validate_url(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ExecutableScenarioError("EXECUTABLE_TARGET_URL_INVALID")
    if parsed.username or parsed.password:
        raise ExecutableScenarioError("EXECUTABLE_TARGET_URL_CREDENTIALS_FORBIDDEN")


def _stable_id(*parts: str) -> str:
    seed = "\x1f".join(parts)
    return f"scenario-{sha256(seed.encode('utf-8')).hexdigest()[:20]}"


def _bounded_text(value: object, limit: int) -> str:
    text = str(value or "").strip()[:limit]
    if text and contains_sensitive_material(text):
        raise ExecutableScenarioError(
            "EXECUTABLE_SCENARIO_SENSITIVE_MATERIAL_FORBIDDEN"
        )
    return text


def _revision(value: object) -> int:
    try:
        revision = int(value or 1)
    except (TypeError, ValueError) as exc:
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_REVISION_INVALID") from exc
    if revision < 1:
        raise ExecutableScenarioError("EXECUTABLE_SCENARIO_REVISION_INVALID")
    return revision


def _confidence(value: object, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0.0, min(1.0, parsed))


def _clean_strings(value: object, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return _dedupe(
        [str(item).strip()[:4000] for item in value[:limit] if str(item).strip()]
    )


def _source_refs(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    refs: list[dict[str, str]] = []
    for raw in value[:100]:
        if not isinstance(raw, dict):
            continue
        item = {
            key: _bounded_text(raw.get(key), 1000)
            for key in ("type", "ref", "id", "contentHash")
            if _bounded_text(raw.get(key), 1000)
        }
        if item.get("type") and (item.get("ref") or item.get("id")):
            refs.append(item)
    return refs


def _allowlisted_object(value: object, fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for key in fields:
        if key not in value:
            continue
        raw = value[key]
        if isinstance(raw, (str, int, float, bool)) and str(raw).strip():
            result[key] = raw if isinstance(raw, bool) else _bounded_text(raw, 2000)
    return result


def _json_object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key)[:120]: item
        for key, item in value.items()
        if isinstance(item, (str, int, float, bool)) or item is None
    }


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


__all__ = [
    "ExecutableScenarioError",
    "SCHEMA_VERSION",
    "compile_confirmed_scenarios",
    "generated_collection",
    "normalize_collection",
    "normalize_functional_config",
    "source_fingerprint",
]

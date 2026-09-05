# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError
from yaml.events import AliasEvent, NodeEvent  # type: ignore[import-untyped]

from agentic_qa.schemas.gate_policy import MAX_GATE_POLICY_RULES, validate_gate_policy_document
from agentic_qa.schemas.gate_policy_governance import GatePolicyImportPreview
from agentic_qa.services.common import canonical_hash

MAX_IMPORT_BYTES = 64 * 1024
MAX_IMPORT_DEPTH = 12
MAX_IMPORT_NODES = 4096
MAX_IMPORT_ALIASES = 32
MAX_IMPORT_STRING_LENGTH = 16 * 1024
ALLOWED_EXTENSIONS = {".json", ".yaml", ".yml"}
FORBIDDEN_KEYS = {"__proto__", "prototype", "constructor"}
REDACTED = "[REDACTED]"
SECRET_MARKERS = ("secret", "password", "token", "credential", "apikey", "privatekey", "accesskey")


class GatePolicyImportError(ValueError):
    def __init__(self, code: str, *, status_code: int = 422, path: str = "$", parameters: dict[str, Any] | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.path = path
        self.parameters = parameters or {}
        super().__init__(code)

    def as_dict(self) -> dict[str, Any]:
        return {"errorCode": self.code, "field": self.path, "details": self.parameters}


class _NoDuplicateSafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _NoDuplicateSafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, (str, int, float, bool, type(None))):
            raise GatePolicyImportError("GATE_POLICY_IMPORT_KEY_TYPE_INVALID")
        if key in result:
            raise GatePolicyImportError("GATE_POLICY_IMPORT_DUPLICATE_KEY", path=str(key))
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_NoDuplicateSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


@dataclass(frozen=True)
class ParsedImport:
    document: dict[str, Any] | None
    issues: list[dict[str, Any]]
    content_hash: str | None


class GatePolicyImportService:
    def parse_and_validate(self, content: bytes, *, format_hint: str, baseline: dict[str, Any] | None = None) -> dict[str, Any]:
        if not content:
            raise GatePolicyImportError("GATE_POLICY_IMPORT_EMPTY")
        if len(content) > MAX_IMPORT_BYTES:
            raise GatePolicyImportError("GATE_POLICY_IMPORT_TOO_LARGE", status_code=413, parameters={"maxBytes": MAX_IMPORT_BYTES})
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise GatePolicyImportError("GATE_POLICY_IMPORT_ENCODING_INVALID") from exc
        fmt = self._format(format_hint)
        try:
            value = self._load_json(text) if fmt == "json" else self._load_yaml(text)
        except GatePolicyImportError:
            raise
        except (json.JSONDecodeError, yaml.YAMLError, UnicodeError) as exc:
            raise GatePolicyImportError("GATE_POLICY_IMPORT_SYNTAX_INVALID") from exc
        if not isinstance(value, dict):
            raise GatePolicyImportError("GATE_POLICY_IMPORT_ROOT_INVALID")
        self._check_structure(value)
        issues: list[dict[str, Any]] = []
        canonical: dict[str, Any] | None = None
        try:
            canonical = validate_gate_policy_document(value)
        except ValidationError as exc:
            issues = [self._validation_issue(item) for item in exc.errors(include_input=False, include_url=False)]
        except ValueError:
            issues = [self._issue("$", "GATE_POLICY_SCHEMA_INVALID")]
        content_hash = canonical_hash(canonical) if canonical is not None else None
        preview = {
            "schemaVersion": "phase8.gate-policy-import-preview.v1",
            "format": fmt,
            "valid": not issues,
            "contentHash": content_hash,
            "validationIssues": issues,
            "canonicalPolicy": self._redact(canonical) if canonical is not None else None,
            "diff": self.structured_diff(baseline, canonical) if canonical is not None else self.structured_diff(baseline, None),
            "limits": {
                "maxBytes": MAX_IMPORT_BYTES,
                "maxDepth": MAX_IMPORT_DEPTH,
                "maxNodes": MAX_IMPORT_NODES,
                "maxAliases": MAX_IMPORT_ALIASES,
                "maxStringLength": MAX_IMPORT_STRING_LENGTH,
                "maxRules": MAX_GATE_POLICY_RULES,
            },
            "activatesProduction": False,
            "executesGate": False,
        }
        return GatePolicyImportPreview.model_validate(preview).model_dump(mode="json")

    @staticmethod
    def _format(hint: str) -> str:
        value = hint.lower().strip()
        if value.startswith("."):
            value = value[1:]
        if value == "yml":
            value = "yaml"
        if value not in {"json", "yaml"}:
            raise GatePolicyImportError("GATE_POLICY_IMPORT_FORMAT_UNSUPPORTED", status_code=415)
        return value

    @staticmethod
    def _load_json(text: str) -> Any:
        def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise GatePolicyImportError("GATE_POLICY_IMPORT_DUPLICATE_KEY", path=key)
                result[key] = value
            return result
        return json.loads(text, object_pairs_hook=reject_duplicate, parse_constant=lambda _value: (_ for _ in ()).throw(GatePolicyImportError("GATE_POLICY_IMPORT_NON_FINITE_NUMBER")))

    @staticmethod
    def _load_yaml(text: str) -> Any:
        aliases = 0
        nodes = 0
        for event in yaml.parse(text, Loader=_NoDuplicateSafeLoader):
            if isinstance(event, AliasEvent):
                aliases += 1
                if aliases > MAX_IMPORT_ALIASES:
                    raise GatePolicyImportError("GATE_POLICY_IMPORT_ALIAS_LIMIT")
            if isinstance(event, NodeEvent):
                nodes += 1
                if nodes > MAX_IMPORT_NODES:
                    raise GatePolicyImportError("GATE_POLICY_IMPORT_NODE_LIMIT")
        return yaml.load(text, Loader=_NoDuplicateSafeLoader)

    @classmethod
    def _check_structure(cls, value: Any) -> None:
        nodes = 0
        stack: list[tuple[Any, int, str]] = [(value, 1, "$")]
        while stack:
            current, depth, path = stack.pop()
            nodes += 1
            if nodes > MAX_IMPORT_NODES:
                raise GatePolicyImportError("GATE_POLICY_IMPORT_NODE_LIMIT")
            if depth > MAX_IMPORT_DEPTH:
                raise GatePolicyImportError("GATE_POLICY_IMPORT_DEPTH_LIMIT", path=path)
            if isinstance(current, str) and len(current) > MAX_IMPORT_STRING_LENGTH:
                raise GatePolicyImportError("GATE_POLICY_IMPORT_STRING_LIMIT", path=path)
            if isinstance(current, dict):
                for key, child in current.items():
                    key_text = str(key)
                    if key_text.lower() in FORBIDDEN_KEYS:
                        raise GatePolicyImportError("GATE_POLICY_IMPORT_PROTOTYPE_KEY", path=f"{path}.{key_text}")
                    stack.append((child, depth + 1, f"{path}.{key_text}"))
            elif isinstance(current, list):
                stack.extend((child, depth + 1, f"{path}[{index}]") for index, child in enumerate(current))
        rules = value.get("rules") if isinstance(value, dict) else None
        if isinstance(rules, list) and len(rules) > MAX_GATE_POLICY_RULES:
            raise GatePolicyImportError("GATE_POLICY_IMPORT_RULE_LIMIT", path="$.rules")

    @staticmethod
    def _validation_issue(item: Mapping[str, Any]) -> dict[str, Any]:
        location = item.get("loc") or ()
        path = "$" + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in location)
        issue_type = str(item.get("type") or "value_error")
        return GatePolicyImportService._issue(path, "GATE_POLICY_SCHEMA_VALIDATION_FAILED", {"issueType": issue_type})

    @staticmethod
    def _issue(path: str, code: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"path": path, "code": code, "severity": "error", "messageKey": f"gatePolicy.validation.{code}", "parameters": parameters or {}}

    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): REDACTED if any(marker in str(key).lower().replace("_", "") for marker in SECRET_MARKERS) else cls._redact(child) for key, child in value.items()}
        if isinstance(value, list):
            return [cls._redact(child) for child in value]
        return value

    @classmethod
    def structured_diff(cls, before: dict[str, Any] | None, after: dict[str, Any] | None) -> dict[str, Any]:
        changes: list[dict[str, Any]] = []
        cls._diff(cls._redact(before), cls._redact(after), "$", changes)
        return {"schemaVersion": "phase8.gate-policy-structured-diff.v1", "changes": changes, "summary": {kind: sum(1 for item in changes if item["operation"] == kind) for kind in ("add", "remove", "change")}, "redacted": True, "computedBy": "backend"}

    @classmethod
    def _diff(cls, before: Any, after: Any, path: str, changes: list[dict[str, Any]]) -> None:
        if before == after:
            return
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(set(before) | set(after)):
                child_path = f"{path}.{key}"
                if key not in before:
                    changes.append({"operation": "add", "path": child_path, "before": None, "after": after[key]})
                elif key not in after:
                    changes.append({"operation": "remove", "path": child_path, "before": before[key], "after": None})
                else:
                    cls._diff(before[key], after[key], child_path, changes)
            return
        if isinstance(before, list) and isinstance(after, list):
            for index in range(max(len(before), len(after))):
                child_path = f"{path}[{index}]"
                if index >= len(before):
                    changes.append({"operation": "add", "path": child_path, "before": None, "after": after[index]})
                elif index >= len(after):
                    changes.append({"operation": "remove", "path": child_path, "before": before[index], "after": None})
                else:
                    cls._diff(before[index], after[index], child_path, changes)
            return
        changes.append({"operation": "change", "path": path, "before": before, "after": after})

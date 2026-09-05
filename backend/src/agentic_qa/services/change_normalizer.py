# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from dataclasses import dataclass, field as dataclass_field
from pathlib import PurePosixPath
from typing import Any

from agentic_qa.infra.redaction import redact_sensitive_text
from agentic_qa.services.common import canonical_hash


CHANGE_NORMALIZER_VERSION = "p17.change-normalizer.v1"
MAX_FILES = 5_000
MAX_HUNKS = 20_000
MAX_SYMBOLS_PER_HUNK = 100

_DIFF_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)$")
_HUNK_HEADER = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:\s?(.*))?$"
)
_SYMBOL_PATTERNS = (
    ("class", re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)")),
    ("function", re.compile(r"^\s*(?:export\s+)?(?:async\s+)?def\s+([A-Za-z_]\w*)")),
    ("function", re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)")),
    ("function", re.compile(r"^\s*(?:pub\s+)?fn\s+([A-Za-z_]\w*)")),
    ("function", re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)")),
    ("type", re.compile(r"^\s*(?:export\s+)?(?:interface|type|enum)\s+([A-Za-z_$][\w$]*)")),
)
_GENERATED_MARKERS = (
    ".min.js",
    ".min.css",
    ".generated.",
    ".g.cs",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
)
_VENDOR_PARTS = {"vendor", "vendors", "third_party", "third-party", "node_modules"}
_RISK_PATHS = {
    "security": ("auth", "security", "permission", "policy", "crypto", "secret"),
    "database": ("migration", "schema", "database", "models"),
    "deployment": ("docker", "deploy", "terraform", "helm", ".github/workflows"),
    "api_contract": ("api", "schema", "contract", "openapi"),
}
_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".sql": "sql",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".md": "markdown",
}


@dataclass(slots=True)
class NormalizationIssueData:
    category: str
    code: str
    message: str
    field: str | None = None
    recoverable: bool = True
    evidence: list[dict[str, Any]] = dataclass_field(default_factory=list)


@dataclass(slots=True)
class RequirementItemData:
    requirement_id: str
    change_type: str
    before_refs: list[dict[str, Any]]
    after_refs: list[dict[str, Any]]
    changed_fields: list[str]
    capability_refs: list[dict[str, Any]]
    related_requirement_ids: list[str]
    confidence: float
    evidence: list[dict[str, Any]]


@dataclass(slots=True)
class RequirementNormalizationResult:
    items: list[RequirementItemData]
    issues: list[NormalizationIssueData]


@dataclass(slots=True)
class CodeSymbolData:
    name: str
    kind: str
    change_type: str
    old_line_start: int | None
    old_line_end: int | None
    new_line_start: int | None
    new_line_end: int | None
    confidence: float
    evidence: list[dict[str, Any]]


@dataclass(slots=True)
class CodeHunkData:
    header: str
    old_line_start: int | None
    old_line_count: int | None
    new_line_start: int | None
    new_line_count: int | None
    content_hash: str
    sensitive: bool
    redaction_count: int
    symbols: list[CodeSymbolData]


@dataclass(slots=True)
class CodeFileData:
    path: str
    old_path: str | None
    change_type: str
    language: str | None
    binary: bool
    generated: bool
    vendor: bool
    submodule: bool
    risk_hints: list[str]
    hunks: list[CodeHunkData]


@dataclass(slots=True)
class CodeNormalizationResult:
    files: list[CodeFileData]
    issues: list[NormalizationIssueData]
    redacted_diff: str
    redaction_count: int


def normalize_requirement_changes(
    *,
    base_version_id: str | None,
    base_items: list[Any],
    head_version_id: str,
    head_items: list[Any],
    change_hints: list[dict[str, Any]],
) -> RequirementNormalizationResult:
    base = _requirement_item_map(base_items)
    head = _requirement_item_map(head_items)
    issues: list[NormalizationIssueData] = []
    items: list[RequirementItemData] = []

    for requirement_id in sorted(set(base) | set(head)):
        before = base.get(requirement_id)
        after = head.get(requirement_id)
        if before is None:
            change_type = "add"
        elif after is None:
            change_type = "remove"
        else:
            changed_fields = _changed_fields(before, after)
            if not changed_fields:
                continue
            change_type = "update"
        changed_fields = _changed_fields(before, after)
        capability_refs = _capability_refs(after or before or {})
        items.append(
            RequirementItemData(
                requirement_id=requirement_id,
                change_type=change_type,
                before_refs=_requirement_refs(base_version_id, requirement_id, before),
                after_refs=_requirement_refs(head_version_id, requirement_id, after),
                changed_fields=changed_fields,
                capability_refs=capability_refs,
                related_requirement_ids=[],
                confidence=1.0,
                evidence=[
                    ref
                    for ref in (
                        _version_evidence(base_version_id),
                        _version_evidence(head_version_id),
                    )
                    if ref is not None
                ],
            )
        )

    by_key = {(item.requirement_id, item.change_type): item for item in items}
    for hint in change_hints:
        requirement_id = str(hint["requirementId"])
        change_type = str(hint["changeType"])
        related = _unique_strings(
            [*hint.get("beforeRequirementIds", []), *hint.get("afterRequirementIds", [])]
        )
        if change_type == "unknown":
            issues.append(
                NormalizationIssueData(
                    "ambiguous",
                    "REQUIREMENT_CHANGE_UNKNOWN",
                    "Requirement source declared an unknown change type.",
                    "changeHints",
                    True,
                    list(hint.get("evidence", [])),
                )
            )
        existing = next(
            (item for item in items if item.requirement_id == requirement_id),
            None,
        )
        hinted = RequirementItemData(
            requirement_id=requirement_id,
            change_type=change_type,
            before_refs=_requirement_refs(base_version_id, requirement_id, base.get(requirement_id)),
            after_refs=_requirement_refs(head_version_id, requirement_id, head.get(requirement_id)),
            changed_fields=_unique_strings(hint.get("changedFields", [])),
            capability_refs=[dict(value) for value in hint.get("explicitCapabilityRefs", [])],
            related_requirement_ids=related,
            confidence=float(hint.get("confidence", 1.0)),
            evidence=[dict(value) for value in hint.get("evidence", [])],
        )
        if existing is not None:
            items.remove(existing)
        items.append(hinted)
        by_key[(requirement_id, change_type)] = hinted

    if not items:
        issues.append(
            NormalizationIssueData(
                "incomplete",
                "REQUIREMENT_CHANGE_EMPTY",
                "No changed requirement items were found between the supplied versions.",
                recoverable=True,
            )
        )
    items.sort(key=lambda item: (item.requirement_id, item.change_type))
    return RequirementNormalizationResult(items, issues)


def normalize_code_diff(diff: str) -> CodeNormalizationResult:
    redacted_diff = redact_sensitive_text(diff)
    redaction_count = redacted_diff.count("[REDACTED]") - diff.count("[REDACTED]")
    redaction_count = max(redaction_count, 0)
    issues: list[NormalizationIssueData] = []
    if redaction_count:
        issues.append(
            NormalizationIssueData(
                "sensitive",
                "CODE_DIFF_SENSITIVE_CONTENT_REDACTED",
                "Secret or PII-like material was removed before diff artifact persistence.",
                "diff",
                True,
                [{"type": "redaction", "count": redaction_count}],
            )
        )
    if not diff.strip():
        issues.append(
            NormalizationIssueData(
                "incomplete",
                "CODE_DIFF_EMPTY",
                "The SCM source returned an empty diff; this is not treated as no impact.",
                "diff",
                True,
            )
        )
        return CodeNormalizationResult([], issues, redacted_diff, redaction_count)

    lines = redacted_diff.splitlines(keepends=True)
    files: list[CodeFileData] = []
    current: dict[str, Any] | None = None
    current_hunk: dict[str, Any] | None = None

    def finish_hunk() -> None:
        nonlocal current_hunk
        if current is None or current_hunk is None:
            return
        text = "".join(current_hunk.pop("lines"))
        current_hunk["content_hash"] = canonical_hash(text)
        current_hunk["sensitive"] = "[REDACTED]" in text
        current_hunk["redaction_count"] = text.count("[REDACTED]")
        current_hunk["symbols"] = _extract_symbols(
            text,
            current_hunk["old_line_start"],
            current_hunk["new_line_start"],
        )
        current["hunks"].append(CodeHunkData(**current_hunk))
        current_hunk = None

    def finish_file() -> None:
        nonlocal current
        finish_hunk()
        if current is None:
            return
        current["change_type"] = _file_change_type(current)
        path = current["path"]
        current["language"] = _language(path)
        current["generated"] = _is_generated(path)
        current["vendor"] = _is_vendor(path)
        current["risk_hints"] = _risk_hints(path, current)
        files.append(
            CodeFileData(
                path=current["path"],
                old_path=current["old_path"],
                change_type=current["change_type"],
                language=current["language"],
                binary=current["binary"],
                generated=current["generated"],
                vendor=current["vendor"],
                submodule=current["submodule"],
                risk_hints=current["risk_hints"],
                hunks=current["hunks"],
            )
        )
        current = None

    for line in lines:
        stripped = line.rstrip("\r\n")
        header = _DIFF_HEADER.match(stripped)
        if header:
            finish_file()
            current = {
                "path": _safe_diff_path(header.group(2)),
                "old_path": _safe_diff_path(header.group(1)),
                "change_type": "unknown",
                "language": None,
                "binary": False,
                "generated": False,
                "vendor": False,
                "submodule": False,
                "risk_hints": [],
                "hunks": [],
                "new_file": False,
                "deleted_file": False,
                "rename_from": None,
                "rename_to": None,
                "copy_from": None,
                "copy_to": None,
            }
            if len(files) >= MAX_FILES:
                issues.append(
                    NormalizationIssueData(
                        "unsupported",
                        "CODE_DIFF_FILE_LIMIT",
                        f"Diff exceeds the {MAX_FILES} file normalization limit.",
                        "diff",
                        False,
                    )
                )
                break
            continue
        if current is None:
            continue
        if stripped.startswith("new file mode "):
            current["new_file"] = True
        elif stripped.startswith("deleted file mode "):
            current["deleted_file"] = True
        elif stripped.startswith("rename from "):
            current["rename_from"] = _safe_diff_path(stripped.removeprefix("rename from "))
        elif stripped.startswith("rename to "):
            current["rename_to"] = _safe_diff_path(stripped.removeprefix("rename to "))
            current["path"] = current["rename_to"]
        elif stripped.startswith("copy from "):
            current["copy_from"] = _safe_diff_path(stripped.removeprefix("copy from "))
        elif stripped.startswith("copy to "):
            current["copy_to"] = _safe_diff_path(stripped.removeprefix("copy to "))
            current["path"] = current["copy_to"]
        elif stripped.startswith("Binary files ") or stripped.startswith("GIT binary patch"):
            current["binary"] = True
        elif stripped.startswith("Subproject commit ") or stripped.startswith("160000"):
            current["submodule"] = True
        hunk = _HUNK_HEADER.match(stripped)
        if hunk:
            finish_hunk()
            if sum(len(item.hunks) for item in files) + len(current["hunks"]) >= MAX_HUNKS:
                issues.append(
                    NormalizationIssueData(
                        "unsupported",
                        "CODE_DIFF_HUNK_LIMIT",
                        f"Diff exceeds the {MAX_HUNKS} hunk normalization limit.",
                        "diff",
                        False,
                    )
                )
                continue
            current_hunk = {
                "header": stripped[:500],
                "old_line_start": int(hunk.group(1)),
                "old_line_count": int(hunk.group(2) or 1),
                "new_line_start": int(hunk.group(3)),
                "new_line_count": int(hunk.group(4) or 1),
                "lines": [line],
            }
        elif current_hunk is not None:
            current_hunk["lines"].append(line)

    finish_file()
    if not files:
        issues.append(
            NormalizationIssueData(
                "unsupported",
                "CODE_DIFF_FORMAT_UNSUPPORTED",
                "The source was non-empty but contained no supported unified-diff file headers.",
                "diff",
                False,
            )
        )
    for file in files:
        if file.change_type == "unknown":
            issues.append(
                NormalizationIssueData(
                    "ambiguous",
                    "CODE_FILE_CHANGE_UNKNOWN",
                    "File change type could not be determined from SCM-native diff metadata.",
                    "files.changeType",
                    True,
                    [{"type": "code_file", "pathHash": canonical_hash(file.path)}],
                )
            )
        if file.binary:
            issues.append(
                NormalizationIssueData(
                    "unsupported",
                    "CODE_BINARY_CONTENT_NOT_PARSED",
                    "Binary file content is represented by metadata only.",
                    "files.binary",
                    True,
                    [{"type": "code_file", "pathHash": canonical_hash(file.path)}],
                )
            )
        if file.submodule:
            issues.append(
                NormalizationIssueData(
                    "unsupported",
                    "CODE_SUBMODULE_CONTENT_NOT_EXPANDED",
                    "Submodule changes are represented by revision metadata only.",
                    "files.submodule",
                    True,
                    [{"type": "code_file", "pathHash": canonical_hash(file.path)}],
                )
            )
    return CodeNormalizationResult(files, issues, redacted_diff, redaction_count)


def _requirement_item_map(values: list[Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(values, start=1):
        if isinstance(value, dict):
            item = dict(value)
            requirement_id = str(item.get("id") or item.get("requirementItemId") or f"requirement-{index}")
            item.setdefault("text", str(item.get("title") or requirement_id))
        else:
            requirement_id = f"requirement-{index}"
            item = {"text": str(value)}
        result[requirement_id] = item
    return result


def _changed_fields(before: dict[str, Any] | None, after: dict[str, Any] | None) -> list[str]:
    if before is None:
        return sorted(after or {})
    if after is None:
        return sorted(before)
    return sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))


def _requirement_refs(
    version_id: str | None,
    requirement_id: str,
    value: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if version_id is None or value is None:
        return []
    return [
        {
            "type": "requirement_item",
            "ref": f"requirement://versions/{version_id}/items/{requirement_id}",
            "contentHash": canonical_hash(value),
        }
    ]


def _version_evidence(version_id: str | None) -> dict[str, Any] | None:
    if version_id is None:
        return None
    return {"type": "requirement_version", "ref": f"requirement://versions/{version_id}"}


def _capability_refs(item: dict[str, Any]) -> list[dict[str, Any]]:
    raw = item.get("explicitCapabilityRefs") or item.get("capabilityRefs") or []
    refs: list[dict[str, Any]] = []
    for value in raw if isinstance(raw, list) else []:
        if isinstance(value, dict) and value.get("ref"):
            refs.append(dict(value))
        elif isinstance(value, str) and value.strip():
            refs.append({"type": "capability", "ref": value.strip()})
    return refs


def _unique_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


def _safe_diff_path(value: str) -> str:
    path = value.strip().strip('"').replace("\\", "/")
    if path.startswith(("a/", "b/")):
        path = path[2:]
    parts = PurePosixPath(path).parts
    if not path or path.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        return "[invalid-path]"
    return path[:2000]


def _file_change_type(value: dict[str, Any]) -> str:
    if value.get("rename_to"):
        value["old_path"] = value.get("rename_from") or value.get("old_path")
        return "rename"
    if value.get("copy_to"):
        value["old_path"] = value.get("copy_from") or value.get("old_path")
        return "copy"
    if value.get("new_file"):
        value["old_path"] = None
        return "add"
    if value.get("deleted_file"):
        return "remove"
    if value.get("hunks") or value.get("binary") or value.get("submodule"):
        return "update"
    return "unknown"


def _language(path: str) -> str | None:
    return _LANGUAGES.get(PurePosixPath(path.lower()).suffix)


def _is_generated(path: str) -> bool:
    lower = path.lower()
    return any(marker in lower for marker in _GENERATED_MARKERS) or lower.startswith(
        ("dist/", "build/", "coverage/")
    )


def _is_vendor(path: str) -> bool:
    return any(part.lower() in _VENDOR_PARTS for part in PurePosixPath(path).parts)


def _risk_hints(path: str, value: dict[str, Any]) -> list[str]:
    lower = path.lower()
    hints = [hint for hint, markers in _RISK_PATHS.items() if any(marker in lower for marker in markers)]
    if value.get("binary"):
        hints.append("binary")
    if value.get("submodule"):
        hints.append("submodule")
    if _is_generated(path):
        hints.append("generated")
    if _is_vendor(path):
        hints.append("vendor")
    return sorted(set(hints))


def _extract_symbols(text: str, old_start: int | None, new_start: int | None) -> list[CodeSymbolData]:
    old_line = old_start
    new_line = new_start
    found: dict[tuple[str, str], CodeSymbolData] = {}
    for raw in text.splitlines()[1:]:
        prefix = raw[:1]
        body = raw[1:] if prefix in {"+", "-", " "} else raw
        current_old = old_line
        current_new = new_line
        for kind, pattern in _SYMBOL_PATTERNS:
            match = pattern.match(body)
            if not match:
                continue
            change_type = "add" if prefix == "+" else "remove" if prefix == "-" else "update"
            name = match.group(1)
            found[(kind, name)] = CodeSymbolData(
                name=name,
                kind=kind,
                change_type=change_type,
                old_line_start=current_old if prefix != "+" else None,
                old_line_end=current_old if prefix != "+" else None,
                new_line_start=current_new if prefix != "-" else None,
                new_line_end=current_new if prefix != "-" else None,
                confidence=0.85,
                evidence=[{"type": "diff_hunk", "contentHash": canonical_hash(text)}],
            )
            break
        if prefix != "+" and old_line is not None:
            old_line += 1
        if prefix != "-" and new_line is not None:
            new_line += 1
        if len(found) >= MAX_SYMBOLS_PER_HUNK:
            break
    return sorted(found.values(), key=lambda item: (item.kind, item.name))


__all__ = [
    "CHANGE_NORMALIZER_VERSION",
    "CodeNormalizationResult",
    "NormalizationIssueData",
    "RequirementNormalizationResult",
    "normalize_code_diff",
    "normalize_requirement_changes",
]

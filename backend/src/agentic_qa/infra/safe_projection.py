# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from agentic_qa.infra.redaction import (
    contains_sensitive_material,
    normalize_sensitive_key,
    redact_sensitive_text,
)


CONNECTOR_BINDING_REDACTION_POLICY_VERSION = "p27.connector-binding-safe-projection.v1"
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,511}$")
_PERMISSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$")


class SafeProjectionError(ValueError):
    """Raised when a connector binding cannot be projected without leakage."""


class ConnectorBindingSafeProjectionBuilder:
    """Build the only persistence/API-safe Connector Binding snapshot.

    The builder is deliberately allowlist-only. It never serializes an ORM
    object, arbitrary metadata/extensions, Connector configuration, or a
    resolvable secret/credential reference.
    """

    max_depth = 12
    max_nodes = 2_500
    max_total_characters = 262_144

    _TOP_LEVEL_ALIASES: dict[str, tuple[str, ...]] = {
        "connectorBindingId": ("connectorBindingId", "bindingId", "id"),
        "connectorType": ("connectorType", "connectorName", "provider"),
        "capability": ("capability", "connectorCapability"),
        "tenantId": ("tenantId",),
        "workspaceId": ("workspaceId",),
        "projectId": ("projectId",),
        "environmentId": ("environmentId",),
        "scopeType": ("scopeType",),
        "repositoryRef": ("repositoryRef",),
        "repositoryNativeId": ("repositoryNativeId",),
        "installationRef": ("installationRef",),
        "bindingRevision": ("bindingRevision", "revision", "lockVersion"),
        "bindingVersion": ("bindingVersion", "version"),
        "configurationHash": ("configurationHash", "configHash", "bindingHash"),
        "permissionHash": ("permissionHash",),
        "createdAt": ("createdAt",),
        "effectiveFrom": ("effectiveFrom",),
        "effectiveUntil": ("effectiveUntil",),
    }
    _SCOPE_FIELDS = ("tenantId", "workspaceId", "projectId", "environmentId", "scopeType")

    def build(self, source: Mapping[str, Any] | None) -> dict[str, Any]:
        if not source:
            return {}
        if not isinstance(source, Mapping):
            raise SafeProjectionError("connector binding snapshot source must be an object")
        self._validate_source_shape(source)

        scope = self._mapping_value(source, "scope")
        scope_mapping = scope if isinstance(scope, Mapping) else {}
        projection: dict[str, Any] = {
            "schemaVersion": "phase8.connector-binding-safe-projection.v1",
            "redactionPolicyVersion": CONNECTOR_BINDING_REDACTION_POLICY_VERSION,
        }
        for target, aliases in self._TOP_LEVEL_ALIASES.items():
            value = self._first_value(source, aliases)
            if value is None and target in self._SCOPE_FIELDS:
                value = self._first_value(scope_mapping, aliases)
            normalized = self._normalize_field(target, value)
            if normalized is not None:
                projection[target] = normalized

        permissions = self._permission_summary(source)
        if permissions:
            projection["minimumPermissionSummary"] = permissions
            projection["permissionHash"] = self._hash_payload(permissions)

        if "configurationHash" not in projection:
            configuration_identity = {
                key: projection[key]
                for key in (
                    "connectorBindingId",
                    "connectorType",
                    "capability",
                    "tenantId",
                    "workspaceId",
                    "projectId",
                    "environmentId",
                    "scopeType",
                    "repositoryRef",
                    "repositoryNativeId",
                    "installationRef",
                    "bindingRevision",
                    "bindingVersion",
                )
                if key in projection
            }
            projection["configurationHash"] = self._hash_payload(configuration_identity)

        self.assert_safe(projection)
        return projection

    def assert_safe(self, projection: Mapping[str, Any]) -> None:
        allowed = {
            "schemaVersion",
            "redactionPolicyVersion",
            *self._TOP_LEVEL_ALIASES.keys(),
            "minimumPermissionSummary",
        }
        unknown = set(projection) - allowed
        if unknown:
            raise SafeProjectionError("connector binding safe projection contains non-allowlisted fields")
        try:
            encoded = json.dumps(
                projection,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise SafeProjectionError("connector binding safe projection is not serializable") from exc
        if len(encoded) > self.max_total_characters:
            raise SafeProjectionError("connector binding safe projection exceeds size limit")
        if contains_sensitive_material(projection):
            raise SafeProjectionError("connector binding safe projection failed the final Secret scan")

    def _validate_source_shape(self, source: Mapping[str, Any]) -> None:
        seen: set[int] = set()
        nodes = 0
        characters = 0

        def visit(value: Any, depth: int) -> None:
            nonlocal nodes, characters
            nodes += 1
            if nodes > self.max_nodes:
                raise SafeProjectionError("connector binding snapshot source exceeds node limit")
            if depth > self.max_depth:
                raise SafeProjectionError("connector binding snapshot source exceeds depth limit")
            if isinstance(value, str):
                characters += len(value)
                if characters > self.max_total_characters:
                    raise SafeProjectionError("connector binding snapshot source exceeds size limit")
                return
            if isinstance(value, Mapping):
                identity = id(value)
                if identity in seen:
                    raise SafeProjectionError("connector binding snapshot source is circular")
                seen.add(identity)
                for item_key, item_value in value.items():
                    characters += len(str(item_key))
                    visit(item_value, depth + 1)
                seen.remove(identity)
                return
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                identity = id(value)
                if identity in seen:
                    raise SafeProjectionError("connector binding snapshot source is circular")
                seen.add(identity)
                for item in value:
                    visit(item, depth + 1)
                seen.remove(identity)

        visit(source, 0)

    @staticmethod
    def _normalized_items(source: Mapping[str, Any]) -> dict[str, Any]:
        return {normalize_sensitive_key(str(key)): value for key, value in source.items()}

    def _first_value(self, source: Mapping[str, Any], aliases: tuple[str, ...]) -> Any:
        normalized = self._normalized_items(source)
        for alias in aliases:
            key = normalize_sensitive_key(alias)
            if key in normalized:
                return normalized[key]
        return None

    def _mapping_value(self, source: Mapping[str, Any], alias: str) -> Any:
        return self._first_value(source, (alias,))

    def _normalize_field(self, field: str, value: Any) -> Any:
        if value is None or value == "":
            return None
        if field in {"bindingRevision"}:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SafeProjectionError(f"connector binding {field} is invalid")
            return value
        if field in {"createdAt", "effectiveFrom", "effectiveUntil"}:
            if isinstance(value, datetime):
                return value.isoformat()
            return self._safe_scalar(field, value, max_length=80)
        if field in {"configurationHash", "permissionHash"}:
            normalized = str(value).strip().lower()
            if not _HASH_PATTERN.fullmatch(normalized):
                raise SafeProjectionError(f"connector binding {field} is invalid")
            return normalized
        return self._safe_scalar(field, value)

    def _safe_scalar(self, field: str, value: Any, *, max_length: int = 512) -> str:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise SafeProjectionError(f"connector binding {field} must be a scalar")
        normalized = str(value).strip()
        if not normalized or len(normalized) > max_length:
            raise SafeProjectionError(f"connector binding {field} is invalid")
        if redact_sensitive_text(normalized) != normalized or contains_sensitive_material(normalized):
            raise SafeProjectionError(f"connector binding {field} contains sensitive material")
        if field in {"repositoryRef", "installationRef"}:
            if "?" in normalized or "#" in normalized or re.search(r"://[^/@]+:[^/@]+@", normalized):
                raise SafeProjectionError(f"connector binding {field} contains unsafe URI material")
        elif not _SAFE_TOKEN_PATTERN.fullmatch(normalized):
            raise SafeProjectionError(f"connector binding {field} contains unsupported characters")
        return normalized

    def _permission_summary(self, source: Mapping[str, Any]) -> list[str]:
        value = self._first_value(
            source,
            ("minimumPermissionSummary", "minimumPermissions", "permissionSummary", "permissions"),
        )
        if value in (None, [], ()):
            return []
        if isinstance(value, Mapping):
            items = [str(key) for key, enabled in value.items() if enabled is True]
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            items = [str(item) for item in value]
        else:
            raise SafeProjectionError("connector binding permission summary must be a list or boolean map")
        normalized = sorted(set(item.strip() for item in items if item.strip()))
        if len(normalized) > 128 or any(not _PERMISSION_PATTERN.fullmatch(item) for item in normalized):
            raise SafeProjectionError("connector binding permission summary is invalid")
        return normalized

    @staticmethod
    def _hash_payload(value: Any) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


REQUIREMENT_SCOPE_SCHEMA_VERSION = "phase8.requirement-scope.v1"
REQUIREMENT_SCOPE_V2_SCHEMA_VERSION = "phase8.requirement-scope.v2"


class RequirementItemRef(BaseModel):
    requirementVersionId: UUID
    requirementItemIds: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def ensure_item_ids_are_unique(self) -> "RequirementItemRef":
        self.requirementItemIds = _dedupe_strings(self.requirementItemIds)
        return self


class RequirementScopeItemRef(BaseModel):
    scopeItemId: str
    requirementVersionId: UUID
    requirementItemId: str


class RequirementScope(BaseModel):
    schemaVersion: str = REQUIREMENT_SCOPE_SCHEMA_VERSION
    requirementVersionId: UUID
    selectedRequirementItemIds: list[str] = Field(default_factory=list)
    requirementVersionIds: list[UUID] = Field(default_factory=list)
    requirementItemRefs: list[RequirementItemRef] = Field(default_factory=list)
    scopeItemRefs: list[RequirementScopeItemRef] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ensure_scope_refs_are_consistent(self) -> "RequirementScope":
        self.selectedRequirementItemIds = _dedupe_strings(self.selectedRequirementItemIds)
        versions = _dedupe_uuids(self.requirementVersionIds or [self.requirementVersionId])
        if self.requirementVersionId not in versions:
            versions.insert(0, self.requirementVersionId)
        self.requirementVersionIds = versions
        if self.schemaVersion == REQUIREMENT_SCOPE_V2_SCHEMA_VERSION and not self.requirementItemRefs:
            self.requirementItemRefs = [RequirementItemRef(requirementVersionId=item) for item in versions]
        unknown_versions = {
            item.requirementVersionId for item in self.requirementItemRefs if item.requirementVersionId not in versions
        }
        if unknown_versions:
            raise ValueError("requirementItemRefs must reference requirementVersionIds in the same scope")
        return self


def normalize_requirement_scope(
    *,
    requirement_version_id: UUID,
    selected_requirement_item_ids: list[str] | None = None,
    requirement_version_ids: list[UUID | str] | None = None,
    requirement_item_refs: list[dict[str, Any] | RequirementItemRef] | None = None,
    filters: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    force_v2: bool = False,
) -> dict[str, Any]:
    versions = _dedupe_uuids(requirement_version_ids or [requirement_version_id])
    if requirement_version_id not in versions:
        versions.insert(0, requirement_version_id)
    normalized_item_refs = _normalize_item_refs(requirement_item_refs or [])
    if selected_requirement_item_ids and not normalized_item_refs:
        normalized_item_refs = [
            RequirementItemRef(
                requirementVersionId=requirement_version_id,
                requirementItemIds=selected_requirement_item_ids,
            )
        ]
    is_v2 = force_v2 or len(versions) > 1 or any(
        item.requirementVersionId != requirement_version_id for item in normalized_item_refs
    )
    if not is_v2:
        scope = RequirementScope(
            requirementVersionId=requirement_version_id,
            selectedRequirementItemIds=selected_requirement_item_ids or [],
            filters=filters or {},
            metadata=metadata or {},
        )
        payload = scope.model_dump(mode="json")
        for key in ("requirementVersionIds", "requirementItemRefs", "scopeItemRefs"):
            payload.pop(key, None)
    else:
        refs_by_version = {item.requirementVersionId: item for item in normalized_item_refs}
        ordered_refs = [
            refs_by_version.get(version_id, RequirementItemRef(requirementVersionId=version_id))
            for version_id in versions
        ]
        scope_refs = [
            RequirementScopeItemRef(
                scopeItemId=requirement_scope_item_id(item.requirementVersionId, item_id),
                requirementVersionId=item.requirementVersionId,
                requirementItemId=item_id,
            )
            for item in ordered_refs
            for item_id in item.requirementItemIds
        ]
        scope = RequirementScope(
            schemaVersion=REQUIREMENT_SCOPE_V2_SCHEMA_VERSION,
            requirementVersionId=requirement_version_id,
            selectedRequirementItemIds=[item.scopeItemId for item in scope_refs],
            requirementVersionIds=versions,
            requirementItemRefs=ordered_refs,
            scopeItemRefs=scope_refs,
            filters=filters or {},
            metadata=metadata or {},
        )
        payload = scope.model_dump(mode="json")
    payload["scopeId"] = requirement_scope_id(payload)
    return payload


def requirement_scope_id(scope: dict[str, Any] | None) -> str | None:
    if not scope:
        return None
    requirement_version_id = scope.get("requirementVersionId")
    if not requirement_version_id:
        return None
    if scope.get("schemaVersion") != REQUIREMENT_SCOPE_V2_SCHEMA_VERSION:
        selected_ids = _dedupe_strings(scope.get("selectedRequirementItemIds") or [])
        if not selected_ids:
            return str(requirement_version_id)
        canonical_payload = {
            "schemaVersion": REQUIREMENT_SCOPE_SCHEMA_VERSION,
            "requirementVersionId": str(requirement_version_id),
            "selectedRequirementItemIds": selected_ids,
        }
        prefix = f"requirement-scope:{requirement_version_id}"
    else:
        canonical_payload = {
            "schemaVersion": REQUIREMENT_SCOPE_V2_SCHEMA_VERSION,
            "requirementVersionIds": [str(item) for item in scope.get("requirementVersionIds") or []],
            "requirementItemRefs": [
                {
                    "requirementVersionId": str(item.get("requirementVersionId")),
                    "requirementItemIds": _dedupe_strings(item.get("requirementItemIds") or []),
                }
                for item in scope.get("requirementItemRefs") or []
            ],
        }
        prefix = "requirement-scope-v2"
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}:{digest}"


def requirement_scope_item_id(requirement_version_id: UUID | str, requirement_item_id: str) -> str:
    return f"{requirement_version_id}::{str(requirement_item_id).strip()}"


def scope_item_ids(scope: dict[str, Any] | None) -> list[str]:
    if not scope:
        return []
    return _dedupe_strings(scope.get("selectedRequirementItemIds") or [])


def scope_item_refs(scope: dict[str, Any] | None) -> list[dict[str, str]]:
    if not scope or scope.get("schemaVersion") != REQUIREMENT_SCOPE_V2_SCHEMA_VERSION:
        requirement_version_id = scope.get("requirementVersionId") if scope else None
        return [
            {
                "scopeItemId": item_id,
                "requirementVersionId": str(requirement_version_id),
                "requirementItemId": item_id,
            }
            for item_id in scope_item_ids(scope)
            if requirement_version_id
        ]
    return [
        {
            "scopeItemId": str(item.get("scopeItemId")),
            "requirementVersionId": str(item.get("requirementVersionId")),
            "requirementItemId": str(item.get("requirementItemId")),
        }
        for item in scope.get("scopeItemRefs") or []
        if item.get("scopeItemId") and item.get("requirementVersionId") and item.get("requirementItemId")
    ]


def scope_version_ids(scope: dict[str, Any] | None) -> list[UUID]:
    if not scope:
        return []
    raw = scope.get("requirementVersionIds") or [scope.get("requirementVersionId")]
    return _dedupe_uuids([item for item in raw if item])


def _normalize_item_refs(values: list[dict[str, Any] | RequirementItemRef]) -> list[RequirementItemRef]:
    by_version: dict[UUID, list[str]] = {}
    order: list[UUID] = []
    for value in values:
        item = value if isinstance(value, RequirementItemRef) else RequirementItemRef.model_validate(value)
        if item.requirementVersionId not in order:
            order.append(item.requirementVersionId)
        by_version.setdefault(item.requirementVersionId, []).extend(item.requirementItemIds)
    return [
        RequirementItemRef(requirementVersionId=version_id, requirementItemIds=_dedupe_strings(by_version[version_id]))
        for version_id in order
    ]


def _dedupe_strings(values: list[Any]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def _dedupe_uuids(values: list[UUID | str]) -> list[UUID]:
    cleaned: list[UUID] = []
    for value in values:
        item = UUID(str(value))
        if item not in cleaned:
            cleaned.append(item)
    return cleaned

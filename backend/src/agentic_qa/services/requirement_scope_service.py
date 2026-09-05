# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import RequirementScopeRecord, RequirementScopeVersionRef, RequirementVersion
from agentic_qa.schemas.requirement_scope import (
    REQUIREMENT_SCOPE_V2_SCHEMA_VERSION,
    requirement_scope_id,
    scope_version_ids,
)
from agentic_qa.services.common import ServiceContext


class RequirementScopeService:
    """Owns immutable RequirementScope persistence and referential validation."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def persist(self, scope: dict[str, Any], context: ServiceContext | None = None) -> dict[str, Any]:
        payload = dict(scope)
        scope_id = str(payload.get("scopeId") or requirement_scope_id(payload) or "")
        if not scope_id:
            raise ValueError("requirement scope is missing scopeId")
        payload["scopeId"] = scope_id
        primary_version_id = UUID(str(payload.get("requirementVersionId")))
        item_refs = self._validated_item_refs(payload)
        existing = self.db.get(RequirementScopeRecord, scope_id)
        if existing is not None:
            self._ensure_same_selection(existing.scope_payload, payload)
            return dict(existing.scope_payload)

        record = RequirementScopeRecord(
            scope_id=scope_id,
            schema_version=str(payload.get("schemaVersion")),
            primary_requirement_version_id=primary_version_id,
            scope_payload=payload,
            created_by=context.user.id if context else None,
        )
        self.db.add(record)
        self.db.flush()
        for version_id in scope_version_ids(payload):
            self.db.add(
                RequirementScopeVersionRef(
                    id=uuid4(),
                    scope_id=scope_id,
                    requirement_version_id=version_id,
                    requirement_item_ids=item_refs.get(version_id, []),
                )
            )
        self.db.flush()
        return payload

    def get(self, scope_id: str) -> dict[str, Any]:
        record = self.db.get(RequirementScopeRecord, scope_id)
        if record is None:
            raise LookupError("requirement scope not found")
        payload = dict(record.scope_payload)
        refs = list(
            self.db.scalars(
                select(RequirementScopeVersionRef)
                .where(RequirementScopeVersionRef.scope_id == scope_id)
                .order_by(RequirementScopeVersionRef.id.asc())
            )
        )
        projected_versions = {str(item.requirement_version_id) for item in refs}
        expected_versions = {str(item) for item in scope_version_ids(payload)}
        if projected_versions != expected_versions:
            raise ValueError("requirement scope version refs are incomplete")
        return payload

    def _validated_item_refs(self, scope: dict[str, Any]) -> dict[UUID, list[str]]:
        item_refs: dict[UUID, list[str]] = {}
        if scope.get("schemaVersion") == REQUIREMENT_SCOPE_V2_SCHEMA_VERSION:
            for item in scope.get("requirementItemRefs") or []:
                item_refs[UUID(str(item.get("requirementVersionId")))] = [
                    str(value) for value in item.get("requirementItemIds") or []
                ]
        else:
            item_refs[UUID(str(scope.get("requirementVersionId")))] = [
                str(value) for value in scope.get("selectedRequirementItemIds") or []
            ]

        for version_id in scope_version_ids(scope):
            version = self.db.get(RequirementVersion, version_id)
            if version is None:
                raise LookupError(f"requirement version not found: {version_id}")
            available_ids = self._requirement_item_ids(version)
            selected_ids = item_refs.setdefault(version_id, [])
            unknown = [item_id for item_id in selected_ids if item_id not in available_ids]
            if unknown:
                raise ValueError(
                    f"requirementItemRefs contains unknown requirement item id for {version_id}: {unknown[0]}"
                )
        return item_refs

    def _requirement_item_ids(self, version: RequirementVersion) -> set[str]:
        result: set[str] = set()
        for index, raw_item in enumerate(version.requirements or [], start=1):
            if isinstance(raw_item, dict):
                result.add(str(raw_item.get("id") or raw_item.get("requirementItemId") or f"requirement-{index}"))
            else:
                result.add(f"requirement-{index}")
        return result

    def _ensure_same_selection(self, existing: dict[str, Any], requested: dict[str, Any]) -> None:
        keys = ("schemaVersion", "requirementVersionId", "requirementVersionIds", "requirementItemRefs")
        if any(existing.get(key) != requested.get(key) for key in keys):
            raise ValueError("requirement scope id conflicts with a different persisted selection")

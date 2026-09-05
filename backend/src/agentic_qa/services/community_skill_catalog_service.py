# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from agentic_qa.infra.settings import get_settings
from agentic_qa.services.common import ServiceContext, canonical_hash
from agentic_qa.services.skill_service import SkillService


MAX_MANIFEST_BYTES = 256 * 1024


class CommunitySkillCatalogService:
    """Read data-only Skill manifests from one explicitly configured directory."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.root = Path(get_settings().community_skill_manifest_dir).resolve()

    def list_manifests(self) -> dict[str, object]:
        items: list[dict[str, object]] = []
        if self.root.is_dir():
            for path in sorted(self.root.glob("*.json"))[:100]:
                try:
                    manifest = self._read_manifest(path.name)
                except ValueError as exc:
                    items.append({"fileName": path.name, "valid": False, "error": str(exc)})
                    continue
                items.append(
                    {
                        "fileName": path.name,
                        "valid": True,
                        "skillId": manifest.get("skillId"),
                        "displayName": manifest.get("displayName"),
                        "version": manifest.get("version"),
                        "extensionPoints": manifest.get("extensionPoints", []),
                        "manifestHash": canonical_hash(manifest),
                    }
                )
        return {
            "schemaVersion": "community.local-skill-catalog.v1",
            "configuredDirectory": get_settings().community_skill_manifest_dir,
            "codeUploadAllowed": False,
            "remoteFetchAllowed": False,
            "items": items,
            "total": len(items),
        }

    def register(self, file_name: str, context: ServiceContext) -> dict[str, object]:
        manifest = self._read_manifest(file_name)
        return SkillService(self.db).register_trusted_local_manifest(
            manifest,
            source_name=file_name,
            context=context,
        )

    def _read_manifest(self, file_name: str) -> dict[str, object]:
        if not file_name or Path(file_name).name != file_name or not file_name.endswith(".json"):
            raise ValueError("COMMUNITY_SKILL_MANIFEST_FILE_INVALID")
        source = self.root / file_name
        if source.is_symlink():
            raise ValueError("COMMUNITY_SKILL_MANIFEST_SYMLINK_FORBIDDEN")
        path = source.resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("COMMUNITY_SKILL_MANIFEST_OUTSIDE_CONFIGURED_DIRECTORY") from exc
        if not path.is_file() or path.is_symlink():
            raise ValueError("COMMUNITY_SKILL_MANIFEST_NOT_FOUND")
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError("COMMUNITY_SKILL_MANIFEST_TOO_LARGE")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("COMMUNITY_SKILL_MANIFEST_JSON_INVALID") from exc
        if not isinstance(payload, dict):
            raise ValueError("COMMUNITY_SKILL_MANIFEST_OBJECT_REQUIRED")
        forbidden = {"code", "script", "command", "binary", "url", "downloadUrl"}.intersection(payload)
        if forbidden:
            raise ValueError("COMMUNITY_SKILL_EXECUTABLE_CONTENT_FORBIDDEN")
        return payload

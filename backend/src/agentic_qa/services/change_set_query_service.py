# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    ChangeNormalizationIssueRecord,
    ChangeSetRecord,
    ChangeSourceSnapshot,
    CodeChangeFileRecord,
    CodeChangeHunkRecord,
    CodeChangeSetRecord,
    CodeChangeSymbolRecord,
    Project,
    ProjectEnvironment,
    RequirementChangeItemRecord,
    RequirementChangeSetRecord,
    RequirementVersion,
    TestPlan,
)
from agentic_qa.schemas.change_sets import CodeChangeSetContract, RequirementChangeSetContract
from agentic_qa.infra.redaction import redact_sensitive_text
from agentic_qa.services.change_normalizer import _requirement_item_map
from agentic_qa.services.common import ServiceContext, canonical_hash, paginate_result
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


@dataclass(frozen=True, slots=True)
class ChangeSetScope:
    project: Project
    tenant_id: str
    workspace_id: str
    environment: ProjectEnvironment | None


class ChangeSetError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


class ChangeSetQueryService:
    """Project-scoped, read-only Change Set projection for the OSS boundary."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def list_change_sets(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        page: int,
        page_size: int,
        change_set_type: str | None = None,
        status: str | None = None,
        environment_id: UUID | None = None,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, environment_id, context, "change.read")
        statement = select(ChangeSetRecord).where(
            ChangeSetRecord.tenant_id == scope.tenant_id,
            ChangeSetRecord.workspace_id == scope.workspace_id,
            ChangeSetRecord.project_id == scope.project.id,
        )
        if environment_id is not None:
            statement = statement.where(ChangeSetRecord.environment_id == environment_id)
        if change_set_type:
            statement = statement.where(ChangeSetRecord.change_set_type == change_set_type)
        if status:
            statement = statement.where(ChangeSetRecord.status == status)
        total = self.db.scalar(select(func.count()).select_from(statement.subquery())) or 0
        rows = list(
            self.db.scalars(
                statement.order_by(ChangeSetRecord.created_at.desc(), ChangeSetRecord.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        snapshots: dict[UUID, ChangeSourceSnapshot] = {}
        if rows:
            snapshots = {
                snapshot.id: snapshot
                for snapshot in self.db.scalars(
                    select(ChangeSourceSnapshot).where(
                        ChangeSourceSnapshot.id.in_({row.source_snapshot_id for row in rows})
                    )
                )
            }
        result = paginate_result(
            [self._summary(row, scope, snapshots.get(row.source_snapshot_id)) for row in rows],
            total,
            page,
            page_size,
        )
        result.update(
            {
                "schemaVersion": "phase8.change-set-list.v1",
                "projectId": str(scope.project.id),
                "readOnly": True,
                "impactAnalysisPerformed": False,
            }
        )
        return result

    def get_change_set(
        self,
        project_id: UUID,
        change_set_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, None, context, "change.read")
        row = self.db.scalar(
            select(ChangeSetRecord).where(
                ChangeSetRecord.id == change_set_id,
                ChangeSetRecord.tenant_id == scope.tenant_id,
                ChangeSetRecord.workspace_id == scope.workspace_id,
                ChangeSetRecord.project_id == scope.project.id,
            )
        )
        if row is None:
            raise ChangeSetError("CHANGE_SET_NOT_FOUND", status_code=404)
        return self._detail(row, scope, deduplicated=False)

    def get_requirement_content_preview(
        self,
        project_id: UUID,
        change_set_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, None, context, "change.read")
        if "requirements.read" not in set(context.user.capabilities):
            raise ChangeSetError("REQUIREMENTS_CAPABILITY_REQUIRED", status_code=403, field="requirements.read")
        change_set = self.db.scalar(
            select(ChangeSetRecord).where(
                ChangeSetRecord.id == change_set_id,
                ChangeSetRecord.tenant_id == scope.tenant_id,
                ChangeSetRecord.workspace_id == scope.workspace_id,
                ChangeSetRecord.project_id == scope.project.id,
            )
        )
        if change_set is None:
            raise ChangeSetError("CHANGE_SET_NOT_FOUND", status_code=404)
        if change_set.change_set_type != "requirement":
            raise ChangeSetError("REQUIREMENT_CHANGE_SET_NOT_FOUND", status_code=404)
        snapshot = self.db.get(ChangeSourceSnapshot, change_set.source_snapshot_id)
        if (
            snapshot is None
            or snapshot.tenant_id != scope.tenant_id
            or snapshot.workspace_id != scope.workspace_id
            or snapshot.project_id != scope.project.id
        ):
            raise ChangeSetError("CHANGE_SET_SOURCE_SNAPSHOT_INVALID")
        subtype = self.db.get(RequirementChangeSetRecord, change_set.id)
        if subtype is None:
            raise ChangeSetError("REQUIREMENT_CHANGE_SET_INVALID")
        versions: dict[UUID, dict[str, dict[str, Any]]] = {}
        explicit_ids: dict[UUID, set[str]] = {}
        library_version_ids: list[str] = []
        for version_id in filter(None, (subtype.base_requirement_version_id, subtype.head_requirement_version_id)):
            version = self.db.get(RequirementVersion, version_id)
            if version is None:
                raise ChangeSetError("CHANGE_REQUIREMENT_VERSION_NOT_FOUND", status_code=404)
            project_from_metadata = str((version.metadata_json or {}).get("projectId"))
            if project_from_metadata != str(scope.project.id):
                linked_plan = self.db.scalar(
                    select(TestPlan.id).where(
                        TestPlan.project_id == scope.project.id,
                        TestPlan.requirement_version_id == version_id,
                    )
                )
                if linked_plan is None:
                    raise ChangeSetError("CHANGE_REQUIREMENT_VERSION_NOT_FOUND", status_code=404)
            else:
                library_version_ids.append(str(version_id))
            source_ref = f"requirement://versions/{version_id}"
            if not any(
                isinstance(ref, dict)
                and ref.get("type") == "requirement_version"
                and ref.get("ref") == source_ref
                and ref.get("contentHash") == version.content_hash
                for ref in snapshot.source_refs or []
            ):
                raise ChangeSetError("CHANGE_REQUIREMENT_SOURCE_MISMATCH")
            versions[version_id] = _requirement_item_map(version.requirements or [])
            explicit_ids[version_id] = {
                str(raw.get("id") or raw.get("requirementItemId"))
                for raw in version.requirements or []
                if isinstance(raw, dict) and (raw.get("id") or raw.get("requirementItemId"))
            }
        items = list(
            self.db.scalars(
                select(RequirementChangeItemRecord)
                .where(RequirementChangeItemRecord.change_set_id == change_set.id)
                .order_by(RequirementChangeItemRecord.ordinal.asc())
            )
        )
        return {
            "schemaVersion": "phase8.requirement-change-content-preview.v1",
            "changeSetId": str(change_set.id),
            "projectId": str(scope.project.id),
            "readOnly": True,
            "libraryVersionIds": library_version_ids,
            "items": [
                {
                    "itemId": str(item.id),
                    "requirementId": item.requirement_id,
                    "changeType": item.change_type,
                    "identityBasis": self._requirement_identity_basis(item, explicit_ids),
                    "before": self._requirement_text_preview(
                        item.requirement_id,
                        item.before_requirement_version_id,
                        subtype.base_requirement_version_id,
                        item.before_refs,
                        versions,
                    ),
                    "after": self._requirement_text_preview(
                        item.requirement_id,
                        item.after_requirement_version_id,
                        subtype.head_requirement_version_id,
                        item.after_refs,
                        versions,
                    ),
                }
                for item in items
            ],
        }

    @staticmethod
    def _requirement_identity_basis(
        item: RequirementChangeItemRecord,
        explicit_ids: dict[UUID, set[str]],
    ) -> str:
        version_ids = (
            item.before_requirement_version_id,
            item.after_requirement_version_id,
        )
        return (
            "source_id"
            if any(version_ids)
            and all(
                item.requirement_id in explicit_ids.get(version_id, set())
                for version_id in version_ids
                if version_id is not None
            )
            else "position"
        )

    @staticmethod
    def _requirement_text_preview(
        requirement_id: str,
        item_version_id: UUID | None,
        expected_version_id: UUID | None,
        refs: list[dict[str, Any]],
        versions: dict[UUID, dict[str, dict[str, Any]]],
    ) -> dict[str, Any]:
        if item_version_id is None and not refs:
            return {"status": "absent", "text": None, "truncated": False}
        if item_version_id is None or item_version_id != expected_version_id or len(refs) != 1:
            return {"status": "unavailable", "text": None, "truncated": False}
        value = versions.get(item_version_id, {}).get(requirement_id)
        expected_ref = f"requirement://versions/{item_version_id}/items/{requirement_id}"
        ref = refs[0]
        if (
            value is None
            or not isinstance(ref, dict)
            or ref.get("ref") != expected_ref
            or ref.get("contentHash") != canonical_hash(value)
            or not isinstance(value.get("text"), str)
        ):
            return {"status": "unavailable", "text": None, "truncated": False}
        safe_text = redact_sensitive_text(value["text"])
        return {
            "status": "available",
            "text": safe_text[:4000],
            "truncated": len(safe_text) > 4000,
        }

    def _detail(
        self,
        row: ChangeSetRecord,
        scope: ChangeSetScope,
        *,
        deduplicated: bool,
    ) -> dict[str, Any]:
        snapshot = self.db.get(ChangeSourceSnapshot, row.source_snapshot_id)
        if (
            snapshot is None
            or snapshot.tenant_id != scope.tenant_id
            or snapshot.workspace_id != scope.workspace_id
            or snapshot.project_id != scope.project.id
        ):
            raise ChangeSetError("CHANGE_SET_SOURCE_SNAPSHOT_INVALID", status_code=409)
        issues = list(
            self.db.scalars(
                select(ChangeNormalizationIssueRecord)
                .where(ChangeNormalizationIssueRecord.change_set_id == row.id)
                .order_by(ChangeNormalizationIssueRecord.ordinal.asc())
            )
        )
        base = {
            "changeSetId": str(row.id),
            "changeSetType": row.change_set_type,
            "projectId": str(row.project_id),
            "environmentId": str(row.environment_id) if row.environment_id else None,
            "sourceSnapshotId": str(snapshot.id),
            "sourceType": snapshot.source_type,
            "sourceId": snapshot.source_id,
            "sourceRevision": snapshot.revision,
            "sourceContentHash": snapshot.content_hash,
            "fingerprint": row.fingerprint,
            "normalizerVersion": row.normalizer_version,
            "status": row.status,
            "itemCount": row.item_count,
            "issueCount": row.issue_count,
            "sensitive": row.sensitive,
            "sourceRefs": snapshot.source_refs,
            "artifactRefs": row.artifact_refs,
            "replayRefs": row.replay_refs,
            "traceId": str(row.trace_id),
            "issues": [self._issue_projection(issue) for issue in issues],
            "deduplicated": deduplicated,
            "createdAt": row.created_at,
        }
        if row.change_set_type == "requirement":
            requirement_subtype = self.db.get(RequirementChangeSetRecord, row.id)
            if requirement_subtype is None:
                raise ChangeSetError("REQUIREMENT_CHANGE_SET_INVALID", status_code=409)
            items = list(
                self.db.scalars(
                    select(RequirementChangeItemRecord)
                    .where(RequirementChangeItemRecord.change_set_id == row.id)
                    .order_by(RequirementChangeItemRecord.ordinal.asc())
                )
            )
            payload = {
                **base,
                "schemaVersion": "phase8.requirement-change-set.v1",
                "baseRequirementVersionId": (
                    str(requirement_subtype.base_requirement_version_id)
                    if requirement_subtype.base_requirement_version_id
                    else None
                ),
                "headRequirementVersionId": str(requirement_subtype.head_requirement_version_id),
                "items": [self._requirement_item_projection(item) for item in items],
                "impactAnalysisPerformed": False,
            }
            return RequirementChangeSetContract.model_validate(payload).model_dump(mode="json")
        code_subtype = self.db.get(CodeChangeSetRecord, row.id)
        if code_subtype is None:
            raise ChangeSetError("CODE_CHANGE_SET_INVALID", status_code=409)
        files = list(
            self.db.scalars(
                select(CodeChangeFileRecord)
                .where(CodeChangeFileRecord.change_set_id == row.id)
                .order_by(CodeChangeFileRecord.ordinal.asc())
            )
        )
        hunks_by_file: dict[UUID, list[CodeChangeHunkRecord]] = {}
        symbols_by_hunk: dict[UUID, list[CodeChangeSymbolRecord]] = {}
        if files:
            hunks = list(self.db.scalars(
                select(CodeChangeHunkRecord)
                .where(CodeChangeHunkRecord.file_id.in_([file.id for file in files]))
                .order_by(CodeChangeHunkRecord.file_id, CodeChangeHunkRecord.ordinal)
            ))
            for hunk in hunks:
                hunks_by_file.setdefault(hunk.file_id, []).append(hunk)
            if hunks:
                symbols = self.db.scalars(
                    select(CodeChangeSymbolRecord)
                    .where(CodeChangeSymbolRecord.hunk_id.in_([hunk.id for hunk in hunks]))
                    .order_by(CodeChangeSymbolRecord.hunk_id, CodeChangeSymbolRecord.ordinal)
                )
                for symbol in symbols:
                    symbols_by_hunk.setdefault(symbol.hunk_id, []).append(symbol)
        payload = {
            **base,
            "schemaVersion": "phase8.code-change-set.v1",
            "repositoryRef": code_subtype.repository_ref,
            "baseSha": code_subtype.base_sha,
            "headSha": code_subtype.head_sha,
            "files": [
                self._code_file_projection(item, hunks_by_file.get(item.id, []), symbols_by_hunk)
                for item in files
            ],
            "fullDiffStoredInDatabase": False,
            "impactAnalysisPerformed": False,
        }
        return CodeChangeSetContract.model_validate(payload).model_dump(mode="json")

    def _code_file_projection(
        self,
        row: CodeChangeFileRecord,
        hunks: list[CodeChangeHunkRecord],
        symbols_by_hunk: dict[UUID, list[CodeChangeSymbolRecord]],
    ) -> dict[str, Any]:
        return {
            "fileId": str(row.id),
            "path": row.path,
            "oldPath": row.old_path,
            "changeType": row.change_type,
            "language": row.language,
            "binary": row.binary,
            "generated": row.generated,
            "vendor": row.vendor,
            "submodule": row.submodule,
            "riskHints": row.risk_hints,
            "diffArtifactRefs": row.diff_artifact_refs,
            "hunks": [self._hunk_projection(item, symbols_by_hunk.get(item.id, [])) for item in hunks],
        }

    def _hunk_projection(
        self, row: CodeChangeHunkRecord, symbols: list[CodeChangeSymbolRecord]
    ) -> dict[str, Any]:
        return {
            "hunkId": str(row.id),
            "header": row.header,
            "oldLineStart": row.old_line_start,
            "oldLineCount": row.old_line_count,
            "newLineStart": row.new_line_start,
            "newLineCount": row.new_line_count,
            "contentHash": row.content_hash,
            "diffArtifactRefs": row.diff_artifact_refs,
            "sensitive": row.sensitive,
            "redactionCount": row.redaction_count,
            "symbols": [
                {
                    "symbolId": str(item.id),
                    "name": item.name,
                    "kind": item.kind,
                    "changeType": item.change_type,
                    "oldLineStart": item.old_line_start,
                    "oldLineEnd": item.old_line_end,
                    "newLineStart": item.new_line_start,
                    "newLineEnd": item.new_line_end,
                    "confidence": float(item.confidence),
                    "evidence": item.evidence_refs,
                }
                for item in symbols
            ],
        }

    @staticmethod
    def _requirement_item_projection(row: RequirementChangeItemRecord) -> dict[str, Any]:
        return {
            "itemId": str(row.id),
            "requirementId": row.requirement_id,
            "beforeRequirementVersionId": (
                str(row.before_requirement_version_id) if row.before_requirement_version_id else None
            ),
            "afterRequirementVersionId": (
                str(row.after_requirement_version_id) if row.after_requirement_version_id else None
            ),
            "changeType": row.change_type,
            "beforeRefs": row.before_refs,
            "afterRefs": row.after_refs,
            "changedFields": row.changed_fields,
            "explicitCapabilityRefs": row.explicit_capability_refs,
            "relatedRequirementIds": row.related_requirement_ids,
            "confidence": float(row.confidence),
            "evidence": row.evidence_refs,
        }

    @staticmethod
    def _issue_projection(row: ChangeNormalizationIssueRecord) -> dict[str, Any]:
        return {
            "schemaVersion": "phase8.normalization-issue.v1",
            "issueId": str(row.id),
            "category": row.category,
            "code": row.code,
            "message": row.message,
            "field": row.field,
            "recoverable": row.recoverable,
            "evidence": row.evidence_refs,
        }

    def _summary(
        self, row: ChangeSetRecord, scope: ChangeSetScope, snapshot: ChangeSourceSnapshot | None
    ) -> dict[str, Any]:
        if (
            snapshot is None
            or snapshot.tenant_id != scope.tenant_id
            or snapshot.workspace_id != scope.workspace_id
            or snapshot.project_id != scope.project.id
        ):
            raise ChangeSetError("CHANGE_SET_SOURCE_SNAPSHOT_INVALID", status_code=409)
        return {
            "changeSetId": str(row.id),
            "changeSetType": row.change_set_type,
            "status": row.status,
            "sourceType": snapshot.source_type,
            "sourceId": snapshot.source_id,
            "sourceRevision": snapshot.revision,
            "sourceContentHash": snapshot.content_hash,
            "normalizerVersion": row.normalizer_version,
            "itemCount": row.item_count,
            "issueCount": row.issue_count,
            "sensitive": row.sensitive,
            "impactAnalysisPerformed": False,
            "createdAt": row.created_at.isoformat(),
        }

    def _require_scope(
        self,
        project_id: UUID,
        environment_id: UUID | None,
        context: ServiceContext,
        capability: str,
    ) -> ChangeSetScope:
        if capability not in set(context.user.capabilities):
            raise ChangeSetError("CHANGE_CAPABILITY_REQUIRED", status_code=403, field=capability)
        try:
            scope = ScopeAuthorizationService(self.db).resolve_project(
                project_id,
                context,
                environment_id=environment_id,
            )
        except ScopeAuthorizationError as exc:
            if exc.field == "gateContext":
                code = "CHANGE_SCOPE_INVALID"
            elif exc.code == "SCOPE_ENVIRONMENT_NOT_FOUND":
                code = "CHANGE_ENVIRONMENT_NOT_FOUND"
            else:
                code = "CHANGE_PROJECT_NOT_FOUND"
            raise ChangeSetError(code, status_code=exc.status_code, field=exc.field) from exc
        return ChangeSetScope(
            scope.project,
            scope.tenant_id,
            scope.workspace_id,
            scope.environment,
        )


__all__ = ["ChangeSetError", "ChangeSetQueryService", "ChangeSetScope"]

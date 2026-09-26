# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import JobStatus
from agentic_qa.domain.models import (
    OrchestrationRun,
    Project,
    ProjectEnvironment,
    RequirementIntakeDraft,
    RequirementIntakePreview,
    RequirementVersion,
)
from agentic_qa.schemas.requirement_library import (
    RequirementLibraryFilters,
    RequirementLibraryItem,
    RequirementLibraryResponse,
    RequirementLibrarySummary,
)
from agentic_qa.services.common import ServiceContext, paginate
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


class RequirementLibraryService:
    """Read-only Requirement Library projection over existing requirement records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def list_library(
        self,
        *,
        page: int,
        page_size: int,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
        requirement_version_id: UUID | None = None,
        source_type: str | None = None,
        status: str | None = None,
        keyword: str | None = None,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        self._validate_scope(
            project_id,
            environment_id,
            requirement_version_id,
            context=context,
        )
        filters = RequirementLibraryFilters(
            projectId=project_id,
            environmentId=environment_id,
            requirementVersionId=requirement_version_id,
            sourceType=self._normalize_filter(source_type),
            status=self._normalize_filter(status),
            keyword=(keyword or "").strip() or None,
        )
        entries = self._collect_entries()
        if context is not None and (
            context.user.edition == "community"
            or not {"admin", "system"}.intersection(context.user.roles)
        ):
            authorized_project_ids = ScopeAuthorizationService(self.db).authorized_project_ids(context)
            entries = [entry for entry in entries if entry.projectId in authorized_project_ids]
        filtered = [entry for entry in entries if self._matches(entry, filters)]
        filtered.sort(key=lambda item: (str(item.createdAt), item.itemType, item.itemId), reverse=True)
        page_result = paginate(filtered, page, page_size)
        summary = self._summary(filtered, returned_count=len(page_result["items"]))
        response = RequirementLibraryResponse(
            generatedAt=datetime.now(timezone.utc),
            filters=filters,
            items=page_result["items"],
            total=page_result["total"],
            page=page_result["page"],
            pageSize=page_result["pageSize"],
            summary=summary,
            capability={
                "required": "requirements.read",
                "readOnly": True,
                "directMutation": False,
            },
        )
        return response.model_dump(mode="json")

    def _collect_entries(self) -> list[RequirementLibraryItem]:
        versions = list(self.db.scalars(select(RequirementVersion).order_by(RequirementVersion.created_at.desc())))
        drafts = list(self.db.scalars(select(RequirementIntakeDraft).order_by(RequirementIntakeDraft.created_at.desc())))
        previews = list(self.db.scalars(select(RequirementIntakePreview).order_by(RequirementIntakePreview.created_at.desc())))
        drafts_by_id = {draft.id: draft for draft in drafts}

        entries: list[RequirementLibraryItem] = []
        for version in versions:
            entries.append(self._version_entry(version))
            entries.extend(self._requirement_item_entries(version))
        for draft in drafts:
            entries.append(self._draft_entry(draft))
        for preview in previews:
            entries.append(self._preview_entry(preview, drafts_by_id.get(preview.draft_id)))
        linked_runs: dict[tuple[str, str, str | None], UUID | None] = {}
        runs = self.db.scalars(
            select(OrchestrationRun)
            .where(
                OrchestrationRun.trigger_type == "requirement_library_selection",
                OrchestrationRun.linked_requirement_version_id.in_([version.id for version in versions]),
            )
            .order_by(OrchestrationRun.created_at.desc())
        )
        for run in runs:
            selection = (run.envelope_snapshot or {}).get("requirementLibrarySelection") or {}
            version_id = str(run.linked_requirement_version_id or "")
            mode = selection.get("selectionMode")
            linked_id = None if run.status in {JobStatus.FAILED, JobStatus.CANCELLED} else run.id
            if mode == "requirement_version":
                linked_runs.setdefault(("requirement_version", version_id, None), linked_id)
            elif mode == "requirement_items":
                item_ids = selection.get("selectedRequirementItemIds") or []
                if len(item_ids) == 1:
                    linked_runs.setdefault(("requirement_item", version_id, str(item_ids[0])), linked_id)
        for entry in entries:
            if entry.itemType in {"requirement_version", "requirement_item"} and entry.requirementVersionId:
                entry.linkedPipelineId = linked_runs.get(
                    (entry.itemType, str(entry.requirementVersionId), entry.requirementItemId)
                )
        return entries

    def _version_entry(self, version: RequirementVersion) -> RequirementLibraryItem:
        metadata = dict(version.metadata_json or {})
        source_type = self._version_source_type(metadata)
        project_id = self._uuid_from_value(metadata.get("projectId"))
        environment_id = self._uuid_from_value(metadata.get("environmentId"))
        title = str(metadata.get("name") or version.source_ref)
        return RequirementLibraryItem(
            itemId=f"requirement-version:{version.id}",
            itemType="requirement_version",
            sourceType=source_type,
            status=str(metadata.get("status") or "active"),
            title=title,
            summary=self._summary_text([*list(version.requirements or []), version.document]),
            projectId=project_id,
            environmentId=environment_id,
            environment=self._string_or_none(metadata.get("environment")),
            sourceRef=version.source_ref,
            requirementVersionId=version.id,
            linkedRequirementVersionId=version.id,
            contentHash=version.content_hash,
            requirementCount=len(version.requirements or []),
            acceptanceCriteriaCount=len(version.acceptance_criteria or []),
            createdAt=version.created_at,
            updatedAt=version.updated_at,
            metadata={
                **metadata,
                "version": version.version_no,
                "projectionSource": "requirement_versions",
            },
        )

    def _requirement_item_entries(self, version: RequirementVersion) -> list[RequirementLibraryItem]:
        metadata = dict(version.metadata_json or {})
        source_type = self._version_source_type(metadata)
        project_id = self._uuid_from_value(metadata.get("projectId"))
        environment_id = self._uuid_from_value(metadata.get("environmentId"))
        items: list[RequirementLibraryItem] = []
        for index, raw_item in enumerate(version.requirements or [], start=1):
            item = self._requirement_item_payload(raw_item, index)
            requirement_item_id = item["id"]
            items.append(
                RequirementLibraryItem(
                    itemId=f"requirement-item:{version.id}:{requirement_item_id}",
                    itemType="requirement_item",
                    sourceType=source_type,
                    status=item["status"],
                    title=item["text"],
                    summary=item["text"],
                    projectId=project_id,
                    environmentId=environment_id,
                    environment=self._string_or_none(metadata.get("environment")),
                    sourceRef=version.source_ref,
                    requirementVersionId=version.id,
                    linkedRequirementVersionId=version.id,
                    requirementItemId=requirement_item_id,
                    requirementItemIndex=index,
                    contentHash=version.content_hash,
                    requirementCount=1,
                    acceptanceCriteriaCount=len(version.acceptance_criteria or []),
                    createdAt=version.created_at,
                    updatedAt=version.updated_at,
                    metadata={
                        **item["metadata"],
                        "projectionSource": "requirement_versions.requirements",
                        "requirementVersionSourceRef": version.source_ref,
                    },
                )
            )
        return items

    def _draft_entry(self, draft: RequirementIntakeDraft) -> RequirementLibraryItem:
        return RequirementLibraryItem(
            itemId=f"requirement-intake-draft:{draft.id}",
            itemType="requirement_intake_draft",
            sourceType=draft.source_type,
            status=draft.status,
            title=draft.name,
            summary=self._summary_text([draft.normalized_document, draft.raw_content, draft.source_uri, draft.source_ref]),
            projectId=draft.project_id,
            environmentId=draft.environment_id,
            environment=draft.environment,
            sourceRef=draft.source_ref,
            sourceUri=draft.source_uri,
            intakeDraftId=draft.id,
            contentHash=draft.content_hash,
            artifactRefs=list(draft.artifact_refs or []),
            evidenceRefs=list(draft.evidence_refs or []),
            traceId=draft.trace_id,
            createdAt=draft.created_at,
            updatedAt=draft.updated_at,
            metadata={
                **dict(draft.metadata_json or {}),
                "redactionStatus": draft.redaction_status,
                "projectionSource": "requirement_intake_drafts",
            },
        )

    def _preview_entry(
        self,
        preview: RequirementIntakePreview,
        draft: RequirementIntakeDraft | None,
    ) -> RequirementLibraryItem:
        project_id = draft.project_id if draft else self._uuid_from_value(preview.pipeline_payload.get("projectId"))
        environment_id = draft.environment_id if draft else self._uuid_from_value(preview.pipeline_payload.get("environmentId"))
        environment = draft.environment if draft else self._string_or_none(preview.pipeline_payload.get("environment"))
        title = str((preview.pipeline_payload or {}).get("name") or (draft.name if draft else preview.source_ref))
        return RequirementLibraryItem(
            itemId=f"requirement-intake-preview:{preview.id}",
            itemType="requirement_intake_preview",
            sourceType=preview.source_type,
            status=preview.status,
            title=title,
            summary=self._summary_text([*list(preview.requirements or []), preview.source_uri, preview.source_ref]),
            projectId=project_id,
            environmentId=environment_id,
            environment=environment,
            sourceRef=preview.source_ref,
            sourceUri=preview.source_uri,
            requirementVersionId=preview.linked_requirement_version_id,
            linkedRequirementVersionId=preview.linked_requirement_version_id,
            intakeDraftId=preview.draft_id,
            intakePreviewId=preview.id,
            linkedPipelineId=preview.linked_pipeline_id,
            contentHash=preview.content_hash,
            requirementCount=len(preview.requirements or []),
            acceptanceCriteriaCount=len(preview.acceptance_criteria or []),
            artifactRefs=list(preview.artifact_refs or []),
            evidenceRefs=list(preview.evidence_refs or []),
            traceId=preview.trace_id,
            createdAt=preview.created_at,
            updatedAt=preview.updated_at,
            metadata={
                **dict(preview.metadata_json or {}),
                "warnings": list(preview.warnings or []),
                "redactionStatus": preview.redaction_status,
                "projectionSource": "requirement_intake_previews",
            },
        )

    def _matches(self, item: RequirementLibraryItem, filters: RequirementLibraryFilters) -> bool:
        if filters.projectId is not None and item.projectId != filters.projectId:
            return False
        if filters.environmentId is not None and item.environmentId != filters.environmentId:
            return False
        if filters.requirementVersionId is not None and (
            item.requirementVersionId != filters.requirementVersionId
            and item.linkedRequirementVersionId != filters.requirementVersionId
        ):
            return False
        if filters.sourceType is not None and item.sourceType.lower() != filters.sourceType:
            return False
        if filters.status is not None and item.status.lower() != filters.status:
            return False
        if filters.keyword is not None and filters.keyword.lower() not in self._search_text(item):
            return False
        return True

    def _summary(self, items: list[RequirementLibraryItem], *, returned_count: int) -> RequirementLibrarySummary:
        return RequirementLibrarySummary(
            requirementVersionCount=len([item for item in items if item.itemType == "requirement_version"]),
            intakeDraftCount=len([item for item in items if item.itemType == "requirement_intake_draft"]),
            intakePreviewCount=len([item for item in items if item.itemType == "requirement_intake_preview"]),
            requirementItemCount=len([item for item in items if item.itemType == "requirement_item"]),
            returnedCount=returned_count,
        )

    def _validate_scope(
        self,
        project_id: UUID | None,
        environment_id: UUID | None,
        requirement_version_id: UUID | None,
        *,
        context: ServiceContext | None,
    ) -> None:
        project = self.db.get(Project, project_id) if project_id else None
        if project_id is not None and project is None:
            raise LookupError("project not found")
        environment = self.db.get(ProjectEnvironment, environment_id) if environment_id else None
        if environment_id is not None and environment is None:
            raise LookupError("environment not found")
        if project is not None and environment is not None and environment.project_id != project.id:
            raise ValueError("environment does not belong to project")
        if requirement_version_id is not None and self.db.get(RequirementVersion, requirement_version_id) is None:
            raise LookupError("requirement version not found")
        if context is None:
            return
        resolved_project_id = project_id
        resolved_environment_id = environment_id
        if resolved_project_id is None and environment is not None:
            resolved_project_id = environment.project_id
        if resolved_project_id is None and requirement_version_id is not None:
            requirement = self.db.get(RequirementVersion, requirement_version_id)
            metadata = dict(requirement.metadata_json or {}) if requirement is not None else {}
            resolved_project_id = self._uuid_from_value(metadata.get("projectId"))
            resolved_environment_id = self._uuid_from_value(metadata.get("environmentId"))
        if resolved_project_id is not None:
            ScopeAuthorizationService(self.db).resolve_project(
                resolved_project_id,
                context,
                environment_id=resolved_environment_id,
                write=False,
            )
        elif requirement_version_id is not None and context.user.edition == "community":
            raise ScopeAuthorizationError("SCOPE_PROJECT_NOT_FOUND")

    def authorize_requirement_version(
        self,
        requirement_version_id: UUID,
        context: ServiceContext,
        *,
        write: bool,
    ) -> None:
        requirement = self.db.get(RequirementVersion, requirement_version_id)
        if requirement is None:
            raise LookupError("requirement version not found")
        metadata = dict(requirement.metadata_json or {})
        project_id = self._uuid_from_value(metadata.get("projectId"))
        environment_id = self._uuid_from_value(metadata.get("environmentId"))
        if project_id is None:
            if context.user.edition == "community":
                raise ScopeAuthorizationError("SCOPE_PROJECT_NOT_FOUND")
            return
        ScopeAuthorizationService(self.db).resolve_project(
            project_id,
            context,
            environment_id=environment_id,
            write=write,
        )

    def _version_source_type(self, metadata: dict[str, Any]) -> str:
        for key in ("intakeSourceType", "sourceType"):
            value = self._string_or_none(metadata.get(key))
            if value:
                return value
        return "requirement_version"

    def _requirement_item_payload(self, raw_item: object, index: int) -> dict[str, Any]:
        if isinstance(raw_item, dict):
            metadata = dict(raw_item)
            item_id = str(raw_item.get("id") or raw_item.get("requirementItemId") or f"requirement-{index}")
            text = str(raw_item.get("text") or raw_item.get("title") or item_id)
            status = str(raw_item.get("status") or "active")
            return {"id": item_id, "text": text, "status": status, "metadata": metadata}
        return {
            "id": f"requirement-{index}",
            "text": str(raw_item),
            "status": "active",
            "metadata": {},
        }

    def _summary_text(self, values: list[object | None]) -> str | None:
        for value in values:
            text = self._string_or_none(value)
            if not text:
                continue
            for line in text.splitlines():
                normalized = line.strip(" -*\t")
                if normalized:
                    return normalized[:280]
        return None

    def _search_text(self, item: RequirementLibraryItem) -> str:
        payload = item.model_dump(mode="json")
        pieces = [
            payload.get("itemId"),
            payload.get("itemType"),
            payload.get("sourceType"),
            payload.get("status"),
            payload.get("title"),
            payload.get("summary"),
            payload.get("sourceRef"),
            payload.get("sourceUri"),
            payload.get("requirementVersionId"),
            payload.get("requirementItemId"),
            payload.get("metadata"),
        ]
        return " ".join(str(piece).lower() for piece in pieces if piece is not None)

    def _uuid_from_value(self, value: object) -> UUID | None:
        try:
            return UUID(str(value))
        except (TypeError, ValueError):
            return None

    def _string_or_none(self, value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _normalize_filter(self, value: str | None) -> str | None:
        text = (value or "").strip().lower()
        return text or None

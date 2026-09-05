# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import Project, ProjectMember, User, WorkItem
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result


WORK_ITEM_STATUSES = {"open", "assigned", "in_progress", "completed", "cancelled"}


class WorkItemQueryService:
    """Project-scoped, read-only WorkItem projection for the OSS boundary."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def list_work_items(
        self,
        page: int,
        page_size: int,
        *,
        context: ServiceContext,
        project_id: UUID | None = None,
        status: str | None = None,
        assignee_id: UUID | None = None,
    ) -> dict[str, object]:
        statement = select(WorkItem).order_by(WorkItem.created_at.desc())
        if project_id is not None:
            self._require_project(project_id)
            self._require_project_access(project_id, context)
            statement = statement.where(WorkItem.project_id == project_id)
        elif not self._is_privileged(context):
            project_ids = self._readable_project_ids(context.user.id)
            if not project_ids:
                return paginate_result([], 0, page, page_size)
            statement = statement.where(WorkItem.project_id.in_(project_ids))
        if status is not None:
            self._validate_status(status)
            statement = statement.where(WorkItem.status == status)
        if assignee_id is not None:
            statement = statement.where(WorkItem.assignee_id == assignee_id)
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result(
            [self.serialize_work_item(row) for row in rows],
            total,
            page,
            page_size,
        )

    def get_work_item(
        self,
        work_item_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        work_item = self._require_work_item(work_item_id)
        self._require_project_access(work_item.project_id, context)
        return self.serialize_work_item(work_item)

    def serialize_work_item(self, work_item: WorkItem) -> dict[str, object]:
        assignee = self._user_summary(work_item.assignee_id)
        claimed_by = self._user_summary(work_item.claimed_by)
        return {
            "id": str(work_item.id),
            "projectId": str(work_item.project_id),
            "requirementVersionId": (
                str(work_item.requirement_version_id)
                if work_item.requirement_version_id
                else None
            ),
            "requirementItemId": work_item.requirement_item_id,
            "executionId": str(work_item.execution_id) if work_item.execution_id else None,
            "findingId": str(work_item.finding_id) if work_item.finding_id else None,
            "evidenceArtifactId": (
                str(work_item.evidence_artifact_id) if work_item.evidence_artifact_id else None
            ),
            "title": work_item.title,
            "description": work_item.description,
            "status": work_item.status,
            "priority": work_item.priority,
            "assigneeId": str(work_item.assignee_id) if work_item.assignee_id else None,
            "assigneeName": assignee["name"] if assignee else None,
            "claimedBy": str(work_item.claimed_by) if work_item.claimed_by else None,
            "claimedByName": claimed_by["name"] if claimed_by else None,
            "completedAt": work_item.completed_at.isoformat() if work_item.completed_at else None,
            "cancelledAt": work_item.cancelled_at.isoformat() if work_item.cancelled_at else None,
            "evidenceRefs": work_item.evidence_refs,
            "traceId": str(work_item.trace_id) if work_item.trace_id else None,
            "metadata": work_item.metadata_json,
            "createdBy": str(work_item.created_by) if work_item.created_by else None,
            "updatedBy": str(work_item.updated_by) if work_item.updated_by else None,
            "createdAt": work_item.created_at.isoformat(),
            "updatedAt": work_item.updated_at.isoformat(),
            "linkedResources": {
                "projectId": str(work_item.project_id),
                "requirementVersionId": (
                    str(work_item.requirement_version_id)
                    if work_item.requirement_version_id
                    else None
                ),
                "requirementItemId": work_item.requirement_item_id,
                "executionId": (
                    str(work_item.execution_id) if work_item.execution_id else None
                ),
                "findingId": str(work_item.finding_id) if work_item.finding_id else None,
                "evidenceArtifactId": (
                    str(work_item.evidence_artifact_id)
                    if work_item.evidence_artifact_id
                    else None
                ),
                "evidenceRefCount": len(work_item.evidence_refs),
            },
        }

    def _require_project_access(
        self,
        project_id: UUID,
        context: ServiceContext,
    ) -> ProjectMember | None:
        if self._is_privileged(context):
            return None
        member = self.db.scalar(
            select(ProjectMember).where(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == context.user.id,
                ProjectMember.status == "active",
            )
        )
        if member is None:
            raise PermissionError("project membership required")
        return member

    def _readable_project_ids(self, user_id: UUID) -> list[UUID]:
        return list(
            self.db.scalars(
                select(ProjectMember.project_id).where(
                    ProjectMember.user_id == user_id,
                    ProjectMember.status == "active",
                )
            )
        )

    def _user_summary(self, user_id: UUID | None) -> dict[str, str] | None:
        if user_id is None:
            return None
        user = self.db.get(User, user_id)
        if user is None:
            return None
        return {"id": str(user.id), "name": user.name, "email": user.email}

    @staticmethod
    def _is_privileged(context: ServiceContext) -> bool:
        return bool({"admin", "system"}.intersection(set(context.user.roles)))

    def _require_project(self, project_id: UUID) -> Project:
        project = self.db.get(Project, project_id)
        if project is None:
            raise LookupError("project not found")
        return project

    def _require_work_item(self, work_item_id: UUID) -> WorkItem:
        work_item = self.db.get(WorkItem, work_item_id)
        if work_item is None:
            raise LookupError("work item not found")
        return work_item

    @staticmethod
    def _validate_status(status: str) -> None:
        if status not in WORK_ITEM_STATUSES:
            raise ValueError("invalid work item status")

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import Execution, ExecutionArtifact, Finding, Project, ProjectMember, RequirementVersion, TestPlan, User, WorkItem
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.work_items import WorkItemAssignRequest, WorkItemCreateRequest, WorkItemTransitionRequest
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result


WORK_ITEM_STATUSES = {"open", "assigned", "in_progress", "completed", "cancelled"}
WORK_ITEM_PRIORITIES = {"low", "medium", "high", "urgent"}
TERMINAL_STATUSES = {"completed", "cancelled"}
PROJECT_WRITE_ROLES = {"owner", "admin", "member"}
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "open": {"assigned", "in_progress", "cancelled"},
    "assigned": {"open", "in_progress", "completed", "cancelled"},
    "in_progress": {"assigned", "completed", "cancelled"},
    "completed": set(),
    "cancelled": set(),
}


class WorkItemService:
    """Service-owned human collaboration tasks.

    WorkItems are separate from ExecutionTask runner units and only store
    references to execution/finding/evidence resources.
    """

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
            self._require_project_access(project_id, context, write=False)
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
        return paginate_result([self.serialize_work_item(row) for row in rows], total, page, page_size)

    def get_work_item(self, work_item_id: UUID, context: ServiceContext) -> dict[str, object]:
        work_item = self._require_work_item(work_item_id)
        self._require_project_access(work_item.project_id, context, write=False)
        return self.serialize_work_item(work_item)

    def create_work_item(self, payload: WorkItemCreateRequest, context: ServiceContext) -> dict[str, object]:
        project = self._require_project(payload.projectId)
        self._require_project_access(project.id, context, write=True)
        self._validate_priority(payload.priority)
        if payload.assigneeId is not None:
            self._validate_assignee(project.id, payload.assigneeId)
        self._validate_links(project.id, payload)

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=payload.executionId,
            root_span_name="work_item",
            span_name="work_item.create",
            service_name="orchestrator-service",
            attributes={"projectId": str(project.id), "hasExecution": payload.executionId is not None},
            parent_span_id=context.parent_span_id,
        ):
            work_item = WorkItem(
                id=uuid4(),
                project_id=project.id,
                requirement_version_id=payload.requirementVersionId,
                requirement_item_id=payload.requirementItemId,
                execution_id=payload.executionId,
                finding_id=payload.findingId,
                evidence_artifact_id=payload.evidenceArtifactId,
                title=payload.title.strip(),
                description=payload.description,
                status="assigned" if payload.assigneeId else "open",
                priority=payload.priority,
                assignee_id=payload.assigneeId,
                evidence_refs=[dict(item) for item in payload.evidenceRefs],
                trace_id=UUID(str(context.trace_id)),
                metadata_json=payload.metadata,
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(work_item)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "work_item.create",
                "work_item",
                str(work_item.id),
                context.request_id,
                context.trace_id,
                details=self._audit_details(work_item, {"status": work_item.status}),
                execution_id=work_item.execution_id,
            )
        self.db.commit()
        self.db.refresh(work_item)
        return self.serialize_work_item(work_item)

    def assign_work_item(self, work_item_id: UUID, payload: WorkItemAssignRequest, context: ServiceContext) -> dict[str, object]:
        work_item = self._require_work_item(work_item_id)
        self._require_project_access(work_item.project_id, context, write=True)
        if work_item.status in TERMINAL_STATUSES:
            raise ValueError("terminal work item cannot be reassigned")
        if payload.assigneeId is not None:
            self._validate_assignee(work_item.project_id, payload.assigneeId)

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=work_item.execution_id,
            root_span_name="work_item",
            span_name="work_item.assign",
            service_name="orchestrator-service",
            attributes={"workItemId": str(work_item.id), "projectId": str(work_item.project_id)},
            parent_span_id=context.parent_span_id,
        ):
            previous_assignee = work_item.assignee_id
            work_item.assignee_id = payload.assigneeId
            work_item.updated_by = context.user.id
            work_item.trace_id = UUID(str(context.trace_id))
            if payload.assigneeId is None:
                work_item.claimed_by = None
                work_item.status = "open"
            elif work_item.status == "open":
                work_item.status = "assigned"
            elif work_item.status == "in_progress" and work_item.claimed_by and work_item.claimed_by != payload.assigneeId:
                work_item.claimed_by = None
                work_item.status = "assigned"
            write_audit_log(
                self.db,
                str(context.user.id),
                "work_item.assign",
                "work_item",
                str(work_item.id),
                context.request_id,
                context.trace_id,
                details=self._audit_details(
                    work_item,
                    {
                        "previousAssigneeId": str(previous_assignee) if previous_assignee else None,
                        "assigneeId": str(work_item.assignee_id) if work_item.assignee_id else None,
                    },
                ),
                execution_id=work_item.execution_id,
            )
        self.db.commit()
        self.db.refresh(work_item)
        return self.serialize_work_item(work_item)

    def claim_work_item(self, work_item_id: UUID, context: ServiceContext) -> dict[str, object]:
        work_item = self._require_work_item(work_item_id)
        self._require_project_access(work_item.project_id, context, write=True)
        if work_item.status in TERMINAL_STATUSES:
            raise ValueError("terminal work item cannot be claimed")
        if work_item.assignee_id and work_item.assignee_id != context.user.id and not self._is_privileged(context):
            raise PermissionError("work item is assigned to another user")
        self._validate_assignee(work_item.project_id, context.user.id)

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=work_item.execution_id,
            root_span_name="work_item",
            span_name="work_item.claim",
            service_name="orchestrator-service",
            attributes={"workItemId": str(work_item.id), "projectId": str(work_item.project_id)},
            parent_span_id=context.parent_span_id,
        ):
            work_item.assignee_id = context.user.id
            work_item.claimed_by = context.user.id
            work_item.status = "in_progress"
            work_item.updated_by = context.user.id
            work_item.trace_id = UUID(str(context.trace_id))
            write_audit_log(
                self.db,
                str(context.user.id),
                "work_item.claim",
                "work_item",
                str(work_item.id),
                context.request_id,
                context.trace_id,
                details=self._audit_details(work_item, {"claimedBy": str(context.user.id)}),
                execution_id=work_item.execution_id,
            )
        self.db.commit()
        self.db.refresh(work_item)
        return self.serialize_work_item(work_item)

    def transition_work_item(self, work_item_id: UUID, payload: WorkItemTransitionRequest, context: ServiceContext) -> dict[str, object]:
        work_item = self._require_work_item(work_item_id)
        self._require_project_access(work_item.project_id, context, write=True)
        self._validate_status(payload.status)
        if payload.status == work_item.status:
            return self.serialize_work_item(work_item)
        allowed = ALLOWED_TRANSITIONS.get(work_item.status, set())
        if payload.status not in allowed:
            raise ValueError(f"invalid work item status transition: {work_item.status} -> {payload.status}")
        if payload.status == "assigned" and work_item.assignee_id is None:
            raise ValueError("assigned status requires assignee")

        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=work_item.execution_id,
            root_span_name="work_item",
            span_name="work_item.transition",
            service_name="orchestrator-service",
            attributes={"workItemId": str(work_item.id), "from": work_item.status, "to": payload.status},
            parent_span_id=context.parent_span_id,
        ):
            previous_status = work_item.status
            self._apply_transition(work_item, payload.status, context)
            write_audit_log(
                self.db,
                str(context.user.id),
                "work_item.transition",
                "work_item",
                str(work_item.id),
                context.request_id,
                context.trace_id,
                details=self._audit_details(
                    work_item,
                    {
                        "previousStatus": previous_status,
                        "status": work_item.status,
                        "comment": payload.comment,
                    },
                ),
                execution_id=work_item.execution_id,
            )
        self.db.commit()
        self.db.refresh(work_item)
        return self.serialize_work_item(work_item)

    def serialize_work_item(self, work_item: WorkItem) -> dict[str, object]:
        assignee = self._user_summary(work_item.assignee_id)
        claimed_by = self._user_summary(work_item.claimed_by)
        return {
            "id": str(work_item.id),
            "projectId": str(work_item.project_id),
            "requirementVersionId": str(work_item.requirement_version_id) if work_item.requirement_version_id else None,
            "requirementItemId": work_item.requirement_item_id,
            "executionId": str(work_item.execution_id) if work_item.execution_id else None,
            "findingId": str(work_item.finding_id) if work_item.finding_id else None,
            "evidenceArtifactId": str(work_item.evidence_artifact_id) if work_item.evidence_artifact_id else None,
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
                "requirementVersionId": str(work_item.requirement_version_id) if work_item.requirement_version_id else None,
                "requirementItemId": work_item.requirement_item_id,
                "executionId": str(work_item.execution_id) if work_item.execution_id else None,
                "findingId": str(work_item.finding_id) if work_item.finding_id else None,
                "evidenceArtifactId": str(work_item.evidence_artifact_id) if work_item.evidence_artifact_id else None,
                "evidenceRefCount": len(work_item.evidence_refs),
            },
        }

    def _apply_transition(self, work_item: WorkItem, status: str, context: ServiceContext) -> None:
        now = datetime.now(timezone.utc)
        work_item.status = status
        work_item.updated_by = context.user.id
        work_item.trace_id = UUID(str(context.trace_id))
        if status == "open":
            work_item.assignee_id = None
            work_item.claimed_by = None
        elif status == "in_progress":
            work_item.claimed_by = context.user.id
            if work_item.assignee_id is None:
                work_item.assignee_id = context.user.id
        elif status == "completed":
            work_item.completed_at = now
        elif status == "cancelled":
            work_item.cancelled_at = now

    def _validate_links(self, project_id: UUID, payload: WorkItemCreateRequest) -> None:
        if payload.requirementVersionId is not None and self.db.get(RequirementVersion, payload.requirementVersionId) is None:
            raise LookupError("requirement version not found")
        execution_id = payload.executionId
        if execution_id is not None:
            self._require_execution_project(execution_id, project_id)
        if payload.findingId is not None:
            finding = self.db.get(Finding, payload.findingId)
            if finding is None:
                raise LookupError("finding not found")
            if execution_id is not None and finding.execution_id != execution_id:
                raise ValueError("finding does not belong to execution")
            self._require_execution_project(finding.execution_id, project_id)
        if payload.evidenceArtifactId is not None:
            artifact = self.db.get(ExecutionArtifact, payload.evidenceArtifactId)
            if artifact is None:
                raise LookupError("evidence artifact not found")
            if execution_id is not None and artifact.execution_id != execution_id:
                raise ValueError("evidence artifact does not belong to execution")
            self._require_execution_project(artifact.execution_id, project_id)

    def _require_execution_project(self, execution_id: UUID, project_id: UUID) -> None:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            raise LookupError("execution not found")
        plan = self.db.get(TestPlan, execution.plan_id)
        if plan is None:
            raise LookupError("execution plan not found")
        if plan.project_id is None:
            raise ValueError("execution is not project-scoped")
        if plan.project_id != project_id:
            raise ValueError("execution does not belong to project")

    def _require_project_access(self, project_id: UUID, context: ServiceContext, *, write: bool) -> ProjectMember | None:
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
        if write and member.role not in PROJECT_WRITE_ROLES:
            raise PermissionError("project write role required")
        return member

    def _validate_assignee(self, project_id: UUID, user_id: UUID) -> None:
        if self.db.get(User, user_id) is None:
            raise LookupError("assignee not found")
        member = self.db.scalar(
            select(ProjectMember).where(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == user_id,
                ProjectMember.status == "active",
            )
        )
        if member is None:
            raise ValueError("assignee is not an active project member")

    def _readable_project_ids(self, user_id: UUID) -> list[UUID]:
        return list(
            self.db.scalars(
                select(ProjectMember.project_id).where(
                    ProjectMember.user_id == user_id,
                    ProjectMember.status == "active",
                )
            )
        )

    def _audit_details(self, work_item: WorkItem, extra: dict[str, object] | None = None) -> dict[str, object]:
        details: dict[str, object] = {
            "projectId": str(work_item.project_id),
            "executionId": str(work_item.execution_id) if work_item.execution_id else None,
            "findingId": str(work_item.finding_id) if work_item.finding_id else None,
            "evidenceArtifactId": str(work_item.evidence_artifact_id) if work_item.evidence_artifact_id else None,
            "status": work_item.status,
        }
        if extra:
            details.update(extra)
        return details

    def _user_summary(self, user_id: UUID | None) -> dict[str, str] | None:
        if user_id is None:
            return None
        user = self.db.get(User, user_id)
        if user is None:
            return None
        return {"id": str(user.id), "name": user.name, "email": user.email}

    def _is_privileged(self, context: ServiceContext) -> bool:
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

    def _validate_status(self, status: str) -> None:
        if status not in WORK_ITEM_STATUSES:
            raise ValueError("invalid work item status")

    def _validate_priority(self, priority: str) -> None:
        if priority not in WORK_ITEM_PRIORITIES:
            raise ValueError("invalid work item priority")


# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    Execution,
    Project,
    ProjectEnvironment,
    ProjectMember,
    TestPlan,
    User,
)
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


PROJECT_STATUSES = {"active", "archived"}
ENVIRONMENT_STATUSES = {"active", "disabled", "archived"}


class ProjectSettingsQueryService:
    """Scope-authorized project, environment, and member read projections."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def list_projects(
        self,
        page: int,
        page_size: int,
        context: ServiceContext,
        *,
        status: str | None = None,
    ) -> dict[str, object]:
        project_ids = ScopeAuthorizationService(self.db).authorized_project_ids(context)
        statement = (
            select(Project)
            .where(Project.id.in_(project_ids))
            .order_by(Project.created_at.desc())
        )
        if status:
            self._validate_project_status(status)
            statement = statement.where(Project.status == status)
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result(
            [self.serialize_project(row) for row in rows],
            total,
            page,
            page_size,
        )

    def get_project(self, project_id: UUID, context: ServiceContext) -> dict[str, object]:
        return self.serialize_project(self._scoped_project(project_id, context))

    def list_environments(
        self,
        page: int,
        page_size: int,
        *,
        context: ServiceContext,
        project_id: UUID | None = None,
        status: str | None = None,
    ) -> dict[str, object]:
        project_ids = ScopeAuthorizationService(self.db).authorized_project_ids(context)
        statement = (
            select(ProjectEnvironment)
            .where(ProjectEnvironment.project_id.in_(project_ids))
            .order_by(ProjectEnvironment.created_at.desc())
        )
        if project_id is not None:
            self._scoped_project(project_id, context)
            statement = statement.where(ProjectEnvironment.project_id == project_id)
        if status:
            self._validate_environment_status(status)
            statement = statement.where(ProjectEnvironment.status == status)
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result(
            [self.serialize_environment(row) for row in rows],
            total,
            page,
            page_size,
        )

    def get_environment(
        self,
        environment_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        return self.serialize_environment(self._scoped_environment(environment_id, context))

    def list_members(
        self,
        project_id: UUID,
        page: int,
        page_size: int,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._scoped_project(project_id, context)
        statement = (
            select(ProjectMember)
            .where(ProjectMember.project_id == project_id)
            .order_by(ProjectMember.created_at.desc())
        )
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result(
            [self.serialize_member(row) for row in rows],
            total,
            page,
            page_size,
        )

    def serialize_project(self, project: Project) -> dict[str, object]:
        return {
            "id": str(project.id),
            "key": project.key,
            "name": project.name,
            "description": project.description,
            "status": project.status,
            "metadata": project.metadata_json,
            "planCount": self._plan_count(project.id),
            "executionCount": self._execution_count(project.id),
            "environmentCount": self._environment_count(project.id),
            "memberCount": self._member_count(project.id),
            "createdBy": str(project.created_by) if project.created_by else None,
            "createdAt": project.created_at.isoformat(),
            "updatedAt": project.updated_at.isoformat(),
        }

    @staticmethod
    def serialize_environment(environment: ProjectEnvironment) -> dict[str, object]:
        return {
            "id": str(environment.id),
            "projectId": str(environment.project_id),
            "key": environment.key,
            "name": environment.name,
            "description": environment.description,
            "baseUrl": environment.base_url,
            "status": environment.status,
            "variables": environment.variables,
            "metadata": environment.metadata_json,
            "createdBy": str(environment.created_by) if environment.created_by else None,
            "createdAt": environment.created_at.isoformat(),
            "updatedAt": environment.updated_at.isoformat(),
        }

    def serialize_member(self, member: ProjectMember) -> dict[str, object]:
        user = self.db.get(User, member.user_id) if member.user_id else None
        return {
            "id": str(member.id),
            "projectId": str(member.project_id),
            "userId": str(member.user_id) if member.user_id else None,
            "userName": user.name if user else None,
            "userEmail": user.email if user else None,
            "role": member.role,
            "status": member.status,
            "metadata": member.metadata_json,
            "createdBy": str(member.created_by) if member.created_by else None,
            "createdAt": member.created_at.isoformat(),
            "updatedAt": member.updated_at.isoformat(),
        }

    def _require_environment(self, environment_id: UUID) -> ProjectEnvironment:
        environment = self.db.get(ProjectEnvironment, environment_id)
        if environment is None:
            raise LookupError("environment not found")
        return environment

    def _scoped_project(
        self,
        project_id: UUID,
        context: ServiceContext,
    ) -> Project:
        return ScopeAuthorizationService(self.db).resolve_project(
            project_id,
            context,
            write=False,
        ).project

    def _scoped_environment(
        self,
        environment_id: UUID,
        context: ServiceContext,
    ) -> ProjectEnvironment:
        environment = self._require_environment(environment_id)
        scope = ScopeAuthorizationService(self.db).resolve_project(
            environment.project_id,
            context,
            environment_id=environment.id,
            write=False,
        )
        if scope.environment is None:
            raise ScopeAuthorizationError("SCOPE_ENVIRONMENT_NOT_FOUND")
        return scope.environment

    def _plan_count(self, project_id: UUID) -> int:
        return self.db.scalar(select(func.count()).where(TestPlan.project_id == project_id)) or 0

    def _execution_count(self, project_id: UUID) -> int:
        return (
            self.db.scalar(
                select(func.count())
                .select_from(Execution)
                .join(TestPlan, Execution.plan_id == TestPlan.id)
                .where(TestPlan.project_id == project_id)
            )
            or 0
        )

    def _environment_count(self, project_id: UUID) -> int:
        return (
            self.db.scalar(
                select(func.count()).where(ProjectEnvironment.project_id == project_id)
            )
            or 0
        )

    def _member_count(self, project_id: UUID) -> int:
        return (
            self.db.scalar(select(func.count()).where(ProjectMember.project_id == project_id))
            or 0
        )

    @staticmethod
    def _validate_project_status(status: str) -> None:
        if status not in PROJECT_STATUSES:
            raise ValueError("invalid project status")

    @staticmethod
    def _validate_environment_status(status: str) -> None:
        if status not in ENVIRONMENT_STATUSES:
            raise ValueError("invalid environment status")

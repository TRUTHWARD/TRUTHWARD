# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import Execution, Project, ProjectEnvironment, ProjectMember, TestPlan, User
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.project_settings import (
    EnvironmentRequest,
    EnvironmentUpdateRequest,
    ProjectMemberRequest,
    ProjectMemberUpdateRequest,
    ProjectRequest,
    ProjectUpdateRequest,
)
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result
from agentic_qa.services.scope_service import (
    PLATFORM_SCOPE_ROLES,
    ScopeAuthorizationError,
    ScopeAuthorizationService,
)


PROJECT_STATUSES = {"active", "archived"}
ENVIRONMENT_STATUSES = {"active", "disabled", "archived"}
PROJECT_MEMBER_ROLES = {"owner", "admin", "member", "viewer"}
PROJECT_MEMBER_STATUSES = {"active", "inactive"}


class ProjectSettingsService:
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
        return paginate_result([self.serialize_project(row) for row in rows], total, page, page_size)

    def get_project(self, project_id: UUID, context: ServiceContext) -> dict[str, object]:
        return self.serialize_project(self._scoped_project(project_id, context))

    def create_project(self, payload: ProjectRequest, context: ServiceContext) -> dict[str, object]:
        key = self._normalize_key(payload.key)
        self._validate_project_status(payload.status)
        if self._project_by_key(key) is not None:
            raise ValueError("project key already exists")
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="project.settings",
            span_name="project.create",
            service_name="orchestrator-service",
            attributes={"projectKey": key},
            parent_span_id=context.parent_span_id,
        ):
            project_id = uuid4()
            metadata = dict(payload.metadata)
            supplied_authority = metadata.get("gateContext")
            if PLATFORM_SCOPE_ROLES.intersection(context.user.roles) and isinstance(
                supplied_authority, dict
            ):
                tenant_id = str(supplied_authority.get("tenantId") or "").strip()
                workspace_id = str(supplied_authority.get("workspaceId") or "").strip()
                if not tenant_id or not workspace_id or len(tenant_id) > 128 or len(workspace_id) > 128:
                    raise ValueError("invalid gateContext authority")
            else:
                tenant_id = f"tenant-{context.user.id}"
                workspace_id = f"project-{project_id}"
            metadata["gateContext"] = {
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
            }
            project = Project(
                id=project_id,
                key=key,
                name=payload.name.strip(),
                description=payload.description,
                status=payload.status,
                metadata_json=metadata,
                created_by=context.user.id,
            )
            self.db.add(project)
            self.db.flush()
            self.db.add(
                ProjectMember(
                    id=uuid4(),
                    project_id=project.id,
                    user_id=context.user.id,
                    role="owner",
                    status="active",
                    metadata_json={"source": "project.create"},
                    created_by=context.user.id,
                )
            )
            write_audit_log(
                self.db,
                str(context.user.id),
                "project.create",
                "project",
                str(project.id),
                context.request_id,
                context.trace_id,
                details={"projectKey": project.key, "status": project.status},
            )
        self.db.commit()
        self.db.refresh(project)
        return self.serialize_project(project)

    def update_project(self, project_id: UUID, payload: ProjectUpdateRequest, context: ServiceContext) -> dict[str, object]:
        project = self._scoped_project(project_id, context, write=True)
        updates = payload.model_dump(exclude_unset=True)
        if "key" in updates and updates["key"] is not None:
            key = self._normalize_key(str(updates["key"]))
            existing = self._project_by_key(key)
            if existing is not None and existing.id != project.id:
                raise ValueError("project key already exists")
            project.key = key
        if "name" in updates and updates["name"] is not None:
            project.name = str(updates["name"]).strip()
        if "description" in updates:
            project.description = updates["description"]
        if "status" in updates and updates["status"] is not None:
            self._validate_project_status(str(updates["status"]))
            project.status = str(updates["status"])
        if "metadata" in updates and updates["metadata"] is not None:
            metadata = dict(updates["metadata"])
            existing_authority = project.metadata_json.get("gateContext")
            requested_authority = metadata.get("gateContext", existing_authority)
            if requested_authority != existing_authority:
                raise ScopeAuthorizationError(
                    "SCOPE_CONTEXT_IMMUTABLE",
                    status_code=409,
                    field="metadata.gateContext",
                )
            metadata["gateContext"] = existing_authority
            project.metadata_json = metadata
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="project.settings",
            span_name="project.update",
            service_name="orchestrator-service",
            attributes={"projectId": str(project.id), "projectKey": project.key},
            parent_span_id=context.parent_span_id,
        ):
            write_audit_log(
                self.db,
                str(context.user.id),
                "project.update",
                "project",
                str(project.id),
                context.request_id,
                context.trace_id,
                details={"projectKey": project.key, "status": project.status, "fields": sorted(updates)},
            )
        self.db.commit()
        self.db.refresh(project)
        return self.serialize_project(project)

    def archive_project(self, project_id: UUID, context: ServiceContext) -> dict[str, object]:
        project = self._scoped_project(project_id, context, write=True)
        project.status = "archived"
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="project.settings",
            span_name="project.archive",
            service_name="orchestrator-service",
            attributes={"projectId": str(project.id), "projectKey": project.key},
            parent_span_id=context.parent_span_id,
        ):
            write_audit_log(
                self.db,
                str(context.user.id),
                "project.archive",
                "project",
                str(project.id),
                context.request_id,
                context.trace_id,
                details={"projectKey": project.key},
            )
        self.db.commit()
        self.db.refresh(project)
        return self.serialize_project(project)

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
        return paginate_result([self.serialize_environment(row) for row in rows], total, page, page_size)

    def get_environment(self, environment_id: UUID, context: ServiceContext) -> dict[str, object]:
        return self.serialize_environment(self._scoped_environment(environment_id, context))

    def create_environment(self, project_id: UUID, payload: EnvironmentRequest, context: ServiceContext) -> dict[str, object]:
        project = self._scoped_project(project_id, context, write=True)
        key = self._normalize_key(payload.key)
        self._validate_environment_status(payload.status)
        if self._environment_by_key(project_id, key) is not None:
            raise ValueError("environment key already exists in project")
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="environment.settings",
            span_name="environment.create",
            service_name="orchestrator-service",
            attributes={"projectId": str(project.id), "environmentKey": key},
            parent_span_id=context.parent_span_id,
        ):
            environment = ProjectEnvironment(
                id=uuid4(),
                project_id=project.id,
                key=key,
                name=payload.name.strip(),
                description=payload.description,
                base_url=payload.baseUrl,
                status=payload.status,
                variables=payload.variables,
                metadata_json=payload.metadata,
                created_by=context.user.id,
            )
            self.db.add(environment)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "environment.create",
                "environment",
                str(environment.id),
                context.request_id,
                context.trace_id,
                details={"projectId": str(project.id), "environmentKey": environment.key, "status": environment.status},
            )
        self.db.commit()
        self.db.refresh(environment)
        return self.serialize_environment(environment)

    def update_environment(
        self,
        environment_id: UUID,
        payload: EnvironmentUpdateRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        environment = self._scoped_environment(environment_id, context, write=True)
        updates = payload.model_dump(exclude_unset=True)
        if "key" in updates and updates["key"] is not None:
            key = self._normalize_key(str(updates["key"]))
            existing = self._environment_by_key(environment.project_id, key)
            if existing is not None and existing.id != environment.id:
                raise ValueError("environment key already exists in project")
            environment.key = key
        if "name" in updates and updates["name"] is not None:
            environment.name = str(updates["name"]).strip()
        if "description" in updates:
            environment.description = updates["description"]
        if "baseUrl" in updates:
            environment.base_url = updates["baseUrl"]
        if "status" in updates and updates["status"] is not None:
            self._validate_environment_status(str(updates["status"]))
            environment.status = str(updates["status"])
        if "variables" in updates and updates["variables"] is not None:
            environment.variables = dict(updates["variables"])
        if "metadata" in updates and updates["metadata"] is not None:
            environment.metadata_json = dict(updates["metadata"])
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="environment.settings",
            span_name="environment.update",
            service_name="orchestrator-service",
            attributes={"environmentId": str(environment.id), "projectId": str(environment.project_id)},
            parent_span_id=context.parent_span_id,
        ):
            write_audit_log(
                self.db,
                str(context.user.id),
                "environment.update",
                "environment",
                str(environment.id),
                context.request_id,
                context.trace_id,
                details={"projectId": str(environment.project_id), "environmentKey": environment.key, "fields": sorted(updates)},
            )
        self.db.commit()
        self.db.refresh(environment)
        return self.serialize_environment(environment)

    def archive_environment(self, environment_id: UUID, context: ServiceContext) -> dict[str, object]:
        environment = self._scoped_environment(environment_id, context, write=True)
        environment.status = "archived"
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="environment.settings",
            span_name="environment.archive",
            service_name="orchestrator-service",
            attributes={"environmentId": str(environment.id), "projectId": str(environment.project_id)},
            parent_span_id=context.parent_span_id,
        ):
            write_audit_log(
                self.db,
                str(context.user.id),
                "environment.archive",
                "environment",
                str(environment.id),
                context.request_id,
                context.trace_id,
                details={"projectId": str(environment.project_id), "environmentKey": environment.key},
            )
        self.db.commit()
        self.db.refresh(environment)
        return self.serialize_environment(environment)

    def list_members(
        self,
        project_id: UUID,
        page: int,
        page_size: int,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._scoped_project(project_id, context)
        statement = select(ProjectMember).where(ProjectMember.project_id == project_id).order_by(ProjectMember.created_at.desc())
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result([self.serialize_member(row) for row in rows], total, page, page_size)

    def create_member(self, project_id: UUID, payload: ProjectMemberRequest, context: ServiceContext) -> dict[str, object]:
        project = self._scoped_project(project_id, context, write=True)
        self._require_user(payload.userId)
        self._validate_member_role(payload.role)
        self._validate_member_status(payload.status)
        existing = self.db.scalar(
            select(ProjectMember).where(
                ProjectMember.project_id == project.id,
                ProjectMember.user_id == payload.userId,
            )
        )
        if existing is not None:
            raise ValueError("project member already exists")
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="project.member",
            span_name="project_member.create",
            service_name="orchestrator-service",
            attributes={"projectId": str(project.id), "userId": str(payload.userId), "role": payload.role},
            parent_span_id=context.parent_span_id,
        ):
            member = ProjectMember(
                id=uuid4(),
                project_id=project.id,
                user_id=payload.userId,
                role=payload.role,
                status=payload.status,
                metadata_json=payload.metadata,
                created_by=context.user.id,
            )
            self.db.add(member)
            self.db.flush()
            write_audit_log(
                self.db,
                str(context.user.id),
                "project_member.create",
                "project_member",
                str(member.id),
                context.request_id,
                context.trace_id,
                details={"projectId": str(project.id), "userId": str(payload.userId), "role": payload.role},
            )
        self.db.commit()
        self.db.refresh(member)
        return self.serialize_member(member)

    def update_member(self, member_id: UUID, payload: ProjectMemberUpdateRequest, context: ServiceContext) -> dict[str, object]:
        member = self._scoped_member(member_id, context, write=True)
        updates = payload.model_dump(exclude_unset=True)
        if "role" in updates and updates["role"] is not None:
            self._validate_member_role(str(updates["role"]))
            member.role = str(updates["role"])
        if "status" in updates and updates["status"] is not None:
            self._validate_member_status(str(updates["status"]))
            member.status = str(updates["status"])
        if "metadata" in updates and updates["metadata"] is not None:
            member.metadata_json = dict(updates["metadata"])
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="project.member",
            span_name="project_member.update",
            service_name="orchestrator-service",
            attributes={"projectMemberId": str(member.id), "projectId": str(member.project_id)},
            parent_span_id=context.parent_span_id,
        ):
            write_audit_log(
                self.db,
                str(context.user.id),
                "project_member.update",
                "project_member",
                str(member.id),
                context.request_id,
                context.trace_id,
                details={"projectId": str(member.project_id), "fields": sorted(updates), "role": member.role, "status": member.status},
            )
        self.db.commit()
        self.db.refresh(member)
        return self.serialize_member(member)

    def deactivate_member(self, member_id: UUID, context: ServiceContext) -> dict[str, object]:
        member = self._scoped_member(member_id, context, write=True)
        member.status = "inactive"
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="project.member",
            span_name="project_member.deactivate",
            service_name="orchestrator-service",
            attributes={"projectMemberId": str(member.id), "projectId": str(member.project_id)},
            parent_span_id=context.parent_span_id,
        ):
            write_audit_log(
                self.db,
                str(context.user.id),
                "project_member.deactivate",
                "project_member",
                str(member.id),
                context.request_id,
                context.trace_id,
                details={"projectId": str(member.project_id), "userId": str(member.user_id) if member.user_id else None},
            )
        self.db.commit()
        self.db.refresh(member)
        return self.serialize_member(member)

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

    def serialize_environment(self, environment: ProjectEnvironment) -> dict[str, object]:
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

    def _require_project(self, project_id: UUID) -> Project:
        project = self.db.get(Project, project_id)
        if project is None:
            raise LookupError("project not found")
        return project

    def _scoped_project(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        write: bool = False,
    ) -> Project:
        return ScopeAuthorizationService(self.db).resolve_project(
            project_id,
            context,
            write=write,
        ).project

    def _require_environment(self, environment_id: UUID) -> ProjectEnvironment:
        environment = self.db.get(ProjectEnvironment, environment_id)
        if environment is None:
            raise LookupError("environment not found")
        return environment

    def _scoped_environment(
        self,
        environment_id: UUID,
        context: ServiceContext,
        *,
        write: bool = False,
    ) -> ProjectEnvironment:
        environment = self._require_environment(environment_id)
        scope = ScopeAuthorizationService(self.db).resolve_project(
            environment.project_id,
            context,
            environment_id=environment.id,
            write=write,
        )
        if scope.environment is None:
            raise ScopeAuthorizationError("SCOPE_ENVIRONMENT_NOT_FOUND")
        return scope.environment

    def _require_member(self, member_id: UUID) -> ProjectMember:
        member = self.db.get(ProjectMember, member_id)
        if member is None:
            raise LookupError("project member not found")
        return member

    def _scoped_member(
        self,
        member_id: UUID,
        context: ServiceContext,
        *,
        write: bool = False,
    ) -> ProjectMember:
        member = self._require_member(member_id)
        ScopeAuthorizationService(self.db).resolve_project(
            member.project_id,
            context,
            write=write,
        )
        return member

    def _require_user(self, user_id: UUID) -> User:
        user = self.db.get(User, user_id)
        if user is None:
            raise LookupError("user not found")
        return user

    def _project_by_key(self, key: str) -> Project | None:
        return self.db.scalar(select(Project).where(Project.key == key))

    def _environment_by_key(self, project_id: UUID, key: str) -> ProjectEnvironment | None:
        return self.db.scalar(
            select(ProjectEnvironment).where(
                ProjectEnvironment.project_id == project_id,
                ProjectEnvironment.key == key,
            )
        )

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
        return self.db.scalar(select(func.count()).where(ProjectEnvironment.project_id == project_id)) or 0

    def _member_count(self, project_id: UUID) -> int:
        return self.db.scalar(select(func.count()).where(ProjectMember.project_id == project_id)) or 0

    def _normalize_key(self, key: str) -> str:
        normalized = key.strip().lower()
        if not normalized:
            raise ValueError("key is required")
        if len(normalized) > 80:
            raise ValueError("key is too long")
        if not all(char.isalnum() or char in {"-", "_"} for char in normalized):
            raise ValueError("key may only contain letters, numbers, dash, or underscore")
        return normalized

    def _validate_project_status(self, status: str) -> None:
        if status not in PROJECT_STATUSES:
            raise ValueError("invalid project status")

    def _validate_environment_status(self, status: str) -> None:
        if status not in ENVIRONMENT_STATUSES:
            raise ValueError("invalid environment status")

    def _validate_member_role(self, role: str) -> None:
        if role not in PROJECT_MEMBER_ROLES:
            raise ValueError("invalid project member role")

    def _validate_member_status(self, status: str) -> None:
        if status not in PROJECT_MEMBER_STATUSES:
            raise ValueError("invalid project member status")

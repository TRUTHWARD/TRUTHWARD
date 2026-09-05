# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import Project, ProjectEnvironment, ProjectMember
from agentic_qa.services.common import ServiceContext, canonical_hash


PROJECT_WRITE_ROLES = frozenset({"owner", "admin"})
PLATFORM_SCOPE_ROLES = frozenset({"admin", "system"})


class ScopeAuthorizationError(ValueError):
    def __init__(self, code: str, *, status_code: int = 404, field: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.field = field


@dataclass(frozen=True, slots=True)
class ScopeContext:
    project: Project
    tenant_id: str
    workspace_id: str
    environment: ProjectEnvironment | None
    membership_role: str | None
    access_source: str
    decision_ref: str

    def projection(self) -> dict[str, object]:
        return {
            "schemaVersion": "phase8.scope-context.v1",
            "tenantId": self.tenant_id,
            "workspaceId": self.workspace_id,
            "projectId": str(self.project.id),
            "environmentId": str(self.environment.id) if self.environment else None,
            "membershipRole": self.membership_role,
            "accessSource": self.access_source,
            "decisionRef": self.decision_ref,
            "serverDerived": True,
        }


class ScopeAuthorizationService:
    """Single Service-owned project/environment scope authority.

    Tenant and workspace are derived from the persisted Project authority. Client
    payload tenant/workspace values are never accepted by this boundary.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def resolve_project(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        environment_id: UUID | None = None,
        write: bool = False,
    ) -> ScopeContext:
        project = self.db.get(Project, project_id)
        if project is None:
            raise ScopeAuthorizationError("SCOPE_PROJECT_NOT_FOUND")

        membership = self.db.scalar(
            select(ProjectMember).where(
                ProjectMember.project_id == project.id,
                ProjectMember.user_id == context.user.id,
                ProjectMember.status == "active",
            )
        )
        platform_roles = PLATFORM_SCOPE_ROLES.intersection(context.user.roles)
        if membership is None and not platform_roles:
            # Hide resource existence for IDOR and cross-tenant probes.
            raise ScopeAuthorizationError("SCOPE_PROJECT_NOT_FOUND")
        if write and membership is not None and membership.role not in PROJECT_WRITE_ROLES and not platform_roles:
            raise ScopeAuthorizationError(
                "SCOPE_PROJECT_WRITE_FORBIDDEN",
                status_code=403,
                field="projectId",
            )

        environment = None
        if environment_id is not None:
            environment = self.db.scalar(
                select(ProjectEnvironment).where(
                    ProjectEnvironment.id == environment_id,
                    ProjectEnvironment.project_id == project.id,
                )
            )
            if environment is None:
                raise ScopeAuthorizationError("SCOPE_ENVIRONMENT_NOT_FOUND")

        tenant_id, workspace_id = self.project_authority(project)
        access_source = (
            "project_membership"
            if membership is not None
            else "service_role"
            if "system" in platform_roles
            else "platform_admin"
        )
        decision_hash = canonical_hash(
            {
                "actorId": str(context.user.id),
                "tenantId": tenant_id,
                "workspaceId": workspace_id,
                "projectId": str(project.id),
                "environmentId": str(environment.id) if environment else None,
                "membershipRole": membership.role if membership else None,
                "accessSource": access_source,
                "write": write,
            }
        )
        return ScopeContext(
            project=project,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            environment=environment,
            membership_role=membership.role if membership else None,
            access_source=access_source,
            decision_ref=f"scope-decision://{decision_hash.removeprefix('sha256:')}",
        )

    def authorized_projects_in_workspace(
        self,
        anchor: ScopeContext,
        context: ServiceContext,
    ) -> tuple[list[Project], int]:
        projects = list(self.db.scalars(select(Project).order_by(Project.id)))
        same_workspace = [
            project
            for project in projects
            if self.project_authority(project) == (anchor.tenant_id, anchor.workspace_id)
        ]
        if PLATFORM_SCOPE_ROLES.intersection(context.user.roles):
            return same_workspace, 0

        memberships = {
            row.project_id
            for row in self.db.scalars(
                select(ProjectMember).where(
                    ProjectMember.user_id == context.user.id,
                    ProjectMember.status == "active",
                )
            )
        }
        visible = [project for project in same_workspace if project.id in memberships]
        return visible, len(same_workspace) - len(visible)

    def authorized_project_ids(self, context: ServiceContext) -> set[UUID]:
        if PLATFORM_SCOPE_ROLES.intersection(context.user.roles):
            return set(self.db.scalars(select(Project.id)))
        return {
            project_id
            for project_id in self.db.scalars(
                select(ProjectMember.project_id).where(
                    ProjectMember.user_id == context.user.id,
                    ProjectMember.status == "active",
                )
            )
        }

    @staticmethod
    def project_authority(project: Project) -> tuple[str, str]:
        gate_context = project.metadata_json.get("gateContext")
        gate_context = gate_context if isinstance(gate_context, dict) else {}
        tenant_id = str(gate_context.get("tenantId") or "local-tenant").strip()
        workspace_id = str(gate_context.get("workspaceId") or f"project-{project.id}").strip()
        if (
            not tenant_id
            or not workspace_id
            or len(tenant_id) > 128
            or len(workspace_id) > 128
        ):
            raise ScopeAuthorizationError(
                "SCOPE_CONTEXT_INVALID",
                status_code=409,
                field="gateContext",
            )
        return tenant_id, workspace_id

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request

from agentic_qa.api.deps import capability_dependency, get_db
from agentic_qa.api.responses import success_response
from agentic_qa.api.routers.project_settings_common import (
    project_settings_context,
    raise_project_settings_error,
)
from agentic_qa.schemas.project_settings import (
    EnvironmentRequest,
    EnvironmentUpdateRequest,
    ProjectMemberRequest,
    ProjectMemberUpdateRequest,
    ProjectRequest,
    ProjectUpdateRequest,
)
from agentic_qa.services.project_settings_service import ProjectSettingsService


router = APIRouter(tags=["project-settings"])


@router.post("/projects")
def create_project(
    request: Request,
    payload: ProjectRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("project.settings.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.create_project(
            payload,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "created")


@router.put("/projects/{project_id}")
def update_project(
    request: Request,
    project_id: UUID,
    payload: ProjectUpdateRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("project.settings.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.update_project(
            project_id,
            payload,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "updated")


@router.delete("/projects/{project_id}")
def archive_project(
    request: Request,
    project_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("project.settings.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.archive_project(
            project_id,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "archived")


@router.post("/projects/{project_id}/environments")
def create_environment(
    request: Request,
    project_id: UUID,
    payload: EnvironmentRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("environment.settings.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.create_environment(
            project_id,
            payload,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "created")


@router.put("/environments/{environment_id}")
def update_environment(
    request: Request,
    environment_id: UUID,
    payload: EnvironmentUpdateRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("environment.settings.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.update_environment(
            environment_id,
            payload,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "updated")


@router.delete("/environments/{environment_id}")
def archive_environment(
    request: Request,
    environment_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("environment.settings.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.archive_environment(
            environment_id,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "archived")


@router.post("/projects/{project_id}/members")
def create_project_member(
    request: Request,
    project_id: UUID,
    payload: ProjectMemberRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("project.members.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.create_member(
            project_id,
            payload,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "created")


@router.put("/project-members/{member_id}")
def update_project_member(
    request: Request,
    member_id: UUID,
    payload: ProjectMemberUpdateRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("project.members.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.update_member(
            member_id,
            payload,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "updated")


@router.delete("/project-members/{member_id}")
def deactivate_project_member(
    request: Request,
    member_id: UUID,
    db=Depends(get_db),
    user=Depends(capability_dependency("project.members.manage")),
) -> dict[str, object]:
    service = ProjectSettingsService(db)
    try:
        data = service.deactivate_member(
            member_id,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data, "deactivated")


__all__ = ["router"]

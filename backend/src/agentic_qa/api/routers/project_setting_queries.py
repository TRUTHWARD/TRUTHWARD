# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from agentic_qa.api.deps import get_current_user, get_db
from agentic_qa.api.responses import success_response
from agentic_qa.api.routers.project_settings_common import (
    project_settings_context,
    raise_project_settings_error,
)
from agentic_qa.services.project_settings_query_service import ProjectSettingsQueryService


router = APIRouter(tags=["project-settings"])


@router.get("/projects")
def list_projects(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ProjectSettingsQueryService(db)
    try:
        data = service.list_projects(
            page,
            page_size,
            project_settings_context(request, user),
            status=status_filter,
        )
    except ValueError as exc:
        raise_project_settings_error(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}")
def get_project(
    request: Request,
    project_id: UUID,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ProjectSettingsQueryService(db)
    try:
        data = service.get_project(project_id, project_settings_context(request, user))
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data)


@router.get("/environments")
def list_environments(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    project_id: UUID | None = Query(None, alias="projectId"),
    status_filter: str | None = Query(None, alias="status"),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ProjectSettingsQueryService(db)
    try:
        data = service.list_environments(
            page,
            page_size,
            context=project_settings_context(request, user),
            project_id=project_id,
            status=status_filter,
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}/environments")
def list_project_environments(
    request: Request,
    project_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ProjectSettingsQueryService(db)
    try:
        data = service.list_environments(
            page,
            page_size,
            context=project_settings_context(request, user),
            project_id=project_id,
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data)


@router.get("/environments/{environment_id}")
def get_environment(
    request: Request,
    environment_id: UUID,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ProjectSettingsQueryService(db)
    try:
        data = service.get_environment(
            environment_id,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data)


@router.get("/projects/{project_id}/members")
def list_project_members(
    request: Request,
    project_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ProjectSettingsQueryService(db)
    try:
        data = service.list_members(
            project_id,
            page,
            page_size,
            project_settings_context(request, user),
        )
    except Exception as exc:
        raise_project_settings_error(exc)
    return success_response(request, data)


__all__ = ["router"]

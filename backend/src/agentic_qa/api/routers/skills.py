# SPDX-License-Identifier: Apache-2.0
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from agentic_qa.api.deps import any_capability_dependency, capability_dependency, get_current_user, get_db, get_parent_span_id, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.skills import CapabilityBindingRequest, CapabilityBindingUpdateRequest, CommunityBindingLifecycleRequest, ConnectorBindingRequest, ConnectorBindingUpdateRequest, SkillInvocationRequest
from agentic_qa.services.common import IdempotencyConflictError, ServiceContext
from agentic_qa.services.community_skill_catalog_service import CommunitySkillCatalogService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService
from agentic_qa.services.skill_service import SkillService


router = APIRouter(tags=["skills"])


@router.get("/community/skills/local-manifests")
def list_community_local_skill_manifests(
    request: Request,
    db=Depends(get_db),
    user=Depends(capability_dependency("community_skills.manage")),
) -> dict[str, object]:
    return success_response(request, CommunitySkillCatalogService(db).list_manifests())


@router.post("/community/skills/local-manifests/{file_name}/register")
def register_community_local_skill_manifest(
    request: Request,
    file_name: str,
    db=Depends(get_db),
    user=Depends(capability_dependency("community_skills.manage")),
) -> dict[str, object]:
    try:
        data = CommunitySkillCatalogService(db).register(
            file_name,
            ServiceContext(
                user=user,
                request_id=get_request_id(request),
                trace_id=get_trace_id(request),
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data, "registered")


@router.post("/community/capability-bindings/{binding_id}/lifecycle")
def community_binding_lifecycle(
    request: Request,
    binding_id: UUID,
    payload: CommunityBindingLifecycleRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("community_skills.manage")),
) -> dict[str, object]:
    try:
        data = SkillService(db).community_binding_lifecycle(
            binding_id, payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except IdempotencyConflictError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ScopeAuthorizationError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail="scope access denied") from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/skills")
def list_skills(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    db=Depends(get_db),
    user=Depends(capability_dependency("skills.catalog.read")),
) -> dict[str, object]:
    service = SkillService(db)
    data = service.list_skills(page, page_size)
    return success_response(request, data)


@router.get("/skills/{skill_id}")
def get_skill(request: Request, skill_id: str, db=Depends(get_db), user=Depends(capability_dependency("skills.catalog.read"))) -> dict[str, object]:
    service = SkillService(db)
    try:
        data = service.get_skill(skill_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/skill-invocations")
def list_skill_invocations(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    skill_id: str | None = Query(None, alias="skillId"),
    execution_id: str | None = Query(None, alias="executionId"),
    include_snapshots: bool = Query(False, alias="includeSnapshots"),
    db=Depends(get_db),
    user=Depends(capability_dependency("skill_invocations.read")),
) -> dict[str, object]:
    service = SkillService(db)
    if include_snapshots and "capability_bindings.admin" not in set(user.capabilities):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "errorCode": "CAPABILITY_REQUIRED",
                "capability": "capability_bindings.admin",
                "message": "raw Skill Invocation snapshots require elevated audit/admin capability",
            },
        )
    data = service.list_invocations(
        page, page_size, skill_id=skill_id, execution_id=execution_id, include_snapshots=include_snapshots,
        context=ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
    )
    return success_response(request, data)


@router.post("/skill-invocations")
def create_skill_invocation(
    request: Request,
    payload: SkillInvocationRequest,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "errorCode": "SKILL_INVOCATION_DIRECT_EXECUTION_DISABLED",
            "message": "Skill Invocation creation is Service-owned and must be triggered by a business workflow.",
        },
    )


@router.get("/skill-invocations/{invocation_id}")
def get_skill_invocation(
    request: Request,
    invocation_id: UUID,
    include_snapshots: bool = Query(False, alias="includeSnapshots"),
    db=Depends(get_db),
    user=Depends(capability_dependency("skill_invocations.read")),
) -> dict[str, object]:
    service = SkillService(db)
    if include_snapshots and "capability_bindings.admin" not in set(user.capabilities):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "errorCode": "CAPABILITY_REQUIRED",
                "capability": "capability_bindings.admin",
                "message": "raw Skill Invocation snapshots require elevated audit/admin capability",
            },
        )
    try:
        data = service.get_invocation(
            invocation_id, include_snapshots=include_snapshots,
            context=ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/skill-runs")
def list_skill_runs(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    skill_id: str | None = Query(None, alias="skillId"),
    execution_id: str | None = Query(None, alias="executionId"),
    db=Depends(get_db),
    user=Depends(capability_dependency("skill_invocations.read")),
) -> dict[str, object]:
    service = SkillService(db)
    data = service.list_invocations(
        page, page_size, skill_id=skill_id, execution_id=execution_id,
        context=ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
    )
    data["view"] = "skill-runs"
    data["semantics"] = "ui_query_view"
    return success_response(request, data)


@router.get("/workflow-capability-graph")
def workflow_capability_graph(
    request: Request,
    workspace_id: str | None = Query(None, alias="workspaceId"),
    project_id: str | None = Query(None, alias="projectId"),
    environment: str | None = Query(None),
    stage: str | None = Query(None),
    domain: str | None = Query(None),
    db=Depends(get_db),
    user=Depends(capability_dependency("capability_bindings.read")),
) -> dict[str, object]:
    service = SkillService(db)
    scope_payload: dict[str, object] = {
        "workspaceId": workspace_id,
        "projectId": project_id,
        "environment": environment,
        "stage": stage,
        "domain": domain,
    }
    if user.edition == "community" and project_id:
        try:
            scope = ScopeAuthorizationService(db).resolve_project(
                UUID(project_id),
                ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
                environment_id=UUID(environment) if environment else None,
            )
        except (ValueError, ScopeAuthorizationError) as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scope not found") from exc
        scope_payload.update(scope.projection())
    data = service.workflow_capability_graph(
        scope_payload,
        edition=user.edition,
    )
    return success_response(request, data)


@router.get("/capability-bindings")
def list_capability_bindings(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    extension_point_id: str | None = Query(None, alias="extensionPointId"),
    binding_status: str | None = Query(None, alias="status"),
    db=Depends(get_db),
    user=Depends(capability_dependency("capability_bindings.read")),
) -> dict[str, object]:
    data = SkillService(db).list_capability_bindings(
        page,
        page_size,
        extension_point_id=extension_point_id,
        status=binding_status,
        context=ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
    )
    return success_response(request, data)


@router.post("/capability-bindings")
def create_capability_binding(
    request: Request,
    payload: CapabilityBindingRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("capability_bindings.write")),
) -> dict[str, object]:
    try:
        data = SkillService(db).create_capability_binding(
            payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request), parent_span_id=get_parent_span_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data, "created")


@router.patch("/capability-bindings/{binding_id}")
def update_capability_binding(
    request: Request,
    binding_id: UUID,
    payload: CapabilityBindingUpdateRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("capability_bindings.write")),
) -> dict[str, object]:
    try:
        data = SkillService(db).update_capability_binding(
            binding_id,
            payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/connector-bindings")
def list_connector_bindings(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, alias="page_size", ge=1, le=100),
    connector_name: str | None = Query(None, alias="connectorName"),
    project_id: str | None = Query(None, alias="projectId"),
    environment_id: str | None = Query(None, alias="environmentId"),
    status_filter: str | None = Query(None, alias="status"),
    db=Depends(get_db),
    user=Depends(any_capability_dependency("connector_bindings.manage", "capability_bindings.admin")),
) -> dict[str, object]:
    service = SkillService(db)
    try:
        data = service.list_connector_bindings(
            page,
            page_size,
            connector_name=connector_name,
            project_id=project_id,
            environment_id=environment_id,
            status=status_filter,
            context=ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/connector-bindings")
def create_connector_binding(
    request: Request,
    payload: ConnectorBindingRequest,
    db=Depends(get_db),
    user=Depends(any_capability_dependency("connector_bindings.manage", "capability_bindings.admin")),
) -> dict[str, object]:
    service = SkillService(db)
    try:
        data = service.create_connector_binding(
            payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data, "created")


@router.get("/connector-bindings/{binding_id}")
def get_connector_binding(
    request: Request,
    binding_id: UUID,
    db=Depends(get_db),
    user=Depends(any_capability_dependency("connector_bindings.manage", "capability_bindings.admin")),
) -> dict[str, object]:
    service = SkillService(db)
    try:
        data = service.get_connector_binding(
            binding_id,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.patch("/connector-bindings/{binding_id}")
def update_connector_binding(
    request: Request,
    binding_id: UUID,
    payload: ConnectorBindingUpdateRequest,
    db=Depends(get_db),
    user=Depends(any_capability_dependency("connector_bindings.manage", "capability_bindings.admin")),
) -> dict[str, object]:
    service = SkillService(db)
    try:
        data = service.update_connector_binding(
            binding_id,
            payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request), parent_span_id=get_parent_span_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data, "updated")


@router.delete("/connector-bindings/{binding_id}")
def archive_connector_binding(
    request: Request,
    binding_id: UUID,
    db=Depends(get_db),
    user=Depends(any_capability_dependency("connector_bindings.manage", "capability_bindings.admin")),
) -> dict[str, object]:
    service = SkillService(db)
    try:
        data = service.archive_connector_binding(
            binding_id,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request), parent_span_id=get_parent_span_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data, "archived")

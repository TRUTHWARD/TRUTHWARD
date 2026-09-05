# SPDX-License-Identifier: Apache-2.0
from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, status

from agentic_qa.api.deps import CurrentUser, capability_dependency, get_current_user, get_db, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.auth import (
    CommunityBootstrapRequest,
    CommunityBootstrapStatus,
    CommunityLoginRequest,
    CommunityTokenResponse,
    CommunityUserCreateRequest,
    CurrentUserResponse,
)
from agentic_qa.services.auth_service import CommunityAuthenticationError, CommunityAuthService


router = APIRouter(tags=["auth"])


def _current_user_response(user: CurrentUser) -> CurrentUserResponse:
    return CurrentUserResponse.model_validate(
        {
            "id": str(user.id),
            "name": user.name,
            "email": user.email,
            "roles": user.roles,
            "status": "active",
            "edition": user.edition,
            "capabilities": user.capabilities,
            "deploymentProfile": user.deployment_profile,
            "authorizationRevision": user.authorization_revision,
            "editionProjection": user.edition_projection,
        }
    )


def _raise_auth_error(exc: CommunityAuthenticationError) -> NoReturn:
    code = str(exc)
    status_code = {
        "COMMUNITY_LOGIN_INVALID": status.HTTP_401_UNAUTHORIZED,
        "COMMUNITY_BOOTSTRAP_ALREADY_COMPLETED": status.HTTP_409_CONFLICT,
        "COMMUNITY_IDENTITY_ALREADY_EXISTS": status.HTTP_409_CONFLICT,
        "COMMUNITY_AUTH_REQUIRES_OSS_PROFILE": status.HTTP_404_NOT_FOUND,
        "COMMUNITY_TOKEN_NOT_FOUND": status.HTTP_401_UNAUTHORIZED,
        "COMMUNITY_USER_NOT_FOUND": status.HTTP_404_NOT_FOUND,
    }.get(code, status.HTTP_400_BAD_REQUEST)
    raise HTTPException(status_code=status_code, detail={"code": code, "message": "Community authentication request was rejected"}) from exc


@router.get("/auth/bootstrap-status")
def community_bootstrap_status(request: Request, db=Depends(get_db)) -> dict[str, object]:
    data = CommunityBootstrapStatus.model_validate(CommunityAuthService(db).bootstrap_status())
    return success_response(request, data.model_dump(mode="json"))


@router.post("/auth/bootstrap")
def community_bootstrap(
    request: Request,
    payload: CommunityBootstrapRequest,
    db=Depends(get_db),
) -> dict[str, object]:
    try:
        token, expires_at, _ = CommunityAuthService(db).bootstrap(
            payload,
            request_id=get_request_id(request),
            trace_id=get_trace_id(request),
        )
    except CommunityAuthenticationError as exc:
        _raise_auth_error(exc)
    user = CommunityAuthService(db).resolve_current_user(token)
    data = CommunityTokenResponse(
        token=token,
        expiresAt=expires_at.isoformat(),
        user=_current_user_response(user),
    )
    return success_response(request, data.model_dump(mode="json"), "created")


@router.post("/auth/login")
def community_login(
    request: Request,
    payload: CommunityLoginRequest,
    db=Depends(get_db),
) -> dict[str, object]:
    try:
        token, expires_at, _ = CommunityAuthService(db).login(
            payload,
            request_id=get_request_id(request),
            trace_id=get_trace_id(request),
        )
    except CommunityAuthenticationError as exc:
        _raise_auth_error(exc)
    user = CommunityAuthService(db).resolve_current_user(token)
    data = CommunityTokenResponse(
        token=token,
        expiresAt=expires_at.isoformat(),
        user=_current_user_response(user),
    )
    return success_response(request, data.model_dump(mode="json"))


@router.post("/auth/logout")
def community_logout(
    request: Request,
    db=Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    if user.token_id is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"code": "COMMUNITY_SESSION_REQUIRED"})
    try:
        CommunityAuthService(db).logout(
            token_id=user.token_id,
            user_id=user.id,
            request_id=get_request_id(request),
            trace_id=get_trace_id(request),
        )
    except CommunityAuthenticationError as exc:
        _raise_auth_error(exc)
    return success_response(request, {"revoked": True})


@router.post("/auth/tokens/revoke-all")
def community_revoke_all_tokens(
    request: Request,
    db=Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    try:
        CommunityAuthService(db).revoke_all(
            user_id=user.id,
            request_id=get_request_id(request),
            trace_id=get_trace_id(request),
        )
    except CommunityAuthenticationError as exc:
        _raise_auth_error(exc)
    return success_response(request, {"revoked": True, "scope": "all"})


@router.get("/community/users")
def list_community_users(
    request: Request,
    db=Depends(get_db),
    user: CurrentUser = Depends(capability_dependency("project.members.manage")),
) -> dict[str, object]:
    return success_response(request, {"items": CommunityAuthService(db).list_users()})


@router.post("/community/users")
def create_community_user(
    request: Request,
    payload: CommunityUserCreateRequest,
    db=Depends(get_db),
    user: CurrentUser = Depends(capability_dependency("project.members.manage")),
) -> dict[str, object]:
    try:
        data = CommunityAuthService(db).create_user(
            payload,
            actor_id=user.id,
            request_id=get_request_id(request),
            trace_id=get_trace_id(request),
        )
    except CommunityAuthenticationError as exc:
        _raise_auth_error(exc)
    return success_response(request, data, "created")


@router.get("/auth/me")
def get_me(request: Request, user: CurrentUser = Depends(get_current_user)) -> dict[str, object]:
    data = _current_user_response(user)
    return success_response(
        request,
        data.model_dump(),
    )

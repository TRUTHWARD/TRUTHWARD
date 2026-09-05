# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from uuid import UUID, uuid5, NAMESPACE_DNS

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import UserRole, UserStatus
from agentic_qa.domain.models import AuthToken, User
from agentic_qa.infra.settings import get_settings
from agentic_qa.services.capability_service import (
    COMMUNITY_CAPABILITIES,
    CapabilityService,
    EDITION_BASIC,
    EDITION_COMMUNITY,
    EDITION_ENTERPRISE,
)


DEMO_ADMIN_ID = uuid5(NAMESPACE_DNS, "agentic-qa-admin")
DEMO_USER_ID = uuid5(NAMESPACE_DNS, "agentic-qa-user")


@dataclass(slots=True)
class CurrentUser:
    id: UUID
    name: str
    email: str
    roles: list[str]
    edition: str = EDITION_BASIC
    capabilities: list[str] = field(default_factory=list)
    deployment_profile: str = "full"
    authorization_revision: str = ""
    edition_projection: dict[str, object] = field(default_factory=dict)
    token_id: UUID | None = None


def resolve_user_from_token(token: str, db: Session | None = None) -> CurrentUser:
    settings = get_settings()
    if db is not None:
        token_row = db.scalar(
            select(AuthToken).where(
                AuthToken.token_hash == hashlib.sha256(token.encode("utf-8")).hexdigest()
            )
        )
        if token_row is not None:
            expires_at = token_row.expires_at
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            user = db.get(User, token_row.user_id)
            invalid = (
                token_row.revoked_at is not None
                or (expires_at is not None and expires_at <= datetime.now(timezone.utc))
                or user is None
                or user.status != UserStatus.ACTIVE
                or (settings.deployment_profile == "oss" and user.edition != EDITION_COMMUNITY)
            )
            if invalid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="invalid bearer token",
                )
            assert user is not None
            ceiling = COMMUNITY_CAPABILITIES if settings.deployment_profile == "oss" else None
            edition, capabilities, projection = CapabilityService(db).effective_access_projection_for_user(
                user.id,
                user.edition,
                edition_override=EDITION_COMMUNITY if settings.deployment_profile == "oss" else None,
                capability_ceiling=ceiling,
            )
            return CurrentUser(
                id=user.id,
                name=user.display_name or user.name,
                email=user.email,
                roles=[str(role) for role in (user.roles or [])],
                edition=edition,
                capabilities=capabilities,
                deployment_profile=settings.deployment_profile,
                authorization_revision=str(projection["authorizationRevision"]),
                edition_projection=projection,
                token_id=token_row.id,
            )
    if settings.deployment_profile == "oss" and token in {
        settings.demo_admin_token,
        settings.demo_user_token,
    }:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid bearer token",
        )
    if token == settings.demo_admin_token:
        edition, capabilities, projection = CapabilityService(db).effective_access_projection_for_user(DEMO_ADMIN_ID, EDITION_ENTERPRISE)
        return CurrentUser(
            id=DEMO_ADMIN_ID,
            name="admin",
            email="admin@example.com",
            roles=[UserRole.ADMIN.value],
            edition=edition,
            capabilities=capabilities,
            deployment_profile=settings.deployment_profile,
            authorization_revision=str(projection["authorizationRevision"]),
            edition_projection=projection,
        )
    if token == settings.demo_user_token:
        edition, capabilities, projection = CapabilityService(db).effective_access_projection_for_user(
            DEMO_USER_ID,
            EDITION_BASIC,
        )
        return CurrentUser(
            id=DEMO_USER_ID,
            name="user",
            email="user@example.com",
            roles=[UserRole.USER.value],
            edition=edition,
            capabilities=capabilities,
            deployment_profile=settings.deployment_profile,
            authorization_revision=str(projection["authorizationRevision"]),
            edition_projection=projection,
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid bearer token",
    )


def require_roles(user: CurrentUser, roles: set[str]) -> CurrentUser:
    if not roles.intersection(set(user.roles)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="insufficient permissions",
        )
    return user

# SPDX-License-Identifier: Apache-2.0
from typing import Literal

from pydantic import BaseModel, Field

from agentic_qa.schemas.governance import EditionProjection


class CurrentUserResponse(BaseModel):
    id: str
    name: str
    email: str
    roles: list[str]
    status: str = "active"
    edition: Literal["basic", "community", "pro", "enterprise"]
    capabilities: list[str]
    deploymentProfile: Literal["full", "oss"] = "full"
    authorizationRevision: str
    editionProjection: EditionProjection


class CommunityBootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9._-]+$")
    email: str = Field(min_length=3, max_length=255)
    displayName: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=256)


class CommunityLoginRequest(BaseModel):
    identity: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=256)
    tokenName: str = Field(default="community-web", min_length=1, max_length=100)


class CommunityUserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9._-]+$")
    email: str = Field(min_length=3, max_length=255)
    displayName: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=256)


class CommunityBootstrapStatus(BaseModel):
    deploymentProfile: Literal["full", "oss"]
    bootstrapRequired: bool
    authenticationMode: Literal["demo", "community_local"]


class CommunityTokenResponse(BaseModel):
    token: str
    tokenType: Literal["bearer"] = "bearer"
    expiresAt: str
    user: CurrentUserResponse

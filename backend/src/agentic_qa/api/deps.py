# SPDX-License-Identifier: Apache-2.0
from collections.abc import Callable
import re
from uuid import UUID, uuid4

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from agentic_qa.db.session import get_db_session
from agentic_qa.infra.trace import set_current_parent_span_id
from agentic_qa.infra.security import CurrentUser, require_roles, resolve_user_from_token
from agentic_qa.services.capability_service import require_capability


bearer_scheme = HTTPBearer(auto_error=False)
CANONICAL_BEARER_PATTERN = re.compile(
    rb"(?i:Bearer) [A-Za-z0-9._~+/=-]+"
)


def get_request_id(request: Request) -> str:
    return request.state.request_id


def get_trace_id(request: Request) -> str:
    return request.state.trace_id


def get_parent_span_id(request: Request) -> str | None:
    return request.state.parent_span_id


def get_db() -> Session:
    yield from get_db_session()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> CurrentUser:
    authorization_headers = [
        value
        for name, value in request.scope.get("headers", [])
        if name.lower() == b"authorization"
    ]
    if (
        len(authorization_headers) != 1
        or CANONICAL_BEARER_PATTERN.fullmatch(authorization_headers[0]) is None
        or credentials is None
        or not credentials.credentials
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or malformed bearer token",
        )
    return resolve_user_from_token(credentials.credentials, db)


def role_dependency(*roles: str) -> Callable[[CurrentUser], CurrentUser]:
    def dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        return require_roles(user, set(roles))

    return dependency


def capability_dependency(capability: str) -> Callable[[CurrentUser], CurrentUser]:
    def dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        require_capability(user.capabilities, capability)
        return user

    return dependency


def any_capability_dependency(*capabilities: str) -> Callable[[CurrentUser], CurrentUser]:
    def dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not set(capabilities).intersection(user.capabilities):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "CAPABILITY_REQUIRED",
                    "errorCode": "CAPABILITY_REQUIRED",
                    "capability": capabilities[0],
                    "capabilities": list(capabilities),
                    "message": "current user edition does not grant any accepted capability",
                },
            )
        return user

    return dependency


def initialize_request_context(
    request: Request,
    x_request_id: str | None = Header(default=None),
    x_trace_id: str | None = Header(default=None),
    x_parent_span_id: str | None = Header(default=None),
) -> None:
    request.state.request_id = x_request_id or f"req_{uuid4().hex}"
    request.state.trace_id = _normalize_trace_id(x_trace_id)
    request.state.parent_span_id = _normalize_optional_uuid(x_parent_span_id)
    set_current_parent_span_id(request.state.parent_span_id)


def _normalize_trace_id(trace_id: str | None) -> str:
    """Guarantee a UUID trace id so downstream tracing stays type-safe."""

    if trace_id is None:
        return str(uuid4())
    try:
        return str(UUID(trace_id))
    except ValueError:
        return str(uuid4())


def _normalize_optional_uuid(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None

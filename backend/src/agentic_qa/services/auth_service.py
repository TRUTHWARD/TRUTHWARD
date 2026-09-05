# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from uuid import UUID, uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import UserRole, UserStatus
from agentic_qa.domain.models import AuthToken, User
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.security import CurrentUser, resolve_user_from_token
from agentic_qa.infra.settings import get_settings
from agentic_qa.schemas.auth import CommunityBootstrapRequest, CommunityLoginRequest, CommunityUserCreateRequest
from agentic_qa.services.capability_service import EDITION_COMMUNITY
from agentic_qa.services.common import acquire_transaction_advisory_lock


class CommunityAuthenticationError(ValueError):
    pass


class CommunityAuthService:
    """Local self-hosted authentication for the OSS Community profile.

    The service stores only scrypt password verifiers and SHA-256 token hashes.
    Demo identities remain a separate full-profile development mechanism.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()

    def bootstrap_status(self) -> dict[str, object]:
        if self.settings.deployment_profile != "oss":
            return {
                "deploymentProfile": "full",
                "bootstrapRequired": False,
                "authenticationMode": "demo",
            }
        return {
            "deploymentProfile": "oss",
            "bootstrapRequired": not self._community_user_exists(),
            "authenticationMode": "community_local",
        }

    def resolve_current_user(self, token: str) -> CurrentUser:
        """Resolve a newly issued token inside the Service boundary."""
        return resolve_user_from_token(token, self.db)

    def bootstrap(
        self,
        payload: CommunityBootstrapRequest,
        *,
        request_id: str,
        trace_id: str,
    ) -> tuple[str, datetime, UUID]:
        self._require_oss_profile()
        acquire_transaction_advisory_lock(self.db, "community-bootstrap", "singleton")
        if self._community_user_exists():
            raise CommunityAuthenticationError("COMMUNITY_BOOTSTRAP_ALREADY_COMPLETED")
        self._require_unique_identity(payload.username, payload.email)
        user = User(
            id=uuid4(),
            name=payload.displayName.strip(),
            username=payload.username.strip().lower(),
            email=payload.email.strip().lower(),
            display_name=payload.displayName.strip(),
            password_hash=self.hash_password(payload.password),
            roles=[UserRole.ADMIN.value],
            edition=EDITION_COMMUNITY,
            status=UserStatus.ACTIVE,
            token_version=1,
            last_login_at=datetime.now(timezone.utc),
        )
        self.db.add(user)
        self.db.flush()
        token, expires_at, _ = self._issue_token(user, "community-bootstrap")
        write_audit_log(
            self.db,
            str(user.id),
            "community.bootstrap",
            "user",
            str(user.id),
            request_id,
            trace_id,
            details={"edition": EDITION_COMMUNITY, "roles": [UserRole.ADMIN.value]},
        )
        self.db.commit()
        return token, expires_at, user.id

    def login(
        self,
        payload: CommunityLoginRequest,
        *,
        request_id: str,
        trace_id: str,
    ) -> tuple[str, datetime, UUID]:
        self._require_oss_profile()
        identity = payload.identity.strip().lower()
        user = self.db.scalar(
            select(User).where(
                or_(User.username == identity, User.email == identity),
                User.edition == EDITION_COMMUNITY,
            )
        )
        if (
            user is None
            or user.status != UserStatus.ACTIVE
            or not user.password_hash
            or not self.verify_password(payload.password, user.password_hash)
        ):
            raise CommunityAuthenticationError("COMMUNITY_LOGIN_INVALID")
        user.last_login_at = datetime.now(timezone.utc)
        token, expires_at, _ = self._issue_token(user, payload.tokenName)
        write_audit_log(
            self.db,
            str(user.id),
            "community.login",
            "auth_token",
            str(user.id),
            request_id,
            trace_id,
            details={"tokenName": payload.tokenName},
        )
        self.db.commit()
        return token, expires_at, user.id

    def list_users(self) -> list[dict[str, object]]:
        self._require_oss_profile()
        users = list(
            self.db.scalars(
                select(User)
                .where(User.edition == EDITION_COMMUNITY)
                .order_by(User.created_at.asc())
            )
        )
        return [self._safe_user_projection(user) for user in users]

    def create_user(
        self,
        payload: CommunityUserCreateRequest,
        *,
        actor_id: UUID,
        request_id: str,
        trace_id: str,
    ) -> dict[str, object]:
        self._require_oss_profile()
        self._require_unique_identity(payload.username, payload.email)
        user = User(
            id=uuid4(),
            name=payload.displayName.strip(),
            username=payload.username.strip().lower(),
            email=payload.email.strip().lower(),
            display_name=payload.displayName.strip(),
            password_hash=self.hash_password(payload.password),
            roles=[UserRole.USER.value],
            edition=EDITION_COMMUNITY,
            status=UserStatus.ACTIVE,
            token_version=1,
        )
        self.db.add(user)
        self.db.flush()
        write_audit_log(
            self.db,
            str(actor_id),
            "community.user.create",
            "user",
            str(user.id),
            request_id,
            trace_id,
            details={"roles": [UserRole.USER.value], "edition": EDITION_COMMUNITY},
        )
        self.db.commit()
        return self._safe_user_projection(user)

    def logout(
        self,
        *,
        token_id: UUID,
        user_id: UUID,
        request_id: str,
        trace_id: str,
    ) -> None:
        token = self.db.get(AuthToken, token_id)
        if token is None or token.user_id != user_id:
            raise CommunityAuthenticationError("COMMUNITY_TOKEN_NOT_FOUND")
        if token.revoked_at is None:
            token.revoked_at = datetime.now(timezone.utc)
        write_audit_log(
            self.db,
            str(user_id),
            "community.logout",
            "auth_token",
            str(token.id),
            request_id,
            trace_id,
        )
        self.db.commit()

    def revoke_all(
        self,
        *,
        user_id: UUID,
        request_id: str,
        trace_id: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        user = self.db.get(User, user_id)
        if user is None:
            raise CommunityAuthenticationError("COMMUNITY_USER_NOT_FOUND")
        user.token_version += 1
        self.db.execute(
            update(AuthToken)
            .where(AuthToken.user_id == user_id, AuthToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        write_audit_log(
            self.db,
            str(user_id),
            "community.tokens.revoke_all",
            "user",
            str(user_id),
            request_id,
            trace_id,
        )
        self.db.commit()

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )
        return "scrypt$16384$8$1$" + base64.urlsafe_b64encode(salt).decode("ascii") + "$" + base64.urlsafe_b64encode(digest).decode("ascii")

    @staticmethod
    def verify_password(password: str, encoded: str) -> bool:
        try:
            algorithm, n_value, r_value, p_value, salt_value, digest_value = encoded.split("$", 5)
            if algorithm != "scrypt":
                return False
            salt = base64.urlsafe_b64decode(salt_value.encode("ascii"))
            expected = base64.urlsafe_b64decode(digest_value.encode("ascii"))
            actual = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=int(n_value),
                r=int(r_value),
                p=int(p_value),
                dklen=len(expected),
            )
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(actual, expected)

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _community_user_exists(self) -> bool:
        return self.db.scalar(select(User.id).where(User.edition == EDITION_COMMUNITY).limit(1)) is not None

    def _require_oss_profile(self) -> None:
        if self.settings.deployment_profile != "oss":
            raise CommunityAuthenticationError("COMMUNITY_AUTH_REQUIRES_OSS_PROFILE")

    def _require_unique_identity(self, username: str, email: str) -> None:
        normalized_username = username.strip().lower()
        normalized_email = email.strip().lower()
        existing = self.db.scalar(
            select(User.id).where(
                or_(User.username == normalized_username, User.email == normalized_email)
            )
        )
        if existing is not None:
            raise CommunityAuthenticationError("COMMUNITY_IDENTITY_ALREADY_EXISTS")

    def _issue_token(self, user: User, token_name: str) -> tuple[str, datetime, UUID]:
        token = "twc_" + secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=self.settings.community_token_ttl_hours)
        row = AuthToken(
            id=uuid4(),
            user_id=user.id,
            token_hash=self.token_hash(token),
            token_name=token_name.strip(),
            expires_at=expires_at,
        )
        self.db.add(row)
        self.db.flush()
        return token, expires_at, row.id

    @staticmethod
    def _safe_user_projection(user: User) -> dict[str, object]:
        return {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "displayName": user.display_name or user.name,
            "roles": [str(role) for role in (user.roles or [])],
            "edition": user.edition,
            "status": user.status.value,
            "createdAt": user.created_at.isoformat(),
        }

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
import base64
import binascii
from datetime import datetime, timezone
from uuid import UUID
from threading import RLock
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, event, func, or_, select
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from agentic_qa.infra.security import CurrentUser


_LOCAL_TRANSACTION_LOCKS_GUARD = RLock()
_LOCAL_TRANSACTION_LOCKS: dict[str, RLock] = {}
_LOCAL_SESSION_LOCKS_KEY = "service_transaction_advisory_locks"


@event.listens_for(Session, "after_transaction_end")
def _release_local_transaction_advisory_locks(session: Session, transaction: Any) -> None:
    """Release process-local test locks when the outer transaction ends."""

    if transaction.parent is not None:
        return
    acquired = session.info.pop(_LOCAL_SESSION_LOCKS_KEY, [])
    for _key, lock in reversed(acquired):
        lock.release()


@dataclass(slots=True)
class ServiceContext:
    user: CurrentUser
    request_id: str
    trace_id: str
    parent_span_id: str | None = None


class IdempotencyConflictError(ValueError):
    """Raised when an idempotency key is reused for a different request."""


class InvalidPaginationCursor(ValueError):
    """Raised when an opaque keyset cursor cannot be safely decoded."""


def canonical_json(payload: object) -> str:
    """Serialize a snapshot with the platform's existing deterministic JSON form."""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def canonical_hash(payload: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def acquire_transaction_advisory_lock(
    db: Session,
    namespace: str,
    scope_key: str,
) -> None:
    """Serialize a service-owned key for the lifetime of the DB transaction.

    PostgreSQL advisory transaction locks cover the important empty-row race
    where ``SELECT ... FOR UPDATE`` cannot lock a record that does not exist.
    SQLite and other local test profiles use a process-local lock with the same
    transaction lifetime. Production cross-process safety remains PostgreSQL's
    advisory lock plus database constraints.
    """

    if db.get_bind().dialect.name != "postgresql":
        key = f"{namespace}:{scope_key}"
        held = db.info.setdefault(_LOCAL_SESSION_LOCKS_KEY, [])
        if any(item[0] == key for item in held):
            return
        with _LOCAL_TRANSACTION_LOCKS_GUARD:
            lock = _LOCAL_TRANSACTION_LOCKS.setdefault(key, RLock())
        lock.acquire()
        held.append((key, lock))
        return
    digest = hashlib.sha256(f"{namespace}:{scope_key}".encode("utf-8")).digest()
    lock_key = int.from_bytes(digest[:8], byteorder="big", signed=True)
    db.execute(select(func.pg_advisory_xact_lock(lock_key)))


@contextmanager
def session_advisory_lock(
    db: Session,
    namespace: str,
    scope_key: str,
) -> Iterator[None]:
    """Hold a PostgreSQL key across service-owned intermediate commits."""

    if db.get_bind().dialect.name != "postgresql":
        yield
        return
    digest = hashlib.sha256(f"{namespace}:{scope_key}".encode("utf-8")).digest()
    lock_key = int.from_bytes(digest[:8], byteorder="big", signed=True)
    # Requirement Intake performs several service-owned commits while building
    # a complete batch snapshot. Keep a dedicated physical connection pinned
    # so a session-level lock cannot leak or migrate through the pool.
    bind = db.get_bind()
    engine = bind.engine if isinstance(bind, Connection) else bind
    with engine.connect() as lock_connection:
        lock_connection.execute(select(func.pg_advisory_lock(lock_key)))
        try:
            yield
        finally:
            lock_connection.execute(select(func.pg_advisory_unlock(lock_key)))


def paginate(items: list[Any], page: int, page_size: int) -> dict[str, Any]:
    start = (page - 1) * page_size
    end = start + page_size
    return paginate_result(items[start:end], len(items), page, page_size)


def paginate_result(items: list[Any], total: int, page: int, page_size: int) -> dict[str, Any]:
    return {
        "items": items,
        "total": total,
        "page": page,
        "pageSize": page_size,
    }


def paginate_query(db: Session, statement: Select[Any], page: int, page_size: int) -> tuple[list[Any], int]:
    offset = (page - 1) * page_size
    total = db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0
    rows = list(db.scalars(statement.offset(offset).limit(page_size)))
    return rows, total


def paginate_keyset_query(
    db: Session,
    statement: Select[Any],
    *,
    created_at_column: Any,
    id_column: Any,
    cursor: str,
    page_size: int,
) -> tuple[list[Any], str | None, bool]:
    """Page a descending ``created_at, id`` order without COUNT or OFFSET."""

    if cursor != "start":
        created_at, row_id = _decode_keyset_cursor(cursor)
        statement = statement.where(
            or_(
                created_at_column < created_at,
                and_(created_at_column == created_at, id_column < row_id),
            )
        )
    rows = list(db.scalars(statement.limit(page_size + 1)))
    has_more = len(rows) > page_size
    page_rows = rows[:page_size]
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = _encode_keyset_cursor(
            getattr(last, created_at_column.key),
            getattr(last, id_column.key),
        )
    return page_rows, next_cursor, has_more


def paginate_cursor_result(
    items: list[Any],
    *,
    page_size: int,
    next_cursor: str | None,
    has_more: bool,
) -> dict[str, Any]:
    return {
        "items": items,
        "total": None,
        "page": None,
        "pageSize": page_size,
        "nextCursor": next_cursor,
        "hasMore": has_more,
        "paginationMode": "keyset",
        "totalIsExact": False,
    }


def _encode_keyset_cursor(created_at: datetime, row_id: object) -> str:
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    payload = canonical_json(
        {
            "createdAt": created_at.isoformat(),
            "id": str(row_id),
            "version": 1,
        }
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_keyset_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        padding = "=" * (-len(cursor) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode((cursor + padding).encode("ascii")).decode("utf-8")
        )
        if not isinstance(payload, dict):
            raise ValueError("cursor payload must be an object")
        if payload.get("version") != 1:
            raise ValueError("unsupported cursor version")
        created_at = datetime.fromisoformat(str(payload["createdAt"]))
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError("cursor timestamp must include timezone")
        row_id = UUID(str(payload["id"]))
        return created_at, row_id
    except (binascii.Error, KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise InvalidPaginationCursor("invalid pagination cursor") from exc

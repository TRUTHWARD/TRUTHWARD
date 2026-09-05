# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from threading import RLock
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from sqlalchemy import event, func, select
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

# SPDX-License-Identifier: Apache-2.0
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from agentic_qa.domain.models import Trace, TraceSpan
from agentic_qa.infra.redaction import redact_sensitive_data, redact_sensitive_text


_current_parent_span_id: ContextVar[str | None] = ContextVar("current_parent_span_id", default=None)


def set_current_parent_span_id(parent_span_id: str | UUID | None) -> None:
    _current_parent_span_id.set(str(parent_span_id) if parent_span_id else None)


def get_current_parent_span_id() -> str | None:
    return _current_parent_span_id.get()


def _ensure_parent_span(db: Session, trace_id: str | UUID, parent_span_id: str | UUID | None) -> UUID | None:
    if parent_span_id is None:
        return None
    normalized_parent_span_id = UUID(str(parent_span_id))
    if db.get(TraceSpan, normalized_parent_span_id) is not None:
        return normalized_parent_span_id
    now = datetime.now(timezone.utc)
    db.add(
        TraceSpan(
            id=normalized_parent_span_id,
            trace_id=UUID(str(trace_id)),
            span_name="external.parent",
            span_type="external",
            service_name="upstream",
            status="linked",
            start_time=now,
            end_time=now,
            duration_ms=0,
            attributes={"source": "trace_propagation"},
        )
    )
    return normalized_parent_span_id


def ensure_trace(db: Session, execution_id: str | UUID | None, root_span_name: str, trace_id: str | UUID) -> Trace:
    normalized_trace_id = UUID(str(trace_id))
    normalized_execution_id = UUID(str(execution_id)) if execution_id else None
    trace = db.get(Trace, normalized_trace_id)
    if trace is None:
        trace = Trace(
            id=normalized_trace_id,
            execution_id=normalized_execution_id,
            root_span_name=root_span_name,
            trace_metadata={},
        )
        db.add(trace)
        db.flush()
    elif trace.execution_id is None and normalized_execution_id is not None:
        trace.execution_id = normalized_execution_id
        db.flush()
    return trace


def record_span(
    db: Session,
    trace_id: str | UUID,
    span_name: str,
    service_name: str,
    status: str = "ok",
    attributes: dict[str, object] | None = None,
    parent_span_id: str | UUID | None = None,
) -> TraceSpan:
    resolved_parent_span_id = parent_span_id or get_current_parent_span_id()
    normalized_parent_span_id = _ensure_parent_span(db, trace_id, resolved_parent_span_id)
    now = datetime.now(timezone.utc)
    span = TraceSpan(
        id=uuid4(),
        trace_id=UUID(str(trace_id)),
        parent_span_id=normalized_parent_span_id,
        span_name=span_name,
        span_type="service",
        service_name=service_name,
        status=status,
        start_time=now,
        end_time=now,
        duration_ms=0,
        attributes=redact_sensitive_data(attributes or {}),
    )
    db.add(span)
    return span


@contextmanager
def traced_operation(
    db: Session,
    trace_id: str | UUID,
    execution_id: str | UUID | None,
    root_span_name: str,
    span_name: str,
    service_name: str,
    attributes: dict[str, object] | None = None,
    parent_span_id: str | UUID | None = None,
):
    # Create the trace/span eagerly so downstream writes in the same
    # transaction can safely attach audit logs and model invocations to it.
    resolved_parent_span_id = parent_span_id or get_current_parent_span_id()
    ensure_trace(db, execution_id=execution_id, root_span_name=root_span_name, trace_id=trace_id)
    normalized_parent_span_id = _ensure_parent_span(db, trace_id, resolved_parent_span_id)
    started = datetime.now(timezone.utc)
    safe_attributes = redact_sensitive_data(attributes or {})
    span = TraceSpan(
        id=uuid4(),
        trace_id=UUID(str(trace_id)),
        parent_span_id=normalized_parent_span_id,
        span_name=span_name,
        span_type="service",
        service_name=service_name,
        status="running",
        start_time=started,
        end_time=None,
        duration_ms=None,
        attributes=safe_attributes,
    )
    db.add(span)
    db.flush()
    try:
        yield span
        span.status = "ok"
    except Exception as exc:
        span.status = "error"
        span.attributes = {
            **safe_attributes,
            "error": redact_sensitive_text(str(exc)),
        }
        raise
    finally:
        finished = datetime.now(timezone.utc)
        span.end_time = finished
        span.duration_ms = int((finished - started).total_seconds() * 1000)

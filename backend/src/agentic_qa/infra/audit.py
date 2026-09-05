# SPDX-License-Identifier: Apache-2.0
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from agentic_qa.domain.models import AuditLog
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.infra.trace import ensure_trace


def write_audit_log(
    db: Session,
    actor_id: str | UUID | None,
    action: str,
    resource_type: str,
    resource_id: str,
    request_id: str,
    trace_id: str | UUID,
    details: dict[str, Any] | None = None,
    execution_id: str | UUID | None = None,
) -> AuditLog:
    normalized_actor_id = UUID(str(actor_id)) if actor_id else None
    normalized_trace_id = UUID(str(trace_id))
    # PostgreSQL enforces the audit_logs.trace_id foreign key immediately, so
    # make sure the trace row exists before the audit record is flushed.
    ensure_trace(
        db,
        execution_id=execution_id,
        root_span_name=action,
        trace_id=normalized_trace_id,
    )
    db.flush()
    audit_log = AuditLog(
        id=uuid4(),
        actor_id=normalized_actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=request_id,
        trace_id=normalized_trace_id,
        details=redact_sensitive_data(details or {}),
    )
    db.add(audit_log)
    return audit_log

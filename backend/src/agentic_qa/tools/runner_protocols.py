# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import json
from typing import Any, Protocol
from uuid import UUID

from agentic_qa.domain.enums import ArtifactType, TestDomain


RUNNER_STATUS_TOOL_STATUS: dict[str, frozenset[str]] = {
    "queued": frozenset({"ok"}),
    "running": frozenset({"ok"}),
    "completed": frozenset({"ok", "findings_detected", "threshold_exceeded"}),
    "failed": frozenset({"tool_error", "infra_error", "timeout", "partial"}),
    "cancelled": frozenset({"cancelled"}),
}
TERMINAL_RUNNER_STATUSES = frozenset({"completed", "failed", "cancelled"})
SAFE_RETRY_TOOL_STATUSES = frozenset({"infra_error", "timeout"})
UNSAFE_RETRY_TOOL_STATUSES = frozenset({"tool_error", "partial", "cancelled"})
MAX_INLINE_EVIDENCE_BYTES = 64 * 1024
MAX_ARTIFACT_REF_BYTES = 4096


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class RunnerArtifactRef:
    artifact_type: ArtifactType
    uri: str
    summary: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RunnerMetricRecord:
    name: str
    value: Decimal
    unit: str | None = None
    threshold_value: Decimal | None = None
    baseline_value: Decimal | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RunnerFindingRecord:
    source: str
    category: str
    severity: str
    title: str
    summary: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    location: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    dedupe_key: str = ""
    raw_ref: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RunnerLogRecord:
    level: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RunnerExecutionRequest:
    task_id: UUID
    execution_id: UUID
    domain: TestDomain
    task_type: str
    runner_id: str
    timeout_seconds: int
    parallelism: int
    config: dict[str, Any]
    envelope: dict[str, Any]
    deadline_at: datetime | None = None


@dataclass(slots=True)
class RunnerExecutionResult:
    task_id: UUID
    execution_id: UUID
    runner_id: str
    domain: TestDomain
    status: str
    tool_status: str
    exit_code: int
    timed_out: bool
    started_at: datetime
    ended_at: datetime
    duration_ms: int
    artifact_refs: list[RunnerArtifactRef] = field(default_factory=list)
    raw_metrics: list[RunnerMetricRecord] = field(default_factory=list)
    raw_findings: list[RunnerFindingRecord] = field(default_factory=list)
    logs: list[RunnerLogRecord] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def runner_retry_safety(tool_status: str) -> str:
    if tool_status in SAFE_RETRY_TOOL_STATUSES:
        return "safe"
    if tool_status in UNSAFE_RETRY_TOOL_STATUSES:
        return "unsafe"
    return "not_applicable"


def validate_runner_execution_result(
    result: RunnerExecutionResult,
    *,
    request: RunnerExecutionRequest | None = None,
    require_terminal: bool = False,
) -> RunnerExecutionResult:
    errors: list[str] = []
    allowed_tool_statuses = RUNNER_STATUS_TOOL_STATUS.get(result.status)
    if allowed_tool_statuses is None:
        errors.append(f"unsupported status={result.status}")
    elif result.tool_status not in allowed_tool_statuses:
        errors.append(f"status={result.status} cannot use toolStatus={result.tool_status}")
    if require_terminal and result.status not in TERMINAL_RUNNER_STATUSES:
        errors.append(f"managed execution requires a terminal status, got {result.status}")
    if result.tool_status == "timeout" and not result.timed_out:
        errors.append("toolStatus=timeout requires timedOut=true")
    if result.timed_out and (result.status != "failed" or result.tool_status != "timeout"):
        errors.append("timedOut=true requires status=failed and toolStatus=timeout")
    if result.status == "failed" and not result.error:
        errors.append("status=failed requires an error classification")
    if result.tool_status == "findings_detected" and not result.raw_findings:
        errors.append("toolStatus=findings_detected requires raw findings")
    if result.tool_status == "threshold_exceeded" and not result.raw_metrics:
        errors.append("toolStatus=threshold_exceeded requires raw metrics")
    if result.tool_status == "partial" and not (
        result.artifact_refs or result.raw_metrics or result.raw_findings or result.logs
    ):
        errors.append("toolStatus=partial requires preserved partial evidence")
    if result.ended_at < result.started_at:
        errors.append("endedAt precedes startedAt")
    if result.duration_ms < 0:
        errors.append("durationMs must be non-negative")

    if request is not None:
        if result.task_id != request.task_id:
            errors.append("taskId does not match the managed request")
        if result.execution_id != request.execution_id:
            errors.append("executionId does not match the managed request")
        if result.runner_id != request.runner_id:
            errors.append("runnerId does not match the managed request")
        if result.domain != request.domain:
            errors.append("domain does not match the managed request")

    for artifact in result.artifact_refs:
        uri = str(artifact.uri or "")
        if not uri:
            errors.append("artifact uri is required")
        elif uri.startswith("data:"):
            errors.append("artifact payloads must be ref-only; data URIs are forbidden")
        elif len(uri.encode("utf-8")) > MAX_ARTIFACT_REF_BYTES:
            errors.append("artifact uri exceeds the ref-only size limit")

    inline_items: list[tuple[str, object]] = [
        *[("log", {"message": item.message, "context": item.context}) for item in result.logs],
        *[
            (
                "metric",
                {
                    "name": item.name,
                    "value": str(item.value),
                    "unit": item.unit,
                    "metadata": item.metadata,
                },
            )
            for item in result.raw_metrics
        ],
        *[
            (
                "finding",
                {
                    "source": item.source,
                    "category": item.category,
                    "severity": item.severity,
                    "title": item.title,
                    "summary": item.summary,
                    "evidence": item.evidence,
                    "location": item.location,
                    "metadata": item.metadata,
                },
            )
            for item in result.raw_findings
        ],
    ]
    for kind, item in inline_items:
        payload_size = len(
            json.dumps(item, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        )
        if payload_size > MAX_INLINE_EVIDENCE_BYTES:
            errors.append(
                f"{kind} payload exceeds {MAX_INLINE_EVIDENCE_BYTES} bytes; persist it externally and return an artifact ref"
            )

    for finding in result.raw_findings:
        missing = [
            name
            for name, value in (
                ("source", finding.source),
                ("category", finding.category),
                ("severity", finding.severity),
                ("title", finding.title),
                ("summary", finding.summary),
                ("dedupeKey", finding.dedupe_key),
                ("rawRef", finding.raw_ref),
            )
            if not value
        ]
        if missing:
            errors.append("raw finding is missing " + ", ".join(missing))
        if not 0.0 <= float(finding.confidence) <= 1.0:
            errors.append("raw finding confidence must be between 0.0 and 1.0")

    if errors:
        raise ValueError("malformed runner output: " + "; ".join(errors))
    return result


class RunnerAdapter(Protocol):
    runner_id: str
    domain: TestDomain
    supports_parallelism: bool
    default_timeout_seconds: int

    def run(self, request: RunnerExecutionRequest) -> RunnerExecutionResult:
        ...

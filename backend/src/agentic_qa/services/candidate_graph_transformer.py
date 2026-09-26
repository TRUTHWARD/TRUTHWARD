# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from agentic_qa.domain.models import (
    Execution,
    ExecutionArtifact,
    ExecutionTask,
    Trace,
    TraceSpan,
    VerificationResult,
    VisualGroundingAttempt,
)
from agentic_qa.schemas.candidate_graph import CandidateAmbiguity, CandidateSourceRef
from agentic_qa.services.common import canonical_hash


_PASS_STATUSES = frozenset({"passed", "pass", "success", "succeeded", "verified", "completed"})
_FAIL_STATUSES = frozenset({"failed", "failure", "error", "blocked", "rejected"})
_COORDINATE_KINDS = frozenset({"coordinate", "coordinates", "screen_coordinate", "bounding_box", "point"})
_SAFE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")


def source_ref(ref_type: str, entity_id: UUID | str, *, available: bool = True, reason: str | None = None) -> dict[str, Any]:
    scheme = {
        "execution": "execution://executions/",
        "trace": "trace://traces/",
        "trace_span": "trace-span://spans/",
        "execution_task": "execution-task://tasks/",
        "visual_attempt": "visual-attempt://attempts/",
        "verification": "verification://results/",
        "tool_call": "tool-call://calls/",
        "connector_call": "connector-call://calls/",
        "artifact": "artifact://artifacts/",
        "evidence": "evidence://entries/",
        "replay": "replay://exports/",
        "audit": "audit://records/",
        "guardrail": "guardrail://events/",
        "model_invocation": "model-invocation://invocations/",
        "candidate_build": "candidate-build://builds/",
    }[ref_type]
    payload: dict[str, Any] = {
        "type": ref_type,
        "ref": f"{scheme}{entity_id}",
        "contentHash": None,
        "available": available,
        "unavailableReason": reason,
    }
    return CandidateSourceRef.model_validate(payload).model_dump(mode="json")


def graph_ref(item: dict[str, Any]) -> dict[str, Any] | None:
    if item["type"] not in {"execution", "trace", "artifact", "evidence", "replay", "audit"}:
        return None
    return {"type": item["type"], "ref": item["ref"], "contentHash": item.get("contentHash")}


def unique_refs(items: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in sorted(items, key=lambda value: (str(value.get("type")), str(value.get("ref")))):
        marker = (str(item.get("type")), str(item.get("ref")))
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
        if limit is not None and len(result) >= limit:
            break
    return result


@dataclass(slots=True)
class ObservedAction:
    action_type: str
    intent_key: str
    semantic_key: str
    node_type: str
    risk_level: str
    confidence: float
    outcome: str
    retry_count: int
    fallback_types: list[str]
    coordinate_click_count: int
    verification_status: str | None
    source_event_refs: list[dict[str, Any]]
    evidence_refs: list[dict[str, Any]]
    ambiguities: list[dict[str, Any]]
    observed_at: datetime
    task_id: UUID | None


@dataclass(slots=True)
class CandidateTransformOutput:
    actions: list[ObservedAction]
    global_ambiguities: list[dict[str, Any]]
    semantic_path_hash: str
    outcome: str
    action_count: int
    verified_action_count: int
    retry_count: int
    coordinate_click_count: int
    fallback_types: list[str]
    observed_at: datetime


class ObservedTraceCandidateTransformer:
    """Pure, bounded interpretation of immutable execution observations.

    It never persists, executes, promotes, chooses a provider, or copies locator,
    screenshot, DOM, coordinate, input value, secretRef, or valueRef payloads.
    """

    def transform(
        self,
        *,
        execution: Execution,
        traces: list[Trace],
        spans: list[TraceSpan],
        tasks: list[ExecutionTask],
        attempts: list[VisualGroundingAttempt],
        verifications: list[VerificationResult],
        artifacts: list[ExecutionArtifact],
        transformer_version: str,
        max_actions: int,
        confidence_floor: float,
    ) -> CandidateTransformOutput:
        global_ambiguities: list[dict[str, Any]] = []
        if not traces:
            global_ambiguities.append(
                self._ambiguity("CANDIDATE_TRACE_MISSING", "warning", "trace_missing", [])
            )
        if any(span.start_time is None for span in spans):
            global_ambiguities.append(
                self._ambiguity(
                    "CANDIDATE_TRACE_ORDER_UNCERTAIN",
                    "warning",
                    "trace_order_uncertain",
                    [source_ref("trace_span", span.id) for span in spans if span.start_time is None][:256],
                )
            )

        task_by_id = {item.id: item for item in tasks}
        verifications_by_attempt: dict[UUID, list[VerificationResult]] = {}
        for verification in verifications:
            if verification.visual_attempt_id is not None:
                verifications_by_attempt.setdefault(verification.visual_attempt_id, []).append(verification)
        artifacts_by_task: dict[UUID | None, list[ExecutionArtifact]] = {}
        for artifact in artifacts:
            artifacts_by_task.setdefault(artifact.task_id, []).append(artifact)

        grouped_attempts: dict[tuple[str, str], list[VisualGroundingAttempt]] = {}
        for attempt in attempts:
            key = (str(attempt.task_id or "execution"), attempt.action_id)
            grouped_attempts.setdefault(key, []).append(attempt)

        raw_actions: list[ObservedAction] = []
        for grouped in grouped_attempts.values():
            ordered = sorted(grouped, key=lambda item: (self._aware(item.created_at), str(item.id)))
            if len(ordered) > 256:
                raise ValueError("CANDIDATE_ACTION_ATTEMPT_LIMIT_EXCEEDED")
            latest = ordered[-1]
            task = task_by_id.get(latest.task_id) if latest.task_id else None
            linked_verifications = sorted(
                [item for attempt in ordered for item in verifications_by_attempt.get(attempt.id, [])],
                key=lambda item: (self._aware(item.created_at), str(item.id)),
            )
            raw_actions.append(
                self._from_attempt_group(
                    execution,
                    task,
                    ordered,
                    linked_verifications,
                    artifacts_by_task.get(latest.task_id, []),
                    transformer_version,
                    confidence_floor,
                )
            )

        attempted_task_ids = {item.task_id for item in attempts if item.task_id is not None}
        for task in tasks:
            if task.id in attempted_task_ids:
                continue
            semantic_action = task.config.get("semanticAction") if isinstance(task.config, dict) else None
            if not isinstance(semantic_action, dict):
                continue
            raw_actions.append(
                self._from_task_action(
                    execution,
                    task,
                    semantic_action,
                    artifacts_by_task.get(task.id, []),
                    transformer_version,
                    confidence_floor,
                )
            )

        raw_actions.sort(key=lambda item: (self._aware(item.observed_at), item.semantic_key, str(item.task_id or "")))
        if not raw_actions:
            raise ValueError("CANDIDATE_AUTHORITATIVE_ACTIONS_NOT_FOUND")
        if len(raw_actions) > max_actions:
            raise ValueError("CANDIDATE_ACTION_LIMIT_EXCEEDED")

        # A repeated contiguous observation is already grouped as retry. A
        # later return to the same semantic action is a loop occurrence and
        # receives a stable suffix so the P11 no-self-loop invariant remains.
        seen_counts: dict[str, int] = {}
        previous_base: str | None = None
        for action in raw_actions:
            base = action.semantic_key
            count = seen_counts.get(base, 0) + 1
            seen_counts[base] = count
            if count > 1 and base != previous_base:
                action.semantic_key = f"{base}.loop{count}"
                action.ambiguities.append(
                    self._ambiguity(
                        "CANDIDATE_LOOP_PATH_OBSERVED",
                        "info",
                        "loop_path_observed",
                        action.source_event_refs,
                    )
                )
            previous_base = base

        timestamps: dict[datetime, list[ObservedAction]] = {}
        for action in raw_actions:
            timestamps.setdefault(self._aware(action.observed_at), []).append(action)
        for same_time in timestamps.values():
            if len(same_time) > 1 and len({item.task_id for item in same_time}) > 1:
                refs = unique_refs([ref for item in same_time for ref in item.source_event_refs], 256)
                global_ambiguities.append(
                    self._ambiguity(
                        "CANDIDATE_PARALLEL_ORDER_AMBIGUOUS",
                        "warning",
                        "parallel_order_ambiguous",
                        refs,
                    )
                )

        semantic_path_hash = canonical_hash(
            [
                {
                    "order": index,
                    "semanticKey": item.semantic_key,
                    "nodeType": item.node_type,
                    "actionType": item.action_type,
                    "intentKey": item.intent_key,
                }
                for index, item in enumerate(raw_actions, start=1)
            ]
        )
        outcomes = {item.outcome for item in raw_actions}
        execution_status = self._enum_value(execution.status)
        if "failure" in outcomes or execution_status in _FAIL_STATUSES:
            outcome = "failure"
        elif execution_status in _PASS_STATUSES and outcomes.issubset({"success", "partial", "unknown"}):
            outcome = "success"
        elif "success" in outcomes:
            outcome = "partial"
        else:
            outcome = "unknown"
        observed_at = max(
            [self._aware(execution.ended_at or execution.updated_at or execution.created_at)]
            + [self._aware(item.observed_at) for item in raw_actions]
        )
        return CandidateTransformOutput(
            actions=raw_actions,
            global_ambiguities=global_ambiguities,
            semantic_path_hash=semantic_path_hash,
            outcome=outcome,
            action_count=len(raw_actions),
            verified_action_count=sum(item.verification_status is not None for item in raw_actions),
            retry_count=sum(item.retry_count for item in raw_actions),
            coordinate_click_count=sum(item.coordinate_click_count for item in raw_actions),
            fallback_types=sorted({value for item in raw_actions for value in item.fallback_types}),
            observed_at=observed_at,
        )

    def _from_attempt_group(
        self,
        execution: Execution,
        task: ExecutionTask | None,
        attempts: list[VisualGroundingAttempt],
        verifications: list[VerificationResult],
        artifacts: list[ExecutionArtifact],
        transformer_version: str,
        confidence_floor: float,
    ) -> ObservedAction:
        latest = attempts[-1]
        semantic_action = latest.semantic_action if isinstance(latest.semantic_action, dict) else {}
        action_type = self._safe_action_type(latest.action_type or semantic_action.get("actionType"))
        intent_key = self._intent_key(semantic_action, latest.action_id)
        node_type = "assertion" if action_type.startswith("assert") else "action"
        refs: list[dict[str, Any]] = [source_ref("execution", execution.id)]
        for item in attempts:
            refs.append(source_ref("visual_attempt", item.id))
            if item.trace_id:
                refs.append(source_ref("trace", item.trace_id))
            if item.trace_span_id:
                refs.append(source_ref("trace_span", item.trace_span_id))
        if task is not None:
            refs.append(source_ref("execution_task", task.id))
        refs.extend(source_ref("verification", item.id) for item in verifications)
        evidence_refs = [self._artifact_ref(item) for item in artifacts]
        ambiguities: list[dict[str, Any]] = []
        schema_version = semantic_action.get("schemaVersion")
        if schema_version != "phase7.v1":
            ambiguities.append(
                self._ambiguity(
                    "CANDIDATE_LEGACY_SEMANTIC_ACTION",
                    "warning",
                    "legacy_semantic_action",
                    refs,
                    {"observedSchemaVersion": str(schema_version or "missing")[:80]},
                )
            )
        verification_status = self._verification_status(latest, verifications)
        if verification_status is None:
            ambiguities.append(
                self._ambiguity(
                    "CANDIDATE_VERIFICATION_MISSING",
                    "warning",
                    "verification_missing",
                    refs,
                )
            )
        fallback_types, coordinate_count = self._fallback_summary(attempts)
        if coordinate_count:
            ambiguities.append(
                self._ambiguity(
                    "CANDIDATE_COORDINATE_FALLBACK_NON_SEMANTIC",
                    "warning",
                    "coordinate_fallback_non_semantic",
                    refs,
                    {"count": coordinate_count},
                )
            )
        retry_count = max(len(attempts) - 1, int(task.retry_count) if task else 0)
        if retry_count:
            ambiguities.append(
                self._ambiguity(
                    "CANDIDATE_RETRY_OBSERVED",
                    "info",
                    "retry_observed",
                    refs,
                    {"count": retry_count},
                )
            )
        outcome = self._outcome(verification_status, latest.status, task.status if task else None)
        confidence_values = [float(item.confidence) for item in attempts if item.confidence is not None]
        confidence = min(confidence_values) if confidence_values else 0.5
        if verification_status is None:
            confidence *= 0.75
        if outcome == "failure":
            confidence *= 0.8
        confidence = max(confidence_floor, min(confidence, 1.0))
        risk = self._enum_value(latest.risk_level)
        return ObservedAction(
            action_type=action_type,
            intent_key=intent_key,
            semantic_key=f"{node_type}.{action_type}.{intent_key}",
            node_type=node_type,
            risk_level=risk if risk in {"low", "medium", "high"} else "medium",
            confidence=confidence,
            outcome=outcome,
            retry_count=retry_count,
            fallback_types=fallback_types,
            coordinate_click_count=coordinate_count,
            verification_status=verification_status,
            source_event_refs=unique_refs(refs),
            evidence_refs=unique_refs(evidence_refs),
            ambiguities=[CandidateAmbiguity.model_validate(item).model_dump(mode="json") for item in ambiguities],
            observed_at=self._aware(latest.created_at),
            task_id=latest.task_id,
        )

    def _from_task_action(
        self,
        execution: Execution,
        task: ExecutionTask,
        semantic_action: dict[str, Any],
        artifacts: list[ExecutionArtifact],
        transformer_version: str,
        confidence_floor: float,
    ) -> ObservedAction:
        action_type = self._safe_action_type(semantic_action.get("actionType") or task.task_type)
        intent_key = self._intent_key(semantic_action, str(task.id))
        node_type = "assertion" if action_type.startswith("assert") else "action"
        refs = [source_ref("execution", execution.id), source_ref("execution_task", task.id)]
        ambiguities = [
            self._ambiguity(
                "CANDIDATE_VISUAL_ATTEMPT_MISSING",
                "warning",
                "visual_attempt_missing",
                refs,
            ),
            self._ambiguity(
                "CANDIDATE_VERIFICATION_MISSING",
                "warning",
                "verification_missing",
                refs,
            ),
        ]
        if semantic_action.get("schemaVersion") != "phase7.v1":
            ambiguities.append(
                self._ambiguity(
                    "CANDIDATE_LEGACY_SEMANTIC_ACTION",
                    "warning",
                    "legacy_semantic_action",
                    refs,
                )
            )
        return ObservedAction(
            action_type=action_type,
            intent_key=intent_key,
            semantic_key=f"{node_type}.{action_type}.{intent_key}",
            node_type=node_type,
            risk_level="medium",
            confidence=max(confidence_floor, 0.35),
            outcome=self._outcome(None, None, task.status),
            retry_count=max(int(task.retry_count), 0),
            fallback_types=[],
            coordinate_click_count=0,
            verification_status=None,
            source_event_refs=refs,
            evidence_refs=unique_refs([self._artifact_ref(item) for item in artifacts]),
            ambiguities=[CandidateAmbiguity.model_validate(item).model_dump(mode="json") for item in ambiguities],
            observed_at=self._aware(task.started_at or task.created_at),
            task_id=task.id,
        )

    @staticmethod
    def _artifact_ref(item: ExecutionArtifact) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        expired = item.expires_at is not None and ObservedTraceCandidateTransformer._aware(item.expires_at) <= now
        unavailable = expired or item.redaction_status in {"purged", "unavailable"}
        reason = "EVIDENCE_RETENTION_EXPIRED" if expired else "EVIDENCE_UNAVAILABLE"
        return source_ref("artifact", item.id, available=not unavailable, reason=reason if unavailable else None)

    @staticmethod
    def _fallback_summary(attempts: list[VisualGroundingAttempt]) -> tuple[list[str], int]:
        fallback_types: set[str] = set()
        coordinate_count = 0
        for item in attempts:
            chosen = item.chosen_locator if isinstance(item.chosen_locator, dict) else {}
            strategy = item.locator_strategy if isinstance(item.locator_strategy, dict) else {}
            chosen_kind = str(chosen.get("kind") or chosen.get("type") or chosen.get("source") or "").lower()
            primary = str(strategy.get("primary") or strategy.get("preferred") or "").lower()
            if chosen_kind and (not primary or chosen_kind != primary):
                fallback_types.add(chosen_kind[:80])
            coordinate_like = chosen_kind in _COORDINATE_KINDS or any(
                key in chosen for key in ("x", "y", "coordinates", "boundingBox", "point")
            )
            if coordinate_like and item.coordinate_click_allowed:
                coordinate_count += 1
                fallback_types.add("coordinate")
        return sorted(fallback_types), coordinate_count

    @staticmethod
    def _verification_status(
        attempt: VisualGroundingAttempt,
        verifications: list[VerificationResult],
    ) -> str | None:
        if verifications:
            statuses = [ObservedTraceCandidateTransformer._enum_value(item.status) for item in verifications]
            if any(item in _FAIL_STATUSES for item in statuses):
                return "failed"
            if all(item in _PASS_STATUSES for item in statuses):
                return "verified"
            return "partial"
        value = str(attempt.verification_status or "").strip().lower()
        return value[:80] or None

    @staticmethod
    def _outcome(verification: str | None, attempt_status: Any, task_status: Any) -> str:
        values = {
            ObservedTraceCandidateTransformer._enum_value(value)
            for value in (verification, attempt_status, task_status)
            if value is not None
        }
        if values.intersection(_FAIL_STATUSES):
            return "failure"
        if verification and verification in _PASS_STATUSES:
            return "success"
        if values.intersection(_PASS_STATUSES):
            return "partial" if verification is None else "success"
        return "unknown"

    @staticmethod
    def _intent_key(semantic_action: dict[str, Any], fallback: str) -> str:
        target = semantic_action.get("semanticTarget")
        target = target if isinstance(target, dict) else {}
        hints = semantic_action.get("targetHints")
        hints = hints if isinstance(hints, dict) else {}
        for value in (
            target.get("intentKey"),
            target.get("targetKey"),
            hints.get("intentKey"),
            semantic_action.get("intentKey"),
        ):
            if isinstance(value, str) and _SAFE_KEY.fullmatch(value):
                return value
        return "observed_" + hashlib.sha256(str(fallback).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _safe_action_type(value: Any) -> str:
        normalized = re.sub(r"[^a-z0-9_]+", "_", str(value or "unknown").strip().lower()).strip("_")
        return (normalized or "unknown")[:80]

    @staticmethod
    def _ambiguity(
        code: str,
        severity: str,
        detail: str,
        refs: list[dict[str, Any]],
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "code": code,
            "severity": severity,
            "entityRef": None,
            "detailKey": f"candidate.ambiguity.{detail}",
            "sourceEventRefs": unique_refs(refs, 256),
            "parameters": parameters or {},
        }

    @staticmethod
    def _enum_value(value: Any) -> str:
        return str(getattr(value, "value", value) or "").strip().lower()

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


__all__ = [
    "CandidateTransformOutput",
    "ObservedAction",
    "ObservedTraceCandidateTransformer",
    "graph_ref",
    "source_ref",
    "unique_refs",
]

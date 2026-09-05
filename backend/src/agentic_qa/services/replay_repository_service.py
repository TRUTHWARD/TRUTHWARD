# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import ApprovalStatus, ApprovalType
from agentic_qa.domain.models import Approval, AuditLog, GuardrailEvent, ReplayGovernancePolicy, ReplayRepositoryEntry, ReplayRepositorySection
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.infra.replay_storage import StorageAdapter, replay_storage_adapter
from agentic_qa.infra.settings import get_settings
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result
from agentic_qa.services.observability_service import ObservabilityService


REPLAY_REPOSITORY_SCHEMA_VERSION = "phase8.replay-repository.v1"
DEFAULT_APPROVAL_MODE = "always"
RISK_RANK = {"low": 1, "medium": 2, "high": 3}
REPLAY_SECTION_NAMES = (
    "manifest-source",
    "summary",
    "timeline",
    "traces",
    "artifacts",
    "raw-findings",
    "findings",
    "gate",
    "guardrails",
    "approvals",
    "skill-invocations",
    "audit-logs",
    "coverage-snapshot",
    "visual-grounding",
    "correction-governance",
)
_FREEZE_LOCKS = tuple(RLock() for _ in range(64))
_PENDING_STORAGE_COMPENSATIONS = "replay_repository_pending_storage_compensations"
_OUTER_COMMIT_PENDING = "replay_repository_outer_commit_pending"
_CANONICAL_HASH_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_REPLAY_ID_PATTERN = re.compile(r"^replay_[a-f0-9]{32}$")
_REPLAY_STORAGE_REF_PATTERN = re.compile(
    r"^(?P<scheme>local://replay-repository|object://(?P<bucket>[A-Za-z0-9_-]+))/"
    r"(?P<replay_id>replay_[a-f0-9]{32})/"
    r"(?P<section>[A-Za-z0-9_-]+)\.(?P<content_hash>[a-f0-9]{64})\.json$"
)


@event.listens_for(Session, "before_commit")
def _mark_outer_replay_storage_commit(session: Session) -> None:
    if (
        session.info.get(_PENDING_STORAGE_COMPENSATIONS)
        and not session.in_nested_transaction()
    ):
        session.info[_OUTER_COMMIT_PENDING] = True


@event.listens_for(Session, "after_commit")
def _finalize_replay_storage_commit(session: Session) -> None:
    if session.info.pop(_OUTER_COMMIT_PENDING, False):
        session.info.pop(_PENDING_STORAGE_COMPENSATIONS, None)


@event.listens_for(Session, "after_rollback")
def _compensate_replay_storage_rollback(session: Session) -> None:
    if session.in_nested_transaction():
        return
    pending = session.info.pop(_PENDING_STORAGE_COMPENSATIONS, [])
    session.info.pop(_OUTER_COMMIT_PENDING, None)
    for storage, storage_refs in reversed(pending):
        for storage_ref in reversed(list(dict.fromkeys(storage_refs))):
            try:
                storage.delete_section(storage_ref)
            except (FileNotFoundError, OSError, ValueError):
                continue


class ReplayRepositoryConflictError(ValueError):
    """Raised when a replay repository mutation is no longer valid."""


class ReplayRepositoryIntegrityError(ReplayRepositoryConflictError):
    """Raised when a frozen Replay Repository package fails integrity checks."""

    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        evidence: dict[str, object] | None = None,
        audit_refs: list[dict[str, object]] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.evidence = evidence or {}
        self.audit_refs = audit_refs or []

    def detail(self) -> dict[str, object]:
        return {
            "code": self.reason_code,
            "message": str(self),
            "auditRefs": self.audit_refs,
        }


class ReplayRepositoryService:
    def __init__(self, db: Session, storage: StorageAdapter | None = None) -> None:
        self.db = db
        self.storage = storage or replay_storage_adapter(get_settings().replay_repository_storage_adapter)

    def list_entries(self, *, page: int, page_size: int) -> dict[str, object]:
        statement = select(ReplayRepositoryEntry).order_by(ReplayRepositoryEntry.created_at.desc())
        rows, total = paginate_query(self.db, statement, page, page_size)
        items: list[dict[str, object]] = []
        for row in rows:
            self._validate_entry_integrity(row, verify_payloads=True)
            items.append(self.serialize_entry(row, include_manifest=False))
        return paginate_result(items, total, page, page_size)

    def get_entry(self, replay_id: str) -> dict[str, object]:
        entry = self._require_entry(replay_id)
        self._validate_entry_integrity(entry, verify_payloads=True)
        return self.serialize_entry(entry, include_manifest=True)

    def get_section(self, replay_id: str, section_name: str) -> dict[str, object]:
        entry = self._require_entry(replay_id)
        if entry.retention_status == "purged":
            raise ReplayRepositoryConflictError("replay repository payload has been purged")
        section = self.db.scalar(
            select(ReplayRepositorySection)
            .where(ReplayRepositorySection.replay_entry_id == entry.id)
            .where(ReplayRepositorySection.section_name == section_name)
        )
        if section is None:
            raise ValueError("replay repository section not found")
        self._validate_entry_integrity(entry, verify_payloads=False)
        payload = self._validate_section_payload(entry, section)
        return {
            "replayId": entry.replay_id,
            "sectionName": section.section_name,
            "contentHash": section.content_hash,
            "byteSize": section.byte_size,
            "compression": section.compression,
            "redactionStatus": section.redaction_status,
            "payload": json.loads(payload.decode("utf-8")),
        }

    def list_audit(self, replay_id: str, *, page: int, page_size: int) -> dict[str, object]:
        entry = self._require_entry(replay_id)
        statement = (
            select(AuditLog)
            .where(AuditLog.resource_type == "replay_repository")
            .where(AuditLog.resource_id == entry.replay_id)
            .order_by(AuditLog.created_at.desc())
        )
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result([self._serialize_audit(row) for row in rows], total, page, page_size)

    def visualization_projection(self) -> dict[str, object]:
        entries = list(self.db.scalars(select(ReplayRepositoryEntry)))
        for entry in entries:
            self._validate_entry_integrity(entry, verify_payloads=True)
        return {
            "schemaVersion": "phase8.replay-repository-visualization.v1",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "totalReplays": len(entries),
            "validityCounts": _count_by(entries, "validity_status"),
            "retentionCounts": _count_by(entries, "retention_status"),
            "storageAdapterCounts": _count_by(entries, "storage_adapter"),
            "approvalModeCounts": _count_by(entries, "approval_mode"),
            "approvalStateCounts": _count_by(entries, "approval_state"),
            "sectionCountTotal": sum(len(entry.section_index or []) for entry in entries),
            "recentReplays": [
                {
                    "replayId": entry.replay_id,
                    "executionId": str(entry.execution_id),
                    "frozenAt": entry.frozen_at.isoformat(),
                    "validityStatus": entry.validity_status,
                    "retentionStatus": entry.retention_status,
                    "approvalMode": entry.approval_mode,
                    "storageAdapter": entry.storage_adapter,
                }
                for entry in sorted(entries, key=lambda item: item.frozen_at, reverse=True)[:10]
            ],
            "evidenceOnly": True,
            "writesDecision": False,
            "canonicalDecisionSources": {
                "gate": "gate_results",
                "coverageProof": "coverage_proof_bundles",
                "replayValidity": "replay_repository_entries.validity_status",
            },
        }

    def retention_policies(self) -> dict[str, object]:
        policy = self.governance_policy()
        return {
            "items": [
                {
                    "retentionPolicy": "default",
                    "defaultRetentionDays": 90,
                    "legalHoldSupported": True,
                    "dryRunRequiredBeforeDestructiveAction": True,
                    "approvalMode": policy["approvalMode"],
                    "thresholdLevel": policy["thresholdLevel"],
                    "policyRules": policy["policyRules"],
                    "systemHardRules": policy["systemHardRules"],
                    "historicalMigration": policy["historicalMigration"],
                    "adminExecution": policy["adminExecution"],
                    "supportedModes": ["always", "policy_only", "threshold"],
                }
            ],
            "total": 1,
        }

    def governance_policy(self) -> dict[str, object]:
        return self._governance_policy_projection(self._policy_record())

    def request_governance_policy_update(self, payload, context: ServiceContext) -> dict[str, object]:
        guardrail_refs = self._record_mutation_guardrail(
            context,
            resource_id="global",
            action="replay_repository.governance_policy.update",
            payload={
                "approvalMode": payload.approvalMode,
                "thresholdLevel": payload.thresholdLevel,
                "policyRules": payload.policyRules,
            },
        )
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="replay_governance_policy",
            resource_id="global",
            summary="Approval required before updating Replay Governance Approval Mode policy.",
            payload={
                "action": "replay_repository.governance_policy.update",
                "approvalMode": payload.approvalMode,
                "thresholdLevel": payload.thresholdLevel,
                "policyRules": payload.policyRules,
                "reason": payload.reason,
                "guardrailEventRefs": guardrail_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "status": approval.status.value,
            "requestedPolicy": {
                "approvalMode": payload.approvalMode,
                "thresholdLevel": payload.thresholdLevel,
                "policyRules": payload.policyRules,
            },
        }

    def execute_approved_governance_policy_update(self, *, approval_payload: dict[str, object], approval_id: UUID, context: ServiceContext) -> dict[str, object]:
        policy = self._policy_record(create=True)
        policy.approval_mode = str(approval_payload["approvalMode"])
        policy.threshold_level = str(approval_payload.get("thresholdLevel") or "high")
        policy.policy_rules = dict(approval_payload.get("policyRules") or {})
        policy.updated_by = context.user.id
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            "replay_repository.governance_policy.update",
            "replay_governance_policy",
            "global",
            context.request_id,
            context.trace_id,
            {
                "approvalId": str(approval_id),
                "approvalMode": policy.approval_mode,
                "thresholdLevel": policy.threshold_level,
                "policyRules": policy.policy_rules,
            },
        )
        self.db.flush()
        result = self._governance_policy_projection(policy)
        result["auditRefs"] = [{"type": "audit_log", "id": str(audit.id), "action": audit.action}]
        result["approvalRefs"] = [{"type": "approval", "id": str(approval_id), "state": "approved"}]
        return result

    def request_freeze(
        self,
        *,
        execution_id: UUID,
        idempotency_key: str | None,
        context: ServiceContext,
    ) -> dict[str, object]:
        replay_export = ObservabilityService(self.db).export_execution_replay(execution_id, request_id=context.request_id, persist=False)
        source_hash = str(replay_export["exportPayloadHash"])
        existing = self._entry_by_source_hash(source_hash)
        if existing is not None:
            self._validate_entry_integrity(existing, verify_payloads=True)
            return {
                "approvalRequired": False,
                "approvalMode": self.governance_policy()["approvalMode"],
                "status": "already_frozen",
                "replay": self.serialize_entry(existing, include_manifest=False),
            }

        with _freeze_lock(source_hash):
            existing = self._entry_by_source_hash(source_hash)
            if existing is not None:
                self._validate_entry_integrity(existing, verify_payloads=True)
                return {
                    "approvalRequired": False,
                    "approvalMode": self.governance_policy()["approvalMode"],
                    "status": "already_frozen",
                    "replay": self.serialize_entry(existing, include_manifest=False),
                }
            return self._request_new_freeze(
                execution_id=execution_id,
                source_hash=source_hash,
                replay_export=replay_export,
                idempotency_key=idempotency_key,
                context=context,
            )

    def _request_new_freeze(
        self,
        *,
        execution_id: UUID,
        source_hash: str,
        replay_export: dict[str, object],
        idempotency_key: str | None,
        context: ServiceContext,
    ) -> dict[str, object]:
        decision = self._policy_decision(action="freeze", risk_level="low")
        guardrail_refs = self._record_mutation_guardrail(
            context,
            resource_id=str(execution_id),
            action="replay_repository.freeze",
            payload={"executionId": str(execution_id), "sourceReplayExportHash": source_hash, "policyOutcome": decision},
        )
        if not decision["approvalRequired"]:
            policy_ref = self._policy_outcome_ref(decision)
            replay = self.execute_approved_freeze(
                execution_id=execution_id,
                source_replay_export_hash=source_hash,
                approval_id=None,
                context=context,
                approval_state="not_required",
                approval_refs=[policy_ref],
                guardrail_refs=guardrail_refs,
            )
            self.db.commit()
            return {
                "approvalRequired": False,
                "approvalMode": decision["approvalMode"],
                "status": "not_required",
                "policyOutcome": decision,
                "replay": replay,
            }
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="replay_repository_freeze",
            resource_id=idempotency_key or f"freeze:{execution_id}:{source_hash}",
            summary=f"Approval required before freezing Replay Repository record for execution {execution_id}.",
            payload={
                "action": "replay_repository.freeze",
                "executionId": str(execution_id),
                "sourceReplayExportHash": source_hash,
                "exportHash": replay_export["exportHash"],
                "approvalMode": decision["approvalMode"],
                "policyOutcome": decision,
                "guardrailEventRefs": guardrail_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalMode": decision["approvalMode"],
            "approvalId": str(approval.id),
            "status": approval.status.value,
            "sourceReplayExportHash": source_hash,
        }

    def execute_approved_freeze(
        self,
        *,
        execution_id: UUID,
        source_replay_export_hash: str,
        approval_id: UUID | None,
        context: ServiceContext,
        approval_state: str = "approved",
        approval_refs: list[dict[str, object]] | None = None,
        guardrail_refs: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        existing = self._entry_by_source_hash(source_replay_export_hash)
        if existing is not None:
            self._validate_entry_integrity(existing, verify_payloads=True)
            return self.serialize_entry(existing, include_manifest=True)

        replay_export = ObservabilityService(self.db).export_execution_replay(execution_id, request_id=context.request_id, persist=False)
        if replay_export["exportPayloadHash"] != source_replay_export_hash:
            raise ReplayRepositoryConflictError("replay payload changed after approval; submit a new freeze approval")

        frozen_at = datetime.now(timezone.utc)
        replay_id = f"replay_{uuid4().hex}"
        sections = self._build_sections(replay_export)
        section_rows: list[ReplayRepositorySection] = []
        section_index: list[dict[str, object]] = []
        written_storage_refs: list[str] = []
        try:
            for section_name, payload in sections.items():
                encoded = _canonical_json_bytes(payload)
                try:
                    storage_result = self.storage.write_section(
                        replay_id=replay_id,
                        section_name=section_name,
                        payload=encoded,
                    )
                except Exception as exc:
                    ambiguous_storage_ref = getattr(exc, "storage_ref", None)
                    if ambiguous_storage_ref:
                        written_storage_refs.append(str(ambiguous_storage_ref))
                    raise
                written_storage_refs.append(str(storage_result["storageRef"]))
                section_projection = {
                    "sectionName": section_name,
                    "storageRef": storage_result["storageRef"],
                    "contentHash": storage_result["contentHash"],
                    "byteSize": storage_result["byteSize"],
                    "compression": storage_result["compression"],
                    "redactionStatus": replay_export["redactionStatus"],
                }
                section_index.append(section_projection)
                section_rows.append(
                    ReplayRepositorySection(
                        id=uuid4(),
                        section_name=section_name,
                        storage_ref=str(storage_result["storageRef"]),
                        content_hash=str(storage_result["contentHash"]),
                        byte_size=int(storage_result["byteSize"]),
                        compression=str(storage_result["compression"]),
                        redaction_status=str(replay_export["redactionStatus"]),
                    )
                )

            payload_hash = _hash_payload({"sections": [{item["sectionName"]: item["contentHash"]} for item in section_index]})
            summary_projection = self._summary_projection(replay_id, replay_export, section_index, frozen_at)
            manifest = {
                "schemaVersion": REPLAY_REPOSITORY_SCHEMA_VERSION,
                "replayId": replay_id,
                "executionId": str(execution_id),
                "frozenAt": frozen_at.isoformat(),
                "sourceReplayExportHash": source_replay_export_hash,
                "sourceExportHash": replay_export["exportHash"],
                "payloadHash": payload_hash,
                "summaryProjectionHash": _hash_payload(summary_projection),
                "storageAdapter": self.storage.adapter_name,
                "sectionIndex": section_index,
            }
            manifest_hash = _hash_payload(manifest)
            if approval_refs is None:
                approval_refs = [{"type": "approval", "id": str(approval_id), "state": "approved"}] if approval_id else []
            if guardrail_refs is None:
                guardrail_refs = list(self._approval_guardrail_refs(approval_id)) if approval_id else []

            entry = ReplayRepositoryEntry(
                id=uuid4(),
                replay_id=replay_id,
                execution_id=execution_id,
                schema_version=REPLAY_REPOSITORY_SCHEMA_VERSION,
                source_replay_export_hash=source_replay_export_hash,
                export_payload_hash=str(replay_export["exportPayloadHash"]),
                manifest_hash=manifest_hash,
                payload_hash=payload_hash,
                manifest=manifest,
                summary_projection=summary_projection,
                section_index=section_index,
                storage_adapter=self.storage.adapter_name,
                redaction_status=str(replay_export["redactionStatus"]),
                validity_status="valid",
                approval_mode=str(self.governance_policy()["approvalMode"]),
                approval_state=approval_state,
                approval_refs=approval_refs,
                guardrail_event_refs=guardrail_refs,
                audit_refs=[],
                retention_policy="default",
                retention_until=frozen_at + timedelta(days=90),
                retention_status="active",
                created_by=context.user.id,
                frozen_at=frozen_at,
            )
            with self.db.begin_nested():
                self.db.add(entry)
                self.db.flush()
                for section in section_rows:
                    section.replay_entry_id = entry.id
                    self.db.add(section)
                audit = write_audit_log(
                    self.db,
                    str(context.user.id),
                    "replay_repository.freeze",
                    "replay_repository",
                    entry.replay_id,
                    context.request_id,
                    context.trace_id,
                    {
                        "executionId": str(execution_id),
                        "sourceReplayExportHash": source_replay_export_hash,
                        "manifestHash": manifest_hash,
                        "payloadHash": payload_hash,
                        "approvalId": str(approval_id) if approval_id else None,
                        "approvalState": approval_state,
                    },
                    execution_id=execution_id,
                )
                self.db.flush()
                entry.audit_refs = [{"type": "audit_log", "id": str(audit.id), "action": audit.action}]
                self.db.flush()
        except IntegrityError:
            self._compensate_storage_writes(written_storage_refs)
            existing = self._entry_by_source_hash(source_replay_export_hash)
            if existing is None:
                raise
            self._validate_entry_integrity(existing, verify_payloads=True)
            return self.serialize_entry(existing, include_manifest=True)
        except Exception:
            self._compensate_storage_writes(written_storage_refs)
            raise
        result = self.serialize_entry(entry, include_manifest=True)
        self.db.info.setdefault(_PENDING_STORAGE_COMPENSATIONS, []).append(
            (self.storage, list(written_storage_refs))
        )
        return result

    def _compensate_storage_writes(
        self,
        storage_refs: list[str],
    ) -> None:
        for storage_ref in reversed(list(dict.fromkeys(storage_refs))):
            try:
                self.storage.delete_section(storage_ref)
            except (FileNotFoundError, OSError, ValueError):
                continue

    def request_retention_action(self, replay_id: str, payload, context: ServiceContext) -> dict[str, object]:
        entry = self._require_entry(replay_id)
        self._validate_entry_integrity(entry, verify_payloads=entry.retention_status != "purged")
        expected_retention_state_hash = _hash_payload(self._retention_state(entry))
        preview = self._retention_preview(entry, payload.action, payload.retentionUntil)
        risk_level = "high" if payload.action in {"purge", "set_legal_hold", "clear_legal_hold"} else "low"
        decision = self._policy_decision(action=f"retention.{payload.action}", risk_level=risk_level)
        if payload.dryRun:
            return {
                "approvalRequired": False,
                "dryRun": True,
                "approvalMode": decision["approvalMode"],
                "replayId": entry.replay_id,
                "action": payload.action,
                "currentRetentionState": self._retention_state(entry),
                "projectedRetentionState": preview,
                "policyOutcome": decision,
            }
        guardrail_refs = self._record_mutation_guardrail(
            context,
            resource_id=entry.replay_id,
            action=f"replay_repository.retention.{payload.action}",
            payload={"replayId": entry.replay_id, "action": payload.action, "projectedRetentionState": preview, "policyOutcome": decision},
        )
        if not decision["approvalRequired"]:
            replay = self.execute_approved_retention_action(
                replay_id=entry.replay_id,
                action=payload.action,
                retention_until=payload.retentionUntil.isoformat() if payload.retentionUntil else None,
                approval_id=None,
                context=context,
                expected_retention_state_hash=expected_retention_state_hash,
                approval_refs=[self._policy_outcome_ref(decision)],
                guardrail_refs=guardrail_refs,
            )
            self.db.commit()
            return {
                "approvalRequired": False,
                "approvalMode": decision["approvalMode"],
                "status": "not_required",
                "replayId": entry.replay_id,
                "action": payload.action,
                "policyOutcome": decision,
                "replay": replay,
            }
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="replay_repository_retention",
            resource_id=f"retention:{entry.replay_id}:{payload.action}",
            summary=f"Approval required before applying replay retention action '{payload.action}' to {entry.replay_id}.",
            payload={
                "action": "replay_repository.retention",
                "replayId": entry.replay_id,
                "retentionAction": payload.action,
                "retentionUntil": payload.retentionUntil.isoformat() if payload.retentionUntil else None,
                "expectedRetentionStateHash": expected_retention_state_hash,
                "reason": payload.reason,
                "approvalMode": decision["approvalMode"],
                "policyOutcome": decision,
                "guardrailEventRefs": guardrail_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "approvalMode": decision["approvalMode"],
            "approvalId": str(approval.id),
            "status": approval.status.value,
            "replayId": entry.replay_id,
            "action": payload.action,
            "projectedRetentionState": preview,
        }

    def execute_approved_retention_action(
        self,
        *,
        replay_id: str,
        action: str,
        retention_until: str | None,
        approval_id: UUID | None,
        context: ServiceContext,
        expected_retention_state_hash: str | None = None,
        approval_refs: list[dict[str, object]] | None = None,
        guardrail_refs: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        entry = self._require_entry(replay_id, for_update=True)
        self._validate_entry_integrity(entry, verify_payloads=entry.retention_status != "purged")
        if (
            expected_retention_state_hash is not None
            and _hash_payload(self._retention_state(entry)) != expected_retention_state_hash
        ):
            raise ReplayRepositoryConflictError(
                "replay retention state changed after approval request"
            )
        if entry.retention_status == "purged":
            raise ReplayRepositoryConflictError(
                "purged replay repository retention state cannot be mutated"
            )
        if action == "purge" and self._pending_legal_hold_approval(entry.replay_id):
            raise ReplayRepositoryConflictError(
                "pending legal hold blocks replay repository purge"
            )
        if action == "purge" and entry.legal_hold:
            raise ReplayRepositoryConflictError("legal hold blocks replay repository purge")
        now = datetime.now(timezone.utc)
        if action == "archive":
            entry.archived_at = now
            entry.retention_status = "archived"
        elif action == "purge":
            for section in self._sections(entry):
                self.storage.delete_section(section.storage_ref)
            entry.retention_status = "purged"
            entry.purge_eligible_at = now
        elif action == "set_legal_hold":
            entry.legal_hold = True
            entry.retention_status = "legal_hold"
        elif action == "clear_legal_hold":
            entry.legal_hold = False
            entry.retention_status = "active"
        else:
            raise ValueError("unsupported retention action")
        if retention_until:
            entry.retention_until = datetime.fromisoformat(retention_until)
        if approval_refs is None:
            approval_refs = [{"type": "approval", "id": str(approval_id), "state": "approved", "action": action}] if approval_id else []
        if guardrail_refs is None:
            guardrail_refs = list(self._approval_guardrail_refs(approval_id)) if approval_id else []
        entry.approval_refs = [*entry.approval_refs, *approval_refs]
        entry.guardrail_event_refs = [*entry.guardrail_event_refs, *guardrail_refs]
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            "replay_repository.retention.apply",
            "replay_repository",
            entry.replay_id,
            context.request_id,
            context.trace_id,
            {"action": action, "approvalId": str(approval_id) if approval_id else None, "retentionState": self._retention_state(entry)},
            execution_id=entry.execution_id,
        )
        self.db.flush()
        entry.audit_refs = [*entry.audit_refs, {"type": "audit_log", "id": str(audit.id), "action": audit.action}]
        return self.serialize_entry(entry, include_manifest=True)

    def serialize_entry(self, entry: ReplayRepositoryEntry, *, include_manifest: bool) -> dict[str, object]:
        sections = entry.section_index or [self._serialize_section(row) for row in self._sections(entry)]
        contract_payload = {
            "schemaVersion": entry.schema_version,
            "replayId": entry.replay_id,
            "executionId": str(entry.execution_id),
            "frozenAt": entry.frozen_at.isoformat(),
            "sourceReplayExportHash": entry.source_replay_export_hash,
            "manifestHash": entry.manifest_hash,
            "payloadHash": entry.payload_hash,
            "storageAdapter": entry.storage_adapter,
            "redactionStatus": entry.redaction_status,
            "validityStatus": entry.validity_status,
            "approvalMode": entry.approval_mode,
            "approvalState": entry.approval_state,
            "retentionState": self._retention_state(entry),
            "summaryProjection": entry.summary_projection,
            "sectionIndex": sections,
            "auditRefs": entry.audit_refs,
            "approvalRefs": entry.approval_refs,
            "guardrailEventRefs": entry.guardrail_event_refs,
        }
        validated = validate_contract("replay-repository", contract_payload)
        if include_manifest:
            validated["manifest"] = entry.manifest
        return validated

    def _validate_entry_integrity(
        self,
        entry: ReplayRepositoryEntry,
        *,
        verify_payloads: bool,
    ) -> None:
        try:
            self._assert_entry_metadata_integrity(entry)
            if verify_payloads and entry.retention_status != "purged":
                for section in self._sections(entry):
                    self._assert_section_payload_integrity(section)
        except ReplayRepositoryIntegrityError as exc:
            self._record_integrity_failure(entry, exc)
            raise

    def _assert_entry_metadata_integrity(
        self,
        entry: ReplayRepositoryEntry,
    ) -> None:
        manifest = entry.manifest
        if not isinstance(manifest, dict):
            raise ReplayRepositoryIntegrityError(
                "manifest_corrupt",
                "replay repository manifest is not an object",
            )
        computed_manifest_hash = _hash_payload(manifest)
        if computed_manifest_hash != entry.manifest_hash:
            raise ReplayRepositoryIntegrityError(
                "manifest_hash_mismatch",
                "replay repository manifest hash mismatch",
                evidence={
                    "expectedHash": entry.manifest_hash,
                    "actualHash": computed_manifest_hash,
                },
            )

        expected_columns = {
            "schemaVersion": entry.schema_version,
            "replayId": entry.replay_id,
            "executionId": str(entry.execution_id),
            "sourceReplayExportHash": entry.source_replay_export_hash,
            "payloadHash": entry.payload_hash,
            "storageAdapter": entry.storage_adapter,
        }
        mismatched_columns = [
            field
            for field, expected in expected_columns.items()
            if manifest.get(field) != expected
        ]
        if entry.export_payload_hash != entry.source_replay_export_hash:
            mismatched_columns.append("exportPayloadHash")
        if not _same_instant(manifest.get("frozenAt"), entry.frozen_at):
            mismatched_columns.append("frozenAt")
        if mismatched_columns:
            raise ReplayRepositoryIntegrityError(
                "manifest_column_mismatch",
                "replay repository manifest does not match frozen metadata",
                evidence={"fields": sorted(set(mismatched_columns))},
            )

        section_index = entry.section_index
        manifest_index = manifest.get("sectionIndex")
        if (
            not isinstance(section_index, list)
            or manifest_index != section_index
        ):
            raise ReplayRepositoryIntegrityError(
                "section_index_mismatch",
                "replay repository section index does not match its manifest",
            )
        section_names = [
            str(item.get("sectionName"))
            for item in section_index
            if isinstance(item, dict)
        ]
        if section_names != list(REPLAY_SECTION_NAMES):
            raise ReplayRepositoryIntegrityError(
                "section_index_mismatch",
                "replay repository section set or order is invalid",
                evidence={
                    "expectedSections": list(REPLAY_SECTION_NAMES),
                    "actualSections": section_names,
                },
            )
        computed_payload_hash = _hash_payload(
            {
                "sections": [
                    {item["sectionName"]: item["contentHash"]}
                    for item in section_index
                ]
            }
        )
        if computed_payload_hash != entry.payload_hash:
            raise ReplayRepositoryIntegrityError(
                "payload_hash_mismatch",
                "replay repository payload hash does not match its section index",
                evidence={
                    "expectedHash": entry.payload_hash,
                    "actualHash": computed_payload_hash,
                },
            )

        summary_hash = manifest.get("summaryProjectionHash")
        computed_summary_hash = _hash_payload(entry.summary_projection)
        if summary_hash != computed_summary_hash:
            raise ReplayRepositoryIntegrityError(
                "summary_hash_mismatch",
                "replay repository summary projection hash mismatch",
                evidence={
                    "expectedHash": summary_hash,
                    "actualHash": computed_summary_hash,
                },
            )

        rows = self._sections(entry)
        row_index = {
            row.section_name: self._serialize_section(row)
            for row in rows
        }
        manifest_row_index = {
            str(item["sectionName"]): item
            for item in section_index
        }
        if (
            len(rows) != len(section_index)
            or len(row_index) != len(rows)
            or row_index != manifest_row_index
        ):
            raise ReplayRepositoryIntegrityError(
                "section_index_mismatch",
                "replay repository section rows do not match the frozen index",
            )

        replay_metadata = {
            "manifest": manifest,
            "summaryProjection": entry.summary_projection,
            "sectionIndex": section_index,
        }
        secret_scan_projection = _replay_metadata_secret_scan_projection(
            replay_metadata
        )
        if redact_sensitive_data(secret_scan_projection) != secret_scan_projection:
            raise ReplayRepositoryIntegrityError(
                "plaintext_secret_detected",
                "replay repository metadata contains plaintext secret material",
            )
        self._assert_freeze_audit_anchor(entry)

    def _assert_freeze_audit_anchor(
        self,
        entry: ReplayRepositoryEntry,
    ) -> None:
        freeze_refs = [
            ref
            for ref in (entry.audit_refs or [])
            if isinstance(ref, dict)
            and ref.get("action") == "replay_repository.freeze"
            and ref.get("id")
        ]
        if not freeze_refs:
            raise ReplayRepositoryIntegrityError(
                "audit_anchor_missing",
                "replay repository freeze audit ref is missing",
            )
        try:
            audit_id = UUID(str(freeze_refs[0]["id"]))
        except ValueError as exc:
            raise ReplayRepositoryIntegrityError(
                "audit_anchor_missing",
                "replay repository freeze audit ref is invalid",
            ) from exc
        audit = self.db.get(AuditLog, audit_id)
        if (
            audit is None
            or audit.action != "replay_repository.freeze"
            or audit.resource_type != "replay_repository"
            or audit.resource_id != entry.replay_id
        ):
            raise ReplayRepositoryIntegrityError(
                "audit_anchor_missing",
                "replay repository freeze audit record is unavailable",
            )
        audit_details = audit.details or {}
        expected_audit = {
            "executionId": str(entry.execution_id),
            "sourceReplayExportHash": entry.source_replay_export_hash,
            "manifestHash": entry.manifest_hash,
            "payloadHash": entry.payload_hash,
        }
        mismatched = [
            key
            for key, expected in expected_audit.items()
            if audit_details.get(key) != expected
        ]
        if mismatched:
            raise ReplayRepositoryIntegrityError(
                "audit_anchor_mismatch",
                "replay repository frozen hashes do not match the freeze audit",
                evidence={"fields": mismatched},
            )

    def _validate_section_payload(
        self,
        entry: ReplayRepositoryEntry,
        section: ReplayRepositorySection,
    ) -> bytes:
        try:
            return self._assert_section_payload_integrity(section)
        except ReplayRepositoryIntegrityError as exc:
            self._record_integrity_failure(entry, exc)
            raise

    def _assert_section_payload_integrity(
        self,
        section: ReplayRepositorySection,
    ) -> bytes:
        try:
            payload = self.storage.read_section(section.storage_ref)
        except (FileNotFoundError, OSError, ValueError) as exc:
            raise ReplayRepositoryIntegrityError(
                "section_missing",
                "replay repository section payload is unavailable",
                evidence={"sectionName": section.section_name},
            ) from exc
        payload_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
        if payload_hash != section.content_hash:
            raise ReplayRepositoryIntegrityError(
                "section_hash_mismatch",
                "replay repository section hash mismatch",
                evidence={
                    "sectionName": section.section_name,
                    "expectedHash": section.content_hash,
                    "actualHash": payload_hash,
                },
            )
        if len(payload) != section.byte_size:
            raise ReplayRepositoryIntegrityError(
                "section_size_mismatch",
                "replay repository section byte size mismatch",
                evidence={
                    "sectionName": section.section_name,
                    "expectedByteSize": section.byte_size,
                    "actualByteSize": len(payload),
                },
            )
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReplayRepositoryIntegrityError(
                "section_corrupt_payload",
                "replay repository section is not valid UTF-8 JSON",
                evidence={"sectionName": section.section_name},
            ) from exc
        if _canonical_json_bytes(decoded) != payload:
            raise ReplayRepositoryIntegrityError(
                "section_noncanonical_payload",
                "replay repository section bytes are not canonical JSON",
                evidence={"sectionName": section.section_name},
            )
        if redact_sensitive_data(decoded) != decoded:
            raise ReplayRepositoryIntegrityError(
                "plaintext_secret_detected",
                "replay repository section contains plaintext secret material",
                evidence={"sectionName": section.section_name},
            )
        return payload

    def _record_integrity_failure(
        self,
        entry: ReplayRepositoryEntry,
        error: ReplayRepositoryIntegrityError,
    ) -> None:
        trace_id = uuid4()
        audit = write_audit_log(
            self.db,
            None,
            "replay_repository.integrity_failure",
            "replay_repository",
            entry.replay_id,
            f"integrity-read:{uuid4().hex}",
            trace_id,
            {
                "reasonCode": error.reason_code,
                "message": str(error),
                "evidence": error.evidence,
            },
            execution_id=entry.execution_id,
        )
        self.db.flush()
        audit_ref: dict[str, object] = {
            "type": "audit_log",
            "id": str(audit.id),
            "action": str(audit.action),
        }
        entry.validity_status = "invalid"
        entry.audit_refs = [*(entry.audit_refs or []), audit_ref]
        self.db.commit()
        error.audit_refs = [audit_ref]

    def _require_entry(
        self,
        replay_id: str,
        *,
        for_update: bool = False,
    ) -> ReplayRepositoryEntry:
        statement = select(ReplayRepositoryEntry).where(
            ReplayRepositoryEntry.replay_id == replay_id
        )
        if for_update:
            statement = statement.with_for_update()
        entry = self.db.scalar(statement)
        if entry is None:
            raise ValueError("replay repository entry not found")
        return entry

    def _entry_by_source_hash(self, source_hash: str) -> ReplayRepositoryEntry | None:
        return self.db.scalar(select(ReplayRepositoryEntry).where(ReplayRepositoryEntry.source_replay_export_hash == source_hash))

    def _sections(self, entry: ReplayRepositoryEntry) -> list[ReplayRepositorySection]:
        return list(
            self.db.scalars(
                select(ReplayRepositorySection)
                .where(ReplayRepositorySection.replay_entry_id == entry.id)
                .order_by(ReplayRepositorySection.section_name.asc())
            )
        )

    def _pending_legal_hold_approval(self, replay_id: str) -> bool:
        return (
            self.db.scalar(
                select(Approval.id)
                .where(Approval.type == ApprovalType.OTHER)
                .where(Approval.resource_type == "replay_repository_retention")
                .where(
                    Approval.resource_id
                    == f"retention:{replay_id}:set_legal_hold"
                )
                .where(Approval.status == ApprovalStatus.PENDING)
                .limit(1)
            )
            is not None
        )

    def _serialize_section(self, section: ReplayRepositorySection) -> dict[str, object]:
        return {
            "sectionName": section.section_name,
            "storageRef": section.storage_ref,
            "contentHash": section.content_hash,
            "byteSize": section.byte_size,
            "compression": section.compression,
            "redactionStatus": section.redaction_status,
        }

    def _build_sections(self, replay_export: dict[str, Any]) -> dict[str, object]:
        replay = dict(replay_export.get("replay") or {})
        return {
            "manifest-source": {
                "schemaVersion": replay_export["schemaVersion"],
                "executionId": replay_export["executionId"],
                "exportPayloadHash": replay_export["exportPayloadHash"],
                "traceabilitySnapshotRef": replay_export.get("traceabilitySnapshotRef"),
            },
            "summary": self._summary_from_replay_export(replay_export),
            "timeline": replay.get("timeline", []),
            "traces": replay.get("traces", []),
            "artifacts": replay.get("artifacts", []),
            "raw-findings": replay.get("rawFindings", []),
            "findings": replay.get("findings", []),
            "gate": replay.get("gate"),
            "guardrails": replay.get("guardrailEvents", []),
            "approvals": replay.get("approvals", []),
            "skill-invocations": replay.get("skillInvocations", []),
            "audit-logs": replay_export.get("auditLogs", []),
            "coverage-snapshot": {
                "traceabilitySnapshotRef": replay_export.get("traceabilitySnapshotRef"),
                "traceabilitySnapshotHash": replay_export.get("traceabilitySnapshotHash"),
                "coverageSummarySnapshot": replay_export.get("coverageSummarySnapshot"),
                "coverageMatrixSnapshotRef": replay_export.get("coverageMatrixSnapshotRef"),
                "graphCoverageSnapshot": replay_export.get("graphCoverageSnapshot"),
            },
            "visual-grounding": replay.get("visualGroundingAttempts", []),
            "correction-governance": replay.get("correctionGovernance", []),
        }

    def _summary_from_replay_export(self, replay_export: dict[str, Any]) -> dict[str, object]:
        replay = dict(replay_export.get("replay") or {})
        gate = replay.get("gate") or {}
        return {
            "executionId": replay_export["executionId"],
            "sourceReplayExportHash": replay_export["exportPayloadHash"],
            "gateOverall": gate.get("overall") if isinstance(gate, dict) else None,
            "timelineCount": len(replay.get("timeline") or []),
            "findingCount": len(replay.get("findings") or []),
            "rawFindingCount": len(replay.get("rawFindings") or []),
            "skillInvocationCount": len(replay.get("skillInvocations") or []),
            "auditLogCount": len(replay_export.get("auditLogs") or []),
            "visualGroundingAttemptCount": len(replay.get("visualGroundingAttempts") or []),
        }

    def _summary_projection(
        self,
        replay_id: str,
        replay_export: dict[str, Any],
        section_index: list[dict[str, object]],
        frozen_at: datetime,
    ) -> dict[str, object]:
        return {
            **self._summary_from_replay_export(replay_export),
            "replayId": replay_id,
            "frozenAt": frozen_at.isoformat(),
            "validityStatus": "valid",
            "sectionCount": len(section_index),
            "sections": [
                {
                    "sectionName": item["sectionName"],
                    "contentHash": item["contentHash"],
                    "byteSize": item["byteSize"],
                    "redactionStatus": item["redactionStatus"],
                }
                for item in section_index
            ],
        }

    def _retention_state(self, entry: ReplayRepositoryEntry) -> dict[str, object]:
        return {
            "retentionPolicy": entry.retention_policy,
            "retentionUntil": entry.retention_until.isoformat() if entry.retention_until else None,
            "legalHold": entry.legal_hold,
            "archivedAt": entry.archived_at.isoformat() if entry.archived_at else None,
            "purgeEligibleAt": entry.purge_eligible_at.isoformat() if entry.purge_eligible_at else None,
            "retentionStatus": entry.retention_status,
        }

    def _retention_preview(self, entry: ReplayRepositoryEntry, action: str, retention_until: datetime | None) -> dict[str, object]:
        preview = self._retention_state(entry)
        if retention_until is not None:
            preview["retentionUntil"] = retention_until.isoformat()
        if action == "archive":
            preview["retentionStatus"] = "archived"
            preview["archivedAt"] = "pending_approval"
        elif action == "purge":
            preview["retentionStatus"] = "purged" if not entry.legal_hold else "legal_hold"
            preview["blockedByLegalHold"] = entry.legal_hold
        elif action == "set_legal_hold":
            preview["legalHold"] = True
            preview["retentionStatus"] = "legal_hold"
        elif action == "clear_legal_hold":
            preview["legalHold"] = False
            preview["retentionStatus"] = "active"
        return preview

    def _policy_record(self, *, create: bool = False) -> ReplayGovernancePolicy | None:
        policy = self.db.scalar(
            select(ReplayGovernancePolicy)
            .where(ReplayGovernancePolicy.scope_type == "global")
            .where(ReplayGovernancePolicy.scope_id == "global")
        )
        if policy is None and create:
            policy = ReplayGovernancePolicy(
                id=uuid4(),
                scope_type="global",
                scope_id="global",
                approval_mode=DEFAULT_APPROVAL_MODE,
                threshold_level="high",
                policy_rules={},
            )
            self.db.add(policy)
            self.db.flush()
        return policy

    def _governance_policy_projection(self, policy: ReplayGovernancePolicy | None) -> dict[str, object]:
        return {
            "scopeType": "global",
            "scopeId": "global",
            "approvalMode": policy.approval_mode if policy else DEFAULT_APPROVAL_MODE,
            "thresholdLevel": policy.threshold_level if policy else "high",
            "policyRules": policy.policy_rules if policy else {},
            "systemHardRules": {
                "highRiskRequiresApproval": True,
                "purgeRequiresApproval": True,
                "legalHoldRequiresApproval": True,
                "supersedeLikeRequiresApproval": True,
            },
            "historicalMigration": {
                "status": "not_applicable",
                "historicalRecordCount": 0,
                "migrationRequired": False,
                "strategy": "no_historical_replay_repository_migration",
                "immutabilityStartsAt": "first_frozen_replay_repository_record",
                "adminActionAvailable": False,
            },
            "adminExecution": {
                "approvalExecutionSurface": "existing_approval_flow",
                "replaySpecificAdminExecutor": False,
                "requiredCapability": "replay.repository.manage",
                "approvalActionTypes": [
                    "replay_repository.freeze",
                    "replay_repository.retention",
                    "replay_repository.governance_policy.update",
                ],
                "guardrailRequired": True,
                "auditRequired": True,
            },
            "auditRefs": self._policy_audit_refs(),
            "approvalRefs": self._policy_approval_refs(),
            "updatedAt": policy.updated_at.isoformat() if policy and policy.updated_at else None,
        }

    def _policy_decision(self, *, action: str, risk_level: str) -> dict[str, object]:
        policy = self.governance_policy()
        approval_mode = str(policy["approvalMode"])
        threshold_level = str(policy["thresholdLevel"])
        policy_rules = dict(policy.get("policyRules") or {})
        system_hard_rule = risk_level == "high" or action in {
            "retention.purge",
            "retention.set_legal_hold",
            "retention.clear_legal_hold",
            "knowledge.supersede",
        }
        if approval_mode == "always":
            approval_required = True
            reason = "approval_mode_always"
        elif system_hard_rule:
            approval_required = True
            reason = "system_hard_rule"
        elif approval_mode == "policy_only":
            rule_key = {
                "freeze": "requireApprovalForFreeze",
                "retention.archive": "requireApprovalForArchive",
            }.get(action, "requireApproval")
            approval_required = bool(policy_rules.get(rule_key, False))
            reason = "policy_rule_required" if approval_required else "approval_not_required_by_policy"
        elif approval_mode == "threshold":
            approval_required = RISK_RANK.get(risk_level, 3) >= RISK_RANK.get(threshold_level, 3)
            reason = "threshold_requires_approval" if approval_required else "below_threshold_approval_not_required"
        else:
            approval_required = True
            reason = "unknown_mode_fails_closed"
        return {
            "approvalMode": approval_mode,
            "approvalRequired": approval_required,
            "policyOutcome": "approval-required" if approval_required else "approval-not-required",
            "reason": reason,
            "action": action,
            "riskLevel": risk_level,
            "thresholdLevel": threshold_level,
            "systemHardRule": system_hard_rule,
        }

    def _policy_outcome_ref(self, decision: dict[str, object]) -> dict[str, object]:
        return {
            "type": "policy_outcome",
            "state": "approval-not-required",
            "approvalMode": decision["approvalMode"],
            "reason": decision["reason"],
            "action": decision["action"],
            "riskLevel": decision["riskLevel"],
        }

    def _record_mutation_guardrail(self, context: ServiceContext, *, resource_id: str, action: str, payload: dict[str, object]) -> list[dict[str, object]]:
        policy_outcome = payload.get("policyOutcome") if isinstance(payload.get("policyOutcome"), dict) else {}
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type="replay_repository",
            resource_id=resource_id,
            payload={"action": action, **payload},
        )
        RuntimeGuardrailEngine(self.db).record_result(
            guardrail_context,
            GuardrailResult(
                rule_id="replay_repository.mutation_preflight",
                decision=GuardrailDecision.ALLOW,
                reason="Replay Repository mutation passed P0 governance preflight",
                evidence=[action],
                metadata={"approvalMode": policy_outcome.get("approvalMode", DEFAULT_APPROVAL_MODE)},
            ),
        )
        self.db.flush()
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.request_id == context.request_id)
                .where(GuardrailEvent.rule_id == "replay_repository.mutation_preflight")
                .order_by(GuardrailEvent.created_at.desc())
            )
        )
        return [{"type": "guardrail_event", "id": str(event.id), "ruleId": event.rule_id, "decision": event.decision.value} for event in events[:1]]

    def _approval_guardrail_refs(self, approval_id: UUID) -> list[dict[str, object]]:
        approval = self.db.get(Approval, approval_id)
        if approval is None:
            return []
        return list(approval.payload.get("guardrailEventRefs") or [])

    def _policy_audit_refs(self) -> list[dict[str, object]]:
        rows = list(
            self.db.scalars(
                select(AuditLog)
                .where(AuditLog.resource_type == "replay_governance_policy")
                .where(AuditLog.resource_id == "global")
                .order_by(AuditLog.created_at.desc())
            )
        )
        return [{"type": "audit_log", "id": str(row.id), "action": row.action} for row in rows[:5]]

    def _policy_approval_refs(self) -> list[dict[str, object]]:
        rows = list(
            self.db.scalars(
                select(Approval)
                .where(Approval.resource_type == "replay_governance_policy")
                .where(Approval.resource_id == "global")
                .order_by(Approval.created_at.desc())
            )
        )
        return [
            {
                "type": "approval",
                "id": str(row.id),
                "state": row.status.value,
                "action": row.payload.get("action"),
            }
            for row in rows[:5]
        ]

    def _serialize_audit(self, audit: AuditLog) -> dict[str, object]:
        return {
            "id": str(audit.id),
            "actorId": str(audit.actor_id) if audit.actor_id else None,
            "action": audit.action,
            "resourceType": audit.resource_type,
            "resourceId": audit.resource_id,
            "requestId": audit.request_id,
            "traceId": str(audit.trace_id),
            "details": audit.details,
            "createdAt": audit.created_at.isoformat(),
        }


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=_json_default).encode("utf-8")


def _replay_metadata_secret_scan_projection(
    value: object,
    *,
    key: str | None = None,
) -> object:
    """Mask only validated content-addressed tokens before free-text scanning."""

    if isinstance(value, dict):
        return {
            item_key: _replay_metadata_secret_scan_projection(
                item_value,
                key=item_key,
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [
            _replay_metadata_secret_scan_projection(item)
            for item in value
        ]
    if not isinstance(value, str):
        return value

    key_lower = (key or "").lower()
    if key_lower.endswith("hash") and _CANONICAL_HASH_PATTERN.fullmatch(value):
        return "[STRUCTURED_SHA256]"
    if key_lower == "replayid" and _REPLAY_ID_PATTERN.fullmatch(value):
        return "[STRUCTURED_REPLAY_ID]"
    if key_lower == "storageref":
        match = _REPLAY_STORAGE_REF_PATTERN.fullmatch(value)
        if match is not None:
            scheme = str(match.group("scheme"))
            section = str(match.group("section"))
            return (
                f"{scheme}/[STRUCTURED_REPLAY_ID]/"
                f"{section}.[STRUCTURED_SHA256].json"
            )
    return value


def _hash_payload(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _freeze_lock(source_hash: str) -> RLock:
    try:
        lock_key = int(source_hash.removeprefix("sha256:")[-8:], 16)
    except ValueError:
        lock_key = sum(source_hash.encode("utf-8"))
    return _FREEZE_LOCKS[lock_key % len(_FREEZE_LOCKS)]


def _same_instant(value: object, expected: datetime) -> bool:
    if not isinstance(value, str):
        return False
    try:
        actual = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    normalized_actual = (
        actual.replace(tzinfo=timezone.utc)
        if actual.tzinfo is None
        else actual.astimezone(timezone.utc)
    )
    normalized_expected = (
        expected.replace(tzinfo=timezone.utc)
        if expected.tzinfo is None
        else expected.astimezone(timezone.utc)
    )
    return normalized_actual == normalized_expected


def _count_by(entries: list[ReplayRepositoryEntry], attribute: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        key = str(getattr(entry, attribute) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _json_default(value: object) -> str:
    if isinstance(value, (datetime, UUID)):
        return str(value)
    return str(value)

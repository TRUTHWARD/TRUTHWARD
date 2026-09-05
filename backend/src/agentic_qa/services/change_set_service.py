# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    ChangeNormalizationIssueRecord,
    ChangeSetRecord,
    ChangeSourceSnapshot,
    CodeChangeFileRecord,
    CodeChangeHunkRecord,
    CodeChangeSetRecord,
    CodeChangeSymbolRecord,
    RequirementChangeItemRecord,
    RequirementChangeSetRecord,
    RequirementVersion,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.artifact_storage import ArtifactStorageAdapter, artifact_storage_adapter
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.redaction import redact_sensitive_data
from agentic_qa.infra.trace import ensure_trace, traced_operation
from agentic_qa.schemas.change_sets import CodeChangeSetIngestRequest, RequirementChangeSetIngestRequest
from agentic_qa.services.change_normalizer import (
    CHANGE_NORMALIZER_VERSION,
    CodeNormalizationResult,
    NormalizationIssueData,
    RequirementNormalizationResult,
    normalize_code_diff,
    normalize_requirement_changes,
)
from agentic_qa.services.change_set_query_service import (
    ChangeSetError,
    ChangeSetQueryService,
    ChangeSetScope,
)
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
)


class ChangeSetService(ChangeSetQueryService):
    """P17 Service-owned source normalization and immutable Change Set boundary."""

    def __init__(self, db: Session, *, storage: ArtifactStorageAdapter | None = None) -> None:
        super().__init__(db)
        self.storage = storage or artifact_storage_adapter()
        self.guardrails = RuntimeGuardrailEngine(db)

    def ingest_requirement(
        self,
        project_id: UUID,
        payload: RequirementChangeSetIngestRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, None, context, "change.create")
        head = self._require_requirement_version(scope, payload.headRequirementVersionId)
        base = (
            self._require_requirement_version(scope, payload.baseRequirementVersionId)
            if payload.baseRequirementVersionId
            else None
        )
        source_material = {
            "sourceType": payload.sourceType,
            "sourceId": payload.sourceId,
            "revision": payload.revision,
            "baseRequirementVersionId": str(base.id) if base else None,
            "baseContentHash": base.content_hash if base else None,
            "headRequirementVersionId": str(head.id),
            "headContentHash": head.content_hash,
            "changeHints": payload.model_dump(mode="json")["changeHints"],
        }
        content_hash = canonical_hash(source_material)
        fingerprint = self._fingerprint(scope, payload.sourceType, payload.sourceId, payload.revision, content_hash)
        acquire_transaction_advisory_lock(
            self.db,
            "p17-change-set-ingest",
            f"{scope.tenant_id}:{scope.workspace_id}:{scope.project.id}:{fingerprint}",
        )
        existing = self._find_by_fingerprint(scope, fingerprint)
        if existing is not None:
            return self._detail(existing, scope, deduplicated=True)

        normalized = normalize_requirement_changes(
            base_version_id=str(base.id) if base else None,
            base_items=list(base.requirements) if base else [],
            head_version_id=str(head.id),
            head_items=list(head.requirements),
            change_hints=payload.model_dump(mode="json")["changeHints"],
        )
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="change-set.normalization",
            trace_id=context.trace_id,
        )
        self._record_preflight(
            scope,
            context,
            change_set_type="requirement",
            sensitive=False,
            issue_count=len(normalized.issues),
            source_ref=f"requirement://versions/{head.id}",
        )
        source_refs = [
            *[item.model_dump(mode="json") for item in payload.sourceRefs],
            {
                "type": "requirement_version",
                "ref": f"requirement://versions/{head.id}",
                "contentHash": head.content_hash,
            },
        ]
        if base is not None:
            source_refs.append(
                {
                    "type": "requirement_version",
                    "ref": f"requirement://versions/{base.id}",
                    "contentHash": base.content_hash,
                }
            )
        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=None,
                root_span_name="change-set.normalization",
                span_name="requirement-change-set.normalize",
                service_name="orchestrator-service",
                attributes={
                    "projectId": str(scope.project.id),
                    "sourceType": payload.sourceType,
                    "sourceRevisionHash": canonical_hash(payload.revision),
                    "sourceContentHash": content_hash,
                    "normalizerVersion": CHANGE_NORMALIZER_VERSION,
                    "impactAnalysisPerformed": False,
                },
                parent_span_id=context.parent_span_id,
            ):
                change_set = self._create_base_records(
                    scope,
                    context,
                    change_set_type="requirement",
                    source_type=payload.sourceType,
                    source_id=payload.sourceId,
                    revision=payload.revision,
                    content_hash=content_hash,
                    fingerprint=fingerprint,
                    source_refs=source_refs,
                    source_metadata={
                        "baseRequirementVersionId": str(base.id) if base else None,
                        "headRequirementVersionId": str(head.id),
                    },
                    item_count=len(normalized.items),
                    issues=normalized.issues,
                    artifact_refs=[],
                    sensitive=False,
                )
                requirement_change_set = RequirementChangeSetRecord(
                    change_set_id=change_set.id,
                    base_requirement_version_id=base.id if base else None,
                    head_requirement_version_id=head.id,
                )
                self.db.add(requirement_change_set)
                self.db.flush([requirement_change_set])
                self._persist_requirement_items(change_set.id, base, head, normalized)
                self._write_ingest_audit(
                    scope, context, change_set, content_hash, payload.revision
                )
                self.db.flush()
            self.db.commit()
            self.db.refresh(change_set)
            return self._detail(change_set, scope, deduplicated=False)
        except IntegrityError as exc:
            self.db.rollback()
            recovered = self._find_by_fingerprint(scope, fingerprint)
            if recovered is not None:
                return self._detail(recovered, scope, deduplicated=True)
            raise ChangeSetError("CHANGE_SET_CONFLICT", status_code=409) from exc

    def ingest_code(
        self,
        project_id: UUID,
        payload: CodeChangeSetIngestRequest,
        context: ServiceContext,
        *,
        environment_id: UUID | None = None,
    ) -> dict[str, Any]:
        scope = self._require_scope(project_id, environment_id, context, "change.create")
        self._require_repository(scope, payload.repositoryRef)
        source_material = {
            "sourceType": payload.sourceType,
            "sourceId": payload.sourceId,
            "revision": payload.revision,
            "repositoryRef": payload.repositoryRef,
            "baseSha": payload.baseSha,
            "headSha": payload.headSha,
            "diffHash": canonical_hash(payload.diff),
            "encoding": payload.encoding,
            "forcePush": payload.forcePush,
            "sourceDeleted": payload.sourceDeleted,
        }
        content_hash = canonical_hash(source_material)
        fingerprint = self._fingerprint(scope, payload.sourceType, payload.sourceId, payload.revision, content_hash)
        acquire_transaction_advisory_lock(
            self.db,
            "p17-change-set-ingest",
            f"{scope.tenant_id}:{scope.workspace_id}:{scope.project.id}:{fingerprint}",
        )
        existing = self._find_by_fingerprint(scope, fingerprint)
        if existing is not None:
            return self._detail(existing, scope, deduplicated=True)

        normalized = normalize_code_diff(payload.diff)
        normalized.issues.extend(self._code_source_issues(payload))
        sensitive = normalized.redaction_count > 0
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="change-set.normalization",
            trace_id=context.trace_id,
        )
        self._record_preflight(
            scope,
            context,
            change_set_type="code",
            sensitive=sensitive,
            issue_count=len(normalized.issues),
            source_ref=payload.repositoryRef,
        )
        change_set_id = uuid4()
        artifact_refs: list[dict[str, Any]] = []
        storage_ref: str | None = None
        if normalized.redacted_diff:
            storage_result = self.storage.write_artifact(
                namespace="change-sets",
                artifact_id=str(change_set_id),
                filename="normalized.diff",
                payload=normalized.redacted_diff.encode("utf-8"),
            )
            storage_ref = str(storage_result["storageRef"])
            artifact_refs = [
                {
                    "type": "redacted_diff",
                    "ref": f"artifact://change-sets/{change_set_id}/normalized.diff",
                    "contentHash": storage_result["contentHash"],
                    "byteSize": storage_result["byteSize"],
                    "redacted": sensitive,
                }
            ]
        source_refs = [item.model_dump(mode="json") for item in payload.sourceRefs]
        source_refs.append(
            {
                "type": "repository",
                "ref": payload.repositoryRef,
                "contentHash": None,
            }
        )
        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=None,
                root_span_name="change-set.normalization",
                span_name="code-change-set.normalize",
                service_name="orchestrator-service",
                attributes={
                    "projectId": str(scope.project.id),
                    "repositoryRefHash": canonical_hash(payload.repositoryRef),
                    "baseSha": payload.baseSha,
                    "headSha": payload.headSha,
                    "sourceContentHash": content_hash,
                    "normalizerVersion": CHANGE_NORMALIZER_VERSION,
                    "redactionCount": normalized.redaction_count,
                    "impactAnalysisPerformed": False,
                },
                parent_span_id=context.parent_span_id,
            ):
                change_set = self._create_base_records(
                    scope,
                    context,
                    change_set_id=change_set_id,
                    change_set_type="code",
                    source_type=payload.sourceType,
                    source_id=payload.sourceId,
                    revision=payload.revision,
                    content_hash=content_hash,
                    fingerprint=fingerprint,
                    source_refs=source_refs,
                    source_metadata={
                        "repositoryRef": payload.repositoryRef,
                        "baseSha": payload.baseSha,
                        "headSha": payload.headSha,
                        "encoding": payload.encoding,
                        "redactionCount": normalized.redaction_count,
                        "artifactStorageRef": storage_ref,
                    },
                    item_count=len(normalized.files),
                    issues=normalized.issues,
                    artifact_refs=artifact_refs,
                    sensitive=sensitive,
                )
                code_change_set = CodeChangeSetRecord(
                    change_set_id=change_set.id,
                    repository_ref=payload.repositoryRef,
                    base_sha=payload.baseSha,
                    head_sha=payload.headSha,
                    empty_diff=not bool(payload.diff.strip()),
                    force_push=payload.forcePush,
                    base_reachable=payload.baseReachable,
                )
                self.db.add(code_change_set)
                self.db.flush([code_change_set])
                self._persist_code_files(change_set.id, normalized, artifact_refs)
                self._write_ingest_audit(
                    scope, context, change_set, content_hash, payload.revision
                )
                self.db.flush()
            self.db.commit()
            self.db.refresh(change_set)
            return self._detail(change_set, scope, deduplicated=False)
        except IntegrityError as exc:
            self.db.rollback()
            if storage_ref is not None:
                self.storage.delete_artifact(storage_ref)
            recovered = self._find_by_fingerprint(scope, fingerprint)
            if recovered is not None:
                return self._detail(recovered, scope, deduplicated=True)
            raise ChangeSetError("CHANGE_SET_CONFLICT", status_code=409) from exc
        except Exception:
            self.db.rollback()
            if storage_ref is not None:
                self.storage.delete_artifact(storage_ref)
            raise

    def _create_base_records(
        self,
        scope: ChangeSetScope,
        context: ServiceContext,
        *,
        change_set_type: str,
        source_type: str,
        source_id: str,
        revision: str,
        content_hash: str,
        fingerprint: str,
        source_refs: list[dict[str, Any]],
        source_metadata: dict[str, Any],
        item_count: int,
        issues: list[NormalizationIssueData],
        artifact_refs: list[dict[str, Any]],
        sensitive: bool,
        change_set_id: UUID | None = None,
    ) -> ChangeSetRecord:
        snapshot_id = uuid4()
        snapshot = ChangeSourceSnapshot(
            id=snapshot_id,
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=scope.project.id,
            environment_id=scope.environment.id if scope.environment else None,
            source_type=source_type,
            source_id=source_id,
            revision=revision,
            content_hash=content_hash,
            snapshot_ref=f"change-source://snapshots/{snapshot_id}",
            source_refs=redact_sensitive_data(source_refs),
            snapshot_metadata=redact_sensitive_data(source_metadata),
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
        )
        self.db.add(snapshot)
        # These immutable records intentionally expose only scalar foreign-key
        # ids and no ORM relationship. Flush the source fact first so the unit
        # of work cannot insert its ChangeSet reference ahead of the snapshot
        # on PostgreSQL. The flush remains inside the caller's transaction, so
        # any later failure rolls both records back together.
        self.db.flush([snapshot])
        normalized_status = self._status(item_count, issues)
        row = ChangeSetRecord(
            id=change_set_id or uuid4(),
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=scope.project.id,
            environment_id=scope.environment.id if scope.environment else None,
            source_snapshot_id=snapshot.id,
            change_set_type=change_set_type,
            fingerprint=fingerprint,
            normalizer_version=CHANGE_NORMALIZER_VERSION,
            status=normalized_status,
            item_count=item_count,
            issue_count=len(issues),
            sensitive=sensitive,
            artifact_refs=artifact_refs,
            replay_refs=[
                {
                    "type": "change_set_snapshot",
                    "ref": f"change-set://change-sets/{change_set_id or 'pending'}",
                    "sourceContentHash": content_hash,
                    "normalizerVersion": CHANGE_NORMALIZER_VERSION,
                }
            ],
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
        )
        row.replay_refs = [
            {
                "type": "change_set_snapshot",
                "ref": f"change-set://change-sets/{row.id}",
                "sourceContentHash": content_hash,
                "normalizerVersion": CHANGE_NORMALIZER_VERSION,
            }
        ]
        self.db.add(row)
        self.db.flush()
        self._persist_issues(row.id, issues)
        return row

    def _persist_requirement_items(
        self,
        change_set_id: UUID,
        base: RequirementVersion | None,
        head: RequirementVersion,
        normalized: RequirementNormalizationResult,
    ) -> None:
        for ordinal, item in enumerate(normalized.items, start=1):
            self.db.add(
                RequirementChangeItemRecord(
                    id=uuid4(),
                    change_set_id=change_set_id,
                    ordinal=ordinal,
                    requirement_id=item.requirement_id,
                    before_requirement_version_id=base.id if base and item.before_refs else None,
                    after_requirement_version_id=head.id if item.after_refs else None,
                    change_type=item.change_type,
                    before_refs=item.before_refs,
                    after_refs=item.after_refs,
                    changed_fields=item.changed_fields,
                    explicit_capability_refs=item.capability_refs,
                    related_requirement_ids=item.related_requirement_ids,
                    confidence=Decimal(str(item.confidence)),
                    evidence_refs=item.evidence,
                )
            )

    def _persist_code_files(
        self,
        change_set_id: UUID,
        normalized: CodeNormalizationResult,
        artifact_refs: list[dict[str, Any]],
    ) -> None:
        file_records: list[CodeChangeFileRecord] = []
        hunk_records: list[CodeChangeHunkRecord] = []
        symbol_records: list[CodeChangeSymbolRecord] = []
        for file_ordinal, item in enumerate(normalized.files, start=1):
            file_id = uuid4()
            file_records.append(
                CodeChangeFileRecord(
                    id=file_id,
                    change_set_id=change_set_id,
                    ordinal=file_ordinal,
                    path=item.path,
                    old_path=item.old_path,
                    change_type=item.change_type,
                    language=item.language,
                    binary=item.binary,
                    generated=item.generated,
                    vendor=item.vendor,
                    submodule=item.submodule,
                    risk_hints=item.risk_hints,
                    diff_artifact_refs=artifact_refs,
                )
            )
            for hunk_ordinal, hunk in enumerate(item.hunks, start=1):
                hunk_id = uuid4()
                hunk_records.append(
                    CodeChangeHunkRecord(
                        id=hunk_id,
                        file_id=file_id,
                        ordinal=hunk_ordinal,
                        header=hunk.header,
                        old_line_start=hunk.old_line_start,
                        old_line_count=hunk.old_line_count,
                        new_line_start=hunk.new_line_start,
                        new_line_count=hunk.new_line_count,
                        content_hash=hunk.content_hash,
                        diff_artifact_refs=artifact_refs,
                        sensitive=hunk.sensitive,
                        redaction_count=hunk.redaction_count,
                    )
                )
                for symbol_ordinal, symbol in enumerate(hunk.symbols, start=1):
                    symbol_records.append(
                        CodeChangeSymbolRecord(
                            id=uuid4(),
                            hunk_id=hunk_id,
                            ordinal=symbol_ordinal,
                            name=symbol.name,
                            kind=symbol.kind,
                            change_type=symbol.change_type,
                            old_line_start=symbol.old_line_start,
                            old_line_end=symbol.old_line_end,
                            new_line_start=symbol.new_line_start,
                            new_line_end=symbol.new_line_end,
                            confidence=Decimal(str(symbol.confidence)),
                            evidence_refs=symbol.evidence,
                        )
                    )

        # Preserve FK order without one round trip per file or hunk. These
        # scalar-FK fact records deliberately do not expose ORM relationships.
        if file_records:
            self.db.add_all(file_records)
            self.db.flush(file_records)
        if hunk_records:
            self.db.add_all(hunk_records)
            self.db.flush(hunk_records)
        if symbol_records:
            self.db.add_all(symbol_records)

    def _persist_issues(self, change_set_id: UUID, issues: list[NormalizationIssueData]) -> None:
        for ordinal, issue in enumerate(issues, start=1):
            self.db.add(
                ChangeNormalizationIssueRecord(
                    id=uuid4(),
                    change_set_id=change_set_id,
                    ordinal=ordinal,
                    category=issue.category,
                    code=issue.code,
                    message=issue.message,
                    field=issue.field,
                    recoverable=issue.recoverable,
                    evidence_refs=redact_sensitive_data(issue.evidence),
                )
            )

    def _record_preflight(
        self,
        scope: ChangeSetScope,
        context: ServiceContext,
        *,
        change_set_type: str,
        sensitive: bool,
        issue_count: int,
        source_ref: str,
    ) -> None:
        decision = GuardrailDecision.WARN if sensitive else GuardrailDecision.ALLOW
        self.guardrails.record_result(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=list(context.user.roles),
                resource_type="change_set",
                resource_id=str(scope.project.id),
                payload={
                    "projectId": str(scope.project.id),
                    "changeSetType": change_set_type,
                    "sensitive": sensitive,
                    "issueCount": issue_count,
                    "normalizerVersion": CHANGE_NORMALIZER_VERSION,
                    "writesGate": False,
                    "writesMemory": False,
                },
            ),
            GuardrailResult(
                rule_id="change.ingest_preflight.v1",
                decision=decision,
                reason=(
                    "Sensitive source content will be redacted before governed artifact persistence."
                    if sensitive
                    else "Change source passed scope and normalization preflight."
                ),
                evidence=[source_ref],
                metadata={"backendAuthorization": True, "impactAnalysisPerformed": False},
            ),
        )
        self.db.flush()

    def _write_ingest_audit(
        self,
        scope: ChangeSetScope,
        context: ServiceContext,
        row: ChangeSetRecord,
        content_hash: str,
        source_revision: str,
    ) -> None:
        write_audit_log(
            self.db,
            context.user.id,
            "change_set.ingest",
            "change_set",
            str(row.id),
            context.request_id,
            context.trace_id,
            details={
                "projectId": str(scope.project.id),
                "changeSetType": row.change_set_type,
                "sourceContentHash": content_hash,
                "sourceRevisionHash": canonical_hash(source_revision),
                "fingerprint": row.fingerprint,
                "normalizerVersion": row.normalizer_version,
                "status": row.status,
                "itemCount": row.item_count,
                "issueCount": row.issue_count,
                "sensitive": row.sensitive,
                "impactAnalysisPerformed": False,
            },
        )

    def _require_requirement_version(
        self,
        scope: ChangeSetScope,
        requirement_version_id: UUID,
    ) -> RequirementVersion:
        version = self.db.get(RequirementVersion, requirement_version_id)
        project_id = str(version.metadata_json.get("projectId")) if version else None
        if version is None or project_id != str(scope.project.id):
            raise ChangeSetError("CHANGE_REQUIREMENT_VERSION_NOT_FOUND", status_code=404)
        return version

    @staticmethod
    def _require_repository(scope: ChangeSetScope, repository_ref: str) -> None:
        configured = scope.project.metadata_json.get("repositories")
        if configured is None:
            configured = scope.project.metadata_json.get("repositoryRefs")
        if not isinstance(configured, list) or not configured:
            raise ChangeSetError("CHANGE_REPOSITORY_AUTHORITY_UNAVAILABLE", status_code=409)
        allowed: set[str] = set()
        for value in configured:
            if isinstance(value, str):
                allowed.add(value)
            elif isinstance(value, dict) and value.get("ref"):
                allowed.add(str(value["ref"]))
        if repository_ref not in allowed:
            raise ChangeSetError("CHANGE_REPOSITORY_NOT_FOUND", status_code=404)

    @staticmethod
    def _code_source_issues(payload: CodeChangeSetIngestRequest) -> list[NormalizationIssueData]:
        issues: list[NormalizationIssueData] = []
        if payload.forcePush:
            issues.append(NormalizationIssueData("ambiguous", "CODE_FORCE_PUSH_DETECTED", "Source history was force-pushed; base lineage requires downstream review.", "forcePush", True))
        if not payload.baseReachable:
            issues.append(NormalizationIssueData("incomplete", "CODE_BASE_SHA_UNREACHABLE", "Base SHA was not reachable from the SCM source.", "baseSha", False))
        if payload.shallowClone:
            issues.append(NormalizationIssueData("incomplete", "CODE_SHALLOW_CLONE", "SCM source reported shallow history.", "shallowClone", True))
        if payload.sourceDeleted:
            issues.append(NormalizationIssueData("incomplete", "CODE_SOURCE_DELETED", "SCM source was deleted after the referenced revision.", "sourceDeleted", True))
        if payload.encoding.lower().replace("_", "-") != "utf-8":
            issues.append(NormalizationIssueData("unsupported", "CODE_ENCODING_NON_UTF8", "Diff was decoded from a non-UTF-8 source encoding.", "encoding", True))
        return issues

    @staticmethod
    def _status(item_count: int, issues: list[NormalizationIssueData]) -> str:
        if item_count == 0 or any(not issue.recoverable for issue in issues):
            return "unknown"
        return "partial" if issues else "completed"

    @staticmethod
    def _fingerprint(
        scope: ChangeSetScope,
        source_type: str,
        source_id: str,
        revision: str,
        content_hash: str,
    ) -> str:
        return canonical_hash(
            {
                "tenantId": scope.tenant_id,
                "workspaceId": scope.workspace_id,
                "projectId": str(scope.project.id),
                "sourceType": source_type,
                "sourceId": source_id,
                "revision": revision,
                "contentHash": content_hash,
            }
        )

    def _find_by_fingerprint(self, scope: ChangeSetScope, fingerprint: str) -> ChangeSetRecord | None:
        return self.db.scalar(
            select(ChangeSetRecord).where(
                ChangeSetRecord.tenant_id == scope.tenant_id,
                ChangeSetRecord.workspace_id == scope.workspace_id,
                ChangeSetRecord.project_id == scope.project.id,
                ChangeSetRecord.fingerprint == fingerprint,
            )
        )


__all__ = ["ChangeSetError", "ChangeSetService"]

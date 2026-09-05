# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import (
    CoverageRiskStatus,
    CoverageStatus,
    FindingSeverity,
    FindingStatus,
    ProofEdgeCurrentStatus,
    ProofStatus,
    TraceabilityRelationSource,
    TraceabilityRelationStatus,
)
from agentic_qa.domain.models import (
    CoverageProofBundleRecord,
    CoverageProofReplayRef,
    EvidenceRawFinding,
    ExecutionArtifact,
    ExecutionTask,
    ExecutionTaskEvidenceArtifact,
    Finding,
    GateDecision,
    GateDecisionReplayExport,
    GateInputSnapshot,
    NormalizedFindingGateDecision,
    RawFindingRecord,
    RawNormalizedFinding,
    RequirementItemTestPoint,
    RequirementVersion,
    TestAsset,
    TestCaseExecutionTask,
    TestPointTestCase,
    TraceabilitySnapshotRecord,
)
from agentic_qa.schemas.traceability import (
    CoverageProofBundle,
    CoverageProofChain,
    CoverageMatrixFilters,
    CoverageMatrixResponse,
    CoverageMatrixRow,
    CoverageScope,
    CoverageSummaryResponse,
    MissingLink,
    Pagination,
    ProofEdge,
    RelationRef,
    TraceabilityNode,
    TraceabilityPathResponse,
    TraceabilityRelationView,
    TraceabilitySnapshot,
)
from agentic_qa.schemas.requirement_scope import (
    REQUIREMENT_SCOPE_V2_SCHEMA_VERSION,
    normalize_requirement_scope,
    requirement_scope_item_id,
    scope_item_ids,
    scope_item_refs,
    scope_version_ids,
)
from agentic_qa.services.common import ServiceContext


EFFECTIVE_RELATION_STATUSES = {
    TraceabilityRelationStatus.CONFIRMED,
    TraceabilityRelationStatus.SYSTEM_VERIFIED,
}

CANDIDATE_RELATION_SOURCES = {
    TraceabilityRelationSource.MODEL_CANDIDATE,
    TraceabilityRelationSource.METADATA_CANDIDATE,
    TraceabilityRelationSource.STRING_MATCH_CANDIDATE,
}


@dataclass(frozen=True)
class RelationSpec:
    table: str
    model: type
    source_field: str
    target_field: str
    source_type: str
    target_type: str


RELATION_SPECS: dict[str, RelationSpec] = {
    "requirement_item_test_points": RelationSpec(
        "requirement_item_test_points",
        RequirementItemTestPoint,
        "requirement_item_id",
        "test_point_id",
        "requirement_item",
        "test_point",
    ),
    "test_point_test_cases": RelationSpec(
        "test_point_test_cases",
        TestPointTestCase,
        "test_point_id",
        "test_case_id",
        "test_point",
        "test_case",
    ),
    "test_case_execution_tasks": RelationSpec(
        "test_case_execution_tasks",
        TestCaseExecutionTask,
        "test_case_id",
        "execution_task_id",
        "test_case",
        "execution_task",
    ),
    "execution_task_evidence_artifacts": RelationSpec(
        "execution_task_evidence_artifacts",
        ExecutionTaskEvidenceArtifact,
        "execution_task_id",
        "evidence_artifact_id",
        "execution_task",
        "evidence_artifact",
    ),
    "evidence_raw_findings": RelationSpec(
        "evidence_raw_findings",
        EvidenceRawFinding,
        "evidence_artifact_id",
        "raw_finding_id",
        "evidence_artifact",
        "raw_finding",
    ),
    "raw_normalized_findings": RelationSpec(
        "raw_normalized_findings",
        RawNormalizedFinding,
        "raw_finding_id",
        "normalized_finding_id",
        "raw_finding",
        "normalized_finding",
    ),
    "normalized_finding_gate_decisions": RelationSpec(
        "normalized_finding_gate_decisions",
        NormalizedFindingGateDecision,
        "normalized_finding_id",
        "gate_decision_id",
        "normalized_finding",
        "gate_decision",
    ),
    "gate_decision_replay_exports": RelationSpec(
        "gate_decision_replay_exports",
        GateDecisionReplayExport,
        "gate_decision_id",
        "replay_export_id",
        "gate_decision",
        "replay_export",
    ),
}


class TraceabilityService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_relation(
        self,
        table: str,
        *,
        source_id: str | UUID,
        target_id: str | UUID,
        scope_id: str,
        relation_type: str = "covers",
        source: TraceabilityRelationSource = TraceabilityRelationSource.MANUAL,
        status: TraceabilityRelationStatus = TraceabilityRelationStatus.CANDIDATE,
        confidence: float = 1.0,
        context: ServiceContext | None = None,
        metadata: dict[str, Any] | None = None,
        **extra_fields: Any,
    ) -> Any:
        spec = RELATION_SPECS[table]
        if status in EFFECTIVE_RELATION_STATUSES and source in CANDIDATE_RELATION_SOURCES:
            raise ValueError("candidate relation sources must be validated before becoming effective")
        relation = spec.model(
            **{
                spec.source_field: source_id,
                spec.target_field: target_id,
                "scope_id": scope_id,
                "relation_type": relation_type,
                "source": source,
                "status": status,
                "confidence": Decimal(str(confidence)),
                "created_by": context.user.id if context else None,
                "trace_id": _uuid_or_none(context.trace_id) if context else None,
                "metadata_json": metadata or {},
                **extra_fields,
            }
        )
        self.db.add(relation)
        self.db.flush()
        return relation

    def confirm_relation(self, table: str, relation_id: UUID, context: ServiceContext | None = None) -> Any:
        relation = self._get_relation(table, relation_id)
        if relation.source in CANDIDATE_RELATION_SOURCES:
            relation.source = TraceabilityRelationSource.MANUAL
        relation.status = TraceabilityRelationStatus.CONFIRMED
        relation.validated_at = _utcnow()
        relation.validated_by = context.user.id if context else None
        self.db.flush()
        return relation

    def invalidate_relation(self, table: str, relation_id: UUID, reason: str, context: ServiceContext | None = None) -> Any:
        relation = self._get_relation(table, relation_id)
        relation.status = TraceabilityRelationStatus.INVALID
        relation.invalidated_at = _utcnow()
        relation.invalidated_reason = reason
        relation.validated_by = context.user.id if context else relation.validated_by
        self.db.flush()
        return relation

    def mark_stale_for_object(self, object_type: str, object_id: str | UUID, reason: str) -> int:
        count = 0
        object_id_text = str(object_id)
        for spec in RELATION_SPECS.values():
            if spec.source_type == object_type:
                count += self._mark_matching_relations_stale(spec, spec.source_field, object_id_text, reason)
            if spec.target_type == object_type:
                count += self._mark_matching_relations_stale(spec, spec.target_field, object_id_text, reason)
        self.db.flush()
        return count

    def coverage_summary(
        self,
        requirement_version_id: UUID,
        *,
        requirement_scope: dict[str, Any] | None = None,
        selected_requirement_item_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        matrix = self.coverage_matrix(
            requirement_version_id=requirement_version_id,
            requirement_scope=requirement_scope,
            selected_requirement_item_ids=selected_requirement_item_ids,
            page=1,
            page_size=100,
            include_all=True,
        )
        return matrix.summary.model_dump(mode="json")

    def coverage_matrix(
        self,
        *,
        requirement_version_id: UUID,
        page: int = 1,
        page_size: int = 50,
        coverage_status: CoverageStatus | None = None,
        risk_status: CoverageRiskStatus | None = None,
        missing_link_code: str | None = None,
        requirement_item_id: str | None = None,
        requirement_scope: dict[str, Any] | None = None,
        selected_requirement_item_ids: list[str] | None = None,
        include_all: bool = False,
    ) -> CoverageMatrixResponse:
        now = _utcnow()
        scope_payload = self._normalize_requirement_scope(
            requirement_version_id,
            requirement_scope=requirement_scope,
            selected_requirement_item_ids=selected_requirement_item_ids,
            filters={
                "coverageStatus": coverage_status.value if coverage_status else None,
                "riskStatus": risk_status.value if risk_status else None,
                "missingLinkCode": missing_link_code,
                "requirementItemId": requirement_item_id,
            },
        )
        scope_id = str(scope_payload["scopeId"])
        selected_scope_item_ids = scope_item_ids(scope_payload)
        items = self._active_requirement_items(
            requirement_version_id,
            requirement_scope=scope_payload,
            selected_requirement_item_ids=selected_scope_item_ids,
        )
        scope = CoverageScope(
            schemaVersion=str(scope_payload.get("schemaVersion")),
            requirementVersionId=requirement_version_id,
            requirementVersionIds=scope_version_ids(scope_payload),
            requirementItemRefs=list(scope_payload.get("requirementItemRefs") or []),
            scopeItemRefs=scope_item_refs(scope_payload),
            scopeId=scope_id,
            selectedRequirementItemIds=selected_scope_item_ids,
            activeInScopeRequirementItems=len(items),
            filters={
                "coverageStatus": coverage_status.value if coverage_status else None,
                "riskStatus": risk_status.value if risk_status else None,
                "missingLinkCode": missing_link_code,
                "requirementItemId": requirement_item_id,
            },
            metadata=dict(scope_payload.get("metadata") or {}),
        )
        if not items:
            summary = CoverageSummaryResponse(
                requirementVersionId=requirement_version_id,
                requirementVersionIds=scope.requirementVersionIds,
                scope=scope,
                status=CoverageStatus.NOT_APPLICABLE,
                reason="EMPTY_SCOPE",
                missingLinks=[],
                calculatedAt=now,
            )
            return CoverageMatrixResponse(
                requirementVersionId=requirement_version_id,
                requirementVersionIds=scope_version_ids(scope_payload),
                summary=summary,
                rows=[],
                missingLinks=[],
                status=CoverageStatus.NOT_APPLICABLE,
                scope=scope,
                calculatedAt=now,
                pagination=Pagination(page=page, pageSize=page_size, total=0),
                filters=CoverageMatrixFilters(
                    coverageStatus=coverage_status,
                    riskStatus=risk_status,
                    missingLinkCode=missing_link_code,
                    requirementItemId=requirement_item_id,
                ),
            )

        graph = self._load_scope_graph(scope_id)
        rows = [self._build_matrix_row(requirement_version_id, item, graph) for item in items]
        rows = self._filter_rows(rows, coverage_status, risk_status, missing_link_code, requirement_item_id)
        all_missing = [missing for row in rows for missing in row.missingLinks]
        summary = self._build_summary(requirement_version_id, scope, rows, graph, now)
        selected_rows = rows if include_all else rows[(page - 1) * page_size : page * page_size]
        return CoverageMatrixResponse(
            requirementVersionId=requirement_version_id,
            requirementVersionIds=scope_version_ids(scope_payload),
            summary=summary,
            rows=selected_rows,
            missingLinks=all_missing,
            status=summary.status,
            scope=scope,
            calculatedAt=now,
            pagination=Pagination(page=page, pageSize=page_size, total=len(rows)),
            filters=CoverageMatrixFilters(
                coverageStatus=coverage_status,
                riskStatus=risk_status,
                missingLinkCode=missing_link_code,
                requirementItemId=requirement_item_id,
            ),
        )

    def traceability_for_requirement(self, requirement_item_id: str) -> dict[str, Any]:
        relations = self._effective_relations(RequirementItemTestPoint)
        relations = [relation for relation in relations if relation.requirement_item_id == requirement_item_id]
        missing = []
        if not relations:
            missing.append(_missing("MISSING_TEST_POINT", "requirement_item", requirement_item_id, "test_point"))
        return TraceabilityPathResponse(
            sourceType="requirement_item",
            sourceId=requirement_item_id,
            downstreamPath=[self._node("test_point", relation.test_point_id) for relation in relations],
            relationStatus=[self._relation_view("requirement_item_test_points", relation) for relation in relations],
            missingLinks=missing,
            staleLinks=[],
        ).model_dump(mode="json")

    def traceability_for_test_case(self, test_case_id: UUID) -> dict[str, Any]:
        upstream = [relation for relation in self._effective_relations(TestPointTestCase) if relation.test_case_id == test_case_id]
        downstream = [relation for relation in self._effective_relations(TestCaseExecutionTask) if relation.test_case_id == test_case_id]
        missing = []
        if not upstream:
            missing.append(_missing("MISSING_TEST_POINT", "test_case", str(test_case_id), "test_point"))
        if not downstream:
            missing.append(_missing("MISSING_EXECUTION_TASK", "test_case", str(test_case_id), "execution_task"))
        return TraceabilityPathResponse(
            sourceType="test_case",
            sourceId=str(test_case_id),
            upstreamPath=[self._node("test_point", relation.test_point_id) for relation in upstream],
            downstreamPath=[self._node("execution_task", relation.execution_task_id) for relation in downstream],
            relationStatus=[
                *[self._relation_view("test_point_test_cases", relation) for relation in upstream],
                *[self._relation_view("test_case_execution_tasks", relation) for relation in downstream],
            ],
            missingLinks=missing,
            staleLinks=[],
        ).model_dump(mode="json")

    def traceability_for_evidence(self, evidence_artifact_id: UUID) -> dict[str, Any]:
        upstream = [relation for relation in self._effective_relations(ExecutionTaskEvidenceArtifact) if relation.evidence_artifact_id == evidence_artifact_id]
        downstream = [relation for relation in self._effective_relations(EvidenceRawFinding) if relation.evidence_artifact_id == evidence_artifact_id]
        missing = []
        if not downstream:
            missing.append(_missing("MISSING_RAW_FINDING", "evidence_artifact", str(evidence_artifact_id), "raw_finding", blocks=False))
        return TraceabilityPathResponse(
            sourceType="evidence_artifact",
            sourceId=str(evidence_artifact_id),
            upstreamPath=[self._node("execution_task", relation.execution_task_id) for relation in upstream],
            downstreamPath=[self._node("raw_finding", relation.raw_finding_id) for relation in downstream],
            relationStatus=[
                *[self._relation_view("execution_task_evidence_artifacts", relation) for relation in upstream],
                *[self._relation_view("evidence_raw_findings", relation) for relation in downstream],
            ],
            missingLinks=missing,
            staleLinks=[],
        ).model_dump(mode="json")

    def traceability_for_finding(self, normalized_finding_id: UUID) -> dict[str, Any]:
        upstream = [relation for relation in self._effective_relations(RawNormalizedFinding) if relation.normalized_finding_id == normalized_finding_id]
        downstream = [relation for relation in self._effective_relations(NormalizedFindingGateDecision) if relation.normalized_finding_id == normalized_finding_id]
        missing = []
        if not upstream:
            missing.append(_missing("MISSING_RAW_FINDING", "normalized_finding", str(normalized_finding_id), "raw_finding"))
        if not downstream:
            missing.append(_missing("MISSING_GATE_DECISION", "normalized_finding", str(normalized_finding_id), "gate_decision", blocks=False))
        return TraceabilityPathResponse(
            sourceType="normalized_finding",
            sourceId=str(normalized_finding_id),
            upstreamPath=[self._node("raw_finding", relation.raw_finding_id) for relation in upstream],
            downstreamPath=[self._node("gate_decision", relation.gate_decision_id) for relation in downstream],
            relationStatus=[
                *[self._relation_view("raw_normalized_findings", relation) for relation in upstream],
                *[self._relation_view("normalized_finding_gate_decisions", relation) for relation in downstream],
            ],
            missingLinks=missing,
            staleLinks=[],
        ).model_dump(mode="json")

    def traceability_for_gate_decision(self, gate_decision_id: UUID) -> dict[str, Any]:
        upstream = [relation for relation in self._effective_relations(NormalizedFindingGateDecision) if relation.gate_decision_id == gate_decision_id]
        downstream = [relation for relation in self._effective_relations(GateDecisionReplayExport) if relation.gate_decision_id == gate_decision_id]
        missing = []
        if not upstream:
            missing.append(_missing("MISSING_NORMALIZED_FINDING", "gate_decision", str(gate_decision_id), "normalized_finding"))
        if not downstream:
            missing.append(_missing("MISSING_REPLAY_EXPORT", "gate_decision", str(gate_decision_id), "replay_export", blocks=False))
        return TraceabilityPathResponse(
            sourceType="gate_decision",
            sourceId=str(gate_decision_id),
            upstreamPath=[self._node("normalized_finding", relation.normalized_finding_id) for relation in upstream],
            downstreamPath=[self._node("replay_export", relation.replay_export_id) for relation in downstream],
            relationStatus=[
                *[self._relation_view("normalized_finding_gate_decisions", relation) for relation in upstream],
                *[self._relation_view("gate_decision_replay_exports", relation) for relation in downstream],
            ],
            missingLinks=missing,
            staleLinks=[],
        ).model_dump(mode="json")

    def freeze_traceability_snapshot(
        self,
        requirement_version_id: UUID,
        *,
        requirement_scope: dict[str, Any] | None = None,
        selected_requirement_item_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        matrix = self.coverage_matrix(
            requirement_version_id=requirement_version_id,
            requirement_scope=requirement_scope,
            selected_requirement_item_ids=selected_requirement_item_ids,
            page=1,
            page_size=100,
            include_all=True,
        )
        payload = matrix.model_dump(mode="json")
        snapshot_hash = canonical_hash(payload)
        scope_payload = matrix.scope.model_dump(mode="json")
        snapshot = TraceabilitySnapshot(
            traceabilitySnapshotRef=f"traceability://{requirement_version_id}/{scope_payload['scopeId']}/{snapshot_hash.removeprefix('sha256:')}",
            traceabilitySnapshotHash=snapshot_hash,
            requirementScope=scope_payload,
            coverageSummarySnapshot=matrix.summary.model_dump(mode="json"),
            coverageMatrixSnapshotRef=f"coverage-matrix://{requirement_version_id}/{scope_payload['scopeId']}/{snapshot_hash.removeprefix('sha256:')}",
            createdAt=_utcnow(),
        )
        return snapshot.model_dump(mode="json")

    def freeze_traceability_snapshot_record(
        self,
        requirement_version_id: UUID,
        *,
        requirement_scope: dict[str, Any] | None = None,
        selected_requirement_item_ids: list[str] | None = None,
    ) -> TraceabilitySnapshotRecord:
        matrix = self.coverage_matrix(
            requirement_version_id=requirement_version_id,
            requirement_scope=requirement_scope,
            selected_requirement_item_ids=selected_requirement_item_ids,
            page=1,
            page_size=100,
            include_all=True,
        )
        scope_payload = matrix.scope.model_dump(mode="json")
        scope_id = str(scope_payload["scopeId"])
        matrix_payload = matrix.model_dump(mode="json")
        coverage_matrix_snapshot_hash = canonical_hash(matrix_payload)
        coverage_matrix_hash_key = coverage_matrix_snapshot_hash.removeprefix("sha256:")
        relation_snapshot = self._relation_snapshot(scope_id)
        traceability_payload = {
            "requirementVersionId": str(requirement_version_id),
            "scopeId": scope_id,
            "requirementScope": scope_payload,
            "relationSnapshot": relation_snapshot,
            "coverageMatrixSnapshotHash": coverage_matrix_snapshot_hash,
            "coverageSummarySnapshot": matrix.summary.model_dump(mode="json"),
        }
        traceability_snapshot_hash = canonical_hash(traceability_payload)
        traceability_hash_key = traceability_snapshot_hash.removeprefix("sha256:")
        existing = self.db.scalar(
            select(TraceabilitySnapshotRecord).where(
                TraceabilitySnapshotRecord.traceability_snapshot_hash == traceability_snapshot_hash
            )
        )
        if existing is not None:
            return existing

        record = TraceabilitySnapshotRecord(
            requirement_version_id=requirement_version_id,
            scope_id=scope_id,
            traceability_snapshot_ref=f"traceability://{requirement_version_id}/{scope_id}/{traceability_hash_key}",
            traceability_snapshot_hash=traceability_snapshot_hash,
            traceability_snapshot=traceability_payload,
            coverage_summary_snapshot=matrix.summary.model_dump(mode="json"),
            coverage_matrix_snapshot_ref=f"coverage-matrix://{requirement_version_id}/{scope_id}/{coverage_matrix_hash_key}",
            coverage_matrix_snapshot_hash=coverage_matrix_snapshot_hash,
            coverage_matrix_snapshot=matrix_payload,
            relation_snapshot=relation_snapshot,
        )
        self.db.add(record)
        self.db.flush()
        return record

    def coverage_proof(
        self,
        *,
        requirement_version_id: UUID,
        requirement_item_id: str,
        replay_export_hash: str | None = None,
        requirement_scope: dict[str, Any] | None = None,
        selected_requirement_item_ids: list[str] | None = None,
        context: ServiceContext | None = None,
    ) -> dict[str, Any]:
        scope_payload = self._normalize_requirement_scope(
            requirement_version_id,
            requirement_scope=requirement_scope,
            selected_requirement_item_ids=selected_requirement_item_ids,
        )
        scope_id = str(scope_payload["scopeId"])
        if replay_export_hash is not None:
            historical = self.db.scalar(
                select(CoverageProofBundleRecord)
                .join(TraceabilitySnapshotRecord, CoverageProofBundleRecord.traceability_snapshot_id == TraceabilitySnapshotRecord.id)
                .where(
                    CoverageProofBundleRecord.requirement_version_id == requirement_version_id,
                    CoverageProofBundleRecord.requirement_item_id == requirement_item_id,
                    CoverageProofBundleRecord.replay_export_hash == replay_export_hash,
                    TraceabilitySnapshotRecord.scope_id == scope_id,
                )
                .order_by(CoverageProofBundleRecord.created_at.desc())
            )
            if historical is None:
                replay_ref = self.db.scalar(
                    select(CoverageProofReplayRef)
                    .join(CoverageProofBundleRecord, CoverageProofReplayRef.coverage_proof_bundle_id == CoverageProofBundleRecord.id)
                    .join(TraceabilitySnapshotRecord, CoverageProofBundleRecord.traceability_snapshot_id == TraceabilitySnapshotRecord.id)
                    .where(
                        CoverageProofBundleRecord.requirement_version_id == requirement_version_id,
                        CoverageProofBundleRecord.requirement_item_id == requirement_item_id,
                        CoverageProofReplayRef.replay_export_hash == replay_export_hash,
                        TraceabilitySnapshotRecord.scope_id == scope_id,
                    )
                    .order_by(CoverageProofReplayRef.created_at.desc())
                )
                if replay_ref is not None:
                    historical = self.db.get(CoverageProofBundleRecord, replay_ref.coverage_proof_bundle_id)
            if historical is None:
                raise ValueError(f"coverage proof not found for replayExportHash: {replay_export_hash}")
            return dict(historical.proof_bundle)

        snapshot_record = self.freeze_traceability_snapshot_record(
            requirement_version_id,
            requirement_scope=scope_payload,
        )
        bundle_payload, first_gate_snapshot_id = self._build_coverage_proof_bundle(
            snapshot_record=snapshot_record,
            requirement_item_id=requirement_item_id,
            trace_id=context.trace_id if context else None,
        )
        first_replay_ref, first_replay_hash = self._first_replay_ref(bundle_payload)
        record = CoverageProofBundleRecord(
            requirement_version_id=requirement_version_id,
            requirement_item_id=requirement_item_id,
            traceability_snapshot_id=snapshot_record.id,
            gate_input_snapshot_id=first_gate_snapshot_id,
            coverage_status=CoverageStatus(bundle_payload["coverageStatus"]),
            proof_status=ProofStatus(bundle_payload["proofStatus"]),
            proof_bundle=bundle_payload,
            proof_chain=bundle_payload["proofChain"],
            proof_issues=bundle_payload["proofIssues"],
            replay_export_ref=first_replay_ref,
            replay_export_hash=first_replay_hash,
            trace_id=_uuid_or_none(context.trace_id) if context else None,
        )
        self.db.add(record)
        self.db.flush()
        self._persist_coverage_proof_replay_refs(record, bundle_payload)
        return bundle_payload

    def ensure_requirement_execution_chain(
        self,
        *,
        requirement_version_id: UUID,
        test_plan_id: UUID,
        execution_id: UUID,
        requirement_scope: dict[str, Any] | None = None,
    ) -> None:
        scope_payload = self._normalize_requirement_scope(requirement_version_id, requirement_scope=requirement_scope)
        scope_id = str(scope_payload["scopeId"])
        assets = list(
            self.db.scalars(
                select(TestAsset)
                .where(
                    TestAsset.requirement_version_id == requirement_version_id,
                    TestAsset.test_plan_id == test_plan_id,
                )
                .order_by(TestAsset.created_at.asc())
            )
        )
        test_points = [asset for asset in assets if asset.asset_type == "test_point"]
        test_cases = [asset for asset in assets if asset.asset_type == "test_case"]
        tasks = list(
            self.db.scalars(
                select(ExecutionTask)
                .where(ExecutionTask.execution_id == execution_id)
                .order_by(ExecutionTask.priority.asc(), ExecutionTask.created_at.asc())
            )
        )
        artifacts = list(
            self.db.scalars(
                select(ExecutionArtifact)
                .where(ExecutionArtifact.execution_id == execution_id)
                .order_by(ExecutionArtifact.created_at.asc())
            )
        )
        raw_findings = list(
            self.db.scalars(
                select(RawFindingRecord)
                .where(RawFindingRecord.execution_id == execution_id)
                .order_by(RawFindingRecord.created_at.asc())
            )
        )
        findings = list(
            self.db.scalars(
                select(Finding)
                .where(Finding.execution_id == execution_id)
                .order_by(Finding.created_at.asc())
            )
        )
        gate = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution_id))
        requirement_items = {
            item["id"]: item
            for item in self._active_requirement_items(
                requirement_version_id,
                requirement_scope=scope_payload,
                selected_requirement_item_ids=scope_item_ids(scope_payload),
            )
        }

        points_by_requirement: dict[str, list[TestAsset]] = {}
        for point in test_points:
            for requirement_item_id in self._verified_asset_requirement_item_ids(point, requirement_items):
                points_by_requirement.setdefault(requirement_item_id, []).append(point)
                self._ensure_relation(
                    "requirement_item_test_points",
                    source_id=requirement_item_id,
                    target_id=point.id,
                    scope_id=scope_id,
                    relation_type="covers",
                    source=TraceabilityRelationSource.DETERMINISTIC_RULE,
                    requirement_version_id=UUID(
                        str(requirement_items[requirement_item_id].get("requirementVersionId") or requirement_version_id)
                    ),
                )

        for case in test_cases:
            case_requirement_ids = set(self._verified_asset_requirement_item_ids(case, requirement_items))
            point_candidates = [
                point
                for requirement_item_id in case_requirement_ids
                for point in points_by_requirement.get(requirement_item_id, [])
                if point.domain == case.domain
            ]
            if not point_candidates:
                point_candidates = [
                    point
                    for requirement_item_id in case_requirement_ids
                    for point in points_by_requirement.get(requirement_item_id, [])
                ]
            for point in point_candidates:
                self._ensure_relation(
                    "test_point_test_cases",
                    source_id=point.id,
                    target_id=case.id,
                    scope_id=scope_id,
                    relation_type="covers",
                    source=TraceabilityRelationSource.DETERMINISTIC_RULE,
                )

        test_cases_by_id = {str(case.id): case for case in test_cases}
        for task in tasks:
            asset_id = str(task.config.get("assetId") or "")
            if not asset_id or asset_id not in test_cases_by_id:
                continue
            self._ensure_relation(
                "test_case_execution_tasks",
                source_id=test_cases_by_id[asset_id].id,
                target_id=task.id,
                scope_id=scope_id,
                relation_type="covers",
                source=TraceabilityRelationSource.EXECUTION_RESULT,
                run_id=execution_id,
            )

        for artifact in artifacts:
            if artifact.task_id is None:
                continue
            self._ensure_relation(
                "execution_task_evidence_artifacts",
                source_id=artifact.task_id,
                target_id=artifact.id,
                scope_id=scope_id,
                relation_type="covers",
                source=TraceabilityRelationSource.EXECUTION_RESULT,
                artifact_type=artifact.artifact_type.value,
            )

        for raw in raw_findings:
            for artifact_id in self._raw_finding_artifact_ids(raw):
                self._ensure_relation(
                    "evidence_raw_findings",
                    source_id=artifact_id,
                    target_id=raw.id,
                    scope_id=scope_id,
                    relation_type="supports",
                    source=TraceabilityRelationSource.EXECUTION_RESULT,
                )
            if raw.normalized_finding_id is not None:
                self._ensure_relation(
                    "raw_normalized_findings",
                    source_id=raw.id,
                    target_id=raw.normalized_finding_id,
                    scope_id=scope_id,
                    relation_type="normalizes",
                    source=TraceabilityRelationSource.DETERMINISTIC_RULE,
                    normalization_method="dedupe",
                    dedupe_key=raw.dedupe_key,
                )

        if gate is None:
            return
        for finding in findings:
            impact = "informational"
            if finding.status == FindingStatus.OPEN:
                impact = "blocking" if finding.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL} else "warning"
            self._ensure_relation(
                "normalized_finding_gate_decisions",
                source_id=finding.id,
                target_id=gate.id,
                scope_id=scope_id,
                relation_type="impacts",
                source=TraceabilityRelationSource.DETERMINISTIC_RULE,
                impact=impact,
                reason="normalized finding evaluated by gate",
            )

    def ensure_gate_replay_export_relation(
        self,
        *,
        requirement_version_id: UUID,
        execution_id: UUID,
        replay_export_id: str,
        replay_export_hash: str,
        requirement_scope: dict[str, Any] | None = None,
    ) -> None:
        gate = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution_id))
        if gate is None:
            return
        self._ensure_relation(
            "gate_decision_replay_exports",
            source_id=gate.id,
            target_id=replay_export_id,
            scope_id=str(self._normalize_requirement_scope(requirement_version_id, requirement_scope=requirement_scope)["scopeId"]),
            relation_type="included_in_replay",
            source=TraceabilityRelationSource.DETERMINISTIC_RULE,
            export_hash=replay_export_hash,
        )

    def _ensure_relation(
        self,
        table: str,
        *,
        source_id: object,
        target_id: object,
        scope_id: str,
        relation_type: str,
        source: TraceabilityRelationSource,
        **extra_fields: object,
    ) -> None:
        spec = RELATION_SPECS[table]
        existing = self.db.scalar(
            select(spec.model).where(
                getattr(spec.model, spec.source_field) == source_id,
                getattr(spec.model, spec.target_field) == target_id,
                spec.model.scope_id == scope_id,
                spec.model.relation_type == relation_type,
                spec.model.status.in_(EFFECTIVE_RELATION_STATUSES),
            )
        )
        if existing is not None:
            return
        self.create_relation(
            table,
            source_id=source_id,
            target_id=target_id,
            scope_id=scope_id,
            relation_type=relation_type,
            source=source,
            status=TraceabilityRelationStatus.SYSTEM_VERIFIED,
            confidence=1.0,
            metadata={"owner": "traceability-service"},
            **extra_fields,
        )

    def _verified_asset_requirement_item_ids(self, asset: TestAsset, requirement_items: dict[str, dict[str, Any]]) -> list[str]:
        verified: list[str] = []
        for ref in asset.requirement_refs or []:
            requirement_item_id = self._requirement_item_id(ref)
            requirement_item = requirement_items.get(requirement_item_id)
            if requirement_item is None:
                continue
            if self._asset_text_matches_requirement(asset, str(requirement_item["text"])):
                verified.append(requirement_item_id)
        return verified

    def _asset_text_matches_requirement(self, asset: TestAsset, requirement_text: str) -> bool:
        haystack = f"{asset.title} {asset.objective}".lower()
        needle = requirement_text.strip().lower()
        return bool(needle and needle in haystack)

    def _requirement_item_id(self, ref: object) -> str:
        value = str(ref)
        if value.startswith("requirement-"):
            return value
        if value.isdigit():
            return f"requirement-{value}"
        return value

    def _raw_finding_artifact_ids(
        self,
        raw: RawFindingRecord,
    ) -> list[UUID]:
        artifact_ids_by_uri = {
            str(uri): artifact_id
            for uri, artifact_id in (
                (uri, self._uuid_or_none(artifact_id))
                for uri, artifact_id in dict(raw.metadata_json.get("artifactIdsByUri", {})).items()
            )
            if artifact_id is not None
        }
        artifact_ids: list[UUID] = []
        for item in raw.evidence or []:
            if item.get("type") != "artifact_ref":
                continue
            ref = item.get("ref")
            artifact_id = artifact_ids_by_uri.get(str(ref))
            if artifact_id is not None and artifact_id not in artifact_ids:
                artifact_ids.append(artifact_id)
        artifact_id = artifact_ids_by_uri.get(raw.raw_ref)
        if artifact_id is not None and artifact_id not in artifact_ids:
            artifact_ids.append(artifact_id)
        return artifact_ids

    def _uuid_or_none(self, value: object) -> UUID | None:
        try:
            return UUID(str(value))
        except (TypeError, ValueError):
            return None

    def _get_relation(self, table: str, relation_id: UUID) -> Any:
        relation = self.db.get(RELATION_SPECS[table].model, relation_id)
        if relation is None:
            raise ValueError(f"traceability relation not found: {table}/{relation_id}")
        return relation

    def _mark_matching_relations_stale(self, spec: RelationSpec, field_name: str, object_id: str, reason: str) -> int:
        count = 0
        for relation in self._effective_relations(spec.model):
            if str(getattr(relation, field_name)) == object_id:
                relation.status = TraceabilityRelationStatus.STALE
                relation.invalidated_at = _utcnow()
                relation.invalidated_reason = reason
                count += 1
        return count

    def _active_requirement_items(
        self,
        requirement_version_id: UUID,
        *,
        requirement_scope: dict[str, Any] | None = None,
        selected_requirement_item_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        if requirement_scope and requirement_scope.get("schemaVersion") == REQUIREMENT_SCOPE_V2_SCHEMA_VERSION:
            selected_by_version = {
                UUID(str(item.get("requirementVersionId"))): [
                    str(value) for value in item.get("requirementItemIds") or []
                ]
                for item in requirement_scope.get("requirementItemRefs") or []
            }
            items: list[dict[str, Any]] = []
            for version_id in scope_version_ids(requirement_scope):
                version = self.db.get(RequirementVersion, version_id)
                if version is None:
                    raise ValueError(f"requirement version not found: {version_id}")
                version_items = self._active_items_for_version(
                    version,
                    selected_ids=selected_by_version.get(version_id, []),
                )
                for item in version_items:
                    original_item_id = str(item["id"])
                    item["id"] = requirement_scope_item_id(version_id, original_item_id)
                    item["requirementVersionId"] = str(version_id)
                    item["requirementItemId"] = original_item_id
                    item["metadata"] = {
                        **dict(item.get("metadata") or {}),
                        "requirementVersionId": str(version_id),
                        "requirementItemId": original_item_id,
                    }
                    items.append(item)
            return items

        version = self.db.get(RequirementVersion, requirement_version_id)
        if version is None:
            raise ValueError(f"requirement version not found: {requirement_version_id}")
        return self._active_items_for_version(version, selected_ids=selected_requirement_item_ids or [])

    def _active_items_for_version(
        self,
        version: RequirementVersion,
        *,
        selected_ids: list[str],
    ) -> list[dict[str, Any]]:
        selected_ids = [str(item) for item in selected_ids or [] if str(item).strip()]
        selected_id_set = set(selected_ids)
        items: list[dict[str, Any]] = []
        for index, item in enumerate(version.requirements or [], start=1):
            if isinstance(item, dict):
                status = str(item.get("status") or "active")
                if status in {"deprecated", "archived", "deleted", "superseded"}:
                    continue
                if item.get("inScope", item.get("in_scope", True)) is False:
                    continue
                if item.get("notApplicable", item.get("not_applicable", False)) is True:
                    continue
                item_id = str(item.get("id") or item.get("requirementItemId") or f"requirement-{index}")
                if selected_id_set and item_id not in selected_id_set:
                    continue
                text = str(item.get("text") or item.get("title") or item_id)
                items.append({"id": item_id, "text": text, "index": index, "metadata": dict(item)})
            else:
                item_id = f"requirement-{index}"
                if selected_id_set and item_id not in selected_id_set:
                    continue
                items.append({"id": item_id, "text": str(item), "index": index, "metadata": {}})
        if selected_id_set:
            found = {str(item["id"]) for item in items}
            missing = [item_id for item_id in selected_ids if item_id not in found]
            if missing:
                raise ValueError(f"requirement scope contains unknown or inactive requirement item id: {missing[0]}")
        return items

    def _normalize_requirement_scope(
        self,
        requirement_version_id: UUID,
        *,
        requirement_scope: dict[str, Any] | None = None,
        selected_requirement_item_ids: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if requirement_scope:
            scope_requirement_version_id = UUID(str(requirement_scope.get("requirementVersionId")))
            if scope_requirement_version_id != requirement_version_id:
                raise ValueError("requirementScope.requirementVersionId must match requirementVersionId")
            selected_ids = scope_item_ids(requirement_scope)
            merged_filters = {**dict(requirement_scope.get("filters") or {}), **(filters or {})}
            scope = normalize_requirement_scope(
                requirement_version_id=requirement_version_id,
                selected_requirement_item_ids=selected_ids,
                requirement_version_ids=list(requirement_scope.get("requirementVersionIds") or []),
                requirement_item_refs=list(requirement_scope.get("requirementItemRefs") or []),
                filters=merged_filters,
                metadata=dict(requirement_scope.get("metadata") or {}),
                force_v2=str(requirement_scope.get("schemaVersion")) == REQUIREMENT_SCOPE_V2_SCHEMA_VERSION,
            )
        else:
            scope = normalize_requirement_scope(
                requirement_version_id=requirement_version_id,
                selected_requirement_item_ids=selected_requirement_item_ids or [],
                filters=filters or {},
                metadata={"selectionMode": "requirement_items" if selected_requirement_item_ids else "requirement_version"},
            )
        self._active_requirement_items(
            requirement_version_id,
            requirement_scope=scope,
            selected_requirement_item_ids=scope_item_ids(scope),
        )
        return scope

    def _load_scope_graph(self, scope_id: str) -> dict[str, list[Any]]:
        return {
            "requirement_item_test_points": self._effective_relations(RequirementItemTestPoint, scope_id),
            "test_point_test_cases": self._effective_relations(TestPointTestCase, scope_id),
            "test_case_execution_tasks": self._effective_relations(TestCaseExecutionTask, scope_id),
            "execution_task_evidence_artifacts": self._effective_relations(ExecutionTaskEvidenceArtifact, scope_id),
            "evidence_raw_findings": self._effective_relations(EvidenceRawFinding, scope_id),
            "raw_normalized_findings": self._effective_relations(RawNormalizedFinding, scope_id),
            "normalized_finding_gate_decisions": self._effective_relations(NormalizedFindingGateDecision, scope_id),
            "gate_decision_replay_exports": self._effective_relations(GateDecisionReplayExport, scope_id),
        }

    def _relation_snapshot(self, scope_id: str) -> list[dict[str, Any]]:
        graph = self._load_scope_graph(scope_id)
        snapshot: list[dict[str, Any]] = []
        for table, relations in graph.items():
            for relation in relations:
                view = self._relation_view(table, relation).model_dump(mode="json")
                if view["status"] not in {TraceabilityRelationStatus.CONFIRMED.value, TraceabilityRelationStatus.SYSTEM_VERIFIED.value}:
                    continue
                if view["source"] in {source.value for source in CANDIDATE_RELATION_SOURCES}:
                    continue
                view["traceId"] = str(relation.trace_id) if relation.trace_id else None
                if table == "gate_decision_replay_exports":
                    view["replayExportHash"] = relation.export_hash
                snapshot.append(view)
        return snapshot

    def _build_coverage_proof_bundle(
        self,
        *,
        snapshot_record: TraceabilitySnapshotRecord,
        requirement_item_id: str,
        trace_id: str | None,
    ) -> tuple[dict[str, Any], UUID | None]:
        matrix = dict(snapshot_record.coverage_matrix_snapshot)
        rows = list(matrix.get("rows") or [])
        row = next((item for item in rows if str((item.get("requirementItem") or {}).get("id")) == requirement_item_id), None)
        if row is None:
            raise ValueError(f"requirement item not found in coverage snapshot: {requirement_item_id}")

        coverage_status = CoverageStatus(str(row.get("coverageStatus")))
        chains, first_gate_snapshot_id = self._proof_chains_from_snapshot(snapshot_record, requirement_item_id)
        bundle_issues = self._bundle_issues(coverage_status, chains)
        proof_status = self._proof_status(coverage_status, chains, bundle_issues)
        scope_payload = dict(snapshot_record.traceability_snapshot.get("requirementScope") or {})
        source_requirement_version_id = UUID(
            str(row.get("requirementVersion") or snapshot_record.requirement_version_id)
        )
        bundle = CoverageProofBundle(
            schemaVersion=(
                "phase8.coverage-proof-bundle.v2"
                if scope_payload.get("schemaVersion") == REQUIREMENT_SCOPE_V2_SCHEMA_VERSION
                else "phase8.coverage-proof-bundle.v1"
            ),
            generatedAt=_utcnow(),
            requirementVersionId=source_requirement_version_id,
            primaryRequirementVersionId=snapshot_record.requirement_version_id,
            requirementVersionIds=scope_version_ids(scope_payload),
            requirementItemId=requirement_item_id,
            requirementScope=scope_payload,
            coverageStatus=coverage_status,
            proofStatus=proof_status,
            proofChain=chains,
            proofIssues=bundle_issues,
            traceId=trace_id,
        )
        return bundle.model_dump(mode="json"), first_gate_snapshot_id

    def _proof_chains_from_snapshot(
        self,
        snapshot_record: TraceabilitySnapshotRecord,
        requirement_item_id: str,
    ) -> tuple[list[CoverageProofChain], UUID | None]:
        relations = [relation for relation in snapshot_record.relation_snapshot if relation.get("scopeId") == snapshot_record.scope_id]
        by_table: dict[str, list[dict[str, Any]]] = {}
        for relation in relations:
            by_table.setdefault(str(relation["table"]), []).append(relation)

        first_gate_snapshot_id: UUID | None = None
        chains: list[CoverageProofChain] = []
        req_tp_relations = [relation for relation in by_table.get("requirement_item_test_points", []) if relation.get("sourceId") == requirement_item_id]
        for req_tp in req_tp_relations:
            tp_tc_relations = self._snapshot_relations_from(by_table, "test_point_test_cases", req_tp["targetId"])
            if not tp_tc_relations:
                chain, gate_snapshot_id = self._chain_from_snapshot_path(snapshot_record, [req_tp])
                chains.append(chain)
                first_gate_snapshot_id = first_gate_snapshot_id or gate_snapshot_id
                continue

            for tp_tc in tp_tc_relations:
                tc_task_relations = self._snapshot_relations_from(by_table, "test_case_execution_tasks", tp_tc["targetId"])
                if not tc_task_relations:
                    chain, gate_snapshot_id = self._chain_from_snapshot_path(snapshot_record, [req_tp, tp_tc])
                    chains.append(chain)
                    first_gate_snapshot_id = first_gate_snapshot_id or gate_snapshot_id
                    continue

                for tc_task in tc_task_relations:
                    task_artifact_relations = self._snapshot_relations_from(by_table, "execution_task_evidence_artifacts", tc_task["targetId"])
                    if not task_artifact_relations:
                        chain, gate_snapshot_id = self._chain_from_snapshot_path(snapshot_record, [req_tp, tp_tc, tc_task])
                        chains.append(chain)
                        first_gate_snapshot_id = first_gate_snapshot_id or gate_snapshot_id
                        continue

                    for task_artifact in task_artifact_relations:
                        evidence_raw_relations = self._snapshot_relations_from(by_table, "evidence_raw_findings", task_artifact["targetId"])
                        if not evidence_raw_relations:
                            chain, gate_snapshot_id = self._chain_from_snapshot_path(snapshot_record, [req_tp, tp_tc, tc_task, task_artifact])
                            chains.append(chain)
                            first_gate_snapshot_id = first_gate_snapshot_id or gate_snapshot_id
                            continue

                        for evidence_raw in evidence_raw_relations:
                            raw_normalized_relations = self._snapshot_relations_from(by_table, "raw_normalized_findings", evidence_raw["targetId"])
                            if not raw_normalized_relations:
                                chain, gate_snapshot_id = self._chain_from_snapshot_path(
                                    snapshot_record,
                                    [req_tp, tp_tc, tc_task, task_artifact, evidence_raw],
                                )
                                chains.append(chain)
                                first_gate_snapshot_id = first_gate_snapshot_id or gate_snapshot_id
                                continue

                            for raw_normalized in raw_normalized_relations:
                                gate_relations = self._snapshot_relations_from(
                                    by_table,
                                    "normalized_finding_gate_decisions",
                                    raw_normalized["targetId"],
                                )
                                if not gate_relations:
                                    chain, gate_snapshot_id = self._chain_from_snapshot_path(
                                        snapshot_record,
                                        [req_tp, tp_tc, tc_task, task_artifact, evidence_raw, raw_normalized],
                                    )
                                    chains.append(chain)
                                    first_gate_snapshot_id = first_gate_snapshot_id or gate_snapshot_id
                                    continue

                                for gate_relation in gate_relations:
                                    replay_relations = self._snapshot_relations_from(
                                        by_table,
                                        "gate_decision_replay_exports",
                                        gate_relation["targetId"],
                                    )
                                    if not replay_relations:
                                        chain, gate_snapshot_id = self._chain_from_snapshot_path(
                                            snapshot_record,
                                            [req_tp, tp_tc, tc_task, task_artifact, evidence_raw, raw_normalized, gate_relation],
                                        )
                                        chains.append(chain)
                                        first_gate_snapshot_id = first_gate_snapshot_id or gate_snapshot_id
                                        continue

                                    for replay_relation in replay_relations:
                                        chain, gate_snapshot_id = self._chain_from_snapshot_path(
                                            snapshot_record,
                                            [
                                                req_tp,
                                                tp_tc,
                                                tc_task,
                                                task_artifact,
                                                evidence_raw,
                                                raw_normalized,
                                                gate_relation,
                                                replay_relation,
                                            ],
                                        )
                                        chains.append(chain)
                                        first_gate_snapshot_id = first_gate_snapshot_id or gate_snapshot_id
        return chains, first_gate_snapshot_id

    def _snapshot_relations_from(self, by_table: dict[str, list[dict[str, Any]]], table: str, source_id: object) -> list[dict[str, Any]]:
        return [relation for relation in by_table.get(table, []) if str(relation.get("sourceId")) == str(source_id)]

    def _chain_from_snapshot_path(
        self,
        snapshot_record: TraceabilitySnapshotRecord,
        path: list[dict[str, Any]],
    ) -> tuple[CoverageProofChain, UUID | None]:
        edges = [self._proof_edge_from_snapshot_relation(relation) for relation in path]
        relation_by_table = {str(relation["table"]): relation for relation in path}
        gate_relation = relation_by_table.get("normalized_finding_gate_decisions")
        replay_relation = relation_by_table.get("gate_decision_replay_exports")
        gate_snapshot = self._ensure_gate_input_snapshot(gate_relation["targetId"]) if gate_relation else None
        proof_issues = self._chain_missing_issues(relation_by_table)
        for edge in edges:
            if edge.currentStatus == ProofEdgeCurrentStatus.STALE:
                proof_issues.append("stale_relation")
            if edge.currentStatus == ProofEdgeCurrentStatus.SUPERSEDED:
                proof_issues.append("superseded_relation")
            if edge.currentStatus in {ProofEdgeCurrentStatus.INVALID, ProofEdgeCurrentStatus.MISSING}:
                proof_issues.append("broken_relation")
        trace_refs = sorted({str(relation["traceId"]) for relation in path if relation.get("traceId")})
        chain = CoverageProofChain(
            testPointId=self._target_id(relation_by_table, "requirement_item_test_points"),
            testCaseId=self._target_id(relation_by_table, "test_point_test_cases"),
            executionTaskId=self._target_id(relation_by_table, "test_case_execution_tasks"),
            proofEdges=edges,
            evidenceArtifactRefs=self._typed_refs(relation_by_table, "execution_task_evidence_artifacts", "evidence_artifact"),
            rawFindingRefs=self._typed_refs(relation_by_table, "evidence_raw_findings", "raw_finding"),
            normalizedFindingRefs=self._typed_refs(relation_by_table, "raw_normalized_findings", "normalized_finding"),
            gateDecisionRef=self._target_id(relation_by_table, "normalized_finding_gate_decisions"),
            gateInputSnapshotRef=gate_snapshot.gate_input_snapshot_ref if gate_snapshot else None,
            policySnapshotRef=gate_snapshot.policy_snapshot_ref if gate_snapshot else None,
            approvalRefs=gate_snapshot.approval_refs if gate_snapshot else [],
            traceRefs=trace_refs,
            auditRefs=gate_snapshot.audit_refs if gate_snapshot else [],
            traceabilitySnapshotRef=snapshot_record.traceability_snapshot_ref,
            traceabilitySnapshotHash=snapshot_record.traceability_snapshot_hash,
            coverageMatrixSnapshotRef=snapshot_record.coverage_matrix_snapshot_ref,
            coverageMatrixSnapshotHash=snapshot_record.coverage_matrix_snapshot_hash,
            replayExportRef=replay_relation["targetId"] if replay_relation else None,
            replayExportHash=replay_relation.get("replayExportHash") if replay_relation else None,
            proofIssues=sorted(set(proof_issues)),
        )
        return chain, gate_snapshot.id if gate_snapshot else None

    def _proof_edge_from_snapshot_relation(self, relation: dict[str, Any]) -> ProofEdge:
        status = TraceabilityRelationStatus(str(relation["status"]))
        if status not in EFFECTIVE_RELATION_STATUSES:
            raise ValueError("coverage proof snapshot contains a non-effective relation")
        return ProofEdge(
            relationRef=RelationRef(
                table=str(relation["table"]),
                id=str(relation["id"]),
                status=status,
                source=TraceabilityRelationSource(str(relation["source"])),
                scopeId=str(relation["scopeId"]),
                confidence=float(relation["confidence"]),
            ),
            sourceId=str(relation["sourceId"]),
            targetId=str(relation["targetId"]),
            relationType=str(relation["relationType"]),
            frozenStatus=status,
            currentStatus=self._current_relation_status(relation),
        )

    def _current_relation_status(self, relation_snapshot: dict[str, Any]) -> ProofEdgeCurrentStatus:
        table = str(relation_snapshot["table"])
        spec = RELATION_SPECS[table]
        relation_id = self._uuid_or_none(relation_snapshot["id"])
        relation = self.db.get(spec.model, relation_id) if relation_id else None
        if relation is None:
            return ProofEdgeCurrentStatus.MISSING
        if relation.status in EFFECTIVE_RELATION_STATUSES:
            return ProofEdgeCurrentStatus(str(relation.status.value))
        if relation.status == TraceabilityRelationStatus.STALE:
            if self._has_superseding_relation(relation_snapshot):
                return ProofEdgeCurrentStatus.SUPERSEDED
            return ProofEdgeCurrentStatus.STALE
        return ProofEdgeCurrentStatus.INVALID

    def _has_superseding_relation(self, relation_snapshot: dict[str, Any]) -> bool:
        spec = RELATION_SPECS[str(relation_snapshot["table"])]
        source_id = str(relation_snapshot["sourceId"])
        target_id = str(relation_snapshot["targetId"])
        relation_id = str(relation_snapshot["id"])
        for relation in self._effective_relations(spec.model, str(relation_snapshot["scopeId"])):
            if str(relation.id) == relation_id:
                continue
            if str(getattr(relation, spec.source_field)) != source_id:
                continue
            if relation.relation_type != str(relation_snapshot["relationType"]):
                continue
            if str(getattr(relation, spec.target_field)) != target_id:
                return True
        return False

    def _ensure_gate_input_snapshot(self, gate_decision_id: object) -> GateInputSnapshot | None:
        gate_uuid = self._uuid_or_none(gate_decision_id)
        if gate_uuid is None:
            return None
        existing_for_gate = self.db.scalar(
            select(GateInputSnapshot).where(GateInputSnapshot.gate_decision_id == gate_uuid)
        )
        if existing_for_gate is not None:
            return existing_for_gate
        gate = self.db.get(GateDecision, gate_uuid)
        if gate is None:
            return None
        policy_snapshot = {
            "schemaVersion": "phase8.legacy-gate-policy-snapshot.v1",
            "source": "gate_results",
            "gateDecisionId": str(gate.id),
            "overall": gate.overall.value,
            "functional": gate.functional.value,
            "performance": gate.performance.value,
            "security": gate.security.value,
        }
        gate_input_snapshot = {
            "schemaVersion": "phase8.legacy-gate-input-snapshot.v1",
            "gateDecisionId": str(gate.id),
            "executionId": str(gate.execution_id),
            "overall": gate.overall.value,
            "reasons": list(gate.reasons or []),
            "reasonCodes": list(gate.reason_codes or []),
            "inputFingerprint": gate.input_fingerprint,
            "decisionSnapshotHash": gate.decision_snapshot_hash,
            "evaluatorVersion": gate.evaluator_version,
            "decidedBy": gate.decided_by,
        }
        gate_hash = canonical_hash(gate_input_snapshot)
        existing = self.db.scalar(select(GateInputSnapshot).where(GateInputSnapshot.gate_input_snapshot_hash == gate_hash))
        if existing is not None:
            return existing
        policy_hash = canonical_hash(policy_snapshot)
        record = GateInputSnapshot(
            gate_decision_id=gate.id,
            execution_id=gate.execution_id,
            gate_input_snapshot_ref=f"gate-input://{gate.id}/{gate_hash.removeprefix('sha256:')}",
            gate_input_snapshot_hash=gate_hash,
            gate_input_snapshot=gate_input_snapshot,
            policy_snapshot_ref=f"policy://gate/{gate.id}/{policy_hash.removeprefix('sha256:')}",
            policy_snapshot_hash=policy_hash,
            policy_snapshot=policy_snapshot,
            approval_refs=[],
            trace_refs=[],
            audit_refs=[],
        )
        self.db.add(record)
        self.db.flush()
        return record

    def _chain_missing_issues(self, relation_by_table: dict[str, dict[str, Any]]) -> list[str]:
        issues: list[str] = []
        if "test_case_execution_tasks" not in relation_by_table:
            issues.append("missing_execution")
        if "execution_task_evidence_artifacts" not in relation_by_table:
            issues.append("missing_evidence")
        if "normalized_finding_gate_decisions" not in relation_by_table:
            issues.append("missing_gate")
        if "gate_decision_replay_exports" not in relation_by_table:
            issues.append("missing_replay")
        return issues

    def _bundle_issues(self, coverage_status: CoverageStatus, chains: list[CoverageProofChain]) -> list[str]:
        issues = sorted({issue for chain in chains for issue in chain.proofIssues})
        if coverage_status in {CoverageStatus.COVERED, CoverageStatus.PARTIAL} and not chains:
            issues.append("missing_proof_chain")
        return sorted(set(issues))

    def _proof_status(self, coverage_status: CoverageStatus, chains: list[CoverageProofChain], bundle_issues: list[str]) -> ProofStatus:
        if coverage_status == CoverageStatus.NOT_COVERED and not chains and not bundle_issues:
            return ProofStatus.VALID
        current_statuses = {edge.currentStatus for chain in chains for edge in chain.proofEdges}
        if ProofEdgeCurrentStatus.SUPERSEDED in current_statuses:
            return ProofStatus.SUPERSEDED
        if ProofEdgeCurrentStatus.STALE in current_statuses:
            return ProofStatus.STALE
        if current_statuses & {ProofEdgeCurrentStatus.INVALID, ProofEdgeCurrentStatus.MISSING}:
            return ProofStatus.BROKEN
        if coverage_status in {CoverageStatus.COVERED, CoverageStatus.PARTIAL} and any(
            issue in bundle_issues for issue in {"missing_execution", "missing_evidence", "missing_gate", "missing_replay", "missing_proof_chain"}
        ):
            return ProofStatus.BROKEN
        return ProofStatus.VALID

    def _target_id(self, relation_by_table: dict[str, dict[str, Any]], table: str) -> str | None:
        relation = relation_by_table.get(table)
        return str(relation["targetId"]) if relation else None

    def _typed_refs(self, relation_by_table: dict[str, dict[str, Any]], table: str, ref_type: str) -> list[dict[str, Any]]:
        target_id = self._target_id(relation_by_table, table)
        return [{"type": ref_type, "id": target_id}] if target_id else []

    def _first_replay_ref(self, bundle_payload: dict[str, Any]) -> tuple[str | None, str | None]:
        for chain in bundle_payload.get("proofChain") or []:
            replay_ref = chain.get("replayExportRef")
            replay_hash = chain.get("replayExportHash")
            if replay_ref and replay_hash:
                return str(replay_ref), str(replay_hash)
        return None, None

    def _persist_coverage_proof_replay_refs(self, record: CoverageProofBundleRecord, bundle_payload: dict[str, Any]) -> None:
        seen_hashes: set[str] = set()
        for chain in bundle_payload.get("proofChain") or []:
            replay_ref = chain.get("replayExportRef")
            replay_hash = chain.get("replayExportHash")
            if not replay_ref or not replay_hash or replay_hash in seen_hashes:
                continue
            seen_hashes.add(str(replay_hash))
            self.db.add(
                CoverageProofReplayRef(
                    coverage_proof_bundle_id=record.id,
                    replay_export_ref=str(replay_ref),
                    replay_export_hash=str(replay_hash),
                    traceability_snapshot_ref=str(chain["traceabilitySnapshotRef"]),
                    traceability_snapshot_hash=str(chain["traceabilitySnapshotHash"]),
                    coverage_matrix_snapshot_ref=str(chain["coverageMatrixSnapshotRef"]),
                    coverage_matrix_snapshot_hash=str(chain["coverageMatrixSnapshotHash"]),
                    metadata_json={},
                )
            )
        self.db.flush()

    def _effective_relations(self, model: type, scope_id: str | None = None) -> list[Any]:
        statement = select(model).where(model.status.in_(EFFECTIVE_RELATION_STATUSES))
        if scope_id is not None:
            statement = statement.where(model.scope_id == scope_id)
        return list(self.db.scalars(statement))

    def _build_matrix_row(self, requirement_version_id: UUID, item: dict[str, Any], graph: dict[str, list[Any]]) -> CoverageMatrixRow:
        item_id = item["id"]
        req_tp = [relation for relation in graph["requirement_item_test_points"] if relation.requirement_item_id == item_id]
        test_point_ids = {relation.test_point_id for relation in req_tp}
        tp_tc = [relation for relation in graph["test_point_test_cases"] if relation.test_point_id in test_point_ids]
        test_case_ids = {relation.test_case_id for relation in tp_tc}
        tc_task = [relation for relation in graph["test_case_execution_tasks"] if relation.test_case_id in test_case_ids]
        task_ids = {relation.execution_task_id for relation in tc_task}
        task_artifact = [relation for relation in graph["execution_task_evidence_artifacts"] if relation.execution_task_id in task_ids]
        artifact_ids = {relation.evidence_artifact_id for relation in task_artifact}
        evidence_raw = [relation for relation in graph["evidence_raw_findings"] if relation.evidence_artifact_id in artifact_ids]
        raw_ids = {relation.raw_finding_id for relation in evidence_raw}
        raw_norm = [relation for relation in graph["raw_normalized_findings"] if relation.raw_finding_id in raw_ids]
        normalized_ids = {relation.normalized_finding_id for relation in raw_norm}
        norm_gate = [relation for relation in graph["normalized_finding_gate_decisions"] if relation.normalized_finding_id in normalized_ids]
        gate_ids = {relation.gate_decision_id for relation in norm_gate}

        missing = self._missing_for_row(item_id, req_tp, tp_tc, tc_task, task_artifact)
        coverage_status = self._coverage_status(req_tp, tp_tc, tc_task, task_artifact)
        normalized_findings = self._load_many(Finding, normalized_ids)
        risk_status = self._risk_status(coverage_status, missing, normalized_findings)
        return CoverageMatrixRow(
            requirement=str(item["text"]),
            requirementVersion=str(item.get("requirementVersionId") or requirement_version_id),
            requirementItem={
                "id": item_id,
                "requirementItemId": item.get("requirementItemId") or item_id,
                "requirementVersionId": item.get("requirementVersionId") or str(requirement_version_id),
                "text": item["text"],
                "index": item["index"],
                "metadata": item["metadata"],
            },
            testPoints=[self._serialize_asset(asset) for asset in self._load_many(TestAsset, test_point_ids)],
            testCases=[self._serialize_asset(asset) for asset in self._load_many(TestAsset, test_case_ids)],
            executionTasks=[self._serialize_task(task) for task in self._load_many(ExecutionTask, task_ids)],
            evidenceArtifacts=[self._serialize_artifact(artifact) for artifact in self._load_many(ExecutionArtifact, artifact_ids)],
            rawFindings=[self._serialize_raw_finding(raw) for raw in self._load_many(RawFindingRecord, raw_ids)],
            normalizedFindings=[self._serialize_finding(finding) for finding in normalized_findings],
            gateImpact=[self._serialize_gate(gate) for gate in self._load_many(GateDecision, gate_ids)],
            coverageStatus=coverage_status,
            riskStatus=risk_status,
            missingLinks=missing,
        )

    def _missing_for_row(self, item_id: str, req_tp: list[Any], tp_tc: list[Any], tc_task: list[Any], task_artifact: list[Any]) -> list[MissingLink]:
        missing: list[MissingLink] = []
        if not req_tp:
            missing.append(_missing("MISSING_TEST_POINT", "requirement_item", item_id, "test_point"))
            return missing
        if not tp_tc:
            missing.append(_missing("MISSING_TEST_CASE", "test_point", str(req_tp[0].test_point_id), "test_case"))
            return missing
        if not tc_task:
            missing.append(_missing("MISSING_EXECUTION_TASK", "test_case", str(tp_tc[0].test_case_id), "execution_task"))
            return missing
        if not task_artifact:
            missing.append(_missing("MISSING_EVIDENCE", "execution_task", str(tc_task[0].execution_task_id), "evidence_artifact"))
        return missing

    def _coverage_status(self, req_tp: list[Any], tp_tc: list[Any], tc_task: list[Any], task_artifact: list[Any]) -> CoverageStatus:
        if req_tp and tp_tc and tc_task and task_artifact:
            return CoverageStatus.COVERED
        if req_tp or tp_tc or tc_task or task_artifact:
            return CoverageStatus.PARTIAL
        return CoverageStatus.NOT_COVERED

    def _risk_status(self, coverage_status: CoverageStatus, missing: list[MissingLink], findings: list[Finding]) -> CoverageRiskStatus:
        if coverage_status == CoverageStatus.BLOCKED:
            return CoverageRiskStatus.BLOCKED
        severities = {finding.severity for finding in findings}
        missing_severities = {link.severity for link in missing if link.blocksCoverage}
        if FindingSeverity.CRITICAL in severities or FindingSeverity.CRITICAL in missing_severities:
            return CoverageRiskStatus.CRITICAL
        if FindingSeverity.HIGH in severities or FindingSeverity.HIGH in missing_severities or coverage_status == CoverageStatus.NOT_COVERED:
            return CoverageRiskStatus.HIGH
        if FindingSeverity.MEDIUM in severities or FindingSeverity.MEDIUM in missing_severities or coverage_status == CoverageStatus.PARTIAL:
            return CoverageRiskStatus.MEDIUM
        if coverage_status == CoverageStatus.UNKNOWN:
            return CoverageRiskStatus.UNKNOWN
        return CoverageRiskStatus.LOW

    def _build_summary(
        self,
        requirement_version_id: UUID,
        scope: CoverageScope,
        rows: list[CoverageMatrixRow],
        graph: dict[str, list[Any]],
        calculated_at: datetime,
    ) -> CoverageSummaryResponse:
        covered_rows = [row for row in rows if row.coverageStatus == CoverageStatus.COVERED]
        requirement_item_ids = {str(row.requirementItem["id"]) for row in rows}
        requirement_test_point_relations = [
            relation
            for relation in graph["requirement_item_test_points"]
            if relation.requirement_item_id in requirement_item_ids
        ]
        test_points = {relation.test_point_id for relation in requirement_test_point_relations}
        test_point_case_relations = [
            relation for relation in graph["test_point_test_cases"] if relation.test_point_id in test_points
        ]
        test_points_with_cases = {relation.test_point_id for relation in test_point_case_relations}
        test_cases = {relation.test_case_id for relation in test_point_case_relations}
        test_case_task_relations = [
            relation for relation in graph["test_case_execution_tasks"] if relation.test_case_id in test_cases
        ]
        test_cases_with_tasks = {relation.test_case_id for relation in test_case_task_relations}
        tasks = {relation.execution_task_id for relation in test_case_task_relations}
        task_artifact_relations = [
            relation for relation in graph["execution_task_evidence_artifacts"] if relation.execution_task_id in tasks
        ]
        tasks_with_evidence = {relation.execution_task_id for relation in task_artifact_relations}
        artifacts = {relation.evidence_artifact_id for relation in task_artifact_relations}
        evidence_raw_relations = [
            relation for relation in graph["evidence_raw_findings"] if relation.evidence_artifact_id in artifacts
        ]
        raw_ids = {relation.raw_finding_id for relation in evidence_raw_relations}
        raw_normalized_relations = [
            relation for relation in graph["raw_normalized_findings"] if relation.raw_finding_id in raw_ids
        ]
        normalized = {relation.normalized_finding_id for relation in raw_normalized_relations}
        traceable_normalized = {
            relation.normalized_finding_id
            for relation in raw_normalized_relations
            if any(raw.raw_finding_id == relation.raw_finding_id for raw in evidence_raw_relations)
        }
        normalized_gate_relations = [
            relation
            for relation in graph["normalized_finding_gate_decisions"]
            if relation.normalized_finding_id in normalized
        ]
        gates_with_findings = {relation.gate_decision_id for relation in normalized_gate_relations}
        gate_replay_relations = [
            relation for relation in graph["gate_decision_replay_exports"] if relation.gate_decision_id in gates_with_findings
        ]
        gates = gates_with_findings | {relation.gate_decision_id for relation in gate_replay_relations}
        missing = [link for row in rows for link in row.missingLinks]
        status = self._aggregate_status(rows)
        return CoverageSummaryResponse(
            requirementVersionId=requirement_version_id,
            requirementVersionIds=scope.requirementVersionIds,
            scope=scope,
            status=status,
            reason=None,
            requirementCoverage=_ratio(len(covered_rows), len(rows)),
            testPointCoverage=_ratio(len(test_points_with_cases), len(test_points)),
            testCaseCoverage=_ratio(len(test_cases_with_tasks), len(test_cases)),
            evidenceCoverage=_ratio(len(tasks_with_evidence), len(tasks)),
            findingTraceCoverage=_ratio(len(traceable_normalized), len(normalized)),
            gateImpactCoverage=_ratio(len(gates_with_findings), len(gates)),
            missingLinks=missing,
            calculatedAt=calculated_at,
        )

    def _aggregate_status(self, rows: list[CoverageMatrixRow]) -> CoverageStatus:
        statuses = {row.coverageStatus for row in rows}
        if not rows:
            return CoverageStatus.NOT_APPLICABLE
        if statuses == {CoverageStatus.COVERED}:
            return CoverageStatus.COVERED
        if CoverageStatus.COVERED in statuses or CoverageStatus.PARTIAL in statuses:
            return CoverageStatus.PARTIAL
        if statuses == {CoverageStatus.NOT_COVERED}:
            return CoverageStatus.NOT_COVERED
        return CoverageStatus.UNKNOWN

    def _filter_rows(
        self,
        rows: list[CoverageMatrixRow],
        coverage_status: CoverageStatus | None,
        risk_status: CoverageRiskStatus | None,
        missing_link_code: str | None,
        requirement_item_id: str | None,
    ) -> list[CoverageMatrixRow]:
        filtered = rows
        if coverage_status is not None:
            filtered = [row for row in filtered if row.coverageStatus == coverage_status]
        if risk_status is not None:
            filtered = [row for row in filtered if row.riskStatus == risk_status]
        if missing_link_code is not None:
            filtered = [row for row in filtered if any(link.code == missing_link_code for link in row.missingLinks)]
        if requirement_item_id is not None:
            filtered = [row for row in filtered if row.requirementItem.get("id") == requirement_item_id]
        return filtered

    def _load_many(self, model: type, ids: set[Any]) -> list[Any]:
        if not ids:
            return []
        return list(self.db.scalars(select(model).where(model.id.in_(ids))))

    def _relation_view(self, table: str, relation: Any) -> TraceabilityRelationView:
        spec = RELATION_SPECS[table]
        return TraceabilityRelationView(
            id=relation.id,
            table=table,
            sourceType=spec.source_type,
            sourceId=str(getattr(relation, spec.source_field)),
            targetType=spec.target_type,
            targetId=str(getattr(relation, spec.target_field)),
            relationType=relation.relation_type,
            status=relation.status,
            source=relation.source,
            confidence=float(relation.confidence),
            scopeId=relation.scope_id,
            stale=relation.status == TraceabilityRelationStatus.STALE,
            metadata=relation.metadata_json,
        )

    def _node(self, node_type: str, node_id: str | UUID) -> TraceabilityNode:
        return TraceabilityNode(type=node_type, id=str(node_id))

    def _serialize_asset(self, asset: TestAsset) -> dict[str, Any]:
        return {"id": str(asset.id), "type": asset.asset_type, "title": asset.title, "status": asset.status}

    def _serialize_task(self, task: ExecutionTask) -> dict[str, Any]:
        return {"id": str(task.id), "status": task.status.value, "runner": task.runner, "taskType": task.task_type}

    def _serialize_artifact(self, artifact: ExecutionArtifact) -> dict[str, Any]:
        return {"id": str(artifact.id), "artifactType": artifact.artifact_type.value, "uri": artifact.uri}

    def _serialize_raw_finding(self, finding: RawFindingRecord) -> dict[str, Any]:
        return {"id": str(finding.id), "severity": finding.severity, "title": finding.title, "dedupeKey": finding.dedupe_key}

    def _serialize_finding(self, finding: Finding) -> dict[str, Any]:
        return {"id": str(finding.id), "severity": finding.severity.value, "title": finding.title, "dedupeKey": finding.dedupe_key}

    def _serialize_gate(self, gate: GateDecision) -> dict[str, Any]:
        return {
            "id": str(gate.id),
            "overall": gate.overall.value,
            "reasons": gate.reasons,
            "reasonCodes": list(gate.reason_codes or []),
            "decisionSnapshotHash": gate.decision_snapshot_hash,
            "evaluatorVersion": gate.evaluator_version,
        }


def canonical_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _missing(
    code: str,
    from_type: str,
    from_id: str,
    expected_target_type: str,
    severity: FindingSeverity = FindingSeverity.HIGH,
    blocks: bool = True,
) -> MissingLink:
    return MissingLink(
        code=code,
        fromType=from_type,
        fromId=from_id,
        expectedTargetType=expected_target_type,
        severity=severity,
        blocksCoverage=blocks,
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _uuid_or_none(value: str | None) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None

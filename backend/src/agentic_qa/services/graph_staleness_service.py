# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import ApprovalStatus, ApprovalType, GraphSource, GraphStatus
from agentic_qa.domain.models import (
    Approval,
    CanonicalExecutionGraphVersion,
    CanonicalGraphPromotionRecord,
    CanonicalGraphStalenessAssessment,
    CanonicalGraphStalenessReview,
    GuardrailEvent,
    RequirementVersion,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import ensure_trace, traced_operation
from agentic_qa.schemas.graph_staleness import (
    ApplyGraphStalenessReview,
    AssessGraphStalenessRequest,
    RequestGraphStalenessReview,
    SelectCanonicalGraphRequest,
)
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import ServiceContext, acquire_transaction_advisory_lock, canonical_hash
from agentic_qa.services.execution_graph_service import ExecutionGraphError, ExecutionGraphService


STATUS_PRIORITY = {"fresh": 0, "suspect": 1, "stale": 2, "unknown": 3, "invalid": 4}
SEVERITY_PRIORITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STALE_USABLE_POLICIES = {"reject", "allow_reviewed"}


class GraphStalenessError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


class GraphStalenessService:
    """Service-owned P14 freshness, applicability, review, and deterministic selection."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.guardrails = RuntimeGuardrailEngine(db)

    def workspace(self, project_id: UUID, context: ServiceContext) -> dict[str, Any]:
        self._require_capability(context, "graph.staleness.read")
        scope = self._scope(project_id, context)
        versions = list(
            self.db.scalars(
                select(CanonicalExecutionGraphVersion).where(
                    CanonicalExecutionGraphVersion.tenant_id == scope.tenant_id,
                    CanonicalExecutionGraphVersion.workspace_id == scope.workspace_id,
                    CanonicalExecutionGraphVersion.project_id == project_id,
                    CanonicalExecutionGraphVersion.source == GraphSource.CANONICAL,
                    CanonicalExecutionGraphVersion.is_frozen.is_(True),
                ).order_by(
                    CanonicalExecutionGraphVersion.graph_id,
                    CanonicalExecutionGraphVersion.version_number.desc(),
                )
            )
        )
        expose_change_refs = "evidence.raw.read" in set(context.user.capabilities)
        return {
            "schemaVersion": "phase8.graph-staleness-workspace.v1",
            "items": [
                self.version_projection(item, expose_change_refs=expose_change_refs)
                for item in versions
            ],
            "selectionRule": {
                "scopePrecedence": ["environment", "project"],
                "candidateOrder": [
                    "scopeMatch", "activeLifecycle", "versionNumber", "assessmentTime", "versionId"
                ],
                "invalidExcluded": True,
                "unknownIsFresh": False,
                "staleRequiresExplicitPolicy": True,
                "replayUsesExactFrozenVersion": True,
            },
            "readOnly": context.user.edition == "basic",
            "authorizationBoundary": "backend_service_api",
            "frontendBoundary": "ux_only",
        }

    def assess(
        self,
        project_id: UUID,
        graph_version_id: UUID,
        payload: AssessGraphStalenessRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.staleness.assess")
        scope = self._scope(project_id, context)
        version = self._version(scope, graph_version_id)
        acquire_transaction_advisory_lock(
            self.db,
            "canonical-graph-staleness",
            f"{scope.tenant_id}:{scope.workspace_id}:{graph_version_id}",
        )
        request = payload.model_dump(mode="json", exclude_none=True)
        request_hash = canonical_hash(request)
        canonical_signals = [
            {key: value for key, value in item.items() if key != "signalId"}
            for item in request["signals"]
        ]
        canonical_signals.sort(
            key=lambda item: (
                str(item.get("source")), str(item.get("type")), str(item.get("ref")),
                str(item.get("oldFingerprint")), str(item.get("newFingerprint")),
            )
        )
        source_material = {
            "applicabilityRange": request["applicabilityRange"],
            "signals": canonical_signals,
            "ruleVersion": payload.ruleVersion,
        }
        source_fingerprint = canonical_hash(source_material)
        retry = self.db.scalar(
            select(CanonicalGraphStalenessAssessment).where(
                CanonicalGraphStalenessAssessment.tenant_id == scope.tenant_id,
                CanonicalGraphStalenessAssessment.workspace_id == scope.workspace_id,
                CanonicalGraphStalenessAssessment.graph_version_id == graph_version_id,
                CanonicalGraphStalenessAssessment.source_fingerprint == source_fingerprint,
            )
        )
        if retry:
            return self._assessment_projection(retry, deduplicated=True)
        key_retry = self.db.scalar(
            select(CanonicalGraphStalenessAssessment).where(
                CanonicalGraphStalenessAssessment.tenant_id == scope.tenant_id,
                CanonicalGraphStalenessAssessment.workspace_id == scope.workspace_id,
                CanonicalGraphStalenessAssessment.graph_version_id == graph_version_id,
                CanonicalGraphStalenessAssessment.idempotency_key == payload.idempotencyKey,
            )
        )
        if key_retry:
            if key_retry.request_hash != request_hash:
                raise GraphStalenessError("GRAPH_STALENESS_IDEMPOTENCY_CONFLICT")
            return self._assessment_projection(key_retry, deduplicated=True)

        status, reasons = self._derive_status(request["signals"])
        required_sources = self._required_signal_sources(request["applicabilityRange"])
        matching_sources = {
            item["source"]
            for item in request["signals"]
            if item["type"] == "match"
            and float(item["confidence"]) >= 0.9
            and item.get("evidence")
        }
        missing_sources = sorted(required_sources - matching_sources)
        if status == "fresh" and missing_sources:
            status = "unknown"
            reasons = [
                "GRAPH_STALENESS_REQUIRED_SIGNAL_MISSING",
                *[f"GRAPH_STALENESS_REQUIRED_{item.upper()}_SIGNAL_MISSING" for item in missing_sources],
            ]
        promotion = self.db.scalar(
            select(CanonicalGraphPromotionRecord).where(
                CanonicalGraphPromotionRecord.target_version_id == graph_version_id
            )
        )
        post_promotion_issue = bool(promotion and status != "fresh")
        impact = {
            "autoPromotionSuspended": status != "fresh",
            "alertRequired": post_promotion_issue,
            "reviewRequired": status != "fresh",
            "controlledRollbackAvailable": post_promotion_issue,
            "historicalVersionRetained": True,
            "promotionRecordRef": (
                f"canonical-graph-promotion://promotions/{promotion.id}" if promotion else None
            ),
            "writesGate": False,
        }
        now = datetime.now(timezone.utc)
        assessment_id = uuid4()
        snapshot = {
            "assessmentId": str(assessment_id),
            "graphId": str(version.graph_id),
            "graphVersionId": str(version.id),
            "status": status,
            "applicabilityRange": request["applicabilityRange"],
            "signals": request["signals"],
            "sourceFingerprint": source_fingerprint,
            "ruleVersion": payload.ruleVersion,
            "reasonCodes": reasons,
            "impact": impact,
            "automaticPromotionEligible": status == "fresh",
            "assessedAt": now.isoformat(),
        }
        assessment_hash = canonical_hash(snapshot)
        ensure_trace(self.db, execution_id=None, root_span_name="ceg.staleness.assess", trace_id=context.trace_id)
        audit_ref = self._audit(
            context,
            "canonical_graph.staleness.assess",
            "canonical_graph_staleness_assessment",
            assessment_id,
            {
                "graphVersionId": str(version.id),
                "status": status,
                "sourceFingerprint": source_fingerprint,
                "ruleVersion": payload.ruleVersion,
                "reasonCodes": reasons,
                "impact": impact,
                "signals": self._redacted_signals(request["signals"]),
            },
        )
        guardrail_ref = self._record_guardrail(
            context,
            rule_id="graph.staleness.assessment.v1",
            resource_type="canonical_graph_staleness_assessment",
            resource_id=assessment_id,
            reason="Structured staleness assessment has evidence and remains outside Gate/Memory writes.",
            evidence=[f"ceg-version://versions/{version.id}"],
            payload={
                "graphVersionId": str(version.id),
                "status": status,
                "ruleVersion": payload.ruleVersion,
                "writesGate": False,
                "writesMemory": False,
            },
        )
        assessment = CanonicalGraphStalenessAssessment(
            id=assessment_id,
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=project_id,
            graph_id=version.graph_id,
            graph_version_id=version.id,
            status=status,
            applicability_range=deepcopy(request["applicabilityRange"]),
            signals_snapshot=deepcopy(request["signals"]),
            source_fingerprint=source_fingerprint,
            rule_version=payload.ruleVersion,
            reason_codes=reasons,
            impact_snapshot=impact,
            automatic_promotion_eligible=status == "fresh",
            assessment_hash=assessment_hash,
            idempotency_key=payload.idempotencyKey,
            request_hash=request_hash,
            guardrail_event_refs=[guardrail_ref],
            audit_refs=[audit_ref],
            trace_id=UUID(context.trace_id),
            assessed_at=now,
            assessed_by=context.user.id,
        )
        self.db.add(assessment)
        self.db.commit()
        return self._assessment_projection(assessment)

    def request_review(
        self,
        project_id: UUID,
        graph_version_id: UUID,
        payload: RequestGraphStalenessReview,
        context: ServiceContext,
    ) -> dict[str, Any]:
        capability = "graph.staleness.deprecate" if payload.action == "deprecate" else "graph.staleness.review"
        self._require_capability(context, capability)
        scope = self._scope(project_id, context)
        version = self._version(scope, graph_version_id)
        assessment = self.current_assessment(scope, version)
        if assessment is None:
            raise GraphStalenessError("GRAPH_STALENESS_ASSESSMENT_REQUIRED")
        if assessment.assessment_hash != payload.expectedAssessmentHash:
            raise GraphStalenessError("GRAPH_STALENESS_ASSESSMENT_CHANGED")
        now = datetime.now(timezone.utc)
        if payload.expiresAt is not None and self._aware(payload.expiresAt) <= now:
            raise GraphStalenessError("GRAPH_STALENESS_OVERRIDE_EXPIRY_INVALID", status_code=422)
        request_hash = canonical_hash(payload.model_dump(mode="json", exclude_none=True))
        retry = self.db.scalar(
            select(CanonicalGraphStalenessReview).where(
                CanonicalGraphStalenessReview.tenant_id == scope.tenant_id,
                CanonicalGraphStalenessReview.workspace_id == scope.workspace_id,
                CanonicalGraphStalenessReview.graph_version_id == version.id,
                CanonicalGraphStalenessReview.idempotency_key == payload.idempotencyKey,
            )
        )
        if retry:
            if retry.request_hash != request_hash:
                raise GraphStalenessError("GRAPH_STALENESS_REVIEW_IDEMPOTENCY_CONFLICT")
            return self._review_projection(retry, deduplicated=True)
        review_id = uuid4()
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="canonical_graph_staleness_review",
            resource_id=str(review_id),
            summary=f"Approval required for Canonical Graph staleness {payload.action} on version {version.id}.",
            payload={
                "action": f"graph_staleness.{payload.action}",
                "projectId": str(project_id),
                "graphId": str(version.graph_id),
                "graphVersionId": str(version.id),
                "assessmentId": str(assessment.id),
                "assessmentHash": assessment.assessment_hash,
                "requestedStatus": payload.requestedStatus,
                "reasonCode": payload.reasonCode,
                "expiresAt": payload.expiresAt.isoformat() if payload.expiresAt else None,
                "evidenceRefs": payload.evidenceRefs,
                "requestedBy": str(context.user.id),
            },
            context=context,
            commit=False,
        )
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="ceg.staleness.review.request",
            trace_id=context.trace_id,
        )
        guardrail_ref = self._record_guardrail(
            context,
            rule_id="graph.staleness.review.v1",
            resource_type="canonical_graph_staleness_review",
            resource_id=review_id,
            reason="Human staleness review is approval-backed and cannot restore controlled autonomy.",
            evidence=[
                f"graph-staleness-assessment://assessments/{assessment.id}",
                *[str(item.get("ref")) for item in payload.evidenceRefs if item.get("ref")],
            ],
            payload={
                "action": payload.action,
                "graphVersionId": str(version.id),
                "assessmentHash": assessment.assessment_hash,
                "approvalId": str(approval.id),
                "automaticPromotionRestored": False,
            },
        )
        audit_ref = self._audit(
            context,
            "canonical_graph.staleness.review.request",
            "canonical_graph_staleness_review",
            review_id,
            {
                "graphVersionId": str(version.id),
                "assessmentHash": assessment.assessment_hash,
                "action": payload.action,
                "requestedStatus": payload.requestedStatus,
                "reasonCode": payload.reasonCode,
                "expiresAt": payload.expiresAt.isoformat() if payload.expiresAt else None,
                "approvalId": str(approval.id),
            },
        )
        review = CanonicalGraphStalenessReview(
            id=review_id,
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=project_id,
            graph_id=version.graph_id,
            graph_version_id=version.id,
            assessment_id=assessment.id,
            action=payload.action,
            requested_status=payload.requestedStatus,
            reason_code=payload.reasonCode,
            evidence_refs=deepcopy(payload.evidenceRefs),
            expires_at=payload.expiresAt,
            status="pending",
            approval_id=approval.id,
            approval_refs=[{"type": "approval", "ref": f"approval://approvals/{approval.id}", "status": "pending"}],
            guardrail_event_refs=[guardrail_ref],
            audit_refs=[audit_ref],
            idempotency_key=payload.idempotencyKey,
            request_hash=request_hash,
            trace_id=UUID(context.trace_id),
            lock_version=1,
            requested_by=context.user.id,
        )
        self.db.add(review)
        self.db.commit()
        return self._review_projection(review)

    def apply_review(
        self,
        project_id: UUID,
        review_id: UUID,
        payload: ApplyGraphStalenessReview,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._scope(project_id, context)
        review = self.db.scalar(
            select(CanonicalGraphStalenessReview).where(
                CanonicalGraphStalenessReview.id == review_id,
                CanonicalGraphStalenessReview.tenant_id == scope.tenant_id,
                CanonicalGraphStalenessReview.workspace_id == scope.workspace_id,
                CanonicalGraphStalenessReview.project_id == project_id,
            ).with_for_update()
        )
        if not review:
            raise GraphStalenessError("GRAPH_STALENESS_REVIEW_NOT_FOUND", status_code=404)
        capability = "graph.staleness.deprecate" if review.action == "deprecate" else "graph.staleness.review"
        self._require_capability(context, capability)
        if review.lock_version != payload.expectedLockVersion:
            raise GraphStalenessError("GRAPH_STALENESS_REVIEW_LOCK_CONFLICT")
        if review.status == "applied":
            return self._review_projection(review, deduplicated=True)
        if review.status != "pending":
            raise GraphStalenessError("GRAPH_STALENESS_REVIEW_STATE_INVALID")
        approval = self.db.get(Approval, payload.approvalId)
        if (
            not approval
            or approval.id != review.approval_id
            or approval.status != ApprovalStatus.APPROVED
            or approval.resource_type != "canonical_graph_staleness_review"
            or approval.resource_id != str(review.id)
        ):
            raise GraphStalenessError("GRAPH_STALENESS_REVIEW_APPROVAL_INVALID")
        assessment = self.db.get(CanonicalGraphStalenessAssessment, review.assessment_id)
        if not assessment:
            raise GraphStalenessError("GRAPH_STALENESS_ASSESSMENT_UNAVAILABLE")
        current = self.current_assessment(scope, self._version(scope, review.graph_version_id))
        if current is None or current.id != assessment.id:
            raise GraphStalenessError("GRAPH_STALENESS_REVIEW_ASSESSMENT_STALE")
        now = datetime.now(timezone.utc)
        if review.expires_at is not None and self._aware(review.expires_at) <= now:
            review.status = "expired"
            self.db.commit()
            raise GraphStalenessError("GRAPH_STALENESS_OVERRIDE_EXPIRED")
        version = self._version(scope, review.graph_version_id)
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="ceg.staleness.review",
            span_name="ceg.staleness.review.apply",
            service_name="orchestrator-service",
            attributes={"reviewId": str(review.id), "action": review.action},
            parent_span_id=context.parent_span_id,
        ):
            apply_guardrail_ref = self._record_guardrail(
                context,
                rule_id="graph.staleness.review.apply.v1",
                resource_type="canonical_graph_staleness_review",
                resource_id=review.id,
                reason="Approved staleness review is applied without rewriting canonical graph history.",
                evidence=[
                    f"approval://approvals/{approval.id}",
                    f"graph-staleness-assessment://assessments/{assessment.id}",
                ],
                payload={
                    "action": review.action,
                    "graphVersionId": str(version.id),
                    "approvalId": str(approval.id),
                    "historicalVersionRetained": True,
                },
            )
            if review.action == "deprecate":
                if version.status in {GraphStatus.ACTIVE, GraphStatus.SUPERSEDED}:
                    version.status = GraphStatus.DEPRECATED
                elif version.status != GraphStatus.DEPRECATED:
                    raise GraphStalenessError("GRAPH_STALENESS_DEPRECATION_STATE_INVALID")
            review.status = "applied"
            review.applied_at = now
            review.applied_by = context.user.id
            review.approval_refs = [{
                "type": "approval",
                "ref": f"approval://approvals/{approval.id}",
                "status": "approved",
                "decidedBy": str(approval.decided_by) if approval.decided_by else None,
            }]
            review.guardrail_event_refs = [*review.guardrail_event_refs, apply_guardrail_ref]
            audit_ref = self._audit(
                context,
                "canonical_graph.staleness.review.apply",
                "canonical_graph_staleness_review",
                review.id,
                {
                    "graphVersionId": str(version.id),
                    "action": review.action,
                    "baseStatus": assessment.status,
                    "requestedStatus": review.requested_status,
                    "expiresAt": review.expires_at.isoformat() if review.expires_at else None,
                    "approvalId": str(approval.id),
                    "automaticPromotionRestored": False,
                    "historicalVersionRetained": True,
                },
            )
            review.audit_refs = [*review.audit_refs, audit_ref]
        self.db.commit()
        return self._review_projection(review)

    def select(
        self,
        project_id: UUID,
        payload: SelectCanonicalGraphRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.staleness.read")
        scope = self._scope(project_id, context)
        expose_change_refs = "evidence.raw.read" in set(context.user.capabilities)
        if payload.mode == "replay":
            version = self._version(scope, payload.exactVersionId)
            return {
                "schemaVersion": "phase8.canonical-graph-selection.v1",
                "selected": self.version_projection(version, expose_change_refs=expose_change_refs),
                "mode": "replay",
                "fallbackReason": "historical_exact_version",
                "authoritative": True,
                "recomputed": False,
            }
        statement = select(CanonicalExecutionGraphVersion).where(
            CanonicalExecutionGraphVersion.tenant_id == scope.tenant_id,
            CanonicalExecutionGraphVersion.workspace_id == scope.workspace_id,
            CanonicalExecutionGraphVersion.project_id == project_id,
            CanonicalExecutionGraphVersion.source == GraphSource.CANONICAL,
            CanonicalExecutionGraphVersion.is_frozen.is_(True),
            CanonicalExecutionGraphVersion.status.in_([GraphStatus.ACTIVE, GraphStatus.SUPERSEDED]),
        )
        if payload.graphId:
            statement = statement.where(CanonicalExecutionGraphVersion.graph_id == payload.graphId)
        candidates: list[tuple[int, int, CanonicalExecutionGraphVersion, CanonicalGraphStalenessAssessment, CanonicalGraphStalenessReview | None]] = []
        rejected: list[dict[str, Any]] = []
        for version in self.db.scalars(statement):
            assessment = self.current_assessment(scope, version)
            if assessment is None:
                rejected.append({"versionId": str(version.id), "reason": "assessment_unknown"})
                continue
            matches, score, reason = self._applicability_match(assessment.applicability_range, payload)
            if not matches:
                rejected.append({"versionId": str(version.id), "reason": reason})
                continue
            override = self._active_review(scope, version.id, action="override")
            if assessment.status == "invalid":
                rejected.append({"versionId": str(version.id), "reason": "invalid_excluded"})
                continue
            if assessment.status in {"suspect", "stale"}:
                if payload.stalePolicy not in STALE_USABLE_POLICIES or payload.stalePolicy == "reject":
                    rejected.append({"versionId": str(version.id), "reason": "stale_policy_reject"})
                    continue
                if override is None:
                    rejected.append({"versionId": str(version.id), "reason": "reviewed_override_required"})
                    continue
            if assessment.status == "unknown":
                rejected.append({"versionId": str(version.id), "reason": "unknown_not_fresh"})
                continue
            lifecycle_score = 1 if version.status == GraphStatus.ACTIVE else 0
            candidates.append((score, lifecycle_score, version, assessment, override))
        if not candidates:
            return {
                "schemaVersion": "phase8.canonical-graph-selection.v1",
                "selected": None,
                "mode": "live",
                "fallbackReason": "no_applicable_non_invalid_version",
                "rejectedCandidates": rejected,
                "authoritative": True,
                "recomputed": False,
            }
        candidates.sort(
            key=lambda item: (
                -item[0],
                -item[1],
                -item[2].version_number,
                -self._aware(item[3].assessed_at).timestamp(),
                str(item[2].id),
            )
        )
        score, _lifecycle_score, version, assessment, override = candidates[0]
        if version.status == GraphStatus.SUPERSEDED:
            fallback_reason = "historical_superseded_fallback"
        elif assessment.status == "fresh":
            fallback_reason = "exact_scope_fresh"
        else:
            fallback_reason = "explicit_reviewed_stale_policy"
        return {
            "schemaVersion": "phase8.canonical-graph-selection.v1",
            "selected": self.version_projection(version, expose_change_refs=expose_change_refs),
            "mode": "live",
            "fallbackReason": fallback_reason,
            "matchScore": score,
            "reviewOverrideRef": f"graph-staleness-review://reviews/{override.id}" if override else None,
            "rejectedCandidates": rejected,
            "authoritative": True,
            "recomputed": False,
        }

    def controlled_autonomy_signal(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_version_id: UUID,
    ) -> dict[str, Any]:
        assessment = self.db.scalar(
            select(CanonicalGraphStalenessAssessment).where(
                CanonicalGraphStalenessAssessment.tenant_id == tenant_id,
                CanonicalGraphStalenessAssessment.workspace_id == workspace_id,
                CanonicalGraphStalenessAssessment.project_id == project_id,
                CanonicalGraphStalenessAssessment.graph_version_id == graph_version_id,
            ).order_by(
                CanonicalGraphStalenessAssessment.assessed_at.desc(),
                CanonicalGraphStalenessAssessment.id.desc(),
            ).limit(1)
        )
        if assessment is None:
            return {
                "status": "unknown",
                "eligible": False,
                "reasonCode": "GRAPH_STALENESS_ASSESSMENT_UNKNOWN",
                "assessmentRef": None,
                "assessmentHash": None,
            }
        eligible = assessment.status == "fresh" and assessment.automatic_promotion_eligible
        return {
            "status": assessment.status,
            "eligible": eligible,
            "reasonCode": "GRAPH_STALENESS_FRESH" if eligible else f"GRAPH_STALENESS_{assessment.status.upper()}_SUSPENDS_AUTONOMY",
            "assessmentRef": f"graph-staleness-assessment://assessments/{assessment.id}",
            "assessmentHash": assessment.assessment_hash,
        }

    def current_assessment(self, scope: Any, version: CanonicalExecutionGraphVersion) -> CanonicalGraphStalenessAssessment | None:
        return self.db.scalar(
            select(CanonicalGraphStalenessAssessment).where(
                CanonicalGraphStalenessAssessment.tenant_id == scope.tenant_id,
                CanonicalGraphStalenessAssessment.workspace_id == scope.workspace_id,
                CanonicalGraphStalenessAssessment.project_id == scope.project.id,
                CanonicalGraphStalenessAssessment.graph_version_id == version.id,
            ).order_by(
                CanonicalGraphStalenessAssessment.assessed_at.desc(),
                CanonicalGraphStalenessAssessment.id.desc(),
            ).limit(1)
        )

    def version_projection(
        self,
        version: CanonicalExecutionGraphVersion,
        *,
        expose_change_refs: bool = False,
    ) -> dict[str, Any]:
        scope = type("Scope", (), {"tenant_id": version.tenant_id, "workspace_id": version.workspace_id, "project": type("Project", (), {"id": version.project_id})()})()
        assessment = self.current_assessment(scope, version)
        override = self._active_review(scope, version.id, action="override")
        confirmation = self._latest_review(scope, version.id, action="confirm")
        deprecation = self._latest_review(scope, version.id, action="deprecate")
        return {
            "graphId": str(version.graph_id),
            "graphVersionId": str(version.id),
            "versionNumber": version.version_number,
            "versionRef": version.version_ref,
            "contentHash": version.content_hash,
            "lifecycleStatus": version.status.value,
            "scope": {
                "type": version.scope_type.value,
                "id": str(version.scope_id),
                "environmentId": str(version.environment_id) if version.environment_id else None,
            },
            "assessment": (
                self._assessment_projection(
                    assessment,
                    redact_change_refs=not expose_change_refs,
                )
                if assessment
                else self._unknown_projection(version)
            ),
            "effectiveUseStatus": override.requested_status if override else (assessment.status if assessment else "unknown"),
            "override": (
                self._review_projection(override, redact_change_refs=not expose_change_refs)
                if override else None
            ),
            "confirmation": (
                self._review_projection(confirmation, redact_change_refs=not expose_change_refs)
                if confirmation else None
            ),
            "deprecation": (
                self._review_projection(deprecation, redact_change_refs=not expose_change_refs)
                if deprecation else None
            ),
            "changeRefsRedacted": not expose_change_refs,
            "automaticPromotionEligible": bool(assessment and assessment.status == "fresh" and not override),
            "historicalVersionRetained": True,
            "replaySelection": "exact_version_only",
        }

    @staticmethod
    def _derive_status(signals: list[dict[str, Any]]) -> tuple[str, list[str]]:
        if not signals:
            return "unknown", ["GRAPH_STALENESS_SIGNAL_MISSING"]
        statuses: list[str] = []
        reasons: list[str] = []
        for signal in signals:
            signal_type = signal["type"]
            severity = signal["severity"]
            confidence = float(signal["confidence"])
            if signal_type == "match" and confidence >= 0.9:
                statuses.append("fresh")
                continue
            if signal_type in {"missing", "unavailable", "retention_deleted"}:
                statuses.append("unknown")
                reasons.append("GRAPH_STALENESS_SOURCE_UNAVAILABLE")
            elif signal_type == "conflict" and severity in {"high", "critical"}:
                statuses.append("invalid")
                reasons.append("GRAPH_STALENESS_CONFLICT_INVALID")
            elif signal_type == "conflict":
                statuses.append("suspect")
                reasons.append("GRAPH_STALENESS_CONFLICT_SUSPECT")
            elif signal_type == "changed" and (SEVERITY_PRIORITY[severity] >= 3 and confidence >= 0.8):
                statuses.append("stale")
                reasons.append("GRAPH_STALENESS_MATERIAL_CHANGE")
            elif signal_type == "changed":
                statuses.append("suspect")
                reasons.append("GRAPH_STALENESS_CHANGE_REQUIRES_REVIEW")
            else:
                statuses.append("unknown")
                reasons.append("GRAPH_STALENESS_SIGNAL_INCONCLUSIVE")
        if not statuses:
            return "unknown", ["GRAPH_STALENESS_SIGNAL_INCONCLUSIVE"]
        status = max(statuses, key=lambda item: STATUS_PRIORITY[item])
        if status == "fresh" and not all(item == "fresh" for item in statuses):
            status = "suspect"
            reasons.append("GRAPH_STALENESS_SIGNAL_CONFLICT")
        return status, sorted(set(reasons)) or ["GRAPH_STALENESS_ALL_SOURCES_MATCH"]

    @staticmethod
    def _required_signal_sources(applicability: dict[str, Any]) -> set[str]:
        required: set[str] = set()
        if applicability.get("requirementVersionRange"):
            required.add("requirement")
        if applicability.get("codeRevisionRange"):
            required.add("scm")
        if applicability.get("environmentIds"):
            required.add("environment")
        if applicability.get("apiSchemaFingerprints"):
            required.add("api_schema")
        if applicability.get("uiAssetFingerprints"):
            required.add("ui_asset")
        return required

    def _applicability_match(self, applicability: dict[str, Any], payload: SelectCanonicalGraphRequest) -> tuple[bool, int, str]:
        context = payload.context
        score = 0
        environment_ids = set(applicability.get("environmentIds") or [])
        if environment_ids:
            if context.environmentId is None or str(context.environmentId) not in {str(item) for item in environment_ids}:
                return False, 0, "environment_out_of_range"
            score += 64
        stages = set(applicability.get("stages") or [])
        if stages:
            if context.stage not in stages:
                return False, 0, "stage_out_of_range"
            score += 16
        domains = set(applicability.get("domains") or [])
        if domains:
            if context.domain not in domains:
                return False, 0, "domain_out_of_range"
            score += 8
        requirement = applicability.get("requirementVersionRange") or {}
        if requirement:
            if context.requirementVersionId is None and context.requirementVersionNo is None:
                return False, 0, "requirement_version_missing"
            number: int
            if context.requirementVersionId is not None:
                row = self.db.get(RequirementVersion, context.requirementVersionId)
                if row is None:
                    return False, 0, "requirement_version_unavailable"
                number = row.version_no
            else:
                context_number = context.requirementVersionNo
                if context_number is None:
                    return False, 0, "requirement_version_missing"
                number = context_number
            if requirement.get("minVersionNo") and number < int(requirement["minVersionNo"]):
                return False, 0, "requirement_version_before_range"
            if requirement.get("maxVersionNo") and number > int(requirement["maxVersionNo"]):
                return False, 0, "requirement_version_after_range"
            if requirement.get("fromVersionId") and context.requirementVersionId and str(context.requirementVersionId) != str(requirement["fromVersionId"]):
                boundary = self.db.get(RequirementVersion, UUID(str(requirement["fromVersionId"])))
                if boundary is None or number < boundary.version_no:
                    return False, 0, "requirement_version_before_range"
            if requirement.get("toVersionId") and context.requirementVersionId and str(context.requirementVersionId) != str(requirement["toVersionId"]):
                boundary = self.db.get(RequirementVersion, UUID(str(requirement["toVersionId"])))
                if boundary is None or number > boundary.version_no:
                    return False, 0, "requirement_version_after_range"
            score += 32
        revision = applicability.get("codeRevisionRange") or {}
        if revision:
            if context.codeRevisionFingerprint is None:
                return False, 0, "code_revision_missing"
            accepted = set(revision.get("acceptedFingerprints") or [])
            lower = revision.get("fromFingerprint")
            upper = revision.get("toFingerprint")
            if accepted and context.codeRevisionFingerprint not in accepted:
                return False, 0, "code_revision_out_of_range"
            if not accepted and context.codeRevisionFingerprint not in {lower, upper}:
                return False, 0, "code_revision_unverified_range_gap"
            score += 32
        api = set(applicability.get("apiSchemaFingerprints") or [])
        if api:
            if context.apiSchemaFingerprint not in api:
                return False, 0, "api_schema_out_of_range"
            score += 4
        ui = set(applicability.get("uiAssetFingerprints") or [])
        if ui:
            if context.uiAssetFingerprint not in ui:
                return False, 0, "ui_asset_out_of_range"
            score += 4
        return True, score, "matched"

    def _active_review(self, scope: Any, version_id: UUID, *, action: str) -> CanonicalGraphStalenessReview | None:
        row = self._latest_review(scope, version_id, action=action)
        if row is None or row.status != "applied":
            return None
        if row.expires_at is not None and self._aware(row.expires_at) <= datetime.now(timezone.utc):
            return None
        return row

    def _latest_review(self, scope: Any, version_id: UUID, *, action: str) -> CanonicalGraphStalenessReview | None:
        return self.db.scalar(
            select(CanonicalGraphStalenessReview).where(
                CanonicalGraphStalenessReview.tenant_id == scope.tenant_id,
                CanonicalGraphStalenessReview.workspace_id == scope.workspace_id,
                CanonicalGraphStalenessReview.project_id == scope.project.id,
                CanonicalGraphStalenessReview.graph_version_id == version_id,
                CanonicalGraphStalenessReview.action == action,
            ).order_by(CanonicalGraphStalenessReview.created_at.desc(), CanonicalGraphStalenessReview.id.desc()).limit(1)
                )
    def _version(self, scope: Any, version_id: UUID | None) -> CanonicalExecutionGraphVersion:
        if version_id is None:
            raise GraphStalenessError("GRAPH_VERSION_REQUIRED", status_code=422)
        version = self.db.scalar(
            select(CanonicalExecutionGraphVersion).where(
                CanonicalExecutionGraphVersion.id == version_id,
                CanonicalExecutionGraphVersion.tenant_id == scope.tenant_id,
                CanonicalExecutionGraphVersion.workspace_id == scope.workspace_id,
                CanonicalExecutionGraphVersion.project_id == scope.project.id,
            )
        )
        if version is None:
            raise GraphStalenessError("GRAPH_VERSION_NOT_FOUND", status_code=404)
        return version

    def _scope(self, project_id: UUID, context: ServiceContext) -> Any:
        try:
            return ExecutionGraphService(self.db)._require_project_scope(project_id, context)
        except ExecutionGraphError as exc:
            raise GraphStalenessError(exc.code, status_code=exc.status_code, field=exc.field) from exc

    @staticmethod
    def _require_capability(context: ServiceContext, capability: str) -> None:
        if capability not in set(context.user.capabilities):
            raise GraphStalenessError("GRAPH_CAPABILITY_REQUIRED", status_code=403, field=capability)

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    @staticmethod
    def _redacted_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "signalId": item.get("signalId"),
                "source": item.get("source"),
                "type": item.get("type"),
                "ref": item.get("ref"),
                "severity": item.get("severity"),
                "confidence": item.get("confidence"),
                "oldFingerprint": item.get("oldFingerprint"),
                "newFingerprint": item.get("newFingerprint"),
                "evidenceCount": len(item.get("evidence") or []),
            }
            for item in signals
        ]

    @staticmethod
    def _unknown_projection(version: CanonicalExecutionGraphVersion) -> dict[str, Any]:
        return {
            "assessmentId": None,
            "graphId": str(version.graph_id),
            "graphVersionId": str(version.id),
            "status": "unknown",
            "applicabilityRange": {},
            "signals": [],
            "sourceFingerprint": None,
            "ruleVersion": None,
            "reasonCodes": ["GRAPH_STALENESS_ASSESSMENT_UNKNOWN"],
            "impact": {
                "autoPromotionSuspended": True,
                "alertRequired": False,
                "reviewRequired": True,
                "historicalVersionRetained": True,
            },
            "automaticPromotionEligible": False,
            "assessmentHash": None,
            "assessedAt": None,
        }

    @staticmethod
    def _assessment_projection(
        assessment: CanonicalGraphStalenessAssessment,
        *,
        deduplicated: bool = False,
        redact_change_refs: bool = False,
    ) -> dict[str, Any]:
        applicability = deepcopy(assessment.applicability_range)
        signals = deepcopy(assessment.signals_snapshot)
        if redact_change_refs:
            requirement_range = applicability.get("requirementVersionRange") or {}
            requirement_range.pop("sourceRef", None)
            revision_range = applicability.get("codeRevisionRange") or {}
            revision_range.pop("repositoryRef", None)
            signals = [
                {
                    "signalId": item.get("signalId"),
                    "source": item.get("source"),
                    "type": item.get("type"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                    "evidenceCount": len(item.get("evidence") or []),
                    "changeRefRedacted": True,
                }
                for item in signals
            ]
        return {
            "schemaVersion": "phase8.graph-staleness-assessment.v1",
            "assessmentId": str(assessment.id),
            "graphId": str(assessment.graph_id),
            "graphVersionId": str(assessment.graph_version_id),
            "status": assessment.status,
            "applicabilityRange": applicability,
            "signals": signals,
            "sourceFingerprint": assessment.source_fingerprint,
            "ruleVersion": assessment.rule_version,
            "reasonCodes": assessment.reason_codes,
            "impact": assessment.impact_snapshot,
            "automaticPromotionEligible": assessment.automatic_promotion_eligible,
            "assessmentHash": assessment.assessment_hash,
            "guardrailEventRefs": assessment.guardrail_event_refs,
            "auditRefs": assessment.audit_refs,
            "traceId": str(assessment.trace_id) if assessment.trace_id else None,
            "assessedAt": assessment.assessed_at.isoformat(),
            "deduplicated": deduplicated,
            "changeRefsRedacted": redact_change_refs,
        }

    @staticmethod
    def _review_projection(
        review: CanonicalGraphStalenessReview,
        *,
        deduplicated: bool = False,
        redact_change_refs: bool = False,
    ) -> dict[str, Any]:
        return {
            "reviewId": str(review.id),
            "graphId": str(review.graph_id),
            "graphVersionId": str(review.graph_version_id),
            "assessmentId": str(review.assessment_id),
            "action": review.action,
            "requestedStatus": review.requested_status,
            "reasonCode": review.reason_code,
            "evidenceRefs": (
                [{"type": "redacted", "ref": "[redacted]"} for _ in review.evidence_refs]
                if redact_change_refs else review.evidence_refs
            ),
            "expiresAt": review.expires_at.isoformat() if review.expires_at else None,
            "status": review.status,
            "approvalId": str(review.approval_id),
            "approvalRefs": review.approval_refs,
            "guardrailEventRefs": review.guardrail_event_refs,
            "auditRefs": review.audit_refs,
            "lockVersion": review.lock_version,
            "automaticPromotionRestored": False,
            "deduplicated": deduplicated,
            "changeRefsRedacted": redact_change_refs,
        }

    def _record_guardrail(
        self,
        context: ServiceContext,
        *,
        rule_id: str,
        resource_type: str,
        resource_id: UUID,
        reason: str,
        evidence: list[str],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        result = GuardrailResult(
            rule_id=rule_id,
            decision=GuardrailDecision.ALLOW,
            reason=reason,
            evidence=evidence,
            metadata={"serviceOwned": True, "frontendAuthoritative": False},
        )
        self.guardrails.record_result(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=list(context.user.roles),
                resource_type=resource_type,
                resource_id=str(resource_id),
                payload=payload,
            ),
            result,
        )
        self.db.flush()
        event = self.db.scalar(
            select(GuardrailEvent).where(
                GuardrailEvent.rule_id == rule_id,
                GuardrailEvent.trace_id == UUID(context.trace_id),
                GuardrailEvent.request_id == context.request_id,
            ).order_by(GuardrailEvent.created_at.desc())
        )
        if event is None:
            raise GraphStalenessError("GRAPH_STALENESS_GUARDRAIL_AUDIT_MISSING", status_code=500)
        return {
            "type": "guardrail",
            "ref": f"guardrail://events/{event.id}",
            "decision": "allow",
            "ruleId": rule_id,
        }

    def _audit(self, context: ServiceContext, action: str, resource_type: str, resource_id: UUID, details: dict[str, Any]) -> dict[str, Any]:
        audit = write_audit_log(
            self.db,
            actor_id=context.user.id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            request_id=context.request_id,
            trace_id=context.trace_id,
            details=details,
        )
        self.db.flush()
        return {"type": "audit", "ref": f"audit://logs/{audit.id}"}

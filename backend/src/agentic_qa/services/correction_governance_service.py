# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import ApprovalStatus, ApprovalType, ProofStatus, RiskLevel
from agentic_qa.domain.models import (
    Approval,
    AuditLog,
    CorrectionApplication,
    CorrectionProposal,
    CorrectionValidation,
    CoverageProofBundleRecord,
    DomainEventRecord,
    GuardrailEvent,
    KnowledgePromotionRecord,
    RollbackRecord,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import ensure_trace
from agentic_qa.schemas.contracts import ContractValidationError, validate_contract
from agentic_qa.schemas.correction_governance import (
    ApplyCorrectionProposalRequest,
    CreateKnowledgePromotionRequest,
    CreateCorrectionProposalRequest,
    CorrectionGovernanceProjectionFilters,
    PromoteCorrectionProposalRequest,
    RollbackKnowledgePromotionRequest,
    RollbackCorrectionProposalRequest,
    SubmitCorrectionApprovalRequest,
    SupersedeKnowledgePromotionRequest,
    ValidateCorrectionProposalRequest,
)
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
)


class CorrectionGovernanceConflictError(ValueError):
    """Raised when a CCG workflow transition is not allowed."""


class CorrectionGovernanceService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_projection(
        self,
        filters: CorrectionGovernanceProjectionFilters,
        context: ServiceContext,
    ) -> dict[str, object]:
        stmt = select(CorrectionProposal).order_by(CorrectionProposal.created_at.desc())
        count_stmt = select(func.count()).select_from(CorrectionProposal)
        if filters.executionId is not None:
            stmt = stmt.where(CorrectionProposal.execution_id == filters.executionId)
            count_stmt = count_stmt.where(CorrectionProposal.execution_id == filters.executionId)
        if filters.requirementVersionId is not None:
            stmt = stmt.where(CorrectionProposal.requirement_version_id == filters.requirementVersionId)
            count_stmt = count_stmt.where(CorrectionProposal.requirement_version_id == filters.requirementVersionId)
        if filters.status:
            stmt = stmt.where(CorrectionProposal.status == filters.status)
            count_stmt = count_stmt.where(CorrectionProposal.status == filters.status)

        total = int(self.db.scalar(count_stmt) or 0)
        rows = list(
            self.db.scalars(
                stmt.offset((filters.page - 1) * filters.pageSize).limit(filters.pageSize)
            )
        )
        for proposal in rows:
            self._sync_approval_status(proposal)
        self.db.flush()

        capabilities = set(context.user.capabilities)
        items = [
            self._proposal_projection_item(proposal, capabilities)
            for proposal in rows
        ]
        can_operate = any(
            capability in capabilities
            for capability in (
                "correction.apply",
                "correction.validate",
                "correction.rollback",
                "correction.promote",
            )
        )
        return {
            "schemaVersion": "phase8.correction-governance-projection.v1",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "filters": {
                "executionId": str(filters.executionId) if filters.executionId else None,
                "requirementVersionId": str(filters.requirementVersionId) if filters.requirementVersionId else None,
                "status": filters.status,
                "page": filters.page,
                "pageSize": filters.pageSize,
            },
            "capability": {
                "read": "correction.read",
                "create": "correction.apply",
                "submitApproval": "correction.apply",
                "apply": "correction.apply",
                "validate": "correction.validate",
                "rollback": "correction.rollback",
                "promote": "correction.promote",
                "authorizationBoundary": "backend capability_dependency",
                "approvalBoundary": "ApprovalService",
                "guardrailBoundary": "RuntimeGuardrailEngine",
                "auditBoundary": "write_audit_log",
            },
            "operationPolicy": self._operation_policy(),
            "operationAvailability": {
                "createProposal": self._operation_state(
                    "createProposal",
                    "correction.apply",
                    capabilities,
                    state_allowed=True,
                    reason="available",
                ),
            },
            "items": items,
            "total": total,
            "page": filters.page,
            "pageSize": filters.pageSize,
            "readOnly": not can_operate,
            "evidenceOnly": True,
            "writesDecision": False,
        }

    def create_proposal(self, payload: CreateCorrectionProposalRequest, context: ServiceContext) -> dict[str, object]:
        if payload.idempotencyKey:
            existing = self.db.scalar(select(CorrectionProposal).where(CorrectionProposal.idempotency_key == payload.idempotencyKey))
            if existing is not None:
                return {**self.get_proposal(existing.id), "deduplicated": True}

        proposal_id = uuid4()
        created_at = datetime.now(timezone.utc)
        guardrail_refs = self._record_operation_guardrail(
            context,
            operation="create_proposal",
            resource_type="correction_proposal",
            resource_id=proposal_id,
            risk_level=payload.riskLevel,
            payload={"proposalType": payload.proposalType},
            approval_required=False,
        )
        metadata = {**payload.metadata, "guardrailEventRefs": guardrail_refs}
        contract = validate_contract(
            "correction-proposal",
            {
                "schemaVersion": "phase8.correction-proposal.v1",
                "correctionProposalId": str(proposal_id),
                "proposalType": payload.proposalType,
                "proposedChange": payload.proposedChange,
                "status": "draft",
                "requirementVersionId": str(payload.requirementVersionId) if payload.requirementVersionId else None,
                "executionId": str(payload.executionId) if payload.executionId else None,
                "findingId": str(payload.findingId) if payload.findingId else None,
                "attributionId": payload.attributionId,
                "riskLevel": payload.riskLevel.value,
                "requesterRef": {"type": "user", "id": str(context.user.id)},
                "approvalRefs": [],
                "evidenceRefs": payload.evidenceRefs,
                "traceRefs": self._merge_trace_refs(payload.traceRefs, context),
                "createdAt": created_at.isoformat(),
                "metadata": metadata,
            },
        )
        proposal = CorrectionProposal(
            id=proposal_id,
            proposal_type=contract["proposalType"],
            status=contract["status"],
            proposed_change=contract["proposedChange"],
            requirement_version_id=payload.requirementVersionId,
            execution_id=payload.executionId,
            finding_id=payload.findingId,
            attribution_id=payload.attributionId,
            risk_level=payload.riskLevel,
            requester_ref=contract["requesterRef"],
            requested_by=context.user.id,
            approval_refs=[],
            evidence_refs=contract["evidenceRefs"],
            trace_refs=contract["traceRefs"],
            contract_snapshot=contract,
            request_id=context.request_id,
            idempotency_key=payload.idempotencyKey,
            metadata_json=contract["metadata"],
        )
        self.db.add(proposal)
        self.db.flush()
        audit_refs = self._audit("correction_governance.proposal.create", "correction_proposal", proposal.id, context)
        proposal.metadata_json = {**proposal.metadata_json, "auditRefs": audit_refs}
        proposal.contract_snapshot = self.serialize_proposal_contract(proposal)
        self._emit_event(
            "CorrectionGovernanceProposalCreated",
            context,
            proposal_id=proposal.id,
            payload={"proposalType": proposal.proposal_type, "status": proposal.status},
            evidence_refs=proposal.evidence_refs,
            replay_refs=[{"type": "correction_proposal", "id": str(proposal.id)}],
        )
        self.db.commit()
        return self.get_proposal(proposal.id)

    def get_proposal(self, proposal_id: UUID) -> dict[str, object]:
        proposal = self._require_proposal(proposal_id)
        self._sync_approval_status(proposal)
        self.db.flush()
        return self.serialize_proposal_detail(proposal)

    def submit_approval(
        self,
        proposal_id: UUID,
        payload: SubmitCorrectionApprovalRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        proposal = self._require_proposal(proposal_id)
        self._sync_approval_status(proposal)
        if proposal.status not in {"draft", "pending_approval"}:
            raise CorrectionGovernanceConflictError("only draft proposals may be submitted for approval")

        guardrail_refs = self._record_operation_guardrail(
            context,
            operation="submit_approval",
            resource_type="correction_proposal",
            resource_id=proposal.id,
            risk_level=proposal.risk_level,
            payload={"proposalType": proposal.proposal_type, "status": proposal.status},
            approval_required=True,
        )
        approval = self._get_or_create_correction_approval(proposal, payload, context, guardrail_refs)
        proposal.status = "pending_approval"
        proposal.approval_refs = self._append_ref(
            proposal.approval_refs,
            {"type": "approval", "id": str(approval.id), "status": approval.status.value},
        )
        proposal.contract_snapshot = self.serialize_proposal_contract(proposal)
        audit_refs = self._audit("correction_governance.approval.submit", "correction_proposal", proposal.id, context)
        proposal.metadata_json = {
            **proposal.metadata_json,
            "approvalSubmitGuardrailEventRefs": guardrail_refs,
            "approvalSubmitAuditRefs": audit_refs,
        }
        proposal.contract_snapshot = self.serialize_proposal_contract(proposal)
        self._emit_event(
            "CorrectionGovernanceApprovalSubmitted",
            context,
            proposal_id=proposal.id,
            payload={"approvalId": str(approval.id), "status": approval.status.value},
            evidence_refs=proposal.evidence_refs,
            replay_refs=[{"type": "approval", "id": str(approval.id)}],
            extra_correlation_refs={"approvalId": str(approval.id)},
        )
        self.db.commit()
        return self.serialize_proposal_detail(proposal)

    def apply_proposal(
        self,
        proposal_id: UUID,
        payload: ApplyCorrectionProposalRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        proposal = self._require_proposal(proposal_id)
        self._sync_approval_status(proposal)
        if proposal.status != "approved":
            raise CorrectionGovernanceConflictError("proposal must be approved before apply")

        request_hash = self._application_request_hash(payload)
        existing = self._application_by_idempotency(proposal.id, payload.idempotencyKey)
        if existing is not None:
            self._ensure_application_idempotency(existing, request_hash)
            return {**self.serialize_application(existing), "deduplicated": True}
        latest_application = self._latest_application(proposal.id)
        if latest_application is not None and latest_application.status == "applied":
            if latest_application.idempotency_key == payload.idempotencyKey:
                self._ensure_application_idempotency(latest_application, request_hash)
                return {**self.serialize_application(latest_application), "deduplicated": True}
            raise CorrectionGovernanceConflictError("proposal already has an applied correction application")

        now = datetime.now(timezone.utc)
        application_id = uuid4()
        trace_refs = self._merge_trace_refs(payload.traceRefs, context)
        guardrail_refs = self._record_operation_guardrail(
            context,
            operation="apply",
            resource_type="correction_application",
            resource_id=application_id,
            risk_level=proposal.risk_level,
            payload={"correctionProposalId": str(proposal.id), "status": payload.status},
            approval_required=True,
        )
        metadata = {
            **payload.metadata,
            "guardrailEventRefs": guardrail_refs,
            "idempotencyRequestHash": request_hash,
        }
        contract = validate_contract(
            "correction-application",
            {
                "schemaVersion": "phase8.correction-application.v1",
                "correctionApplicationId": str(application_id),
                "correctionProposalId": str(proposal.id),
                "idempotencyKey": payload.idempotencyKey,
                "requestId": payload.requestId,
                "status": payload.status,
                "appliedChangeRefs": payload.appliedChangeRefs,
                "sideEffectRefs": payload.sideEffectRefs,
                "evidenceRefs": payload.evidenceRefs,
                "traceRefs": trace_refs,
                "startedAt": now.isoformat(),
                "finishedAt": now.isoformat(),
                "metadata": metadata,
            },
        )
        application = CorrectionApplication(
            id=application_id,
            correction_proposal_id=proposal.id,
            idempotency_key=contract["idempotencyKey"],
            request_id=contract["requestId"],
            status=contract["status"],
            applied_change_refs=contract["appliedChangeRefs"],
            side_effect_refs=contract["sideEffectRefs"],
            evidence_refs=contract["evidenceRefs"],
            trace_refs=contract["traceRefs"],
            contract_snapshot=contract,
            applied_by=context.user.id,
            started_at=now,
            finished_at=now,
            metadata_json=contract["metadata"],
        )
        try:
            with self.db.begin_nested():
                self.db.add(application)
                self.db.flush()
        except IntegrityError:
            existing = self._application_by_idempotency(proposal.id, payload.idempotencyKey)
            if existing is None:
                raise
            self._ensure_application_idempotency(existing, request_hash)
            return {**self.serialize_application(existing), "deduplicated": True}
        audit_refs = self._audit("correction_governance.apply", "correction_application", application.id, context)
        application.metadata_json = {**application.metadata_json, "auditRefs": audit_refs}
        application.contract_snapshot = self.serialize_application(application)
        self._emit_event(
            "CorrectionGovernanceApplicationRecorded",
            context,
            proposal_id=proposal.id,
            payload={"applicationId": str(application.id), "status": application.status},
            evidence_refs=application.evidence_refs,
            replay_refs=[{"type": "correction_application", "id": str(application.id)}],
            extra_correlation_refs={"correctionApplicationId": str(application.id)},
        )
        self.db.commit()
        return self.serialize_application(application)

    def validate_proposal(
        self,
        proposal_id: UUID,
        payload: ValidateCorrectionProposalRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        proposal = self._require_proposal(proposal_id)
        self._sync_approval_status(proposal)
        if proposal.status != "approved":
            raise CorrectionGovernanceConflictError("proposal must be approved before validation")

        application = self._validation_application(proposal.id, payload.correctionApplicationId)
        existing = self._validation_by_idempotency(application.id, payload.idempotencyKey)
        if existing is not None:
            return {**self.serialize_validation(existing), "deduplicated": True}
        if self._latest_successful_validation(application.id) is not None:
            raise CorrectionGovernanceConflictError("application already has a successful validation")

        now = datetime.now(timezone.utc)
        validation_id = uuid4()
        result = payload.result.model_dump(mode="json")
        self._ensure_passed_validation_has_refs(result)
        validation_status = "validated" if result["passed"] else "validation_failed"
        guardrail_refs = self._record_operation_guardrail(
            context,
            operation="validate",
            resource_type="correction_validation",
            resource_id=validation_id,
            risk_level=proposal.risk_level,
            payload={
                "correctionProposalId": str(proposal.id),
                "correctionApplicationId": str(application.id),
                "status": validation_status,
                "passed": result["passed"],
            },
            approval_required=True,
        )
        metadata = {**payload.metadata, "guardrailEventRefs": guardrail_refs}
        contract = validate_contract(
            "correction-validation",
            {
                "schemaVersion": "phase8.correction-validation.v1",
                "correctionValidationId": str(validation_id),
                "correctionProposalId": str(proposal.id),
                "correctionApplicationId": str(application.id),
                "idempotencyKey": payload.idempotencyKey,
                "requestId": payload.requestId,
                "status": validation_status,
                "result": result,
                "traceRefs": self._merge_trace_refs(payload.traceRefs, context),
                "startedAt": now.isoformat(),
                "finishedAt": now.isoformat(),
                "metadata": metadata,
            },
        )
        validation = CorrectionValidation(
            id=validation_id,
            correction_proposal_id=proposal.id,
            correction_application_id=application.id,
            idempotency_key=contract["idempotencyKey"],
            request_id=contract["requestId"],
            status=contract["status"],
            result=contract["result"],
            trace_refs=contract["traceRefs"],
            contract_snapshot=contract,
            started_at=now,
            finished_at=now,
            metadata_json=contract["metadata"],
        )
        self.db.add(validation)
        self.db.flush()
        audit_refs = self._audit("correction_governance.validate", "correction_validation", validation.id, context)
        validation.metadata_json = {**validation.metadata_json, "auditRefs": audit_refs}
        validation.contract_snapshot = self.serialize_validation(validation)
        self._emit_event(
            "CorrectionGovernanceValidationRecorded",
            context,
            proposal_id=proposal.id,
            payload={"validationId": str(validation.id), "status": validation.status, "passed": validation.result["passed"]},
            evidence_refs=validation.result.get("evidenceRefs") or [],
            replay_refs=validation.result.get("replayRefs") or [],
            extra_correlation_refs={
                "correctionApplicationId": str(application.id),
                "correctionValidationId": str(validation.id),
            },
        )
        self.db.commit()
        return self.serialize_validation(validation)

    def rollback_proposal(
        self,
        proposal_id: UUID,
        payload: RollbackCorrectionProposalRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        proposal = self._require_proposal(proposal_id)
        existing = self._rollback_by_idempotency(proposal.id, payload.idempotencyKey)
        if existing is not None:
            return {**self.serialize_rollback(existing), "deduplicated": True}
        terminal = self._latest_terminal_rollback(proposal.id)
        if terminal is not None:
            raise CorrectionGovernanceConflictError("rollback already recorded for proposal")

        application = self._latest_application(proposal.id)
        if application is None:
            raise CorrectionGovernanceConflictError("proposal has no correction application to rollback")
        validation = self._latest_validation(proposal.id)
        status = self._rollback_status(application, validation, payload)
        if status == "rollback_failed" and not payload.evidenceRefs:
            raise CorrectionGovernanceConflictError("rollback_failed must retain evidenceRefs")

        now = datetime.now(timezone.utc)
        rollback_id = uuid4()
        guardrail_refs = self._record_operation_guardrail(
            context,
            operation="rollback",
            resource_type="rollback_record",
            resource_id=rollback_id,
            risk_level=proposal.risk_level,
            payload={
                "correctionProposalId": str(proposal.id),
                "correctionApplicationId": str(application.id),
                "correctionValidationId": str(validation.id) if validation else None,
                "status": status,
            },
            approval_required=True,
        )
        metadata = {**payload.metadata, "guardrailEventRefs": guardrail_refs}
        contract = validate_contract(
            "rollback-record",
            {
                "schemaVersion": "phase8.rollback-record.v1",
                "rollbackRecordId": str(rollback_id),
                "correctionProposalId": str(proposal.id),
                "correctionApplicationId": str(application.id) if application else None,
                "correctionValidationId": str(validation.id) if validation else None,
                "idempotencyKey": payload.idempotencyKey,
                "requestId": payload.requestId,
                "status": status,
                "rollbackReason": payload.rollbackReason,
                "rollbackRefs": payload.rollbackRefs,
                "evidenceRefs": payload.evidenceRefs,
                "traceRefs": self._merge_trace_refs(payload.traceRefs, context),
                "startedAt": None if status == "rollback_not_required" else now.isoformat(),
                "finishedAt": None if status == "rollback_not_required" else now.isoformat(),
                "metadata": metadata,
            },
        )
        rollback = RollbackRecord(
            id=rollback_id,
            correction_proposal_id=proposal.id,
            correction_application_id=application.id if application else None,
            correction_validation_id=validation.id if validation else None,
            idempotency_key=contract["idempotencyKey"],
            request_id=contract["requestId"],
            status=contract["status"],
            rollback_reason=contract["rollbackReason"],
            rollback_refs=contract["rollbackRefs"],
            evidence_refs=contract["evidenceRefs"],
            trace_refs=contract["traceRefs"],
            contract_snapshot=contract,
            started_at=now if status != "rollback_not_required" else None,
            finished_at=now if status != "rollback_not_required" else None,
            metadata_json=contract["metadata"],
        )
        self.db.add(rollback)
        self.db.flush()
        audit_refs = self._audit("correction_governance.rollback", "rollback_record", rollback.id, context)
        rollback.metadata_json = {**rollback.metadata_json, "auditRefs": audit_refs}
        rollback.contract_snapshot = self.serialize_rollback(rollback)
        self._emit_event(
            "CorrectionGovernanceRollbackRecorded",
            context,
            proposal_id=proposal.id,
            payload={"rollbackRecordId": str(rollback.id), "status": rollback.status},
            evidence_refs=rollback.evidence_refs,
            replay_refs=[{"type": "rollback_record", "id": str(rollback.id)}],
            extra_correlation_refs={
                "correctionApplicationId": str(application.id),
                "correctionValidationId": str(validation.id) if validation else None,
                "rollbackRecordId": str(rollback.id),
            },
        )
        self.db.commit()
        return self.serialize_rollback(rollback)

    def promote_proposal(
        self,
        proposal_id: UUID,
        payload: PromoteCorrectionProposalRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        return self._create_knowledge_promotion(proposal_id, payload, context)

    def create_knowledge_promotion(
        self,
        payload: CreateKnowledgePromotionRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        return self._create_knowledge_promotion(payload.correctionProposalId, payload, context)

    def get_knowledge_promotion(self, promotion_id: UUID) -> dict[str, object]:
        return self.serialize_knowledge_promotion(self._require_knowledge_promotion(promotion_id))

    def rollback_knowledge_promotion(
        self,
        promotion_id: UUID,
        payload: RollbackKnowledgePromotionRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        promotion = self._require_knowledge_promotion(promotion_id)
        if promotion.status == "rolled_back":
            if promotion.rollback_ref.get("idempotencyKey") == payload.idempotencyKey:
                return {**self.serialize_knowledge_promotion(promotion), "deduplicated": True}
            raise CorrectionGovernanceConflictError("knowledge promotion already rolled back")
        if promotion.status != "promoted":
            raise CorrectionGovernanceConflictError("only promoted Knowledge Promotion records can be rolled back")

        rollback_ref = {
            **payload.rollbackRef,
            "type": payload.rollbackRef.get("type") or "knowledge_promotion_rollback",
            "id": payload.rollbackRef.get("id") or payload.requestId,
            "reason": payload.rollbackReason,
            "idempotencyKey": payload.idempotencyKey,
        }
        promotion.status = "rolled_back"
        promotion.rollback_ref = rollback_ref
        promotion.evidence_refs = self._append_refs(promotion.evidence_refs, payload.evidenceRefs)
        promotion.metadata_json = {**promotion.metadata_json, "rollback": payload.metadata}
        self._audit("knowledge_promotion.rollback", "knowledge_promotion_record", promotion.id, context)
        promotion.audit_refs = self._append_ref(
            promotion.audit_refs,
            {"type": "audit", "action": "knowledge_promotion.rollback", "requestId": context.request_id},
        )
        promotion.contract_snapshot = self.serialize_knowledge_promotion_contract(promotion)
        self._emit_event(
            "CorrectionGovernanceKnowledgePromotionRolledBack",
            context,
            proposal_id=promotion.source_correction_id,
            payload={"knowledgePromotionId": str(promotion.id), "status": promotion.status, "rollbackReason": payload.rollbackReason},
            evidence_refs=payload.evidenceRefs,
            replay_refs=promotion.replay_refs,
            extra_correlation_refs={
                "knowledgePromotionId": str(promotion.id),
                "correctionValidationId": str(promotion.correction_validation_id),
                "coverageProofBundleId": str(promotion.coverage_proof_bundle_id),
            },
        )
        self.db.commit()
        return self.serialize_knowledge_promotion(promotion)

    def _project_knowledge_promotion(
        self,
        promotion_id: UUID,
        entry: dict[str, Any],
        context: ServiceContext,
    ) -> dict[str, object]:
        from agentic_qa.services.memory_service import MemoryService

        try:
            projection = MemoryService(self.db).promote_test_knowledge_entry(entry, context)
        except Exception as exc:
            self.db.rollback()
            promotion = self._require_knowledge_promotion(promotion_id)
            promotion.projection_state = "projection_failed"
            promotion.projection_refs = self._append_ref(
                promotion.projection_refs,
                {
                    "type": "memory_projection",
                    "id": str(promotion.id),
                    "status": "failed",
                    "errorCode": type(exc).__name__,
                },
            )
            audit_refs = self._audit(
                "knowledge_promotion.projection_failed",
                "knowledge_promotion_record",
                promotion.id,
                context,
            )
            promotion.audit_refs = self._append_refs(promotion.audit_refs, audit_refs)
            promotion.metadata_json = {
                **promotion.metadata_json,
                "projection": {
                    "status": "failed",
                    "errorCode": type(exc).__name__,
                },
            }
            promotion.contract_snapshot = self.serialize_knowledge_promotion_contract(promotion)
            self._emit_event(
                "CorrectionGovernanceKnowledgeProjectionFailed",
                context,
                proposal_id=promotion.source_correction_id,
                payload={
                    "knowledgePromotionId": str(promotion.id),
                    "projectionState": promotion.projection_state,
                    "errorCode": type(exc).__name__,
                },
                evidence_refs=promotion.evidence_refs,
                replay_refs=promotion.replay_refs,
                extra_correlation_refs={
                    "knowledgePromotionId": str(promotion.id),
                    "correctionValidationId": str(promotion.correction_validation_id),
                    "coverageProofBundleId": str(promotion.coverage_proof_bundle_id),
                },
            )
            self.db.commit()
            return self.serialize_knowledge_promotion(promotion)

        promotion = self._require_knowledge_promotion(promotion_id)
        promotion.projection_state = "projected"
        promotion.projection_refs = self._append_ref(
            promotion.projection_refs,
            {
                "type": "memory",
                "id": str(projection["id"]),
                "knowledgeId": str(projection["knowledgeId"]),
                "status": "projected",
            },
        )
        audit_refs = self._audit(
            "knowledge_promotion.projected",
            "knowledge_promotion_record",
            promotion.id,
            context,
        )
        promotion.audit_refs = self._append_refs(promotion.audit_refs, audit_refs)
        promotion.contract_snapshot = self.serialize_knowledge_promotion_contract(promotion)
        self._emit_event(
            "CorrectionGovernanceKnowledgeProjected",
            context,
            proposal_id=promotion.source_correction_id,
            payload={
                "knowledgePromotionId": str(promotion.id),
                "projectionState": promotion.projection_state,
                "memoryId": str(projection["id"]),
            },
            evidence_refs=promotion.evidence_refs,
            replay_refs=promotion.replay_refs,
            extra_correlation_refs={
                "knowledgePromotionId": str(promotion.id),
                "correctionValidationId": str(promotion.correction_validation_id),
                "coverageProofBundleId": str(promotion.coverage_proof_bundle_id),
            },
        )
        self.db.commit()
        return self.serialize_knowledge_promotion(promotion)

    def request_knowledge_promotion_supersede(
        self,
        promotion_id: UUID,
        payload: SupersedeKnowledgePromotionRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        promotion = self._require_knowledge_promotion(promotion_id)
        if promotion.status == "superseded":
            if promotion.supersede_ref.get("idempotencyKey") == payload.idempotencyKey:
                return {**self.serialize_knowledge_promotion(promotion), "deduplicated": True}
            raise CorrectionGovernanceConflictError("knowledge promotion already superseded")
        if promotion.status != "promoted":
            raise CorrectionGovernanceConflictError("only promoted Knowledge Promotion records can be superseded")
        if payload.replacementKnowledgePromotionId is not None:
            replacement = self._require_knowledge_promotion(payload.replacementKnowledgePromotionId)
            if replacement.id == promotion.id:
                raise CorrectionGovernanceConflictError("replacement Knowledge Promotion cannot be the superseded record")

        approval_resource_id = (
            f"knowledge-supersede:{promotion.id}:{payload.idempotencyKey}"
        )
        existing_approval = self.db.scalar(
            select(Approval)
            .where(Approval.type == ApprovalType.OTHER)
            .where(Approval.resource_type == "knowledge_promotion_supersede")
            .where(Approval.resource_id == approval_resource_id)
            .order_by(Approval.created_at.desc())
        )
        if existing_approval is not None:
            return {
                "approvalRequired": True,
                "workflow": "knowledge_supersede",
                "approvalId": str(existing_approval.id),
                "status": existing_approval.status.value,
                "knowledgePromotionId": str(promotion.id),
                "guardrailEventRefs": existing_approval.payload.get(
                    "guardrailEventRefs"
                )
                or [],
                "currentRecord": self.serialize_knowledge_promotion(promotion),
                "deduplicated": True,
            }

        guardrail_refs = self._record_knowledge_supersede_guardrail(
            context,
            promotion_id=promotion.id,
            payload=payload.model_dump(mode="json"),
        )
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="knowledge_promotion_supersede",
            resource_id=approval_resource_id,
            summary=f"Approval required before superseding Knowledge Promotion {promotion.id}.",
            payload={
                "action": "knowledge_promotion.supersede",
                "knowledgePromotionId": str(promotion.id),
                "supersedeReason": payload.supersedeReason,
                "supersedeRef": payload.supersedeRef,
                "replacementKnowledgePromotionId": str(payload.replacementKnowledgePromotionId) if payload.replacementKnowledgePromotionId else None,
                "evidenceRefs": payload.evidenceRefs,
                "traceRefs": payload.traceRefs,
                "metadata": payload.metadata,
                "idempotencyKey": payload.idempotencyKey,
                "requestId": payload.requestId,
                "guardrailEventRefs": guardrail_refs,
                "requestedBy": str(context.user.id),
            },
            context=context,
        )
        return {
            "approvalRequired": True,
            "workflow": "knowledge_supersede",
            "approvalId": str(approval.id),
            "status": approval.status.value,
            "knowledgePromotionId": str(promotion.id),
            "guardrailEventRefs": guardrail_refs,
            "currentRecord": self.serialize_knowledge_promotion(promotion),
        }

    def execute_approved_knowledge_supersede(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        promotion = self._require_knowledge_promotion(UUID(str(approval_payload["knowledgePromotionId"])))
        idempotency_key = str(approval_payload["idempotencyKey"])
        if promotion.status == "superseded":
            if promotion.supersede_ref.get("idempotencyKey") == idempotency_key:
                return {**self.serialize_knowledge_promotion(promotion), "deduplicated": True}
            raise CorrectionGovernanceConflictError("knowledge promotion already superseded")
        if promotion.status != "promoted":
            raise CorrectionGovernanceConflictError("only promoted Knowledge Promotion records can be superseded")

        supplied_ref = dict(approval_payload.get("supersedeRef") or {})
        supersede_ref = {
            **supplied_ref,
            "type": supplied_ref.get("type") or "knowledge_promotion_supersede",
            "id": supplied_ref.get("id") or str(approval_payload["requestId"]),
            "reason": str(approval_payload["supersedeReason"]),
            "idempotencyKey": idempotency_key,
            "approvalId": str(approval_id),
        }
        replacement_id = approval_payload.get("replacementKnowledgePromotionId")
        if replacement_id:
            replacement = self._require_knowledge_promotion(UUID(str(replacement_id)))
            if replacement.id == promotion.id:
                raise CorrectionGovernanceConflictError("replacement Knowledge Promotion cannot be the superseded record")
            supersede_ref["replacementKnowledgePromotionId"] = str(replacement.id)

        evidence_refs = list(approval_payload.get("evidenceRefs") or [])
        promotion.status = "superseded"
        promotion.supersede_ref = supersede_ref
        promotion.evidence_refs = self._append_refs(promotion.evidence_refs, evidence_refs)
        promotion.approval_refs = self._append_ref(
            promotion.approval_refs,
            {"type": "approval", "id": str(approval_id), "status": "approved", "action": "knowledge_promotion.supersede"},
        )
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            "knowledge_promotion.supersede",
            "knowledge_promotion_record",
            str(promotion.id),
            context.request_id,
            context.trace_id,
            {
                "approvalId": str(approval_id),
                "supersedeReason": approval_payload["supersedeReason"],
                "guardrailEventRefs": approval_payload.get("guardrailEventRefs") or [],
                "replacementKnowledgePromotionId": replacement_id,
            },
        )
        self.db.flush()
        promotion.audit_refs = self._append_ref(
            promotion.audit_refs,
            {"type": "audit_log", "id": str(audit.id), "action": "knowledge_promotion.supersede"},
        )
        promotion.metadata_json = {**promotion.metadata_json, "supersede": dict(approval_payload.get("metadata") or {})}
        promotion.contract_snapshot = self.serialize_knowledge_promotion_contract(promotion)
        self._emit_event(
            "CorrectionGovernanceKnowledgePromotionSuperseded",
            context,
            proposal_id=promotion.source_correction_id,
            payload={
                "knowledgePromotionId": str(promotion.id),
                "status": promotion.status,
                "supersedeReason": approval_payload["supersedeReason"],
            },
            evidence_refs=evidence_refs,
            replay_refs=promotion.replay_refs,
            extra_correlation_refs={
                "knowledgePromotionId": str(promotion.id),
                "correctionValidationId": str(promotion.correction_validation_id),
                "coverageProofBundleId": str(promotion.coverage_proof_bundle_id),
            },
        )
        return self.serialize_knowledge_promotion(promotion)

    def _create_knowledge_promotion(
        self,
        proposal_id: UUID,
        payload: PromoteCorrectionProposalRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        acquire_transaction_advisory_lock(
            self.db,
            "knowledge-promotion",
            str(proposal_id),
        )
        proposal = self._require_proposal(proposal_id)
        request_hash = self._promotion_request_hash(payload)
        if payload.idempotencyKey:
            existing = self.db.scalar(
                select(KnowledgePromotionRecord)
                .where(KnowledgePromotionRecord.source_correction_id == proposal.id)
                .where(KnowledgePromotionRecord.idempotency_key == payload.idempotencyKey)
            )
            if existing is not None:
                persisted_hash = existing.metadata_json.get(
                    "idempotencyRequestHash"
                )
                if (
                    persisted_hash is not None
                    and persisted_hash != request_hash
                ) or (
                    persisted_hash is None
                    and existing.knowledge_entry_snapshot
                    != payload.knowledgeEntry.model_dump(mode="json")
                ):
                    raise CorrectionGovernanceConflictError(
                        "knowledge promotion idempotency conflict"
                    )
                return {**self.serialize_knowledge_promotion(existing), "deduplicated": True}

        self._sync_approval_status(proposal)
        validation = self._latest_successful_validation_for_proposal(proposal.id)
        if validation is None:
            raise CorrectionGovernanceConflictError("proposal must be validated before promotion")
        existing_promotion = self._latest_knowledge_promotion(proposal.id)
        if existing_promotion is not None and existing_promotion.status == "promoted":
            return {**self.serialize_knowledge_promotion(existing_promotion), "deduplicated": True}

        entry = payload.knowledgeEntry.model_dump(mode="json")
        self._ensure_ccg_knowledge_entry(entry, proposal, validation)
        replay_validation_ref = self._replay_validation_ref(validation, payload.replayValidationId)
        approval_state, approval_refs, policy_snapshot = self._promotion_approval_state(proposal, payload.approvalRefs)
        self._ensure_no_failed_replay_refs(entry.get("replayRefs") or [])
        coverage_proof = self._require_valid_coverage_proof(payload.coverageProofRef, proposal, validation)

        now = datetime.now(timezone.utc)
        promotion_id = uuid4()
        guardrail_refs = self._record_operation_guardrail(
            context,
            operation="promote",
            resource_type="knowledge_promotion_record",
            resource_id=promotion_id,
            risk_level=proposal.risk_level,
            payload={
                "correctionProposalId": str(proposal.id),
                "correctionValidationId": str(validation.id),
                "coverageProofBundleId": str(coverage_proof.id),
            },
            approval_required=True,
        )
        coverage_proof_ref = {
            **payload.coverageProofRef,
            "id": str(coverage_proof.id),
            "proofStatus": coverage_proof.proof_status.value,
            "source": "persisted_record",
            "requirementVersionId": str(coverage_proof.requirement_version_id),
            "requirementItemId": coverage_proof.requirement_item_id,
            "scope": {
                "correctionProposalId": str(proposal.id),
                "correctionValidationId": str(validation.id),
                "requirementVersionId": str(coverage_proof.requirement_version_id),
                "requirementItemId": coverage_proof.requirement_item_id,
                "replayExportRef": coverage_proof.replay_export_ref,
                "replayExportHash": coverage_proof.replay_export_hash,
            },
        }
        audit_refs = [{"type": "audit", "action": "knowledge_promotion.promote", "requestId": context.request_id}]
        metadata = {
            **payload.metadata,
            "guardrailEventRefs": guardrail_refs,
            "idempotencyRequestHash": request_hash,
        }
        contract = validate_contract(
            "knowledge-promotion-record",
            {
                "schemaVersion": "phase8.knowledge-promotion-record.v1",
                "knowledgePromotionId": str(promotion_id),
                "source": payload.source.value,
                "sourceCorrectionId": str(proposal.id),
                "correctionValidationId": str(validation.id),
                "replayValidationId": payload.replayValidationId,
                "replayValidationRef": replay_validation_ref,
                "coverageProofRef": coverage_proof_ref,
                "knowledgeEntry": entry,
                "evidenceRefs": entry["evidenceRefs"],
                "replayRefs": entry["replayRefs"],
                "approvalRefs": approval_refs,
                "approvalState": approval_state,
                "policySnapshot": policy_snapshot,
                "auditRefs": audit_refs,
                "rollbackRef": {},
                "supersedeRef": {},
                "projectionState": "skipped",
                "projectionRefs": [],
                "status": "promoted",
                "promotedAt": now.isoformat(),
                "promotedBy": str(context.user.id),
                "traceId": context.trace_id,
                "idempotencyKey": payload.idempotencyKey,
                "requestId": context.request_id,
                "metadata": metadata,
            },
        )
        promotion = KnowledgePromotionRecord(
            id=promotion_id,
            source=contract["source"],
            source_correction_id=proposal.id,
            correction_validation_id=validation.id,
            replay_validation_id=contract["replayValidationId"],
            replay_validation_ref=contract["replayValidationRef"],
            coverage_proof_bundle_id=coverage_proof.id,
            coverage_proof_ref=contract["coverageProofRef"],
            knowledge_entry_snapshot=contract["knowledgeEntry"],
            evidence_refs=contract["evidenceRefs"],
            replay_refs=contract["replayRefs"],
            approval_refs=contract["approvalRefs"],
            approval_state=contract["approvalState"],
            policy_snapshot=contract["policySnapshot"],
            audit_refs=contract["auditRefs"],
            rollback_ref=contract["rollbackRef"],
            supersede_ref=contract["supersedeRef"],
            projection_state=contract["projectionState"],
            projection_refs=contract["projectionRefs"],
            status=contract["status"],
            promoted_at=now,
            promoted_by=context.user.id,
            trace_id=UUID(context.trace_id),
            contract_snapshot=contract,
            request_id=contract["requestId"],
            idempotency_key=contract["idempotencyKey"],
            metadata_json=contract["metadata"],
        )
        self.db.add(promotion)
        self.db.flush()
        proposal.promotion_refs = [
            {
                "type": "knowledge_promotion_record",
                "id": str(promotion.id),
                "knowledgeId": entry["knowledgeId"],
                "correctionValidationId": str(validation.id),
                "coverageProofBundleId": str(coverage_proof.id),
            }
        ]
        proposal.promoted_at = now
        proposal.metadata_json = {**proposal.metadata_json, "promotion": payload.metadata}
        audit_refs = self._audit("knowledge_promotion.promote", "knowledge_promotion_record", promotion.id, context)
        promotion.audit_refs = audit_refs
        promotion.metadata_json = {**promotion.metadata_json, "auditRefs": audit_refs}
        promotion.contract_snapshot = self.serialize_knowledge_promotion_contract(promotion)
        self._emit_event(
            "CorrectionGovernanceKnowledgePromotionRequested",
            context,
            proposal_id=proposal.id,
            payload={"knowledgePromotionId": str(promotion.id), "source": promotion.source},
            evidence_refs=promotion.evidence_refs,
            replay_refs=promotion.replay_refs,
            extra_correlation_refs={
                "knowledgePromotionId": str(promotion.id),
                "correctionValidationId": str(validation.id),
                "coverageProofBundleId": str(coverage_proof.id),
            },
        )
        self._emit_event(
            "CorrectionGovernanceKnowledgePromoted",
            context,
            proposal_id=proposal.id,
            payload={"knowledgePromotionId": str(promotion.id), "knowledgeId": entry["knowledgeId"], "status": promotion.status},
            evidence_refs=promotion.evidence_refs,
            replay_refs=promotion.replay_refs,
            extra_correlation_refs={
                "knowledgePromotionId": str(promotion.id),
                "correctionValidationId": str(validation.id),
                "coverageProofBundleId": str(coverage_proof.id),
            },
        )
        self.db.commit()
        if payload.metadata.get("projectToMemory") is True:
            return self._project_knowledge_promotion(promotion.id, entry, context)
        return self.serialize_knowledge_promotion(promotion)

    def _promotion_request_hash(
        self,
        payload: PromoteCorrectionProposalRequest,
    ) -> str:
        encoded = json.dumps(
            payload.model_dump(mode="json", exclude_none=True),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def _application_request_hash(
        self,
        payload: ApplyCorrectionProposalRequest,
    ) -> str:
        encoded = json.dumps(
            payload.model_dump(mode="json", exclude_none=True),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def _ensure_application_idempotency(
        self,
        application: CorrectionApplication,
        request_hash: str,
    ) -> None:
        persisted_hash = application.metadata_json.get("idempotencyRequestHash")
        if persisted_hash is not None and persisted_hash != request_hash:
            raise CorrectionGovernanceConflictError(
                "correction application idempotency conflict"
            )

    def serialize_proposal_detail(self, proposal: CorrectionProposal) -> dict[str, object]:
        applications = list(
            self.db.scalars(
                select(CorrectionApplication)
                .where(CorrectionApplication.correction_proposal_id == proposal.id)
                .order_by(CorrectionApplication.created_at.asc())
            )
        )
        validations = list(
            self.db.scalars(
                select(CorrectionValidation)
                .where(CorrectionValidation.correction_proposal_id == proposal.id)
                .order_by(CorrectionValidation.created_at.asc())
            )
        )
        rollbacks = list(
            self.db.scalars(
                select(RollbackRecord)
                .where(RollbackRecord.correction_proposal_id == proposal.id)
                .order_by(RollbackRecord.created_at.asc())
            )
        )
        approvals = self._correction_approvals(proposal.id)
        promotions = list(
            self.db.scalars(
                select(KnowledgePromotionRecord)
                .where(KnowledgePromotionRecord.source_correction_id == proposal.id)
                .order_by(KnowledgePromotionRecord.created_at.asc())
            )
        )
        return {
            **self.serialize_proposal_contract(proposal),
            "overallStatus": self._overall_status(proposal, applications, validations, rollbacks, promotions),
            "applications": [self.serialize_application(item) for item in applications],
            "validations": [self.serialize_validation(item) for item in validations],
            "rollbackRecords": [self.serialize_rollback(item) for item in rollbacks],
            "approvals": [self._serialize_approval(item) for item in approvals],
            "knowledgePromotions": [self.serialize_knowledge_promotion(item) for item in promotions],
            "promotionRefs": proposal.promotion_refs,
            "promotedAt": proposal.promoted_at.isoformat() if proposal.promoted_at else None,
            "updatedAt": proposal.updated_at.isoformat() if proposal.updated_at else None,
            "timeline": self._timeline(proposal, applications, validations, rollbacks, approvals, promotions),
        }

    def serialize_proposal_contract(self, proposal: CorrectionProposal) -> dict[str, Any]:
        return validate_contract(
            "correction-proposal",
            {
                "schemaVersion": "phase8.correction-proposal.v1",
                "correctionProposalId": str(proposal.id),
                "proposalType": proposal.proposal_type,
                "proposedChange": proposal.proposed_change,
                "status": proposal.status,
                "requirementVersionId": str(proposal.requirement_version_id) if proposal.requirement_version_id else None,
                "executionId": str(proposal.execution_id) if proposal.execution_id else None,
                "findingId": str(proposal.finding_id) if proposal.finding_id else None,
                "attributionId": proposal.attribution_id,
                "riskLevel": proposal.risk_level.value,
                "requesterRef": proposal.requester_ref,
                "approvalRefs": proposal.approval_refs,
                "evidenceRefs": proposal.evidence_refs,
                "traceRefs": proposal.trace_refs,
                "createdAt": self._iso(proposal.created_at),
                "metadata": proposal.metadata_json,
            },
        )

    def serialize_application(self, application: CorrectionApplication) -> dict[str, Any]:
        return validate_contract(
            "correction-application",
            {
                "schemaVersion": "phase8.correction-application.v1",
                "correctionApplicationId": str(application.id),
                "correctionProposalId": str(application.correction_proposal_id),
                "idempotencyKey": application.idempotency_key,
                "requestId": application.request_id,
                "status": application.status,
                "appliedChangeRefs": application.applied_change_refs,
                "sideEffectRefs": application.side_effect_refs,
                "evidenceRefs": application.evidence_refs,
                "traceRefs": application.trace_refs,
                "startedAt": self._iso_optional(application.started_at),
                "finishedAt": self._iso_optional(application.finished_at),
                "metadata": application.metadata_json,
            },
        )

    def serialize_validation(self, validation: CorrectionValidation) -> dict[str, Any]:
        return validate_contract(
            "correction-validation",
            {
                "schemaVersion": "phase8.correction-validation.v1",
                "correctionValidationId": str(validation.id),
                "correctionProposalId": str(validation.correction_proposal_id),
                "correctionApplicationId": str(validation.correction_application_id),
                "idempotencyKey": validation.idempotency_key,
                "requestId": validation.request_id,
                "status": validation.status,
                "result": validation.result,
                "traceRefs": validation.trace_refs,
                "startedAt": self._iso_optional(validation.started_at),
                "finishedAt": self._iso_optional(validation.finished_at),
                "metadata": validation.metadata_json,
            },
        )

    def serialize_rollback(self, rollback: RollbackRecord) -> dict[str, Any]:
        return validate_contract(
            "rollback-record",
            {
                "schemaVersion": "phase8.rollback-record.v1",
                "rollbackRecordId": str(rollback.id),
                "correctionProposalId": str(rollback.correction_proposal_id),
                "correctionApplicationId": str(rollback.correction_application_id) if rollback.correction_application_id else None,
                "correctionValidationId": str(rollback.correction_validation_id) if rollback.correction_validation_id else None,
                "idempotencyKey": rollback.idempotency_key,
                "requestId": rollback.request_id,
                "status": rollback.status,
                "rollbackReason": rollback.rollback_reason,
                "rollbackRefs": rollback.rollback_refs,
                "evidenceRefs": rollback.evidence_refs,
                "traceRefs": rollback.trace_refs,
                "startedAt": self._iso_optional(rollback.started_at),
                "finishedAt": self._iso_optional(rollback.finished_at),
                "metadata": rollback.metadata_json,
            },
        )

    def serialize_knowledge_promotion(self, promotion: KnowledgePromotionRecord) -> dict[str, Any]:
        return self.serialize_knowledge_promotion_contract(promotion)

    def serialize_knowledge_promotion_contract(self, promotion: KnowledgePromotionRecord) -> dict[str, Any]:
        return validate_contract(
            "knowledge-promotion-record",
            {
                "schemaVersion": "phase8.knowledge-promotion-record.v1",
                "knowledgePromotionId": str(promotion.id),
                "source": promotion.source,
                "sourceCorrectionId": str(promotion.source_correction_id),
                "correctionValidationId": str(promotion.correction_validation_id),
                "replayValidationId": promotion.replay_validation_id,
                "replayValidationRef": promotion.replay_validation_ref,
                "coverageProofRef": promotion.coverage_proof_ref,
                "knowledgeEntry": promotion.knowledge_entry_snapshot,
                "evidenceRefs": promotion.evidence_refs,
                "replayRefs": promotion.replay_refs,
                "approvalRefs": promotion.approval_refs,
                "approvalState": promotion.approval_state,
                "policySnapshot": promotion.policy_snapshot,
                "auditRefs": promotion.audit_refs,
                "rollbackRef": promotion.rollback_ref,
                "supersedeRef": promotion.supersede_ref,
                "projectionState": promotion.projection_state,
                "projectionRefs": promotion.projection_refs,
                "status": promotion.status,
                "promotedAt": self._iso_optional(promotion.promoted_at),
                "promotedBy": str(promotion.promoted_by) if promotion.promoted_by else None,
                "traceId": str(promotion.trace_id) if promotion.trace_id else "",
                "idempotencyKey": promotion.idempotency_key,
                "requestId": promotion.request_id,
                "metadata": promotion.metadata_json,
            },
        )

    def _proposal_projection_item(
        self,
        proposal: CorrectionProposal,
        capabilities: set[str],
    ) -> dict[str, object]:
        detail = self.serialize_proposal_detail(proposal)
        detail["applications"] = [
            {
                **item,
                "auditRefs": self._audit_refs_for_resource("correction_application", item["correctionApplicationId"]),
                "guardrailEventRefs": self._dedupe_object_refs(
                    [
                        *self._guardrail_refs_for_request(str(item.get("requestId") or "")),
                        *list((item.get("metadata") or {}).get("guardrailEventRefs") or []),
                    ]
                ),
            }
            for item in detail["applications"]
        ]
        detail["validations"] = [
            {
                **item,
                "auditRefs": self._audit_refs_for_resource("correction_validation", item["correctionValidationId"]),
                "guardrailEventRefs": self._dedupe_object_refs(
                    [
                        *self._guardrail_refs_for_request(str(item.get("requestId") or "")),
                        *list((item.get("metadata") or {}).get("guardrailEventRefs") or []),
                    ]
                ),
            }
            for item in detail["validations"]
        ]
        detail["rollbackRecords"] = [
            {
                **item,
                "auditRefs": self._audit_refs_for_resource("rollback_record", item["rollbackRecordId"]),
                "guardrailEventRefs": self._dedupe_object_refs(
                    [
                        *self._guardrail_refs_for_request(str(item.get("requestId") or "")),
                        *list((item.get("metadata") or {}).get("guardrailEventRefs") or []),
                    ]
                ),
            }
            for item in detail["rollbackRecords"]
        ]
        detail["approvals"] = [
            {
                **item,
                "guardrailEventRefs": list((item.get("payload") or {}).get("guardrailEventRefs") or []),
            }
            for item in detail["approvals"]
        ]
        detail["knowledgePromotions"] = [
            {
                **item,
                "guardrailEventRefs": self._dedupe_object_refs(
                    [
                        *self._guardrail_refs_for_request(str(item.get("requestId") or "")),
                        *list((item.get("metadata") or {}).get("guardrailEventRefs") or []),
                    ]
                ),
            }
            for item in detail["knowledgePromotions"]
        ]
        metadata = detail.get("metadata") if isinstance(detail.get("metadata"), dict) else {}
        detail["auditRefs"] = self._audit_refs_for_resource("correction_proposal", proposal.id)
        detail["guardrailEventRefs"] = self._dedupe_object_refs(
            [
                *self._guardrail_refs_for_request(proposal.request_id or ""),
                *list(metadata.get("guardrailEventRefs") or []),
                *list(metadata.get("approvalSubmitGuardrailEventRefs") or []),
            ]
        )
        detail["replayRefs"] = self._proposal_replay_refs(detail)
        detail["operationAvailability"] = self._proposal_operation_availability(detail, capabilities)
        return detail

    def _proposal_operation_availability(
        self,
        detail: dict[str, object],
        capabilities: set[str],
    ) -> dict[str, dict[str, object]]:
        applications = list(detail.get("applications") or [])
        validations = list(detail.get("validations") or [])
        rollbacks = list(detail.get("rollbackRecords") or [])
        promotions = list(detail.get("knowledgePromotions") or [])
        latest_application = applications[-1] if applications else None
        latest_validation = validations[-1] if validations else None
        latest_promotion = promotions[-1] if promotions else None
        has_successful_validation = any(item.get("status") == "validated" for item in validations)
        has_terminal_rollback = any(item.get("status") in {"rollback_not_required", "rolled_back"} for item in rollbacks)
        has_applied_application = any(item.get("status") == "applied" for item in applications)
        proposal_status = str(detail.get("status") or "")

        rollback_state_allowed = False
        if not has_terminal_rollback and latest_application is not None:
            rollback_state_allowed = latest_application.get("status") == "failed_to_apply" or (
                latest_validation is not None and latest_validation.get("status") == "validation_failed"
            )

        return {
            "submitApproval": self._operation_state(
                "submitApproval",
                "correction.apply",
                capabilities,
                state_allowed=proposal_status in {"draft", "pending_approval"},
                reason="proposal_not_submittable",
            ),
            "apply": self._operation_state(
                "apply",
                "correction.apply",
                capabilities,
                state_allowed=proposal_status == "approved" and not has_applied_application,
                reason="proposal_not_approved_or_already_applied",
            ),
            "validate": self._operation_state(
                "validate",
                "correction.validate",
                capabilities,
                state_allowed=proposal_status == "approved"
                and latest_application is not None
                and latest_application.get("status") == "applied"
                and not has_successful_validation,
                reason="applied_application_required",
            ),
            "rollback": self._operation_state(
                "rollback",
                "correction.rollback",
                capabilities,
                state_allowed=rollback_state_allowed,
                reason="failed_apply_or_validation_required",
            ),
            "promote": self._operation_state(
                "promote",
                "correction.promote",
                capabilities,
                state_allowed=latest_validation is not None
                and latest_validation.get("status") == "validated"
                and not (latest_promotion is not None and latest_promotion.get("status") == "promoted"),
                reason="validated_correction_required",
            ),
        }

    def _operation_policy(self) -> dict[str, dict[str, object]]:
        return {
            "createProposal": self._operation_policy_item("correction.apply", approval_required=False),
            "submitApproval": self._operation_policy_item("correction.apply"),
            "apply": self._operation_policy_item("correction.apply"),
            "validate": self._operation_policy_item("correction.validate"),
            "rollback": self._operation_policy_item("correction.rollback"),
            "promote": self._operation_policy_item("correction.promote"),
        }

    def _operation_policy_item(self, capability: str, *, approval_required: bool = True) -> dict[str, object]:
        return {
            "capability": capability,
            "approvalRequired": approval_required,
            "guardrailRequired": True,
            "auditRequired": True,
            "backendAuthoritative": True,
        }

    def _operation_state(
        self,
        action: str,
        capability: str,
        capabilities: set[str],
        *,
        state_allowed: bool,
        reason: str,
    ) -> dict[str, object]:
        has_capability = capability in capabilities
        return {
            "action": action,
            "capability": capability,
            "available": has_capability and state_allowed,
            "reason": "missing_capability" if not has_capability else ("available" if state_allowed else reason),
            **self._operation_policy_item(capability, approval_required=action != "createProposal"),
        }

    def _proposal_replay_refs(self, detail: dict[str, object]) -> list[dict[str, object]]:
        refs: list[dict[str, object]] = []
        for validation in detail.get("validations") or []:
            result = validation.get("result") or {}
            if isinstance(result, dict):
                refs.extend(result.get("replayRefs") or [])
        for promotion in detail.get("knowledgePromotions") or []:
            refs.extend(promotion.get("replayRefs") or [])
        return self._dedupe_object_refs(refs)

    def _dedupe_object_refs(self, refs: list[dict[str, object]]) -> list[dict[str, object]]:
        deduped: list[dict[str, object]] = []
        seen: set[tuple[str, str]] = set()
        for ref in refs:
            key = (str(ref.get("type") or ""), str(ref.get("id") or ref.get("ref") or ""))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(ref)
        return deduped

    def _audit_refs_for_resource(self, resource_type: str, resource_id: UUID | str) -> list[dict[str, object]]:
        rows = list(
            self.db.scalars(
                select(AuditLog)
                .where(AuditLog.resource_type == resource_type)
                .where(AuditLog.resource_id == str(resource_id))
                .order_by(AuditLog.created_at.asc())
            )
        )
        return [
            {
                "type": "audit",
                "id": str(row.id),
                "action": row.action,
                "requestId": row.request_id,
                "traceId": str(row.trace_id) if row.trace_id else None,
            }
            for row in rows
        ]

    def _guardrail_refs_for_request(self, request_id: str) -> list[dict[str, object]]:
        if not request_id:
            return []
        rows = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.request_id == request_id)
                .order_by(GuardrailEvent.created_at.asc())
            )
        )
        return [
            {
                "type": "guardrail_event",
                "id": str(row.id),
                "ruleId": row.rule_id,
                "decision": row.decision.value,
            }
            for row in rows
        ]

    def _require_proposal(self, proposal_id: UUID) -> CorrectionProposal:
        proposal = self.db.get(CorrectionProposal, proposal_id)
        if proposal is None:
            raise ValueError("correction proposal not found")
        return proposal

    def _require_knowledge_promotion(self, promotion_id: UUID) -> KnowledgePromotionRecord:
        promotion = self.db.get(KnowledgePromotionRecord, promotion_id)
        if promotion is None:
            raise ValueError("knowledge promotion record not found")
        return promotion

    def _get_or_create_correction_approval(
        self,
        proposal: CorrectionProposal,
        payload: SubmitCorrectionApprovalRequest,
        context: ServiceContext,
        guardrail_refs: list[dict[str, object]],
    ) -> Approval:
        existing = self._latest_pending_correction_approval(proposal.id)
        if existing is not None:
            return existing
        approval = Approval(
            id=uuid4(),
            type=ApprovalType.OTHER,
            resource_type="correction_proposal",
            resource_id=str(proposal.id),
            summary=payload.summary or f"Approval required before applying correction proposal {proposal.id}.",
            payload={
                "action": "correction.apply",
                "correctionProposalId": str(proposal.id),
                "proposalType": proposal.proposal_type,
                "riskLevel": proposal.risk_level.value,
                "metadata": payload.metadata,
                "expiresAt": payload.expiresAt.isoformat() if payload.expiresAt else None,
                "requestedBy": str(context.user.id),
                "requestId": context.request_id,
                "traceId": context.trace_id,
                "guardrailEventRefs": guardrail_refs,
            },
            status=ApprovalStatus.PENDING,
            requested_by=context.user.id,
        )
        self.db.add(approval)
        self.db.flush()
        return approval

    def _sync_approval_status(self, proposal: CorrectionProposal) -> None:
        previous_status = proposal.status
        latest = self._latest_correction_approval(proposal.id)
        if latest is None:
            return
        ApprovalService(self.db).expire_pending_approvals(approval_id=latest.id)
        latest = self.db.get(Approval, latest.id)
        if latest is None:
            return
        proposal.approval_refs = self._append_ref(
            proposal.approval_refs,
            {"type": "approval", "id": str(latest.id), "status": latest.status.value},
        )
        if latest.status == ApprovalStatus.APPROVED and proposal.status in {"draft", "pending_approval"}:
            proposal.status = "approved"
        elif latest.status == ApprovalStatus.REJECTED and proposal.status in {"draft", "pending_approval"}:
            proposal.status = "rejected"
        elif latest.status == ApprovalStatus.CANCELLED and proposal.status in {"draft", "pending_approval"}:
            proposal.status = "cancelled"
        elif latest.status == ApprovalStatus.EXPIRED and proposal.status in {"draft", "pending_approval"}:
            proposal.status = "expired"
        proposal.contract_snapshot = self.serialize_proposal_contract(proposal)
        if proposal.status != previous_status:
            self.db.commit()

    def _correction_approvals(self, proposal_id: UUID) -> list[Approval]:
        rows = list(
            self.db.scalars(
                select(Approval)
                .where(Approval.type == ApprovalType.OTHER)
                .where(Approval.resource_type == "correction_proposal")
                .where(Approval.resource_id == str(proposal_id))
                .order_by(Approval.created_at.asc())
            )
        )
        return [row for row in rows if row.payload.get("action") == "correction.apply"]

    def _latest_correction_approval(self, proposal_id: UUID) -> Approval | None:
        approvals = self._correction_approvals(proposal_id)
        return approvals[-1] if approvals else None

    def _latest_pending_correction_approval(self, proposal_id: UUID) -> Approval | None:
        approvals = [row for row in self._correction_approvals(proposal_id) if row.status == ApprovalStatus.PENDING]
        return approvals[-1] if approvals else None

    def _application_by_idempotency(self, proposal_id: UUID, idempotency_key: str) -> CorrectionApplication | None:
        return self.db.scalar(
            select(CorrectionApplication)
            .where(CorrectionApplication.correction_proposal_id == proposal_id)
            .where(CorrectionApplication.idempotency_key == idempotency_key)
        )

    def _validation_by_idempotency(self, application_id: UUID, idempotency_key: str) -> CorrectionValidation | None:
        return self.db.scalar(
            select(CorrectionValidation)
            .where(CorrectionValidation.correction_application_id == application_id)
            .where(CorrectionValidation.idempotency_key == idempotency_key)
        )

    def _rollback_by_idempotency(self, proposal_id: UUID, idempotency_key: str) -> RollbackRecord | None:
        return self.db.scalar(
            select(RollbackRecord)
            .where(RollbackRecord.correction_proposal_id == proposal_id)
            .where(RollbackRecord.idempotency_key == idempotency_key)
        )

    def _latest_application(self, proposal_id: UUID) -> CorrectionApplication | None:
        return self.db.scalar(
            select(CorrectionApplication)
            .where(CorrectionApplication.correction_proposal_id == proposal_id)
            .order_by(CorrectionApplication.created_at.desc())
        )

    def _validation_application(self, proposal_id: UUID, application_id: UUID | None) -> CorrectionApplication:
        if application_id is not None:
            application = self.db.get(CorrectionApplication, application_id)
            if application is None or application.correction_proposal_id != proposal_id:
                raise ValueError("correction application not found")
        else:
            application = self._latest_application(proposal_id)
        if application is None or application.status != "applied":
            raise CorrectionGovernanceConflictError("proposal must have an applied correction application before validation")
        return application

    def _latest_validation(self, proposal_id: UUID) -> CorrectionValidation | None:
        return self.db.scalar(
            select(CorrectionValidation)
            .where(CorrectionValidation.correction_proposal_id == proposal_id)
            .order_by(CorrectionValidation.created_at.desc())
        )

    def _latest_successful_validation(self, application_id: UUID) -> CorrectionValidation | None:
        return self.db.scalar(
            select(CorrectionValidation)
            .where(CorrectionValidation.correction_application_id == application_id)
            .where(CorrectionValidation.status == "validated")
            .order_by(CorrectionValidation.created_at.desc())
        )

    def _latest_successful_validation_for_proposal(self, proposal_id: UUID) -> CorrectionValidation | None:
        return self.db.scalar(
            select(CorrectionValidation)
            .where(CorrectionValidation.correction_proposal_id == proposal_id)
            .where(CorrectionValidation.status == "validated")
            .order_by(CorrectionValidation.created_at.desc())
        )

    def _latest_knowledge_promotion(self, proposal_id: UUID) -> KnowledgePromotionRecord | None:
        return self.db.scalar(
            select(KnowledgePromotionRecord)
            .where(KnowledgePromotionRecord.source_correction_id == proposal_id)
            .order_by(KnowledgePromotionRecord.created_at.desc())
        )

    def _replay_validation_ref(self, validation: CorrectionValidation, replay_validation_id: str | None) -> dict[str, Any]:
        result = dict(validation.result or {})
        if validation.status != "validated" or result.get("passed") is not True:
            raise CorrectionGovernanceConflictError("replay validation must be passed before promotion")
        if not result.get("evidenceRefs"):
            raise CorrectionGovernanceConflictError("validated correction requires evidenceRefs before promotion")
        if not result.get("replayRefs"):
            raise CorrectionGovernanceConflictError("validated correction requires replayRefs before promotion")
        self._ensure_no_failed_replay_refs(result.get("replayRefs") or [])
        self._ensure_no_failed_refs(
            result.get("evidenceRefs") or [],
            "failed validation evidence refs cannot be promoted",
        )
        return {
            "id": replay_validation_id or str(validation.id),
            "status": "passed",
            "source": "persisted_validation_record",
            "correctionValidationId": str(validation.id),
            "evidenceRefs": result.get("evidenceRefs") or [],
            "replayRefs": result.get("replayRefs") or [],
        }

    def _promotion_approval_state(
        self,
        proposal: CorrectionProposal,
        supplied_approval_refs: list[dict[str, Any]],
    ) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
        latest = self._latest_correction_approval(proposal.id)
        approval_refs = list(supplied_approval_refs or proposal.approval_refs or [])
        if latest is None:
            return (
                "not_required",
                approval_refs,
                {
                    "approvalState": "not_required",
                    "approvalPolicy": "not_required",
                    "source": "policy_snapshot",
                    "proposalRiskLevel": proposal.risk_level.value,
                },
            )
        if latest.status != ApprovalStatus.APPROVED:
            raise CorrectionGovernanceConflictError("approval policy must be satisfied before promotion")
        approval_refs = self._append_ref(
            approval_refs,
            {"type": "approval", "id": str(latest.id), "status": latest.status.value},
        )
        return (
            "satisfied",
            approval_refs,
            {
                "approvalState": "satisfied",
                "approvalPolicy": "approval_required",
                "source": "persisted_approval_record",
                "approvalId": str(latest.id),
                "proposalRiskLevel": proposal.risk_level.value,
            },
        )

    def _ensure_no_failed_replay_refs(self, replay_refs: list[dict[str, Any]]) -> None:
        self._ensure_no_failed_refs(replay_refs, "failed replay refs cannot be promoted")

    def _ensure_no_failed_refs(
        self,
        refs: list[dict[str, Any]],
        error_message: str,
    ) -> None:
        failed_statuses = {"failed", "failure", "validation_failed", "replay_failed", "error"}
        for ref in refs:
            status = str(ref.get("status") or "").lower()
            if status in failed_statuses or ref.get("passed") is False:
                raise CorrectionGovernanceConflictError(error_message)

    def _require_valid_coverage_proof(
        self,
        coverage_proof_ref: dict[str, Any],
        proposal: CorrectionProposal,
        validation: CorrectionValidation,
    ) -> CoverageProofBundleRecord:
        proof_id = coverage_proof_ref.get("id")
        if not proof_id:
            raise CorrectionGovernanceConflictError("coverageProofRef.id is required")
        try:
            proof_uuid = UUID(str(proof_id))
        except ValueError as exc:
            raise CorrectionGovernanceConflictError("coverageProofRef.id must be a UUID") from exc
        proof = self.db.get(CoverageProofBundleRecord, proof_uuid)
        if proof is None:
            raise CorrectionGovernanceConflictError("coverage proof bundle not found")
        if proof.proof_status != ProofStatus.VALID:
            raise CorrectionGovernanceConflictError("coverage proof bundle must be valid")
        if proposal.requirement_version_id is None:
            raise CorrectionGovernanceConflictError("promotion requires correction requirement scope")
        if proof.requirement_version_id != proposal.requirement_version_id:
            raise CorrectionGovernanceConflictError("coverage proof scope must match correction requirement scope")
        requested_requirement_id = coverage_proof_ref.get("requirementVersionId")
        if requested_requirement_id and str(requested_requirement_id) != str(proof.requirement_version_id):
            raise CorrectionGovernanceConflictError("coverageProofRef requirement scope does not match persisted proof")
        if not (proof.replay_export_ref or proof.replay_export_hash):
            raise CorrectionGovernanceConflictError("coverage proof must be linked to replay evidence")
        if not (validation.result or {}).get("replayRefs"):
            raise CorrectionGovernanceConflictError("promotion requires replay validation refs")
        return proof

    def _latest_terminal_rollback(self, proposal_id: UUID) -> RollbackRecord | None:
        return self.db.scalar(
            select(RollbackRecord)
            .where(RollbackRecord.correction_proposal_id == proposal_id)
            .where(RollbackRecord.status.in_(["rollback_not_required", "rolled_back"]))
            .order_by(RollbackRecord.created_at.desc())
        )

    def _rollback_status(
        self,
        application: CorrectionApplication,
        validation: CorrectionValidation | None,
        payload: RollbackCorrectionProposalRequest,
    ) -> str:
        if application.status == "failed_to_apply":
            if not application.applied_change_refs and not application.side_effect_refs:
                return "rollback_not_required"
            return payload.status or "rolled_back"
        if validation is not None and validation.status == "validation_failed":
            return payload.status or "rolled_back"
        raise CorrectionGovernanceConflictError("rollback requires failed_to_apply or validation_failed state")

    def _ensure_ccg_knowledge_entry(
        self,
        entry: dict[str, Any],
        proposal: CorrectionProposal,
        validation: CorrectionValidation,
    ) -> None:
        source_types = {str(item.get("type")) for item in entry.get("sourceRefs") or []}
        if "approved_correction" in source_types:
            raise CorrectionGovernanceConflictError("approved_correction is legacy-only and cannot be promoted by CCG")
        if not source_types.intersection({"validated_correction", "replay_validated_correction"}):
            raise CorrectionGovernanceConflictError("CCG promotion requires validated_correction or replay_validated_correction source")
        metadata = dict(entry.get("metadata") or {})
        if metadata.get("correctionProposalId") != str(proposal.id):
            raise CorrectionGovernanceConflictError("knowledge metadata must include correctionProposalId")
        if metadata.get("correctionValidationId") != str(validation.id):
            raise CorrectionGovernanceConflictError("knowledge metadata must include correctionValidationId")
        for key in ("evidenceRefs", "traceRefs", "replayRefs"):
            if not entry.get(key):
                raise CorrectionGovernanceConflictError(f"knowledge entry must include {key}")

    def _ensure_passed_validation_has_refs(self, result: dict[str, Any]) -> None:
        if result.get("passed") is not True:
            return
        if not result.get("evidenceRefs"):
            raise ContractValidationError("correction-validation", ["passed validation requires non-empty evidenceRefs"])
        if not result.get("replayRefs"):
            raise ContractValidationError("correction-validation", ["passed validation requires non-empty replayRefs"])
        failed_statuses = {"failed", "failure", "validation_failed", "replay_failed", "error"}
        for field in ("evidenceRefs", "replayRefs"):
            for ref in result.get(field) or []:
                status = str(ref.get("status") or "").lower()
                if status in failed_statuses or ref.get("passed") is False:
                    raise ContractValidationError(
                        "correction-validation",
                        [f"passed validation rejects failed {field}"],
                    )

    def _overall_status(
        self,
        proposal: CorrectionProposal,
        applications: list[CorrectionApplication],
        validations: list[CorrectionValidation],
        rollbacks: list[RollbackRecord],
        promotions: list[KnowledgePromotionRecord],
    ) -> str:
        if promotions:
            return promotions[-1].status
        if proposal.promotion_refs:
            return "promoted"
        if rollbacks:
            return rollbacks[-1].status
        if validations:
            return validations[-1].status
        if applications:
            return applications[-1].status
        return proposal.status

    def _timeline(
        self,
        proposal: CorrectionProposal,
        applications: list[CorrectionApplication],
        validations: list[CorrectionValidation],
        rollbacks: list[RollbackRecord],
        approvals: list[Approval],
        promotions: list[KnowledgePromotionRecord],
    ) -> list[dict[str, object]]:
        events: list[tuple[str, dict[str, object]]] = [
            (
                self._iso(proposal.created_at),
                {
                    "kind": "correction_governance.proposal",
                    "status": proposal.status,
                    "timestamp": self._iso(proposal.created_at),
                    "details": {"correctionProposalId": str(proposal.id), "proposalType": proposal.proposal_type},
                },
            )
        ]
        for approval in approvals:
            events.append(
                (
                    self._iso(approval.created_at),
                    {
                        "kind": "correction_governance.approval",
                        "status": approval.status.value,
                        "timestamp": self._iso(approval.created_at),
                        "details": {"approvalId": str(approval.id)},
                    },
                )
            )
        for application in applications:
            events.append(
                (
                    self._iso(application.created_at),
                    {
                        "kind": "correction_governance.application",
                        "status": application.status,
                        "timestamp": self._iso(application.created_at),
                        "details": {"correctionApplicationId": str(application.id)},
                    },
                )
            )
        for validation in validations:
            events.append(
                (
                    self._iso(validation.created_at),
                    {
                        "kind": "correction_governance.validation",
                        "status": validation.status,
                        "timestamp": self._iso(validation.created_at),
                        "details": {"correctionValidationId": str(validation.id), "passed": validation.result.get("passed")},
                    },
                )
            )
        for rollback in rollbacks:
            events.append(
                (
                    self._iso(rollback.created_at),
                    {
                        "kind": "correction_governance.rollback",
                        "status": rollback.status,
                        "timestamp": self._iso(rollback.created_at),
                        "details": {"rollbackRecordId": str(rollback.id)},
                    },
                )
            )
        for promotion in promotions:
            events.append(
                (
                    self._iso(promotion.created_at),
                    {
                        "kind": "correction_governance.knowledge_promotion",
                        "status": promotion.status,
                        "timestamp": self._iso(promotion.created_at),
                        "details": {
                            "knowledgePromotionId": str(promotion.id),
                            "correctionValidationId": str(promotion.correction_validation_id),
                            "coverageProofBundleId": str(promotion.coverage_proof_bundle_id),
                            "projectionState": promotion.projection_state,
                        },
                    },
                )
            )
        return [item for _, item in sorted(events, key=lambda item: item[0])]

    def _emit_event(
        self,
        event_type: str,
        context: ServiceContext,
        *,
        proposal_id: UUID,
        payload: dict[str, object],
        evidence_refs: list[dict[str, object]] | None = None,
        replay_refs: list[dict[str, object]] | None = None,
        extra_correlation_refs: dict[str, object] | None = None,
    ) -> None:
        ensure_trace(self.db, execution_id=None, root_span_name="correction-governance", trace_id=context.trace_id)
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        event_id = f"{event_type}:{str(proposal_id)[:8]}:{payload_hash}"
        existing = self.db.scalar(select(DomainEventRecord).where(DomainEventRecord.event_id == event_id))
        if existing is not None:
            return
        proposal = self.db.get(CorrectionProposal, proposal_id)
        correlation_refs: dict[str, object] = {"correctionProposalId": str(proposal_id)}
        if proposal is not None:
            if proposal.execution_id:
                correlation_refs["executionId"] = str(proposal.execution_id)
            if proposal.requirement_version_id:
                correlation_refs["requirementVersionId"] = str(proposal.requirement_version_id)
            if proposal.finding_id:
                correlation_refs["findingId"] = str(proposal.finding_id)
            if proposal.attribution_id:
                correlation_refs["attributionId"] = proposal.attribution_id
        for key, value in (extra_correlation_refs or {}).items():
            if value is not None:
                correlation_refs[key] = value
        occurred_at = datetime.now(timezone.utc)
        contract = validate_contract(
            "domain-event",
            {
                "eventId": event_id,
                "eventType": event_type,
                "schemaVersion": "phase8.domain-event.v1",
                "traceId": context.trace_id,
                "correlationRefs": correlation_refs,
                "occurredAt": occurred_at.isoformat(),
                "actorRef": {"type": "user", "id": str(context.user.id)},
                "sourceRef": {"type": "correction_proposal", "id": str(proposal_id)},
                "payload": payload,
                "evidenceRefs": evidence_refs or [],
                "replayRefs": replay_refs or [],
            },
        )
        self.db.add(
            DomainEventRecord(
                id=uuid4(),
                event_id=contract["eventId"],
                event_type=contract["eventType"],
                schema_version=contract["schemaVersion"],
                trace_id=UUID(context.trace_id),
                correlation_refs=contract["correlationRefs"],
                occurred_at=occurred_at,
                actor_ref=contract["actorRef"],
                source_ref=contract["sourceRef"],
                payload=contract["payload"],
                evidence_refs=contract["evidenceRefs"],
                replay_refs=contract["replayRefs"],
            )
        )

    def _audit(self, action: str, resource_type: str, resource_id: UUID, context: ServiceContext) -> list[dict[str, object]]:
        audit_log = write_audit_log(
            self.db,
            str(context.user.id),
            action,
            resource_type,
            str(resource_id),
            context.request_id,
            context.trace_id,
        )
        self.db.flush()
        return [
            {
                "type": "audit",
                "id": str(audit_log.id),
                "action": action,
                "requestId": context.request_id,
                "traceId": context.trace_id,
            }
        ]

    def _record_knowledge_supersede_guardrail(
        self,
        context: ServiceContext,
        *,
        promotion_id: UUID,
        payload: dict[str, Any],
    ) -> list[dict[str, object]]:
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type="knowledge_promotion_record",
            resource_id=str(promotion_id),
            payload={"action": "knowledge_promotion.supersede", **payload},
        )
        RuntimeGuardrailEngine(self.db).record_result(
            guardrail_context,
            GuardrailResult(
                rule_id="knowledge_promotion.supersede_preflight",
                decision=GuardrailDecision.ALLOW,
                reason="Knowledge Promotion supersede passed governance preflight",
                evidence=["knowledge_promotion.supersede"],
                metadata={"approvalRequired": True, "riskLevel": "high"},
            ),
        )
        self.db.flush()
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.request_id == context.request_id)
                .where(GuardrailEvent.rule_id == "knowledge_promotion.supersede_preflight")
                .order_by(GuardrailEvent.created_at.desc())
            )
        )
        return [{"type": "guardrail_event", "id": str(event.id), "ruleId": event.rule_id, "decision": event.decision.value} for event in events[:1]]

    def _record_operation_guardrail(
        self,
        context: ServiceContext,
        *,
        operation: str,
        resource_type: str,
        resource_id: UUID,
        risk_level: RiskLevel | str,
        payload: dict[str, Any],
        approval_required: bool,
    ) -> list[dict[str, object]]:
        risk_value = risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level)
        rule_id = f"correction_governance.{operation}_preflight"
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type=resource_type,
            resource_id=str(resource_id),
            payload={"action": f"correction.{operation}", **payload},
        )
        RuntimeGuardrailEngine(self.db).record_result(
            guardrail_context,
            GuardrailResult(
                rule_id=rule_id,
                decision=GuardrailDecision.ALLOW,
                reason=f"Correction Governance {operation} passed service preflight",
                evidence=[f"correction_governance.{operation}"],
                metadata={"approvalRequired": approval_required, "riskLevel": risk_value},
            ),
        )
        self.db.flush()
        events = list(
            self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.request_id == context.request_id)
                .where(GuardrailEvent.rule_id == rule_id)
                .order_by(GuardrailEvent.created_at.desc())
            )
        )
        return [{"type": "guardrail_event", "id": str(event.id), "ruleId": event.rule_id, "decision": event.decision.value} for event in events[:1]]

    def _merge_trace_refs(self, trace_refs: list[str], context: ServiceContext) -> list[str]:
        merged = list(dict.fromkeys([*trace_refs, context.trace_id]))
        return [item for item in merged if item]

    def _append_ref(self, refs: list[dict[str, Any]], ref: dict[str, Any]) -> list[dict[str, Any]]:
        updated = list(refs or [])
        if not any(existing.get("type") == ref.get("type") and existing.get("id") == ref.get("id") for existing in updated):
            updated.append(ref)
        return updated

    def _append_refs(self, refs: list[dict[str, Any]], additions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        updated = list(refs or [])
        for ref in additions or []:
            updated = self._append_ref(updated, ref)
        return updated

    def _serialize_approval(self, approval: Approval) -> dict[str, object]:
        return {
            "id": str(approval.id),
            "type": approval.type.value,
            "resourceType": approval.resource_type,
            "resourceId": approval.resource_id,
            "summary": approval.summary,
            "payload": approval.payload,
            "status": approval.status.value,
            "requestedBy": str(approval.requested_by) if approval.requested_by else None,
            "decidedBy": str(approval.decided_by) if approval.decided_by else None,
            "decisionComment": approval.decision_comment,
            "decidedAt": approval.decided_at.isoformat() if approval.decided_at else None,
            "createdAt": self._iso(approval.created_at),
            "updatedAt": self._iso(approval.updated_at),
        }

    def _iso(self, value: datetime | None) -> str:
        return self._iso_optional(value) or datetime.now(timezone.utc).isoformat()

    def _iso_optional(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.isoformat()

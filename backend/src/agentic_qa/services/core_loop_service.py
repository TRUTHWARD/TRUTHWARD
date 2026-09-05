# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    ClarificationItem,
    CorrectionRecord,
    DomainEventRecord,
    ExecutionPlan,
    RequirementVersion,
    TestAsset,
    TestAssetReview,
    TestPlan,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import ensure_trace
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.schemas.requirement_scope import normalize_requirement_scope, requirement_scope_id, scope_item_ids
from agentic_qa.services.common import (
    IdempotencyConflictError,
    ServiceContext,
    acquire_transaction_advisory_lock,
)


class CoreLoopService:
    """Persist and validate requirement-to-execution lifecycle assets."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_requirement_version(self, payload, context: ServiceContext) -> dict[str, object]:
        requirements = self._clean_strings(payload.requirements)
        acceptance_criteria = self._clean_strings(payload.acceptanceCriteria)
        version_metadata = {
            **payload.metadata,
            "name": payload.name,
            "environment": payload.environment,
            "domains": [domain.value for domain in payload.domains],
            "riskLevel": payload.riskLevel.value,
        }
        if getattr(payload, "projectId", None):
            version_metadata["projectId"] = str(payload.projectId)
        if getattr(payload, "environmentId", None):
            version_metadata["environmentId"] = str(payload.environmentId)
        content_hash = self._content_hash(
            {
                "document": payload.document,
                "requirements": requirements,
                "acceptanceCriteria": acceptance_criteria,
                "metadata": version_metadata,
            }
        )
        acquire_transaction_advisory_lock(
            self.db,
            "requirement-version",
            payload.sourceRef,
        )
        existing = self.db.scalar(
            select(RequirementVersion).where(
                RequirementVersion.source_ref == payload.sourceRef,
                RequirementVersion.content_hash == content_hash,
            )
        )
        if existing is not None:
            return self.serialize_requirement_version(existing)

        current_version = self.db.scalar(
            select(func.max(RequirementVersion.version_no)).where(RequirementVersion.source_ref == payload.sourceRef)
        ) or 0
        row = RequirementVersion(
            id=uuid4(),
            source_ref=payload.sourceRef,
            version_no=current_version + 1,
            content_hash=content_hash,
            document=payload.document,
            requirements=requirements,
            acceptance_criteria=acceptance_criteria,
            metadata_json=version_metadata,
            created_by=context.user.id,
        )
        self.db.add(row)
        self.db.flush()
        self.emit_event(
            "RequirementVersionCreated",
            context,
            correlation_refs={"requirementVersionId": str(row.id)},
            source_ref={"type": "requirement_version", "id": str(row.id)},
            payload={"sourceRef": row.source_ref, "version": row.version_no, "contentHash": row.content_hash},
            replay_refs=[{"type": "requirement_version", "id": str(row.id)}],
            event_id=f"RequirementVersionCreated:{row.id}",
        )
        write_audit_log(
            self.db,
            str(context.user.id),
            "requirement_version.create",
            "requirement_version",
            str(row.id),
            context.request_id,
            context.trace_id,
        )
        self.db.commit()
        self.db.refresh(row)
        return self.serialize_requirement_version(row)

    def ensure_clarifications(self, requirement_version_id: UUID, context: ServiceContext) -> list[dict[str, object]]:
        requirement = self._require_requirement(requirement_version_id)
        existing = list(
            self.db.scalars(
                select(ClarificationItem)
                .where(ClarificationItem.requirement_version_id == requirement.id)
                .order_by(ClarificationItem.created_at.asc())
            )
        )
        if existing:
            return [self.serialize_clarification(row) for row in existing]

        definitions: list[tuple[str, str, str]] = []
        if not requirement.requirements:
            definitions.append(("missing_requirements", "P0", "请明确列出本次需要验证的功能需求。"))
        if not requirement.acceptance_criteria:
            definitions.append(("missing_acceptance_criteria", "P0", "请提供可验证的验收标准。"))
        if len(requirement.document.strip()) < 20:
            definitions.append(("short_document", "P1", "需求说明较短，请补充主要业务流程或限制条件。"))

        for question_key, priority, question in definitions:
            row = ClarificationItem(
                id=uuid4(),
                requirement_version_id=requirement.id,
                question_key=question_key,
                question=question,
                priority=priority,
                status="open",
                answer=None,
                evidence_refs=[{"type": "requirement_version", "id": str(requirement.id)}],
                metadata_json={},
            )
            self.db.add(row)
            self.db.flush()
            self.emit_event(
                "ClarificationRequested",
                context,
                correlation_refs={"requirementVersionId": str(requirement.id), "clarificationId": str(row.id)},
                source_ref={"type": "clarification", "id": str(row.id)},
                payload={"priority": priority, "questionKey": question_key},
                evidence_refs=row.evidence_refs,
                replay_refs=[{"type": "clarification", "id": str(row.id)}],
                event_id=f"ClarificationRequested:{row.id}",
            )
        self.db.commit()
        rows = list(
            self.db.scalars(
                select(ClarificationItem)
                .where(ClarificationItem.requirement_version_id == requirement.id)
                .order_by(ClarificationItem.created_at.asc())
            )
        )
        return [self.serialize_clarification(row) for row in rows]

    def answer_clarification(self, clarification_id: UUID, answer: str, context: ServiceContext) -> dict[str, object]:
        row = self._require_clarification(clarification_id)
        normalized_answer = answer.strip()
        if row.status == "closed" and row.answer == normalized_answer:
            return self.serialize_clarification(row)
        row.answer = normalized_answer
        row.status = "closed"
        row.answered_by = context.user.id
        row.evidence_refs = [*row.evidence_refs, {"type": "clarification_answer", "id": str(row.id)}]
        self.emit_event(
            "ClarificationAnswered",
            context,
            correlation_refs={"requirementVersionId": str(row.requirement_version_id), "clarificationId": str(row.id)},
            source_ref={"type": "clarification", "id": str(row.id)},
            payload={"status": "answered"},
            evidence_refs=row.evidence_refs,
            replay_refs=[{"type": "clarification", "id": str(row.id)}],
            event_id=f"ClarificationAnswered:{row.id}:{self._short_hash(normalized_answer)}",
        )
        self.emit_event(
            "ClarificationClosed",
            context,
            correlation_refs={"requirementVersionId": str(row.requirement_version_id), "clarificationId": str(row.id)},
            source_ref={"type": "clarification", "id": str(row.id)},
            payload={"status": "closed"},
            evidence_refs=row.evidence_refs,
            replay_refs=[{"type": "clarification", "id": str(row.id)}],
            event_id=f"ClarificationClosed:{row.id}:{self._short_hash(normalized_answer)}",
        )
        self.db.commit()
        self.db.refresh(row)
        return self.serialize_clarification(row)

    def list_clarifications(self, requirement_version_id: UUID) -> list[dict[str, object]]:
        rows = self.db.scalars(
            select(ClarificationItem)
            .where(ClarificationItem.requirement_version_id == requirement_version_id)
            .order_by(ClarificationItem.created_at.asc())
        )
        return [self.serialize_clarification(row) for row in rows]

    def has_open_p0(self, requirement_version_id: UUID) -> bool:
        return (
            self.db.scalar(
                select(func.count())
                .select_from(ClarificationItem)
                .where(
                    ClarificationItem.requirement_version_id == requirement_version_id,
                    ClarificationItem.priority == "P0",
                    ClarificationItem.status != "closed",
                )
            )
            or 0
        ) > 0

    def requirement_context(self, requirement_version_id: UUID) -> dict[str, object]:
        requirement = self._require_requirement(requirement_version_id)
        requirements = list(requirement.requirements)
        acceptance = list(requirement.acceptance_criteria)
        clarifications = list(
            self.db.scalars(
                select(ClarificationItem).where(
                    ClarificationItem.requirement_version_id == requirement.id,
                    ClarificationItem.status == "closed",
                )
            )
        )
        for row in clarifications:
            if not row.answer:
                continue
            if row.question_key == "missing_requirements":
                requirements.extend(self._split_answer(row.answer))
            if row.question_key == "missing_acceptance_criteria":
                acceptance.extend(self._split_answer(row.answer))
        return {
            "requirementVersionId": str(requirement.id),
            "document": requirement.document,
            "requirements": self._clean_strings(requirements),
            "acceptanceCriteria": self._clean_strings(acceptance),
            "requirementScope": normalize_requirement_scope(
                requirement_version_id=requirement.id,
                filters={"source": "requirement_context"},
                metadata={"selectionMode": "requirement_version", "defaulted": True},
            ),
            "metadata": requirement.metadata_json,
            "clarificationRefs": [str(row.id) for row in clarifications],
        }

    def create_test_assets(self, requirement_version_id: UUID, plan_id: UUID) -> list[dict[str, object]]:
        requirement = self._require_requirement(requirement_version_id)
        plan = self._require_plan(plan_id)
        generated_plan = plan.generated_plan or {}
        self._validate_generated_asset_payload(generated_plan)
        existing = list(
            self.db.scalars(
                select(TestAsset)
                .where(TestAsset.requirement_version_id == requirement.id, TestAsset.test_plan_id == plan.id)
                .order_by(TestAsset.created_at.asc())
            )
        )
        if existing:
            return [self.serialize_test_asset(row) for row in existing]

        effective_requirements = self._clean_strings(
            [str(item) for item in plan.input_payload.get("requirements", requirement.requirements)]
        )
        requirement_scope = self._scope_for_plan(requirement.id, plan)
        selected_item_ids = scope_item_ids(requirement_scope)
        requirement_refs = (
            selected_item_ids
            if selected_item_ids and len(selected_item_ids) == len(effective_requirements)
            else [f"requirement-{index + 1}" for index in range(len(effective_requirements))]
        )
        for domain, key in (("functional", "scenarios"), ("performance", "targets"), ("security", "checks")):
            section = generated_plan.get(domain, {})
            values = section.get(key, []) if isinstance(section, dict) else []
            for value in values:
                self._add_test_asset(
                    requirement,
                    plan,
                    asset_type="test_point",
                    domain=domain,
                    title=str(value),
                    objective=str(value),
                    requirement_refs=self._matching_requirement_refs(str(value), effective_requirements, requirement_refs),
                )
        generated_cases = generated_plan.get("generatedCases", {})
        for domain, cases in generated_cases.items():
            for case in cases:
                objective = str(case["goal"]).strip()
                self._add_test_asset(
                    requirement,
                    plan,
                    asset_type="test_case",
                    domain=str(domain),
                    title=str(case["name"]).strip(),
                    objective=objective,
                    requirement_refs=self._matching_requirement_refs(objective, effective_requirements, requirement_refs),
                )
        self.db.commit()
        rows = list(
            self.db.scalars(
                select(TestAsset)
                .where(TestAsset.requirement_version_id == requirement.id, TestAsset.test_plan_id == plan.id)
                .order_by(TestAsset.created_at.asc())
            )
        )
        return [self.serialize_test_asset(row) for row in rows]

    def review_test_assets(
        self,
        requirement_version_id: UUID,
        plan_id: UUID,
        coverage_map: dict[str, object],
        context: ServiceContext,
    ) -> dict[str, object]:
        existing = self.db.scalar(
            select(TestAssetReview)
            .where(
                TestAssetReview.requirement_version_id == requirement_version_id,
                TestAssetReview.test_plan_id == plan_id,
            )
            .order_by(TestAssetReview.created_at.desc())
        )
        if existing is not None:
            return self.serialize_asset_review(existing)
        assets = list(
            self.db.scalars(
                select(TestAsset).where(
                    TestAsset.requirement_version_id == requirement_version_id,
                    TestAsset.test_plan_id == plan_id,
                )
            )
        )
        issues = [*list(coverage_map.get("weakCoverageAreas", [])), *list(coverage_map.get("duplicateCoverageAreas", []))]
        case_count = len([asset for asset in assets if asset.asset_type == "test_case"])
        requirement_coverage = float(coverage_map.get("requirementCoverage", 0.0))
        if case_count == 0:
            issues.append({"type": "missing_test_cases", "message": "no executable test cases generated"})
        status = "approved" if requirement_coverage >= 0.9 and not issues and case_count > 0 else "needs_review"
        confidence = min(float(coverage_map.get("coverageConfidence", 0.0)), 1.0)
        row = TestAssetReview(
            id=uuid4(),
            requirement_version_id=requirement_version_id,
            test_plan_id=plan_id,
            status=status,
            confidence=Decimal(str(confidence)),
            issues=issues,
            coverage_map=coverage_map,
            evidence_refs=[{"type": "test_asset", "id": str(asset.id)} for asset in assets],
            metadata_json={"assetCount": len(assets), "testCaseCount": case_count, "requirementScope": self._scope_for_plan(requirement_version_id, self._require_plan(plan_id))},
        )
        self.db.add(row)
        for asset in assets:
            asset.status = "approved" if status == "approved" else "reviewed"
        self.db.flush()
        result = self.serialize_asset_review(row)
        self.emit_event(
            "CoverageAnalyzed",
            context,
            correlation_refs={"requirementVersionId": str(requirement_version_id), "planId": str(plan_id)},
            source_ref={"type": "coverage_map", "id": str(row.id)},
            payload={"requirementCoverage": requirement_coverage, "status": status},
            evidence_refs=row.evidence_refs,
            replay_refs=[{"type": "asset_review", "id": str(row.id)}],
            event_id=f"CoverageAnalyzed:{row.id}",
        )
        self.emit_event(
            "TestAssetReviewed",
            context,
            correlation_refs={"requirementVersionId": str(requirement_version_id), "planId": str(plan_id)},
            source_ref={"type": "asset_review", "id": str(row.id)},
            payload={"status": status, "assetCount": len(assets)},
            evidence_refs=row.evidence_refs,
            replay_refs=[{"type": "asset_review", "id": str(row.id)}],
            event_id=f"TestAssetReviewed:{row.id}",
        )
        self.db.commit()
        return result

    def create_execution_plan(
        self,
        requirement_version_id: UUID,
        plan_id: UUID,
        review_id: UUID,
    ) -> dict[str, object]:
        existing = self.db.scalar(
            select(ExecutionPlan)
            .where(
                ExecutionPlan.requirement_version_id == requirement_version_id,
                ExecutionPlan.test_plan_id == plan_id,
            )
            .order_by(ExecutionPlan.created_at.desc())
        )
        if existing is not None:
            return self.serialize_execution_plan(existing)
        review = self.db.get(TestAssetReview, review_id)
        if review is None:
            raise ValueError("test asset review not found")
        assets = list(
            self.db.scalars(
                select(TestAsset).where(
                    TestAsset.requirement_version_id == requirement_version_id,
                    TestAsset.test_plan_id == plan_id,
                    TestAsset.asset_type == "test_case",
                )
            )
        )
        if not assets:
            raise ValueError("execution plan requires reviewed test cases")
        plan = self._require_plan(plan_id)
        requirement_scope = self._scope_for_plan(requirement_version_id, plan)
        runner_by_domain = {"functional": "playwright", "performance": "k6", "security": "semgrep"}
        tasks = [
            {
                "assetId": str(asset.id),
                "domain": asset.domain,
                "taskType": f"{asset.domain}.generated",
                "runner": runner_by_domain.get(asset.domain, "playwright"),
                "objective": asset.objective,
                "requirementRefs": asset.requirement_refs,
                "requirementScope": requirement_scope,
            }
            for asset in assets
        ]
        approval_required = plan.risk_level.value == "high"
        status = "approved" if review.status == "approved" and not approval_required else "blocked"
        row = ExecutionPlan(
            id=uuid4(),
            requirement_version_id=requirement_version_id,
            test_plan_id=plan_id,
            status=status,
            risk_level=plan.risk_level,
            approval_required=approval_required,
            tasks=tasks,
            asset_refs=[{"type": "test_asset", "id": str(asset.id)} for asset in assets],
            retry_strategy={"mode": "failed_only", "maxRetries": 1},
            replay_refs=[{"type": "asset_review", "id": str(review.id)}],
            requirement_scope=requirement_scope,
            requirement_scope_id=str(requirement_scope.get("scopeId")),
            metadata_json={"reviewId": str(review.id), "requirementScope": requirement_scope},
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return self.serialize_execution_plan(row)

    def apply_correction(
        self,
        requirement_version_id: UUID,
        execution_id: UUID | None,
        payload,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_requirement(requirement_version_id)
        row = CorrectionRecord(
            id=uuid4(),
            requirement_version_id=requirement_version_id,
            execution_id=execution_id,
            target_type=payload.targetType,
            target_id=payload.targetId,
            before_payload=payload.before,
            after_payload=payload.after,
            reason=payload.reason,
            actor_ref={"type": "user", "id": str(context.user.id)},
            evidence_refs=payload.evidenceRefs,
            affected_asset_refs=payload.affectedAssetRefs,
            metadata_json=payload.metadata,
        )
        self.db.add(row)
        affected_ids = [item.get("id") for item in payload.affectedAssetRefs if item.get("id")]
        if affected_ids:
            for asset in self.db.scalars(select(TestAsset).where(TestAsset.id.in_([UUID(str(item)) for item in affected_ids]))):
                asset.status = "invalidated"
        self.db.flush()
        result = self.serialize_correction(row)
        self.emit_event(
            "CorrectionApplied",
            context,
            correlation_refs={
                "requirementVersionId": str(requirement_version_id),
                "executionId": str(execution_id) if execution_id else None,
                "correctionId": str(row.id),
            },
            source_ref={"type": "correction", "id": str(row.id)},
            payload={"targetType": row.target_type, "targetId": row.target_id},
            evidence_refs=row.evidence_refs,
            replay_refs=[{"type": "correction", "id": str(row.id)}],
            event_id=f"CorrectionApplied:{row.id}",
        )
        self.db.commit()
        return result

    def list_events(self, correlation_key: str, correlation_value: str) -> list[dict[str, object]]:
        rows = list(self.db.scalars(select(DomainEventRecord).order_by(DomainEventRecord.occurred_at.asc())))
        return [self.serialize_event(row) for row in rows if str(row.correlation_refs.get(correlation_key)) == correlation_value]

    def emit_event(
        self,
        event_type: str,
        context: ServiceContext,
        *,
        correlation_refs: dict[str, object],
        source_ref: dict[str, object] | None,
        payload: dict[str, object],
        evidence_refs: list[dict[str, object]] | None = None,
        replay_refs: list[dict[str, object]] | None = None,
        event_id: str | None = None,
    ) -> dict[str, object]:
        normalized_event_id = event_id or f"{event_type}:{uuid4()}"
        acquire_transaction_advisory_lock(
            self.db,
            "domain-event",
            normalized_event_id,
        )
        existing = self.db.scalar(select(DomainEventRecord).where(DomainEventRecord.event_id == normalized_event_id))
        if existing is not None:
            if not self._event_matches_request(
                existing,
                event_type=event_type,
                correlation_refs=correlation_refs,
                source_ref=source_ref,
                payload=payload,
                evidence_refs=evidence_refs or [],
                replay_refs=replay_refs or [],
            ):
                raise IdempotencyConflictError(
                    f"idempotency conflict for domain event '{normalized_event_id}'"
                )
            return self.serialize_event(existing)
        ensure_trace(self.db, execution_id=None, root_span_name="core-loop", trace_id=context.trace_id)
        occurred_at = datetime.now(timezone.utc)
        contract = validate_contract(
            "domain-event",
            {
                "eventId": normalized_event_id,
                "eventType": event_type,
                "schemaVersion": "phase8.domain-event.v1",
                "traceId": context.trace_id,
                "correlationRefs": correlation_refs,
                "occurredAt": occurred_at.isoformat(),
                "actorRef": {"type": "user", "id": str(context.user.id)},
                "sourceRef": source_ref,
                "payload": payload,
                "evidenceRefs": evidence_refs or [],
                "replayRefs": replay_refs or [],
            },
        )
        row = DomainEventRecord(
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
        self.db.add(row)
        self.db.flush()
        return contract

    def _event_matches_request(
        self,
        row: DomainEventRecord,
        *,
        event_type: str,
        correlation_refs: dict[str, object],
        source_ref: dict[str, object] | None,
        payload: dict[str, object],
        evidence_refs: list[dict[str, object]],
        replay_refs: list[dict[str, object]],
    ) -> bool:
        return (
            row.event_type == event_type
            and row.correlation_refs == correlation_refs
            and row.source_ref == source_ref
            and row.payload == payload
            and row.evidence_refs == evidence_refs
            and row.replay_refs == replay_refs
        )

    def serialize_requirement_version(self, row: RequirementVersion) -> dict[str, object]:
        return validate_contract(
            "requirement-version",
            {
                "schemaVersion": "phase8.requirement-version.v1",
                "requirementVersionId": str(row.id),
                "sourceRef": row.source_ref,
                "version": row.version_no,
                "contentHash": row.content_hash,
                "document": row.document,
                "requirements": row.requirements,
                "acceptanceCriteria": row.acceptance_criteria,
                "metadata": row.metadata_json,
                "createdAt": row.created_at.isoformat(),
            },
        )

    def serialize_clarification(self, row: ClarificationItem) -> dict[str, object]:
        return validate_contract(
            "clarification",
            {
                "schemaVersion": "phase8.clarification.v1",
                "clarificationId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "question": row.question,
                "priority": row.priority,
                "status": row.status,
                "answer": row.answer,
                "evidenceRefs": row.evidence_refs,
                "metadata": {**row.metadata_json, "questionKey": row.question_key},
            },
        )

    def serialize_test_asset(self, row: TestAsset) -> dict[str, object]:
        return validate_contract(
            "test-asset",
            {
                "schemaVersion": "phase8.test-asset.v1",
                "assetId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "assetType": row.asset_type,
                "domain": row.domain,
                "title": row.title,
                "objective": row.objective,
                "requirementRefs": row.requirement_refs,
                "status": row.status,
                "evidenceRefs": row.evidence_refs,
                "metadata": {**row.metadata_json, "testPlanId": str(row.test_plan_id) if row.test_plan_id else None},
            },
        )

    def serialize_asset_review(self, row: TestAssetReview) -> dict[str, object]:
        return validate_contract(
            "asset-review",
            {
                "schemaVersion": "phase8.asset-review.v1",
                "reviewId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "planId": str(row.test_plan_id),
                "status": row.status,
                "confidence": float(row.confidence),
                "issues": row.issues,
                "coverageMap": row.coverage_map,
                "evidenceRefs": row.evidence_refs,
                "metadata": row.metadata_json,
            },
        )

    def serialize_execution_plan(self, row: ExecutionPlan) -> dict[str, object]:
        return validate_contract(
            "execution-plan",
            {
                "schemaVersion": "phase8.execution-plan.v1",
                "executionPlanId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "testPlanId": str(row.test_plan_id),
                "status": row.status,
                "riskLevel": row.risk_level.value,
                "approvalRequired": row.approval_required,
                "tasks": row.tasks,
                "assetRefs": row.asset_refs,
                "retryStrategy": row.retry_strategy,
                "replayRefs": row.replay_refs,
                "requirementScope": row.requirement_scope,
                "metadata": row.metadata_json,
            },
        )

    def serialize_correction(self, row: CorrectionRecord) -> dict[str, object]:
        return validate_contract(
            "correction-record",
            {
                "schemaVersion": "phase8.correction-record.v1",
                "correctionId": str(row.id),
                "requirementVersionId": str(row.requirement_version_id),
                "executionId": str(row.execution_id) if row.execution_id else None,
                "targetType": row.target_type,
                "targetId": row.target_id,
                "before": row.before_payload,
                "after": row.after_payload,
                "reason": row.reason,
                "actorRef": row.actor_ref,
                "evidenceRefs": row.evidence_refs,
                "affectedAssetRefs": row.affected_asset_refs,
                "createdAt": row.created_at.isoformat(),
                "metadata": row.metadata_json,
            },
        )

    def serialize_event(self, row: DomainEventRecord) -> dict[str, object]:
        return validate_contract(
            "domain-event",
            {
                "eventId": row.event_id,
                "eventType": row.event_type,
                "schemaVersion": row.schema_version,
                "traceId": str(row.trace_id) if row.trace_id else "",
                "correlationRefs": row.correlation_refs,
                "occurredAt": row.occurred_at.astimezone(timezone.utc).isoformat(),
                "actorRef": row.actor_ref,
                "sourceRef": row.source_ref,
                "payload": row.payload,
                "evidenceRefs": row.evidence_refs,
                "replayRefs": row.replay_refs,
            },
        )

    def _add_test_asset(
        self,
        requirement: RequirementVersion,
        plan: TestPlan,
        *,
        asset_type: str,
        domain: str,
        title: str,
        objective: str,
        requirement_refs: list[str],
    ) -> None:
        row = TestAsset(
            id=uuid4(),
            requirement_version_id=requirement.id,
            test_plan_id=plan.id,
            asset_type=asset_type,
            domain=domain,
            title=title,
            objective=objective,
            requirement_refs=requirement_refs,
            status="draft",
            evidence_refs=[{"type": "test_plan", "id": str(plan.id)}],
            metadata_json={"requirementScope": self._scope_for_plan(requirement.id, plan)},
        )
        self.db.add(row)
        self.db.flush()
        self.serialize_test_asset(row)

    def _validate_generated_asset_payload(self, generated_plan: dict[str, object]) -> None:
        for domain, key in (("functional", "scenarios"), ("performance", "targets"), ("security", "checks")):
            section = generated_plan.get(domain, {})
            if not isinstance(section, dict):
                raise ValueError(f"{domain} test-point output must be an object")
            values = section.get(key, [])
            if not isinstance(values, list):
                raise ValueError(f"{domain}.{key} test-point output must be a list")
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"{domain}.{key} contains an invalid test point")

        generated_cases = generated_plan.get("generatedCases", {})
        if not isinstance(generated_cases, dict):
            raise ValueError("generatedCases test-case output must be an object")
        for domain, cases in generated_cases.items():
            if not isinstance(domain, str) or not domain.strip():
                raise ValueError("generatedCases contains an invalid domain")
            if not isinstance(cases, list):
                raise ValueError(f"generatedCases.{domain} must be a list")
            for case in cases:
                if not isinstance(case, dict):
                    raise ValueError(f"generatedCases.{domain} contains a non-object test case")
                if not isinstance(case.get("name"), str) or not str(case["name"]).strip():
                    raise ValueError(f"generatedCases.{domain} contains a test case without name")
                if not isinstance(case.get("goal"), str) or not str(case["goal"]).strip():
                    raise ValueError(f"generatedCases.{domain} contains a test case without goal")

    def _matching_requirement_refs(self, text: str, requirements: list[str], fallback: list[str]) -> list[str]:
        lowered = text.lower()
        matched = [fallback[index] for index, requirement in enumerate(requirements) if index < len(fallback) and requirement.lower() in lowered]
        return matched or fallback[:1]

    def _scope_for_plan(self, requirement_version_id: UUID, plan: TestPlan) -> dict[str, object]:
        if plan.requirement_scope:
            scope = dict(plan.requirement_scope)
            if scope.get("requirementVersionId") == str(requirement_version_id):
                if not scope.get("scopeId"):
                    scope["scopeId"] = requirement_scope_id(scope)
                return scope
        raw_scope = plan.input_payload.get("requirementScope") if isinstance(plan.input_payload, dict) else None
        if isinstance(raw_scope, dict) and raw_scope.get("requirementVersionId") == str(requirement_version_id):
            scope = dict(raw_scope)
            scope["scopeId"] = requirement_scope_id(scope)
            return scope
        return normalize_requirement_scope(
            requirement_version_id=requirement_version_id,
            filters={"source": "core_loop"},
            metadata={"selectionMode": "requirement_version", "defaulted": True},
        )

    def _require_requirement(self, requirement_version_id: UUID) -> RequirementVersion:
        row = self.db.get(RequirementVersion, requirement_version_id)
        if row is None:
            raise ValueError("requirement version not found")
        return row

    def _require_clarification(self, clarification_id: UUID) -> ClarificationItem:
        row = self.db.get(ClarificationItem, clarification_id)
        if row is None:
            raise ValueError("clarification not found")
        return row

    def _require_plan(self, plan_id: UUID) -> TestPlan:
        row = self.db.get(TestPlan, plan_id)
        if row is None:
            raise ValueError("test plan not found")
        return row

    def _content_hash(self, payload: dict[str, object]) -> str:
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def _short_hash(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    def _clean_strings(self, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))

    def _split_answer(self, answer: str) -> list[str]:
        normalized = answer.replace(";", "\n").replace("；", "\n")
        return [item.strip(" -\t") for item in normalized.splitlines() if item.strip(" -\t")]

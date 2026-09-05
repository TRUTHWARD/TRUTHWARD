# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import (
    ExecutionStage,
    FindingStatus,
    JobStatus,
    MemoryScope,
    MemoryType,
    RiskLevel,
    SourceType,
    TaskStatus,
    TestDomain,
)
from agentic_qa.domain.models import (
    Execution,
    ExecutionPlan,
    Finding,
    GateDecision,
    IntegrationEvent,
    OrchestrationCheckpoint,
    OrchestrationRun,
    RequirementVersion,
    TestPlan,
)
from agentic_qa.infra.trace import ensure_trace, traced_operation
from agentic_qa.services.analysis_service import AnalysisService
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.core_loop_service import CoreLoopService
from agentic_qa.services.execution_service import ExecutionService
from agentic_qa.services.memory_service import MemoryService
from agentic_qa.services.observability_service import ObservabilityService
from agentic_qa.services.plan_service import TestPlanService
from agentic_qa.schemas.requirement_scope import (
    normalize_requirement_scope,
    requirement_scope_item_id,
)
from agentic_qa.services.requirement_scope_service import RequirementScopeService
from agentic_qa.services.traceability_service import TraceabilityService


class OrchestrationConflictError(Exception):
    """Raised when an orchestration action is invalid for the current run state."""


class OrchestratorService:
    """Own the cross-service pipeline for plan -> execute -> triage -> gate -> memory."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.plan_service = TestPlanService(db)
        self.execution_service = ExecutionService(db)
        self.analysis_service = AnalysisService(db)
        self.memory_service = MemoryService(db)
        self.core_loop_service = CoreLoopService(db)
        self.observability_service = ObservabilityService(db)
        self.approval_service = ApprovalService(db)

    def run_pr_pipeline(self, payload, context: ServiceContext) -> dict[str, object]:
        return self._run_pipeline(payload, context, event_type="pr_trigger", trigger_type="pr_trigger")

    def run_requirement_pipeline(self, payload, context: ServiceContext) -> dict[str, object]:
        requirement = self.core_loop_service.create_requirement_version(payload, context)
        requirement_version_id = UUID(str(requirement["requirementVersionId"]))
        requirement_scope = RequirementScopeService(self.db).persist(
            normalize_requirement_scope(
                requirement_version_id=requirement_version_id,
                filters={"source": "requirement_pipeline"},
                metadata={"selectionMode": "requirement_version", "defaulted": True},
            ),
            context,
        )
        clarifications = self.core_loop_service.ensure_clarifications(requirement_version_id, context)
        ensure_trace(self.db, execution_id=None, root_span_name="orchestrator.requirement-pipeline", trace_id=context.trace_id)
        integration_event = IntegrationEvent(
            id=uuid4(),
            source="requirement",
            event_type="requirement_submitted",
            external_ref=payload.sourceRef,
            payload=self._payload_to_dict(payload),
            status="received",
            linked_requirement_version_id=requirement_version_id,
        )
        run = OrchestrationRun(
            id=uuid4(),
            source="requirement",
            trigger_type="requirement_document",
            status=JobStatus.RUNNING,
            current_step="CLARIFICATION",
            request_id=context.request_id,
            trace_id=UUID(context.trace_id),
            linked_requirement_version_id=requirement_version_id,
            requirement_scope_id=str(requirement_scope["scopeId"]),
            requirement_scope=requirement_scope,
            envelope_snapshot={"requirementVersion": requirement},
            result_payload={"requirementVersion": requirement, "clarifications": clarifications},
            started_at=datetime.now(timezone.utc),
        )
        self.db.add_all([integration_event, run])
        self.db.flush()
        integration_event.linked_pipeline_id = run.id
        self._record_checkpoint(
            run_id=run.id,
            step_name="REQUIREMENT",
            execution_stage=None,
            status=JobStatus.COMPLETED,
            envelope_snapshot=run.envelope_snapshot,
            result_payload={"requirementVersion": requirement},
            trace_id=run.trace_id,
            execution_id=None,
        )
        if self.core_loop_service.has_open_p0(requirement_version_id):
            run.status = JobStatus.QUEUED
            run.current_step = "CLARIFICATION"
            run.result_payload = {**run.result_payload, "blocked": True, "reason": "p0_clarification_open"}
            self._record_checkpoint(
                run_id=run.id,
                step_name="CLARIFICATION",
                execution_stage=None,
                status=JobStatus.QUEUED,
                envelope_snapshot=run.envelope_snapshot,
                result_payload={"clarifications": clarifications, "blocked": True},
                trace_id=run.trace_id,
                execution_id=None,
            )
            self.db.commit()
            return self._requirement_pipeline_response(run)
        self.db.commit()
        return self._continue_requirement_pipeline(run.id, context)

    def run_requirement_library_pipeline(self, payload, context: ServiceContext) -> dict[str, object]:
        requested_version_ids = self._requirement_scope_version_ids(payload)
        requirements = [self.db.get(RequirementVersion, version_id) for version_id in requested_version_ids]
        missing_version_id = next(
            (version_id for version_id, requirement in zip(requested_version_ids, requirements) if requirement is None),
            None,
        )
        if missing_version_id is not None:
            raise LookupError(f"requirement version not found: {missing_version_id}")
        resolved_requirements = [item for item in requirements if item is not None]
        requirement = resolved_requirements[0]
        selection = self._build_requirement_library_selection(resolved_requirements, payload)
        requirement_scope = RequirementScopeService(self.db).persist(
            dict(selection["selectionSnapshot"]["requirementScope"]), context
        )
        requirement_snapshot = self.core_loop_service.serialize_requirement_version(requirement)
        requirement_snapshots = [self.core_loop_service.serialize_requirement_version(item) for item in resolved_requirements]
        clarifications = [
            clarification
            for item in resolved_requirements
            for clarification in self.core_loop_service.ensure_clarifications(item.id, context)
        ]
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="orchestrator.requirement-library-pipeline",
            trace_id=context.trace_id,
        )
        integration_event = IntegrationEvent(
            id=uuid4(),
            source="requirement",
            event_type="requirement_library_selected",
            external_ref=requirement.source_ref,
            payload={
                **self._payload_to_dict(payload),
                "selection": selection["selectionSnapshot"],
            },
            status="received",
            linked_requirement_version_id=requirement.id,
        )
        run = OrchestrationRun(
            id=uuid4(),
            source="requirement",
            trigger_type="requirement_library_selection",
            status=JobStatus.RUNNING,
            current_step="CLARIFICATION",
            request_id=context.request_id,
            trace_id=UUID(context.trace_id),
            linked_requirement_version_id=requirement.id,
            requirement_scope_id=str(requirement_scope["scopeId"]),
            requirement_scope=requirement_scope,
            envelope_snapshot={
                "requirementVersion": requirement_snapshot,
                "requirementVersions": requirement_snapshots,
                "requirementLibrarySelection": selection["selectionSnapshot"],
                "selectedRequirementContext": selection["selectedRequirementContext"],
            },
            result_payload={
                "requirementVersion": requirement_snapshot,
                "requirementVersions": requirement_snapshots,
                "clarifications": clarifications,
                "requirementLibrarySelection": selection["selectionSnapshot"],
            },
            started_at=datetime.now(timezone.utc),
        )
        self.db.add_all([integration_event, run])
        self.db.flush()
        integration_event.linked_pipeline_id = run.id
        self._record_checkpoint(
            run_id=run.id,
            step_name="REQUIREMENT_LIBRARY_SELECTION",
            execution_stage=None,
            status=JobStatus.COMPLETED,
            envelope_snapshot=run.envelope_snapshot,
            result_payload={
                "requirementVersion": requirement_snapshot,
                "requirementLibrarySelection": selection["selectionSnapshot"],
            },
            trace_id=run.trace_id,
            execution_id=None,
        )
        if any(self.core_loop_service.has_open_p0(item.id) for item in resolved_requirements):
            run.status = JobStatus.QUEUED
            run.current_step = "CLARIFICATION"
            run.result_payload = {**run.result_payload, "blocked": True, "reason": "p0_clarification_open"}
            self._record_checkpoint(
                run_id=run.id,
                step_name="CLARIFICATION",
                execution_stage=None,
                status=JobStatus.QUEUED,
                envelope_snapshot=run.envelope_snapshot,
                result_payload={"clarifications": clarifications, "blocked": True},
                trace_id=run.trace_id,
                execution_id=None,
            )
            self.db.commit()
            return self._requirement_pipeline_response(run)
        self.db.commit()
        return self._continue_requirement_pipeline(run.id, context)

    def answer_requirement_clarification(
        self,
        run_id: UUID,
        clarification_id: UUID,
        answer: str,
        context: ServiceContext,
    ) -> dict[str, object]:
        run = self._require_run(run_id)
        if run.source != "requirement" or run.linked_requirement_version_id is None:
            raise OrchestrationConflictError("pipeline is not a requirement pipeline")
        clarification = next(
            (
                item
                for item in self.core_loop_service.list_clarifications(run.linked_requirement_version_id)
                if str(item["clarificationId"]) == str(clarification_id)
            ),
            None,
        )
        if clarification is None:
            raise OrchestrationConflictError("clarification does not belong to pipeline requirement version")
        normalized_answer = answer.strip()
        if run.status == JobStatus.COMPLETED:
            if clarification["status"] == "closed" and clarification["answer"] == normalized_answer:
                return self._requirement_pipeline_response(run)
            raise OrchestrationConflictError("completed pipeline cannot accept clarification answers")
        if run.status != JobStatus.QUEUED or run.current_step != "CLARIFICATION":
            raise OrchestrationConflictError("pipeline is not awaiting clarification")
        clarification = self.core_loop_service.answer_clarification(clarification_id, answer, context)
        remaining = self.core_loop_service.list_clarifications(run.linked_requirement_version_id)
        run.result_payload = {**run.result_payload, "clarifications": remaining}
        if self.core_loop_service.has_open_p0(run.linked_requirement_version_id):
            self.db.commit()
            return self._requirement_pipeline_response(run)
        run.status = JobStatus.RUNNING
        run.current_step = "PLAN"
        self._record_checkpoint(
            run_id=run.id,
            step_name="CLARIFICATION",
            execution_stage=None,
            status=JobStatus.COMPLETED,
            envelope_snapshot=run.envelope_snapshot,
            result_payload={"clarifications": remaining, "blocked": False},
            trace_id=run.trace_id,
            execution_id=None,
        )
        self.db.commit()
        return self._continue_requirement_pipeline(run.id, context)

    def apply_requirement_correction(self, run_id: UUID, payload, context: ServiceContext) -> dict[str, object]:
        run = self._require_run(run_id)
        if run.linked_requirement_version_id is None:
            raise OrchestrationConflictError("pipeline has no requirement version")
        correction = self.core_loop_service.apply_correction(
            run.linked_requirement_version_id,
            run.linked_execution_id,
            payload,
            context,
        )
        if payload.targetType == "finding" and run.linked_execution_id:
            finding = self.db.get(Finding, UUID(payload.targetId))
            if finding is not None:
                requested_status = str(payload.after.get("status", FindingStatus.RESOLVED.value))
                finding.status = FindingStatus(requested_status)
                finding.comment = payload.reason
                self.db.commit()
        regression = None
        retry = None
        if run.linked_execution_id:
            regression = self.execution_service.plan_regression(run.linked_execution_id, context)
            self.core_loop_service.emit_event(
                "RegressionPlanned",
                context,
                correlation_refs={
                    "requirementVersionId": str(run.linked_requirement_version_id),
                    "executionId": str(run.linked_execution_id),
                    "correctionId": correction["correctionId"],
                },
                source_ref={"type": "regression_plan", "id": str(run.linked_execution_id)},
                payload={"caseCount": len(regression["recommendedRegressionSuite"])},
                evidence_refs=regression["evidenceRefs"],
                replay_refs=regression["replayRefs"],
                event_id=f"RegressionPlanned:{correction['correctionId']}",
            )
            failed_cases = [case for case in regression["affectedCases"] if case.get("reason") == "failed task"]
            if failed_cases:
                retry = self.execution_service.execute_approved_retry(
                    run.linked_execution_id,
                    "failed_only",
                    context,
                    approval_id=None,
                )
        run.result_payload = {
            **run.result_payload,
            "latestCorrection": correction,
            "latestRegressionPlan": regression,
            "latestRetry": retry,
        }
        self._record_checkpoint(
            run_id=run.id,
            step_name="CORRECTION",
            execution_stage=None,
            status=JobStatus.COMPLETED,
            envelope_snapshot=run.envelope_snapshot,
            result_payload={"correction": correction, "regression": regression, "retry": retry},
            trace_id=run.trace_id,
            execution_id=run.linked_execution_id,
        )
        self.db.commit()
        return {"pipeline": self._requirement_pipeline_response(run), "correction": correction, "regression": regression, "retry": retry}

    def resume_approved_execution_plan(
        self,
        run_id: UUID,
        execution_plan_id: UUID,
        context: ServiceContext,
        *,
        approval_id: UUID,
    ) -> dict[str, object]:
        run = self._require_run(run_id)
        execution_plan = self.db.get(ExecutionPlan, execution_plan_id)
        if execution_plan is None or run.linked_plan_id != execution_plan.test_plan_id:
            raise OrchestrationConflictError("execution plan does not belong to the requirement pipeline")
        execution_plan.status = "approved"
        execution_plan.metadata_json = {
            **execution_plan.metadata_json,
            "approvalId": str(approval_id),
            "approvedAt": datetime.now(timezone.utc).isoformat(),
        }
        run.status = JobStatus.RUNNING
        run.current_step = "EXECUTION_PLAN_REVIEW"
        run.result_payload = {**run.result_payload, "blocked": False, "approvalId": str(approval_id)}
        self.db.commit()
        return self._continue_requirement_pipeline(run.id, context)

    def reject_execution_plan(
        self,
        run_id: UUID,
        execution_plan_id: UUID,
        context: ServiceContext,
        *,
        approval_id: UUID,
        decision: str,
    ) -> dict[str, object]:
        run = self._require_run(run_id)
        execution_plan = self.db.get(ExecutionPlan, execution_plan_id)
        if execution_plan is None or run.linked_plan_id != execution_plan.test_plan_id:
            raise OrchestrationConflictError("execution plan does not belong to the requirement pipeline")
        execution_plan.status = "blocked"
        execution_plan.metadata_json = {
            **execution_plan.metadata_json,
            "approvalId": str(approval_id),
            "approvalStatus": decision,
        }
        run.status = JobStatus.CANCELLED
        run.current_step = "EXECUTION_PLAN_REVIEW"
        run.result_payload = {
            **run.result_payload,
            "blocked": True,
            "reason": f"high_risk_approval_{decision}",
            "approvalId": str(approval_id),
        }
        run.ended_at = datetime.now(timezone.utc)
        self._record_checkpoint(
            run_id=run.id,
            step_name="EXECUTION_PLAN_REVIEW",
            execution_stage=None,
            status=JobStatus.CANCELLED,
            envelope_snapshot=run.envelope_snapshot,
            result_payload={"executionPlanId": str(execution_plan.id), "approvalId": str(approval_id)},
            trace_id=run.trace_id,
            execution_id=None,
        )
        self.db.commit()
        return self._requirement_pipeline_response(run)

    def retry_pipeline(self, run_id: UUID, context: ServiceContext) -> dict[str, object]:
        run = self._require_run(run_id)
        if run.status in {JobStatus.QUEUED, JobStatus.RUNNING}:
            raise OrchestrationConflictError("running pipeline cannot be retried")
        integration_event = self._find_integration_event_for_run(run.id)
        if integration_event is None:
            raise ValueError("integration event not found")
        payload = self._build_pipeline_payload(integration_event.payload)
        return self._run_pipeline(
            payload,
            context,
            event_type="pipeline_retry",
            trigger_type="pipeline_retry",
            event_payload_overrides={
                "retryOfRunId": str(run.id),
                "retryOfExecutionId": str(run.linked_execution_id) if run.linked_execution_id else None,
            },
        )

    def cancel_pipeline(self, run_id: UUID, context: ServiceContext) -> dict[str, object]:
        run = self._require_run(run_id)
        if run.status == JobStatus.CANCELLED:
            return self.get_pipeline(run.id)
        if run.status in {JobStatus.COMPLETED, JobStatus.FAILED}:
            raise OrchestrationConflictError("finished pipeline cannot be cancelled")

        integration_event = self._find_integration_event_for_run(run.id)
        if run.linked_execution_id:
            execution = self.db.get(Execution, run.linked_execution_id)
            if execution and execution.status not in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
                self.execution_service.cancel(run.linked_execution_id, context)
                run = self._require_run(run.id)
                integration_event = self._find_integration_event_for_run(run.id)

        cancelled_at = datetime.now(timezone.utc)
        run.status = JobStatus.CANCELLED
        run.current_step = "CANCELLED"
        run.error_message = "cancelled by user"
        run.result_payload = {
            **run.result_payload,
            "cancelledBy": str(context.user.id),
            "cancelledAt": cancelled_at.isoformat(),
        }
        run.ended_at = cancelled_at
        if integration_event is not None:
            integration_event.status = "processed"
        self._record_checkpoint(
            run_id=run.id,
            step_name="CANCEL",
            execution_stage=self._envelope_stage(run.envelope_snapshot),
            status=JobStatus.CANCELLED,
            envelope_snapshot=run.envelope_snapshot,
            result_payload={
                "cancelledBy": str(context.user.id),
                "executionId": str(run.linked_execution_id) if run.linked_execution_id else None,
            },
            trace_id=run.trace_id,
            execution_id=run.linked_execution_id,
        )
        self.db.commit()
        return self.get_pipeline(run.id)

    def _requirement_context_for_run(self, run: OrchestrationRun) -> dict[str, object]:
        if run.linked_requirement_version_id is None:
            raise ValueError("requirement pipeline is missing requirement version")
        base_context = self.core_loop_service.requirement_context(run.linked_requirement_version_id)
        raw_selected_context = (run.envelope_snapshot or {}).get("selectedRequirementContext")
        selected_context = dict(raw_selected_context) if isinstance(raw_selected_context, dict) else {}
        if selected_context.get("schemaVersion") not in {
            "phase8.workflow-requirement-selection.v1",
            "phase8.workflow-requirement-selection.v2",
        }:
            return base_context
        if selected_context.get("requirementVersionId") != str(run.linked_requirement_version_id):
            return base_context
        selected_requirements = self._clean_string_list(selected_context.get("requirements"))
        if not selected_requirements:
            return base_context
        selected_acceptance = self._clean_string_list(selected_context.get("acceptanceCriteria"))
        raw_selected_metadata = selected_context.get("metadata")
        selected_metadata = dict(raw_selected_metadata) if isinstance(raw_selected_metadata, dict) else {}
        return {
            **base_context,
            "document": str(selected_context.get("document") or base_context["document"]),
            "documents": list(selected_context.get("documents") or []),
            "requirements": selected_requirements,
            "acceptanceCriteria": selected_acceptance,
            "requirementScope": dict(selected_context.get("requirementScope") or base_context.get("requirementScope") or {}),
            "metadata": {
                **dict(base_context.get("metadata") or {}),
                **selected_metadata,
            },
            "clarificationRefs": list(base_context.get("clarificationRefs") or []),
        }

    def _build_requirement_library_selection(
        self,
        requirements: list[RequirementVersion],
        payload,
    ) -> dict[str, object]:
        requirement = requirements[0]
        mode = str(payload.selectionMode)
        requested_by_version = self._requested_requirement_items(payload, requirements)
        selected_items: list[dict[str, object]] = []
        requirement_item_refs: list[dict[str, object]] = []
        for version in requirements:
            all_items = self._requirement_library_items(version)
            item_by_id = {str(item["itemId"]): item for item in all_items}
            requested_ids = requested_by_version.get(version.id)
            if requested_ids is None or mode == "requirement_version":
                requested_ids = list(item_by_id)
            if not requested_ids:
                raise ValueError(f"requirementItemRefs must include at least one item for {version.id}")
            unknown_ids = [item_id for item_id in requested_ids if item_id not in item_by_id]
            if unknown_ids:
                raise ValueError(
                    f"requirementItemRefs contains unknown requirement item id for {version.id}: {unknown_ids[0]}"
                )
            requirement_item_refs.append(
                {"requirementVersionId": str(version.id), "requirementItemIds": requested_ids}
            )
            for item_id in requested_ids:
                item = dict(item_by_id[item_id])
                item["scopeItemId"] = requirement_scope_item_id(version.id, item_id)
                selected_items.append(item)

        is_v2 = len(requirements) > 1 or mode == "requirement_scope"
        selected_ids = [
            str(item["scopeItemId"] if is_v2 else item["itemId"])
            for item in selected_items
        ]
        document = (
            requirement.document
            if not is_v2
            else f"RequirementScope v2 selection across {len(requirements)} persisted requirement versions."
        )

        selected_requirements = self._clean_string_list([item.get("requirement") for item in selected_items])
        selected_acceptance = self._dedupe_strings(
            [
                criteria
                for item in selected_items
                for criteria in list(item.get("acceptanceCriteria") or [])
            ]
        )
        if not selected_requirements:
            raise ValueError("selected requirement library input has no requirements")

        base_metadata = dict(requirement.metadata_json or {})
        request_metadata = dict(getattr(payload, "metadata", {}) or {})
        requirement_scope = normalize_requirement_scope(
            requirement_version_id=requirement.id,
            selected_requirement_item_ids=selected_ids if mode == "requirement_items" and not is_v2 else [],
            requirement_version_ids=[item.id for item in requirements],
            requirement_item_refs=requirement_item_refs if is_v2 else [],
            filters={"source": "workflow-requirement-library", "selectionMode": mode},
            metadata={
                **request_metadata,
                "selectionMode": mode,
                "selectedRequirementItemCount": len(selected_items),
                "availableRequirementItemCount": sum(len(self._requirement_library_items(item)) for item in requirements),
                "requirementVersionCount": len(requirements),
            },
            force_v2=is_v2,
        )
        selection_snapshot = {
            "schemaVersion": "phase8.workflow-requirement-selection.v2" if is_v2 else "phase8.workflow-requirement-selection.v1",
            "selectionMode": mode,
            "requirementVersionId": str(requirement.id),
            "requirementVersionIds": [str(item.id) for item in requirements],
            "requirementScope": requirement_scope,
            "sourceRef": requirement.source_ref,
            "selectedRequirementItemIds": selected_ids,
            "selectedRequirementItemCount": len(selected_items),
            "availableRequirementItemCount": sum(len(self._requirement_library_items(item)) for item in requirements),
            "projectId": base_metadata.get("projectId"),
            "environmentId": base_metadata.get("environmentId"),
            "sourceType": "requirement_scope" if is_v2 else base_metadata.get("intakeSourceType") or base_metadata.get("sourceType") or "requirement_version",
        }
        selected_context = {
            "schemaVersion": selection_snapshot["schemaVersion"],
            "requirementVersionId": str(requirement.id),
            "requirementVersionIds": [str(item.id) for item in requirements],
            "requirementScope": requirement_scope,
            "document": document,
            "documents": [
                {
                    "requirementVersionId": str(item.id),
                    "sourceRef": item.source_ref,
                    "contentHash": item.content_hash,
                }
                for item in requirements
            ],
            "requirements": selected_requirements,
            "acceptanceCriteria": selected_acceptance,
            "metadata": {
                **base_metadata,
                **request_metadata,
                "source": "workflow-requirement-library",
                "requirementLibrarySelection": selection_snapshot,
                "selectedRequirementItemIds": selected_ids,
                "selectedRequirementItems": selected_items,
                "selectedRequirementItemCount": len(selected_items),
                "requirementScope": requirement_scope,
            },
        }
        return {
            "selectionSnapshot": selection_snapshot,
            "selectedRequirementContext": selected_context,
        }

    def _requirement_scope_version_ids(self, payload) -> list[UUID]:
        raw_ids = list(getattr(payload, "requirementVersionIds", []) or [])
        if getattr(payload, "requirementVersionId", None) is not None:
            raw_ids.insert(0, payload.requirementVersionId)
        raw_scope = getattr(payload, "requirementScope", None)
        if raw_scope is not None:
            scope_payload = raw_scope.model_dump(mode="json")
            raw_ids.extend(scope_payload.get("requirementVersionIds") or [])
            if scope_payload.get("requirementVersionId"):
                raw_ids.insert(0, scope_payload["requirementVersionId"])
        result: list[UUID] = []
        for raw_id in raw_ids:
            version_id = UUID(str(raw_id))
            if version_id not in result:
                result.append(version_id)
        if not result:
            raise ValueError("requirementVersionId or requirementVersionIds is required")
        return result

    def _requested_requirement_items(
        self,
        payload,
        requirements: list[RequirementVersion],
    ) -> dict[UUID, list[str] | None]:
        result: dict[UUID, list[str] | None] = {item.id: None for item in requirements}
        refs = list(getattr(payload, "requirementItemRefs", []) or [])
        raw_scope = getattr(payload, "requirementScope", None)
        if raw_scope is not None:
            refs.extend(raw_scope.requirementItemRefs)
        for ref in refs:
            version_id = UUID(str(ref.requirementVersionId))
            if version_id not in result:
                raise ValueError("requirementItemRefs must reference a selected requirementVersionId")
            result[version_id] = self._dedupe_strings(ref.requirementItemIds)
        legacy_ids = self._dedupe_strings(getattr(payload, "requirementItemIds", []) or [])
        if legacy_ids:
            result[requirements[0].id] = legacy_ids
        if str(payload.selectionMode) in {"requirement_items", "requirement_scope"} and not any(
            item_ids for item_ids in result.values()
        ):
            raise ValueError("requirementItemIds or requirementItemRefs must include at least one requirement item")
        return result

    def _requirement_library_items(self, requirement: RequirementVersion) -> list[dict[str, object]]:
        requirements = list(requirement.requirements or [])
        acceptance = list(requirement.acceptance_criteria or [])
        items: list[dict[str, object]] = []
        for index, raw_item in enumerate(requirements, start=1):
            if isinstance(raw_item, dict):
                item_id = str(raw_item.get("id") or raw_item.get("requirementItemId") or f"requirement-{index}")
                text = str(raw_item.get("text") or raw_item.get("title") or item_id)
                metadata = dict(raw_item)
            else:
                item_id = f"requirement-{index}"
                text = str(raw_item)
                metadata = {}
            items.append(
                {
                    "itemId": item_id,
                    "ordinal": index,
                    "requirement": text,
                    "acceptanceCriteria": self._acceptance_criteria_for_requirement_item(
                        acceptance,
                        index=index,
                        requirement_count=len(requirements),
                    ),
                    "sourceRef": requirement.source_ref,
                    "requirementVersionId": str(requirement.id),
                    "metadata": metadata,
                }
            )
        return items

    def _acceptance_criteria_for_requirement_item(
        self,
        acceptance: list[object],
        *,
        index: int,
        requirement_count: int,
    ) -> list[str]:
        cleaned = self._clean_string_list(acceptance)
        if requirement_count <= 1:
            return cleaned
        if len(cleaned) == requirement_count:
            return [cleaned[index - 1]]
        if index <= len(cleaned):
            return [cleaned[index - 1]]
        return []

    def _document_for_library_requirement_items(
        self,
        requirement: RequirementVersion,
        selected_items: list[dict[str, object]],
    ) -> str:
        lines = [
            f"Selected requirement items from requirement version {requirement.id}",
            f"Source ref: {requirement.source_ref}",
        ]
        for item in selected_items:
            lines.append("")
            lines.append(f"Requirement item: {item['itemId']}")
            lines.append(f"Requirement: {item['requirement']}")
            for criteria in list(item.get("acceptanceCriteria") or []):
                lines.append(f"Acceptance: {criteria}")
        return "\n".join(lines)

    def _clean_string_list(self, values: object) -> list[str]:
        if not isinstance(values, list):
            return []
        return self._dedupe_strings(values)

    def _dedupe_strings(self, values: object) -> list[str]:
        if not isinstance(values, list):
            return []
        cleaned: list[str] = []
        for value in values:
            text = str(value).strip()
            if text and text not in cleaned:
                cleaned.append(text)
        return cleaned

    def _continue_requirement_pipeline(self, run_id: UUID, context: ServiceContext) -> dict[str, object]:
        run = self._require_run(run_id)
        if run.linked_requirement_version_id is None:
            raise ValueError("requirement pipeline is missing requirement version")
        requirement_context = self._requirement_context_for_run(run)
        if not requirement_context["requirements"] or not requirement_context["acceptanceCriteria"]:
            run.status = JobStatus.QUEUED
            run.current_step = "CLARIFICATION"
            run.result_payload = {**run.result_payload, "blocked": True, "reason": "clarification_answers_incomplete"}
            self.db.commit()
            return self._requirement_pipeline_response(run)

        try:
            if run.linked_plan_id is None:
                run.current_step = "PLAN"
                plan_result = self._run_requirement_plan_stage(run.linked_requirement_version_id, requirement_context, context)
                run = self._require_run(run.id)
                run.linked_plan_id = UUID(str(plan_result["planId"]))
                self._record_checkpoint(
                    run_id=run.id,
                    step_name="PLAN",
                    execution_stage=None,
                    status=JobStatus.COMPLETED,
                    envelope_snapshot={"requirement": requirement_context},
                    result_payload=plan_result,
                    trace_id=run.trace_id,
                    execution_id=None,
                )
                self.db.commit()
            else:
                plan_result = {"planId": str(run.linked_plan_id), "jobId": None, "jobStatus": "reused"}

            run.current_step = "ASSET_REVIEW"
            assets = self.core_loop_service.create_test_assets(run.linked_requirement_version_id, run.linked_plan_id)
            coverage = self.plan_service.analyze_coverage(run.linked_plan_id, context)
            review = self.core_loop_service.review_test_assets(
                run.linked_requirement_version_id,
                run.linked_plan_id,
                coverage,
                context,
            )
            self._record_checkpoint(
                run_id=run.id,
                step_name="ASSET_REVIEW",
                execution_stage=None,
                status=JobStatus.COMPLETED if review["status"] == "approved" else JobStatus.QUEUED,
                envelope_snapshot={"requirement": requirement_context},
                result_payload={"assets": assets, "coverage": coverage, "review": review},
                trace_id=run.trace_id,
                execution_id=None,
            )
            if review["status"] != "approved":
                run.status = JobStatus.QUEUED
                run.result_payload = {
                    **run.result_payload,
                    "blocked": True,
                    "reason": "asset_review_required",
                    "plan": plan_result,
                    "assets": assets,
                    "coverage": coverage,
                    "assetReview": review,
                }
                self.db.commit()
                return self._requirement_pipeline_response(run)

            execution_plan = self.core_loop_service.create_execution_plan(
                run.linked_requirement_version_id,
                run.linked_plan_id,
                UUID(str(review["reviewId"])),
            )
            if execution_plan["status"] != "approved":
                approval = self.approval_service.request_execution_plan_review(
                    execution_plan_id=UUID(str(execution_plan["executionPlanId"])),
                    orchestration_run_id=run.id,
                    context=context,
                )
                run = self._require_run(run.id)
                run.status = JobStatus.QUEUED
                run.current_step = "EXECUTION_PLAN_REVIEW"
                run.result_payload = {
                    **run.result_payload,
                    "blocked": True,
                    "reason": "high_risk_approval_required",
                    "executionPlan": execution_plan,
                    "approval": approval,
                }
                self.db.commit()
                return self._requirement_pipeline_response(run)

            run.current_step = "EXECUTE"
            plan = self.db.get(TestPlan, run.linked_plan_id)
            execution_result, current_envelope = self._run_execution_stage(
                run.linked_plan_id,
                context,
                environment=plan.environment if plan else "local",
                execution_plan_id=UUID(str(execution_plan["executionPlanId"])),
            )
            run = self._require_run(run.id)
            run.linked_execution_id = UUID(str(execution_result["executionId"]))
            run.envelope_snapshot = current_envelope
            integration_event = self._find_integration_event_for_run(run.id)
            if integration_event is not None:
                integration_event.linked_plan_id = run.linked_plan_id
                integration_event.linked_execution_id = run.linked_execution_id
            self.core_loop_service.emit_event(
                "ExecutionCompleted",
                context,
                correlation_refs={
                    "requirementVersionId": str(run.linked_requirement_version_id),
                    "executionId": str(run.linked_execution_id),
                },
                source_ref={"type": "execution", "id": str(run.linked_execution_id)},
                payload={"status": execution_result["status"]},
                evidence_refs=current_envelope.get("artifactRefs", []),
                replay_refs=[{"type": "execution", "id": str(run.linked_execution_id)}],
                event_id=f"ExecutionCompleted:{run.linked_execution_id}",
            )
            self.core_loop_service.emit_event(
                "EvidenceCollected",
                context,
                correlation_refs={"executionId": str(run.linked_execution_id)},
                source_ref={"type": "execution", "id": str(run.linked_execution_id)},
                payload={"artifactCount": len(current_envelope.get("artifactRefs", []))},
                evidence_refs=current_envelope.get("artifactRefs", []),
                replay_refs=[{"type": "execution", "id": str(run.linked_execution_id)}],
                event_id=f"EvidenceCollected:{run.linked_execution_id}",
            )
            self._record_checkpoint(
                run_id=run.id,
                step_name="EXECUTION",
                execution_stage=ExecutionStage.OBSERVE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload={"execution": execution_result, "executionPlan": execution_plan},
                trace_id=run.trace_id,
                execution_id=run.linked_execution_id,
            )
            self.db.commit()

            run.current_step = "ANALYZE"
            triage_result, current_envelope = self._run_triage_stage(run.linked_execution_id, context, current_envelope)
            attributions = self.analysis_service.get_failure_attribution(run.linked_execution_id)
            for attribution in attributions["attributions"]:
                self.core_loop_service.emit_event(
                    "FailureAttributed",
                    context,
                    correlation_refs={
                        "requirementVersionId": str(run.linked_requirement_version_id),
                        "executionId": str(run.linked_execution_id),
                        "taskId": attribution["taskId"],
                    },
                    source_ref={"type": "failure_attribution", "id": attribution["taskId"] or str(run.linked_execution_id)},
                    payload={
                        "category": attribution["category"],
                        "confidence": attribution["confidence"],
                        "reviewRequired": attribution["reviewRequired"],
                    },
                    evidence_refs=[item if isinstance(item, dict) else {"type": "evidence", "ref": item} for item in attribution["evidence"]],
                    replay_refs=[{"type": "execution", "id": str(run.linked_execution_id)}],
                    event_id=f"FailureAttributed:{run.linked_execution_id}:{attribution['taskId'] or 'execution'}",
                )
            self._record_checkpoint(
                run_id=run.id,
                step_name="ANALYZE",
                execution_stage=ExecutionStage.ANALYZE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload={"triage": triage_result, "failureAttribution": attributions},
                trace_id=run.trace_id,
                execution_id=run.linked_execution_id,
            )
            self.db.commit()

            run.current_step = "NORMALIZE"
            normalize_result, current_envelope = self._run_normalize_stage(
                run.linked_execution_id,
                context,
                current_envelope,
            )
            if current_envelope.get("findingRefs"):
                self.core_loop_service.emit_event(
                    "FindingNormalized",
                    context,
                    correlation_refs={"executionId": str(run.linked_execution_id)},
                    source_ref={"type": "execution", "id": str(run.linked_execution_id)},
                    payload={"findingCount": len(current_envelope["findingRefs"])},
                    evidence_refs=current_envelope["findingRefs"],
                    replay_refs=[{"type": "execution", "id": str(run.linked_execution_id)}],
                    event_id=f"FindingNormalized:{run.linked_execution_id}",
                )
            self._record_checkpoint(
                run_id=run.id,
                step_name="NORMALIZE",
                execution_stage=ExecutionStage.NORMALIZE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload=normalize_result,
                trace_id=run.trace_id,
                execution_id=run.linked_execution_id,
            )
            self.db.commit()

            run.current_step = "GATE"
            gate_result, current_envelope = self._run_gate_stage(run.linked_execution_id, context, current_envelope)
            gate_result = {**gate_result, "requirementScope": self._requirement_scope_for_run(run)}
            gate = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == run.linked_execution_id))
            self.core_loop_service.emit_event(
                "GateDecided",
                context,
                correlation_refs={
                    "requirementVersionId": str(run.linked_requirement_version_id),
                    "executionId": str(run.linked_execution_id),
                },
                source_ref={"type": "gate_decision", "id": str(gate.id) if gate else str(run.linked_execution_id)},
                payload={"overall": gate_result["overall"]},
                evidence_refs=current_envelope.get("findingRefs", []),
                replay_refs=[{"type": "execution", "id": str(run.linked_execution_id)}],
                event_id=f"GateDecided:{run.linked_execution_id}",
            )
            self._record_checkpoint(
                run_id=run.id,
                step_name="GATE",
                execution_stage=ExecutionStage.GATE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload=gate_result,
                trace_id=run.trace_id,
                execution_id=run.linked_execution_id,
            )
            self.db.commit()

            regression = self.execution_service.plan_regression(run.linked_execution_id, context)
            self.core_loop_service.emit_event(
                "RegressionPlanned",
                context,
                correlation_refs={
                    "requirementVersionId": str(run.linked_requirement_version_id),
                    "executionId": str(run.linked_execution_id),
                },
                source_ref={"type": "regression_plan", "id": str(run.linked_execution_id)},
                payload={"caseCount": len(regression["recommendedRegressionSuite"])},
                evidence_refs=regression["evidenceRefs"],
                replay_refs=regression["replayRefs"],
                event_id=f"RegressionPlanned:{run.linked_execution_id}",
            )

            run.current_step = "KNOWLEDGE"
            gate_evidence = current_envelope.get("findingRefs", []) or [
                {"type": "gate_decision", "id": str(gate.id) if gate else str(run.linked_execution_id)}
            ]
            knowledge = self.memory_service.promote_test_knowledge_entry(
                {
                    "schemaVersion": "phase8.test-knowledge-entry.v1",
                    "knowledgeId": f"gate:{run.linked_execution_id}",
                    "knowledgeType": "execution_outcome",
                    "status": "active",
                    "content": {
                        "summary": f"Execution {run.linked_execution_id} completed with gate={gate_result['overall']}",
                        "gate": gate_result,
                    },
                    "sourceRefs": [{"type": "gate_decision", "id": str(gate.id) if gate else str(run.linked_execution_id)}],
                    "evidenceRefs": gate_evidence,
                    "traceRefs": [context.trace_id],
                    "replayRefs": [{"type": "execution", "id": str(run.linked_execution_id)}],
                    "confidence": 1.0,
                    "lifecycle": {
                        "promote": "verified_gate_decision",
                        "reuse": "similar_requirement",
                        "invalidate": "source_invalidated",
                        "decay": "time_based",
                        "dedupe": "knowledgeId",
                        "conflict_resolution": "review",
                        "replay_validation": "required",
                    },
                    "metadata": {"namespace": f"requirement/{run.linked_requirement_version_id}"},
                },
                context,
            )
            self.core_loop_service.emit_event(
                "KnowledgePromoted",
                context,
                correlation_refs={
                    "requirementVersionId": str(run.linked_requirement_version_id),
                    "executionId": str(run.linked_execution_id),
                },
                source_ref={"type": "memory", "id": knowledge["id"]},
                payload={"knowledgeId": knowledge["knowledgeId"]},
                evidence_refs=gate_evidence,
                replay_refs=[{"type": "execution", "id": str(run.linked_execution_id)}],
                event_id=f"KnowledgePromoted:{run.linked_execution_id}",
            )

            TraceabilityService(self.db).ensure_requirement_execution_chain(
                requirement_version_id=run.linked_requirement_version_id,
                test_plan_id=run.linked_plan_id,
                execution_id=run.linked_execution_id,
                requirement_scope=plan.requirement_scope if plan else None,
            )
            replay_export = self.observability_service.export_execution_replay(
                run.linked_execution_id,
                request_id=context.request_id,
            )
            TraceabilityService(self.db).ensure_gate_replay_export_relation(
                requirement_version_id=run.linked_requirement_version_id,
                execution_id=run.linked_execution_id,
                replay_export_id=str(replay_export["exportHash"]),
                replay_export_hash=str(replay_export["exportHash"]),
                requirement_scope=plan.requirement_scope if plan else None,
            )
            self.core_loop_service.emit_event(
                "ReplayExported",
                context,
                correlation_refs={
                    "requirementVersionId": str(run.linked_requirement_version_id),
                    "executionId": str(run.linked_execution_id),
                },
                source_ref={"type": "replay_export", "id": replay_export["exportHash"]},
                payload={"exportHash": replay_export["exportHash"], "redactionStatus": replay_export["redactionStatus"]},
                evidence_refs=gate_evidence,
                replay_refs=[{"type": "replay_export", "id": replay_export["exportHash"]}],
                event_id=f"ReplayExported:{run.linked_execution_id}",
            )

            run = self._require_run(run.id)
            integration_event = self._find_integration_event_for_run(run.id)
            if integration_event is not None:
                integration_event.status = "processed"
            run.status = JobStatus.COMPLETED
            run.current_step = "COMPLETED"
            run.envelope_snapshot = current_envelope
            run.result_payload = {
                "blocked": False,
                "requirementVersion": run.result_payload.get("requirementVersion"),
                "requirementScope": self._requirement_scope_for_run(run),
                "clarifications": run.result_payload.get("clarifications", []),
                "plan": plan_result,
                "assets": assets,
                "coverage": coverage,
                "assetReview": review,
                "executionPlan": execution_plan,
                "execution": execution_result,
                "triage": triage_result,
                "failureAttribution": attributions,
                "gate": gate_result,
                "regressionPlan": regression,
                "knowledge": knowledge,
                "replayExport": replay_export,
            }
            run.ended_at = datetime.now(timezone.utc)
            self._record_checkpoint(
                run_id=run.id,
                step_name="EXPORT",
                execution_stage=None,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload={"exportHash": replay_export["exportHash"], "knowledge": knowledge},
                trace_id=run.trace_id,
                execution_id=run.linked_execution_id,
            )
            self.db.commit()
            return self._requirement_pipeline_response(run)
        except Exception as exc:
            self.db.rollback()
            run = self._require_run(run_id)
            run.status = JobStatus.FAILED
            run.error_message = str(exc)
            run.ended_at = datetime.now(timezone.utc)
            self._record_checkpoint(
                run_id=run.id,
                step_name=run.current_step,
                execution_stage=self._envelope_stage(run.envelope_snapshot),
                status=JobStatus.FAILED,
                envelope_snapshot=run.envelope_snapshot,
                result_payload={},
                trace_id=run.trace_id,
                execution_id=run.linked_execution_id,
                error_message=str(exc),
            )
            self.db.commit()
            raise

    def _requirement_pipeline_response(self, run: OrchestrationRun) -> dict[str, object]:
        return {
            "orchestrationId": str(run.id),
            "requirementVersionId": str(run.linked_requirement_version_id) if run.linked_requirement_version_id else None,
            "requirementScope": self._requirement_scope_for_run(run),
            "planId": str(run.linked_plan_id) if run.linked_plan_id else None,
            "executionId": str(run.linked_execution_id) if run.linked_execution_id else None,
            "status": run.status.value,
            "currentStep": run.current_step,
            "blocked": bool(run.result_payload.get("blocked", False)),
            "result": run.result_payload,
            "errorMessage": run.error_message,
        }

    def _run_pipeline(
        self,
        payload,
        context: ServiceContext,
        *,
        event_type: str,
        trigger_type: str,
        event_payload_overrides: dict[str, object] | None = None,
    ) -> dict[str, object]:
        payload_dict = self._payload_to_dict(payload)
        integration_event = IntegrationEvent(
            id=uuid4(),
            source="git",
            event_type=event_type,
            external_ref=payload.pullRequestId,
            payload=payload_dict | (event_payload_overrides or {}),
            status="received",
        )
        self.db.add(integration_event)
        self.db.flush()
        # Orchestration runs are linked to traces directly, so create the
        # trace record before inserting the run to satisfy FK constraints.
        ensure_trace(self.db, execution_id=None, root_span_name="orchestrator.pipeline", trace_id=context.trace_id)
        self.db.flush()

        run = OrchestrationRun(
            id=uuid4(),
            source="git",
            trigger_type=trigger_type,
            status=JobStatus.RUNNING,
            current_step="PLAN",
            request_id=context.request_id,
            trace_id=UUID(context.trace_id),
            envelope_snapshot={},
            result_payload={},
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(run)
        self.db.commit()

        active_step = "PLAN"
        current_envelope: dict[str, object] = {}

        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=None,
                root_span_name="orchestrator.pipeline",
                span_name="pipeline.plan",
                service_name="orchestrator-service",
                attributes={"runId": str(run.id), "pullRequestId": payload.pullRequestId},
            ):
                plan_result = self._run_plan_stage(payload, context)
            run = self._require_run(run.id)
            integration_event = self._require_integration_event(integration_event.id)
            run.linked_plan_id = UUID(plan_result["planId"])
            run.current_step = "PREPARE"
            integration_event.linked_pipeline_id = run.id
            integration_event.linked_plan_id = UUID(plan_result["planId"])
            self._record_checkpoint(
                run_id=run.id,
                step_name="PLAN",
                execution_stage=None,
                status=JobStatus.COMPLETED,
                envelope_snapshot={},
                result_payload=plan_result,
                trace_id=run.trace_id,
                execution_id=None,
            )
            self.db.commit()

            active_step = "PREPARE"
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=None,
                root_span_name="orchestrator.pipeline",
                span_name="pipeline.prepare",
                service_name="orchestrator-service",
                attributes={"runId": str(run.id), "planId": plan_result["planId"]},
            ):
                execution_result, current_envelope = self._run_execution_stage(UUID(plan_result["planId"]), context)
            run = self._require_run(run.id)
            integration_event = self._require_integration_event(integration_event.id)
            run.linked_execution_id = UUID(execution_result["executionId"])
            run.current_step = "ANALYZE"
            run.envelope_snapshot = current_envelope
            integration_event.linked_execution_id = UUID(execution_result["executionId"])
            self._record_checkpoint(
                run_id=run.id,
                step_name="PREPARE",
                execution_stage=ExecutionStage.PREPARE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope | {"executionContext": {**current_envelope["executionContext"], "stage": ExecutionStage.PREPARE.value}},
                result_payload={"executionId": execution_result["executionId"], "jobId": execution_result["jobId"]},
                trace_id=run.trace_id,
                execution_id=UUID(execution_result["executionId"]),
            )
            self._record_checkpoint(
                run_id=run.id,
                step_name="OBSERVE",
                execution_stage=ExecutionStage.OBSERVE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload=execution_result,
                trace_id=run.trace_id,
                execution_id=UUID(execution_result["executionId"]),
            )
            self.db.commit()

            active_step = "ANALYZE"
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=UUID(execution_result["executionId"]),
                root_span_name="orchestrator.pipeline",
                span_name="pipeline.analyze",
                service_name="orchestrator-service",
                attributes={"runId": str(run.id), "executionId": execution_result["executionId"]},
            ):
                triage_result, current_envelope = self._run_triage_stage(UUID(execution_result["executionId"]), context, current_envelope)
            run = self._require_run(run.id)
            run.current_step = "NORMALIZE"
            run.envelope_snapshot = current_envelope
            self._record_checkpoint(
                run_id=run.id,
                step_name="ANALYZE",
                execution_stage=ExecutionStage.ANALYZE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload=triage_result,
                trace_id=run.trace_id,
                execution_id=UUID(execution_result["executionId"]),
            )
            self.db.commit()

            active_step = "NORMALIZE"
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=UUID(execution_result["executionId"]),
                root_span_name="orchestrator.pipeline",
                span_name="pipeline.normalize",
                service_name="orchestrator-service",
                attributes={"runId": str(run.id), "executionId": execution_result["executionId"]},
            ):
                normalize_result, current_envelope = self._run_normalize_stage(
                    UUID(execution_result["executionId"]),
                    context,
                    current_envelope,
                )
            run = self._require_run(run.id)
            run.current_step = "GATE"
            run.envelope_snapshot = current_envelope
            self._record_checkpoint(
                run_id=run.id,
                step_name="NORMALIZE",
                execution_stage=ExecutionStage.NORMALIZE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload=normalize_result,
                trace_id=run.trace_id,
                execution_id=UUID(execution_result["executionId"]),
            )
            self.db.commit()

            active_step = "GATE"
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=UUID(execution_result["executionId"]),
                root_span_name="orchestrator.pipeline",
                span_name="pipeline.gate",
                service_name="orchestrator-service",
                attributes={"runId": str(run.id), "executionId": execution_result["executionId"]},
            ):
                gate_result, current_envelope = self._run_gate_stage(UUID(execution_result["executionId"]), context, current_envelope)
            run = self._require_run(run.id)
            run.current_step = "MEMORY"
            run.envelope_snapshot = current_envelope
            self._record_checkpoint(
                run_id=run.id,
                step_name="GATE",
                execution_stage=ExecutionStage.GATE.value,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload=gate_result,
                trace_id=run.trace_id,
                execution_id=UUID(execution_result["executionId"]),
            )
            self.db.commit()

            active_step = "MEMORY"
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=UUID(execution_result["executionId"]),
                root_span_name="orchestrator.pipeline",
                span_name="pipeline.memory",
                service_name="orchestrator-service",
                attributes={"runId": str(run.id), "executionId": execution_result["executionId"]},
            ):
                memory_result = self._run_memory_stage(
                    UUID(execution_result["executionId"]),
                    gate_result,
                    context,
                )
            run = self._require_run(run.id)
            integration_event = self._require_integration_event(integration_event.id)
            integration_event.status = "processed"
            run.status = JobStatus.COMPLETED
            run.current_step = "COMPLETED"
            run.envelope_snapshot = current_envelope
            run.result_payload = {
                "planId": plan_result["planId"],
                "executionId": execution_result["executionId"],
                "gate": gate_result,
                "memory": memory_result,
            }
            run.ended_at = datetime.now(timezone.utc)
            self._record_checkpoint(
                run_id=run.id,
                step_name="MEMORY",
                execution_stage=None,
                status=JobStatus.COMPLETED,
                envelope_snapshot=current_envelope,
                result_payload=memory_result,
                trace_id=run.trace_id,
                execution_id=UUID(execution_result["executionId"]),
            )
            self.db.commit()
            return {
                "orchestrationId": str(run.id),
                "planId": plan_result["planId"],
                "executionId": execution_result["executionId"],
                "status": run.status.value,
                "gateOverall": gate_result["overall"],
                "retryOfRunId": self._string_or_none((event_payload_overrides or {}).get("retryOfRunId")),
            }
        except Exception as exc:
            self.db.rollback()
            run = self._require_run(run.id)
            integration_event = self._require_integration_event(integration_event.id)
            run.status = JobStatus.FAILED
            run.current_step = active_step
            run.error_message = str(exc)
            run.envelope_snapshot = current_envelope
            run.ended_at = datetime.now(timezone.utc)
            integration_event.status = "failed"
            self._record_checkpoint(
                run_id=run.id,
                step_name=active_step,
                execution_stage=current_envelope.get("executionContext", {}).get("stage") if current_envelope else None,
                status=JobStatus.FAILED,
                envelope_snapshot=current_envelope,
                result_payload={},
                trace_id=run.trace_id,
                execution_id=run.linked_execution_id,
                error_message=str(exc),
            )
            self.db.commit()
            raise

    def get_pipeline(self, run_id: UUID) -> dict[str, object]:
        run = self._require_run(run_id)
        integration_event = self._find_integration_event_for_run(run.id)
        retry_info = self._extract_retry_info(integration_event)
        checkpoint_count = self.db.scalar(
            select(func.count()).select_from(OrchestrationCheckpoint).where(OrchestrationCheckpoint.run_id == run.id)
        ) or 0
        return {
            "id": str(run.id),
            "source": run.source,
            "triggerType": run.trigger_type,
            "status": run.status.value,
            "currentStep": run.current_step,
            "traceId": str(run.trace_id) if run.trace_id else None,
            "requestId": run.request_id,
            "planId": str(run.linked_plan_id) if run.linked_plan_id else None,
            "executionId": str(run.linked_execution_id) if run.linked_execution_id else None,
            "requirementVersionId": str(run.linked_requirement_version_id) if run.linked_requirement_version_id else None,
            "requirementScope": self._requirement_scope_for_run(run),
            "retryOfRunId": retry_info["retryOfRunId"],
            "retryOfExecutionId": retry_info["retryOfExecutionId"],
            "checkpointCount": checkpoint_count,
            "result": run.result_payload,
            "errorMessage": run.error_message,
            "startedAt": run.started_at.isoformat() if run.started_at else None,
            "endedAt": run.ended_at.isoformat() if run.ended_at else None,
            "createdAt": run.created_at.isoformat(),
            "updatedAt": run.updated_at.isoformat(),
        }

    def _requirement_scope_for_run(self, run: OrchestrationRun) -> dict[str, object] | None:
        if run.requirement_scope:
            return dict(run.requirement_scope)
        if run.linked_plan_id is not None:
            plan = self.db.get(TestPlan, run.linked_plan_id)
            if plan is not None and plan.requirement_scope:
                return dict(plan.requirement_scope)
        for key in ("selectedRequirementContext", "requirementLibrarySelection"):
            raw = (run.envelope_snapshot or {}).get(key)
            if isinstance(raw, dict):
                scope = raw.get("requirementScope")
                if isinstance(scope, dict):
                    return dict(scope)
        if run.linked_requirement_version_id is not None:
            return normalize_requirement_scope(
                requirement_version_id=run.linked_requirement_version_id,
                filters={"source": "orchestrator"},
                metadata={"selectionMode": "requirement_version", "defaulted": True},
            )
        return None

    def replay_pipeline(self, run_id: UUID) -> dict[str, object]:
        run = self._require_run(run_id)
        checkpoints = list(
            self.db.scalars(
                select(OrchestrationCheckpoint)
                .where(OrchestrationCheckpoint.run_id == run.id)
                .order_by(OrchestrationCheckpoint.sequence_no.asc(), OrchestrationCheckpoint.created_at.asc())
            )
        )
        integration_event = self._find_integration_event_for_run(run.id)
        return {
            **self.get_pipeline(run.id),
            "integrationEvent": self._serialize_integration_event(integration_event) if integration_event else None,
            "finalEnvelope": run.envelope_snapshot,
            "checkpoints": [self._serialize_checkpoint(row) for row in checkpoints],
        }

    def _run_plan_stage(self, payload, context: ServiceContext) -> dict[str, object]:
        plan_payload = SimpleNamespace(
            name=f"PR-{payload.pullRequestId} regression plan",
            sourceType=SourceType.PR,
            sourceRef=f"{payload.repository}/pull/{payload.pullRequestId}",
            environment="staging",
            domains=[TestDomain.FUNCTIONAL, TestDomain.PERFORMANCE, TestDomain.SECURITY],
            domainConfig={},
            riskLevel=RiskLevel.HIGH,
            input={
                "repository": payload.repository,
                "branch": payload.branch,
                "commitSha": payload.commitSha,
            },
        )
        plan_result = self.plan_service.create_plan(plan_payload, context)
        job = self.plan_service.prepare_generate_plan_job(UUID(plan_result["id"]))
        self.db.commit()
        job_result = self.plan_service.run_generate_plan_job(job.id, UUID(plan_result["id"]), context)
        return {"planId": plan_result["id"], "jobId": str(job.id), "jobStatus": job_result["status"]}

    def _run_requirement_plan_stage(
        self,
        requirement_version_id: UUID,
        requirement_context: dict[str, object],
        context: ServiceContext,
    ) -> dict[str, object]:
        metadata = requirement_context["metadata"]
        project_id = metadata.get("projectId")
        environment_id = metadata.get("environmentId")
        plan_payload = SimpleNamespace(
            name=str(metadata.get("name") or f"Requirement {requirement_version_id}"),
            sourceType=SourceType.API,
            sourceRef=f"requirement/{requirement_version_id}",
            environment=str(metadata.get("environment") or "local"),
            projectId=UUID(str(project_id)) if project_id else None,
            environmentId=UUID(str(environment_id)) if environment_id else None,
            domains=[TestDomain(value) for value in metadata.get("domains", [domain.value for domain in TestDomain])],
            domainConfig={},
            riskLevel=RiskLevel(str(metadata.get("riskLevel") or RiskLevel.MEDIUM.value)),
            input={
                "requirementVersionId": str(requirement_version_id),
                "requirementScope": requirement_context.get("requirementScope"),
                "document": requirement_context["document"],
                "requirements": requirement_context["requirements"],
                "acceptanceCriteria": requirement_context["acceptanceCriteria"],
                "clarificationRefs": requirement_context["clarificationRefs"],
            },
        )
        plan_result = self.plan_service.create_plan(plan_payload, context)
        plan = self.db.get(TestPlan, UUID(str(plan_result["id"])))
        if plan is None:
            raise ValueError("created test plan not found")
        plan.requirement_version_id = requirement_version_id
        if isinstance(requirement_context.get("requirementScope"), dict):
            plan.requirement_scope = dict(requirement_context["requirementScope"])
        job = self.plan_service.prepare_generate_plan_job(plan.id)
        self.db.commit()
        job_result = self.plan_service.run_generate_plan_job(job.id, plan.id, context)
        return {"planId": str(plan.id), "jobId": str(job.id), "jobStatus": job_result["status"]}

    def _run_execution_stage(
        self,
        plan_id: UUID,
        context: ServiceContext,
        *,
        environment: str = "staging",
        execution_plan_id: UUID | None = None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        payload = SimpleNamespace(
            planId=plan_id,
            executionPlanId=execution_plan_id,
            environment=environment,
            options=SimpleNamespace(
                model_dump=lambda mode="json": {
                    "runFunctional": True,
                    "runPerformance": True,
                    "runSecurity": True,
                    "enableTriage": True,
                    "enableHealing": False,
                    "parallelism": 5,
                }
            ),
        )
        execution, job = self.execution_service.prepare_execution_job(payload, context)
        self.db.commit()
        job_result = self.execution_service.run_execution_job(
            job.id,
            execution.id,
            context,
            defer_normalize=True,
        )
        envelope = self.execution_service.build_orchestration_envelope(
            execution.id,
            context,
            stage=ExecutionStage.OBSERVE.value,
        )
        return {"executionId": str(execution.id), "jobId": str(job.id), **job_result}, envelope

    def _run_normalize_stage(
        self,
        execution_id: UUID,
        context: ServiceContext,
        current_envelope: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        result = self.execution_service.normalize_execution(execution_id, context)
        envelope = self.execution_service.build_orchestration_envelope(
            execution_id,
            context,
            stage=ExecutionStage.NORMALIZE.value,
            policy_snapshot=current_envelope.get("policySnapshot"),
            memory_snapshot=current_envelope.get("memorySnapshot"),
        )
        return result, envelope

    def _run_triage_stage(
        self,
        execution_id: UUID,
        context: ServiceContext,
        current_envelope: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        job = self.analysis_service.prepare_triage_job(execution_id)
        self.db.commit()
        job_result = self.analysis_service.run_triage_job(job.id, execution_id, context)
        triage = self.analysis_service.get_triage(execution_id)
        envelope = self.execution_service.build_orchestration_envelope(
            execution_id,
            context,
            stage=ExecutionStage.ANALYZE.value,
            policy_snapshot=current_envelope.get("policySnapshot"),
            memory_snapshot=current_envelope.get("memorySnapshot"),
        )
        return {
            "jobId": str(job.id),
            "jobStatus": job_result["status"],
            "resultCount": len(triage["results"]),
            "results": triage["results"],
        }, envelope

    def _run_gate_stage(
        self,
        execution_id: UUID,
        context: ServiceContext,
        current_envelope: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        job = self.execution_service.prepare_gate_job(execution_id, context)
        self.db.commit()
        self.execution_service.run_gate_job(job.id, execution_id, context)
        gate = self.db.scalar(select(GateDecision).where(GateDecision.execution_id == execution_id))
        if gate is None:
            raise ValueError("gate decision not found")
        envelope = self.execution_service.build_orchestration_envelope(
            execution_id,
            context,
            stage=ExecutionStage.GATE.value,
            policy_snapshot=current_envelope.get("policySnapshot"),
            memory_snapshot=current_envelope.get("memorySnapshot"),
        )
        return {
            "jobId": str(job.id),
            "jobStatus": JobStatus.COMPLETED.value,
            "functional": gate.functional.value,
            "performance": gate.performance.value,
            "security": gate.security.value,
            "overall": gate.overall.value,
            "reasons": gate.reasons,
        }, envelope

    def _run_memory_stage(
        self,
        execution_id: UUID,
        gate_result: dict[str, object],
        context: ServiceContext,
    ) -> dict[str, object]:
        execution = self.db.get(Execution, execution_id)
        plan = self.db.get(TestPlan, execution.plan_id) if execution else None
        namespace = plan.source_ref if plan and plan.source_ref else f"execution/{execution_id}"
        memory_payload = SimpleNamespace(
            type=MemoryType.EPISODIC,
            scope=MemoryScope.PROJECT,
            namespace=namespace,
            content=(
                f"Execution {execution_id} completed with gate={gate_result['overall']} "
                f"(functional={gate_result['functional']}, performance={gate_result['performance']}, security={gate_result['security']})."
            ),
            metadata={
                "source": "orchestrator",
                "confirmedFact": True,
                "executionId": str(execution_id),
                "gateOverall": gate_result["overall"],
                "gateReasons": gate_result["reasons"],
                "traceId": context.trace_id,
            },
        )
        result = self.memory_service.create_memory(memory_payload, context)
        return {"memoryIds": [result["id"]], "namespace": namespace}

    def _record_checkpoint(
        self,
        *,
        run_id: UUID,
        step_name: str,
        execution_stage: str | None,
        status: JobStatus,
        envelope_snapshot: dict[str, object],
        result_payload: dict[str, object],
        trace_id: UUID | None,
        execution_id: UUID | None,
        error_message: str | None = None,
    ) -> None:
        sequence_no = (self.db.scalar(select(func.max(OrchestrationCheckpoint.sequence_no)).where(OrchestrationCheckpoint.run_id == run_id)) or 0) + 1
        now = datetime.now(timezone.utc)
        self.db.add(
            OrchestrationCheckpoint(
                id=uuid4(),
                run_id=run_id,
                sequence_no=sequence_no,
                step_name=step_name,
                execution_stage=execution_stage,
                status=status,
                trace_id=trace_id,
                execution_id=execution_id,
                envelope_snapshot=envelope_snapshot,
                result_payload=result_payload,
                error_message=error_message,
                started_at=now,
                ended_at=now,
            )
        )
        self.db.flush()

    def _serialize_checkpoint(self, checkpoint: OrchestrationCheckpoint) -> dict[str, object]:
        return {
            "id": str(checkpoint.id),
            "runId": str(checkpoint.run_id),
            "sequenceNo": checkpoint.sequence_no,
            "stepName": checkpoint.step_name,
            "executionStage": checkpoint.execution_stage,
            "status": checkpoint.status.value,
            "traceId": str(checkpoint.trace_id) if checkpoint.trace_id else None,
            "executionId": str(checkpoint.execution_id) if checkpoint.execution_id else None,
            "envelope": checkpoint.envelope_snapshot,
            "result": checkpoint.result_payload,
            "errorMessage": checkpoint.error_message,
            "startedAt": checkpoint.started_at.isoformat() if checkpoint.started_at else None,
            "endedAt": checkpoint.ended_at.isoformat() if checkpoint.ended_at else None,
            "createdAt": checkpoint.created_at.isoformat(),
        }

    def _serialize_integration_event(self, event: IntegrationEvent) -> dict[str, object]:
        return {
            "id": str(event.id),
            "source": event.source,
            "eventType": event.event_type,
            "externalRef": event.external_ref,
            "status": event.status.value if hasattr(event.status, "value") else event.status,
            "pipelineId": str(event.linked_pipeline_id) if event.linked_pipeline_id else None,
            "planId": str(event.linked_plan_id) if event.linked_plan_id else None,
            "executionId": str(event.linked_execution_id) if event.linked_execution_id else None,
            "requirementVersionId": str(event.linked_requirement_version_id) if event.linked_requirement_version_id else None,
            "payload": event.payload,
            "createdAt": event.created_at.isoformat(),
            "updatedAt": event.updated_at.isoformat(),
        }

    def _payload_to_dict(self, payload) -> dict[str, object]:
        if hasattr(payload, "model_dump"):
            return payload.model_dump(mode="json")
        return {
            "repository": payload.repository,
            "pullRequestId": payload.pullRequestId,
            "branch": payload.branch,
            "commitSha": payload.commitSha,
        }

    def _build_pipeline_payload(self, payload: dict[str, object]) -> SimpleNamespace:
        canonical_payload = {
            "repository": str(payload["repository"]),
            "pullRequestId": str(payload["pullRequestId"]),
            "branch": str(payload["branch"]),
            "commitSha": str(payload["commitSha"]),
        }
        return SimpleNamespace(
            **canonical_payload,
            model_dump=lambda mode="json", data=canonical_payload: dict(data),
        )

    def _extract_retry_info(self, integration_event: IntegrationEvent | None) -> dict[str, str | None]:
        if integration_event is None:
            return {"retryOfRunId": None, "retryOfExecutionId": None}
        return {
            "retryOfRunId": self._string_or_none(integration_event.payload.get("retryOfRunId")),
            "retryOfExecutionId": self._string_or_none(integration_event.payload.get("retryOfExecutionId")),
        }

    def _envelope_stage(self, envelope_snapshot: dict[str, object]) -> str | None:
        execution_context = envelope_snapshot.get("executionContext")
        if not isinstance(execution_context, dict):
            return None
        stage = execution_context.get("stage")
        return str(stage) if stage is not None else None

    def _string_or_none(self, value: object) -> str | None:
        if value is None:
            return None
        return str(value)

    def _require_run(self, run_id: UUID) -> OrchestrationRun:
        run = self.db.get(OrchestrationRun, run_id)
        if run is None:
            raise ValueError("orchestration run not found")
        return run

    def _require_integration_event(self, event_id: UUID | None) -> IntegrationEvent:
        if event_id is None:
            raise ValueError("integration event not found")
        event = self.db.get(IntegrationEvent, event_id)
        if event is None:
            raise ValueError("integration event not found")
        return event

    def _find_integration_event_for_run(self, run_id: UUID) -> IntegrationEvent | None:
        return self.db.scalar(
            select(IntegrationEvent)
            .where(IntegrationEvent.linked_pipeline_id == run_id)
            .order_by(IntegrationEvent.created_at.desc())
        )

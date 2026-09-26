# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
from io import BytesIO
from pathlib import Path
import warnings
from uuid import UUID, uuid4

from PIL import Image, ImageOps, UnidentifiedImageError
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import (
    ArtifactType,
    ExecutionStage,
    GuardrailDecisionType,
    JobStatus,
    PlanStatus,
    RiskLevel,
    SourceType,
    TaskStatus,
    TraceabilityRelationSource,
    TraceabilityRelationStatus,
)
from agentic_qa.domain.models import (
    EvidenceRawFinding,
    Execution,
    ExecutionArtifact,
    ExploratoryBugCandidate,
    ExploratoryEvidenceRef,
    ExploratorySession,
    ExploratorySessionNote,
    Finding,
    GuardrailEvent,
    OrchestrationCheckpoint,
    OrchestrationRun,
    Project,
    ProjectEnvironment,
    RawFindingRecord,
    RawNormalizedFinding,
    TestPlan,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.artifact_storage import ArtifactStorageAdapter, artifact_storage_adapter
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.exploratory_sessions import (
    AddExploratoryEvidenceRequest,
    AddExploratoryNoteRequest,
    CreateBugCandidateRequest,
    CreateExploratorySessionRequest,
    EndExploratorySessionRequest,
    ExploratoryEvidenceRefInput,
)
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.execution_service import ExecutionService
from agentic_qa.services.exploratory_session_query_service import ExploratorySessionQueryService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeContext
from agentic_qa.services.skill_runtime import ManagedSkillRuntimeRegistry
from agentic_qa.services.skill_service import SkillService


MAX_EXPLORATORY_IMAGE_BYTES = 8 * 1024 * 1024
MAX_EXPLORATORY_IMAGE_PIXELS = 40_000_000
EXPLORATORY_IMAGE_POLICY_VERSION = "exploratory-image-upload.v1"
_IMAGE_FORMATS = {
    "PNG": ("image/png", ".png"),
    "JPEG": ("image/jpeg", ".jpg"),
    "WEBP": ("image/webp", ".webp"),
}
_IMAGE_EXTENSIONS = {
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".webp": "WEBP",
}


class ExploratorySessionService(ExploratorySessionQueryService):
    """Service-owned exploratory testing workflow.

    The session records workflow state only. Bug candidates are normalized
    through existing RawFindingRecord -> Finding boundaries.
    """

    def __init__(
        self,
        db: Session,
        runtime_registry: ManagedSkillRuntimeRegistry | None = None,
        artifact_storage: ArtifactStorageAdapter | None = None,
    ) -> None:
        super().__init__(db)
        self.skill_service = SkillService(db, runtime_registry=runtime_registry)
        self.artifact_storage = artifact_storage or artifact_storage_adapter()

    def create_session(
        self, payload: CreateExploratorySessionRequest, context: ServiceContext
    ) -> dict[str, object]:
        scope = self._authorize_project_contribution(
            payload.projectId,
            payload.environmentId,
            context,
        )
        project = scope.project
        environment = scope.environment
        if environment is None:  # pragma: no cover - resolve_project requires it above
            raise ScopeAuthorizationError("SCOPE_ENVIRONMENT_NOT_FOUND")
        session_id = uuid4()
        with traced_operation(
            self.db,
            context.trace_id,
            execution_id=None,
            root_span_name="exploratory.session.create",
            span_name="exploratory.session.create",
            service_name="exploratory-workbench",
            attributes={"projectId": str(project.id), "environmentId": str(environment.id)},
        ):
            plan, execution = self._create_backing_plan_and_execution(
                session_id, project, environment, payload, context
            )
            charter_request = {
                "operation": "recommend_exploratory_charter",
                "payload": {
                    "sessionId": str(session_id),
                    "projectId": str(project.id),
                    "environmentId": str(environment.id),
                    "charter": payload.charter,
                    "scope": payload.scope,
                    "timeboxMinutes": payload.timeboxMinutes,
                },
            }
            charter_invocation = self.skill_service.invoke_extension(
                extension_point_id="PREPARE.exploratory_charter",
                source_workflow="exploratory_session.create",
                context=context,
                execution_id=execution.id,
                request=charter_request,
                scope={
                    "projectId": str(project.id),
                    "environmentId": str(environment.id),
                    "environment": str(environment.id),
                    "stage": "PREPARE",
                    "domain": "exploratory",
                },
                policy_snapshot={
                    "workflow": "exploratory_session.create",
                    "stage": "PREPARE",
                    "suggestionOnly": True,
                },
                capabilities={"execute": self._default_exploratory_charter_runtime},
            )
            charter_result = charter_invocation.runtime_result
            if not isinstance(charter_result, dict):
                raise ValueError(
                    "exploratory charter Skill runtime returned an incompatible result"
                )
            session = ExploratorySession(
                id=session_id,
                project_id=project.id,
                environment_id=environment.id,
                backing_plan_id=plan.id,
                backing_execution_id=execution.id,
                charter=payload.charter,
                scope=payload.scope,
                timebox_minutes=payload.timeboxMinutes,
                tester_id=context.user.id,
                tester_name=payload.tester,
                status="active",
                started_at=datetime.now(timezone.utc),
                trace_id=UUID(str(context.trace_id)),
                replay_refs=self._replay_refs(execution.id, session_id),
                metadata_json={
                    **payload.metadata,
                    "workflow": "exploratory_session",
                    "manualTestSimulation": False,
                    "evidenceMode": "reference_and_sanitized_image_upload",
                    "charterSkillInvocationId": str(charter_invocation.invocation_id),
                    "charterRecommendation": dict(charter_result.get("result") or {}),
                },
                created_by=context.user.id,
                updated_by=context.user.id,
            )
            self.db.add(session)
            audit = write_audit_log(
                self.db,
                str(context.user.id),
                "exploratory_session.create",
                "exploratory_session",
                str(session.id),
                context.request_id,
                context.trace_id,
                details={
                    "projectId": str(project.id),
                    "environmentId": str(environment.id),
                    "executionId": str(execution.id),
                    "timeboxMinutes": payload.timeboxMinutes,
                },
                execution_id=execution.id,
            )
            workflow_run = self._create_workflow_run_for_session(
                session, plan, execution, context, audit_id=audit.id
            )
            session.metadata_json = {**session.metadata_json, "workflowRunId": str(workflow_run.id)}
            session.replay_refs = [
                *session.replay_refs,
                {"type": "audit", "id": str(audit.id)},
                {"type": "workflow_run", "id": str(workflow_run.id)},
                {"type": "skill_invocation", "id": str(charter_invocation.invocation_id)},
            ]
        self.db.commit()
        self.db.refresh(session)
        return self.serialize_session(session, include_detail=True)

    def add_note(
        self, session_id: UUID, payload: AddExploratoryNoteRequest, context: ServiceContext
    ) -> dict[str, object]:
        session = self._require_active_session(session_id, context)
        with traced_operation(
            self.db,
            context.trace_id,
            execution_id=session.backing_execution_id,
            root_span_name="exploratory.session.note",
            span_name=f"exploratory.note.{payload.noteType}",
            service_name="exploratory-workbench",
            attributes={"sessionId": str(session.id), "noteType": payload.noteType},
        ):
            note = ExploratorySessionNote(
                id=uuid4(),
                session_id=session.id,
                note_type=payload.noteType,
                content=payload.content,
                trace_id=UUID(str(context.trace_id)),
                replay_refs=self._replay_refs(session.backing_execution_id, session.id),
                metadata_json=payload.metadata,
                created_by=context.user.id,
            )
            self.db.add(note)
            self.db.flush()
            evidence_refs = self._attach_note_evidence(session, note, payload.evidenceRefIds)
            evidence_refs.extend(
                self._create_evidence_ref(session, evidence, context, note_id=note.id)
                for evidence in payload.evidenceRefs
            )
            note.evidence_refs = [self.serialize_evidence_ref(row) for row in evidence_refs]
            assist_request = {
                "operation": "suggest_exploratory_next_steps",
                "payload": {
                    "sessionId": str(session.id),
                    "noteId": str(note.id),
                    "noteType": note.note_type,
                    "content": note.content,
                    "charter": session.charter,
                    "scope": session.scope,
                    "evidenceRefs": note.evidence_refs,
                },
            }
            assist_invocation = self.skill_service.invoke_extension(
                extension_point_id="EXECUTE.exploratory_assist",
                source_workflow="exploratory_session.note",
                context=context,
                execution_id=session.backing_execution_id,
                request=assist_request,
                scope={
                    "projectId": str(session.project_id),
                    "environmentId": str(session.environment_id),
                    "environment": str(session.environment_id),
                    "stage": "EXECUTE",
                    "domain": "exploratory",
                },
                policy_snapshot={
                    "workflow": "exploratory_session.note",
                    "stage": "EXECUTE",
                    "suggestionOnly": True,
                },
                capabilities={"execute": self._default_exploratory_assist_runtime},
            )
            assist_result = assist_invocation.runtime_result
            if not isinstance(assist_result, dict):
                raise ValueError("exploratory assist Skill runtime returned an incompatible result")
            note.metadata_json = {
                **dict(note.metadata_json or {}),
                "assistSkillInvocationId": str(assist_invocation.invocation_id),
                "assistSuggestion": dict(assist_result.get("result") or {}),
            }
            audit = write_audit_log(
                self.db,
                str(context.user.id),
                "exploratory_session.note.create",
                "exploratory_session",
                str(session.id),
                context.request_id,
                context.trace_id,
                details={"noteId": str(note.id), "noteType": note.note_type},
                execution_id=session.backing_execution_id,
            )
            note.replay_refs = [
                *note.replay_refs,
                {"type": "audit", "id": str(audit.id)},
                {"type": "skill_invocation", "id": str(assist_invocation.invocation_id)},
            ]
        self.db.commit()
        self.db.refresh(note)
        return self.serialize_note(note)

    def add_evidence(
        self, session_id: UUID, payload: AddExploratoryEvidenceRequest, context: ServiceContext
    ) -> dict[str, object]:
        session = self._require_active_session(session_id, context)
        with traced_operation(
            self.db,
            context.trace_id,
            execution_id=session.backing_execution_id,
            root_span_name="exploratory.session.evidence",
            span_name="exploratory.evidence.add",
            service_name="exploratory-workbench",
            attributes={"sessionId": str(session.id), "evidenceType": payload.evidenceType},
        ):
            evidence = self._create_evidence_ref(session, payload, context)
        self.db.commit()
        self.db.refresh(evidence)
        return self.serialize_evidence_ref(evidence)

    def upload_evidence_image(
        self,
        session_id: UUID,
        *,
        filename: str,
        content_type: str | None,
        payload: bytes,
        summary: str | None,
        confirm_safe: bool,
        context: ServiceContext,
    ) -> dict[str, object]:
        session = self._require_active_session(session_id, context)
        if not confirm_safe:
            raise ValueError("EXPLORATORY_IMAGE_CONFIRMATION_REQUIRED")
        normalized, mime_type, extension, width, height = self._normalize_image(
            filename=filename,
            content_type=content_type,
            payload=payload,
        )
        artifact_id = uuid4()
        evidence_id = uuid4()
        safe_filename = self._safe_image_filename(filename, extension)
        logical_ref = f"exploratory://sessions/{session.id}/evidence/{evidence_id}"
        storage_ref: str | None = None
        try:
            with traced_operation(
                self.db,
                context.trace_id,
                execution_id=session.backing_execution_id,
                root_span_name="exploratory.session.evidence_upload",
                span_name="exploratory.evidence.image_upload",
                service_name="exploratory-workbench",
                attributes={
                    "sessionId": str(session.id),
                    "mimeType": mime_type,
                    "byteSize": len(normalized),
                },
            ):
                stored = self.artifact_storage.write_artifact(
                    namespace=f"exploratory-{session.project_id}-{session.id}",
                    artifact_id=str(artifact_id),
                    filename=safe_filename,
                    payload=normalized,
                )
                storage_ref = str(stored["storageRef"])
                artifact = ExecutionArtifact(
                    id=artifact_id,
                    execution_id=session.backing_execution_id,
                    task_id=None,
                    artifact_type=ArtifactType.SCREENSHOT,
                    uri=storage_ref,
                    summary=summary,
                    redaction_status="redacted",
                    redacted_uri=logical_ref,
                    metadata_json={
                        "sourceWorkflow": "exploratory_session",
                        "sessionId": str(session.id),
                        "uploaded": True,
                        "uploadPolicyVersion": EXPLORATORY_IMAGE_POLICY_VERSION,
                        "contentHash": stored["contentHash"],
                        "byteSize": stored["byteSize"],
                        "mimeType": mime_type,
                        "width": width,
                        "height": height,
                        "displayFilename": safe_filename,
                        "metadataStripped": True,
                        "visualSafetyConfirmed": True,
                    },
                )
                self.db.add(artifact)
                self.db.flush()
                evidence = ExploratoryEvidenceRef(
                    id=evidence_id,
                    session_id=session.id,
                    artifact_id=artifact.id,
                    evidence_type="screenshot",
                    ref=logical_ref,
                    summary=summary,
                    redaction_status="redacted",
                    trace_id=UUID(str(context.trace_id)),
                    metadata_json={
                        "artifactType": ArtifactType.SCREENSHOT.value,
                        "uploaded": True,
                        "uploadSupported": True,
                        "uploadPolicyVersion": EXPLORATORY_IMAGE_POLICY_VERSION,
                        "contentHash": stored["contentHash"],
                        "byteSize": stored["byteSize"],
                        "mimeType": mime_type,
                        "width": width,
                        "height": height,
                        "displayFilename": safe_filename,
                        "metadataStripped": True,
                        "visualSafetyConfirmed": True,
                        "redactionGuardrail": "exploratory.evidence_image_upload",
                    },
                    created_by=context.user.id,
                )
                self.db.add(evidence)
                self._record_evidence_guardrail(session, evidence, context)
                audit = write_audit_log(
                    self.db,
                    str(context.user.id),
                    "exploratory_session.evidence_image.upload",
                    "exploratory_evidence_ref",
                    str(evidence.id),
                    context.request_id,
                    context.trace_id,
                    details={
                        "sessionId": str(session.id),
                        "artifactId": str(artifact.id),
                        "mimeType": mime_type,
                        "byteSize": len(normalized),
                        "uploadPolicyVersion": EXPLORATORY_IMAGE_POLICY_VERSION,
                    },
                    execution_id=session.backing_execution_id,
                )
                evidence.metadata_json = {
                    **evidence.metadata_json,
                    "auditRefs": [{"type": "audit", "id": str(audit.id)}],
                }
            self.db.commit()
            self.db.refresh(evidence)
            return self.serialize_evidence_ref(evidence)
        except Exception:
            self.db.rollback()
            if storage_ref is not None:
                try:
                    self.artifact_storage.delete_artifact(storage_ref)
                except Exception:
                    pass
            raise

    def read_evidence_image(
        self,
        session_id: UUID,
        evidence_id: UUID,
        context: ServiceContext,
    ) -> tuple[bytes, str, str]:
        session = self._require_session(session_id)
        self._authorize_session(session, context)
        evidence = self.db.scalar(
            select(ExploratoryEvidenceRef).where(
                ExploratoryEvidenceRef.id == evidence_id,
                ExploratoryEvidenceRef.session_id == session.id,
            )
        )
        if evidence is None or evidence.artifact_id is None:
            raise ValueError("exploratory evidence content not found")
        artifact = self.db.get(ExecutionArtifact, evidence.artifact_id)
        if (
            artifact is None
            or artifact.execution_id != session.backing_execution_id
            or artifact.artifact_type != ArtifactType.SCREENSHOT
            or not bool(artifact.metadata_json.get("uploaded"))
            or artifact.metadata_json.get("sourceWorkflow") != "exploratory_session"
            or artifact.metadata_json.get("sessionId") != str(session.id)
        ):
            raise ValueError("exploratory evidence content not found")
        try:
            content = self.artifact_storage.read_artifact(artifact.uri)
        except (FileNotFoundError, ValueError) as exc:
            raise ValueError("exploratory evidence content not found") from exc
        expected_hash = str(artifact.metadata_json.get("contentHash") or "")
        actual_hash = "sha256:" + hashlib.sha256(content).hexdigest()
        if (
            not content
            or len(content) > MAX_EXPLORATORY_IMAGE_BYTES
            or not expected_hash
            or actual_hash != expected_hash
        ):
            raise ValueError("exploratory evidence content not found")
        mime_type = str(artifact.metadata_json.get("mimeType") or "")
        mime_extensions = {mime: extension for mime, extension in _IMAGE_FORMATS.values()}
        extension = mime_extensions.get(mime_type)
        if extension is None:
            raise ValueError("exploratory evidence content not found")
        filename = self._safe_image_filename(
            str(artifact.metadata_json.get("displayFilename") or "evidence-image"),
            extension,
        )
        return content, mime_type, filename

    def create_bug_candidate(
        self, session_id: UUID, payload: CreateBugCandidateRequest, context: ServiceContext
    ) -> dict[str, object]:
        session = self._require_active_session(session_id, context)
        if not payload.evidenceRefIds and not payload.evidenceRefs:
            raise ValueError("bug candidate requires at least one evidence ref")
        with traced_operation(
            self.db,
            context.trace_id,
            execution_id=session.backing_execution_id,
            root_span_name="exploratory.bug_candidate.create",
            span_name="exploratory.bug_candidate.normalize",
            service_name="exploratory-workbench",
            attributes={"sessionId": str(session.id), "severity": payload.severity},
        ):
            candidate = ExploratoryBugCandidate(
                id=uuid4(),
                session_id=session.id,
                title=payload.title,
                summary=payload.summary,
                severity=payload.severity,
                category=payload.category,
                confidence=Decimal(str(payload.confidence)),
                location=payload.location,
                trace_id=UUID(str(context.trace_id)),
                replay_refs=self._replay_refs(session.backing_execution_id, session.id),
                status="candidate",
                metadata_json={**payload.metadata, "sourceWorkflow": "exploratory_session"},
                created_by=context.user.id,
            )
            self.db.add(candidate)
            self.db.flush()
            evidence_rows = self._attach_candidate_evidence(session, candidate, payload, context)
            raw = self._create_raw_finding(session, candidate, evidence_rows)
            self.db.flush()
            candidate.raw_finding_id = raw.id
            self.db.flush()
            ExecutionService(self.db)._normalize_raw_findings(session.backing_execution_id)
            self.db.flush()
            self.db.refresh(raw)
            if raw.normalized_finding_id is None:
                raise ValueError("bug candidate normalization failed")
            candidate.normalized_finding_id = raw.normalized_finding_id
            candidate.status = "normalized"
            candidate.evidence_refs = [self.serialize_evidence_ref(row) for row in evidence_rows]
            self._create_traceability_links(
                session, raw, raw.normalized_finding_id, evidence_rows, payload.confidence, context
            )
            audit = write_audit_log(
                self.db,
                str(context.user.id),
                "exploratory_session.bug_candidate.normalize",
                "exploratory_bug_candidate",
                str(candidate.id),
                context.request_id,
                context.trace_id,
                details={
                    "sessionId": str(session.id),
                    "rawFindingId": str(raw.id),
                    "normalizedFindingId": str(raw.normalized_finding_id),
                },
                execution_id=session.backing_execution_id,
            )
            candidate.replay_refs = [*candidate.replay_refs, {"type": "audit", "id": str(audit.id)}]
            self._refresh_execution_summary(session.backing_execution_id)
        self.db.commit()
        self.db.refresh(candidate)
        return self.serialize_candidate(candidate)

    def end_session(
        self, session_id: UUID, payload: EndExploratorySessionRequest, context: ServiceContext
    ) -> dict[str, object]:
        session = self._require_active_session(session_id, context)
        with traced_operation(
            self.db,
            context.trace_id,
            execution_id=session.backing_execution_id,
            root_span_name="exploratory.session.end",
            span_name="exploratory.session.report",
            service_name="exploratory-workbench",
            attributes={"sessionId": str(session.id)},
        ):
            session.status = "completed"
            session.ended_at = datetime.now(timezone.utc)
            session.updated_by = context.user.id
            session.debrief = {
                "debrief": payload.debrief,
                "outcomeSummary": payload.outcomeSummary,
                "risks": payload.risks,
                "questions": payload.questions,
                "followUps": payload.followUps,
                "metadata": payload.metadata,
            }
            execution = self.db.get(Execution, session.backing_execution_id)
            if execution is not None:
                execution.status = TaskStatus.COMPLETED
                execution.stage = ExecutionStage.NORMALIZE
                execution.ended_at = session.ended_at
                execution.summary = {
                    **dict(execution.summary or {}),
                    "exploratory": "completed",
                    "normalizedFindingCount": self._candidate_count(session.id, normalized=True),
                }
            session.report_snapshot = self._build_report(session)
            audit = write_audit_log(
                self.db,
                str(context.user.id),
                "exploratory_session.end",
                "exploratory_session",
                str(session.id),
                context.request_id,
                context.trace_id,
                details={
                    "status": session.status,
                    "candidateCount": self._candidate_count(session.id),
                },
                execution_id=session.backing_execution_id,
            )
            session.replay_refs = [*session.replay_refs, {"type": "audit", "id": str(audit.id)}]
            self._complete_workflow_run_for_session(session, context, audit_id=audit.id)
        self.db.commit()
        self.db.refresh(session)
        return self.serialize_session(session, include_detail=True)

    def _create_backing_plan_and_execution(
        self,
        session_id: UUID,
        project: Project,
        environment: ProjectEnvironment,
        payload: CreateExploratorySessionRequest,
        context: ServiceContext,
    ) -> tuple[TestPlan, Execution]:
        plan = TestPlan(
            id=uuid4(),
            name=f"Exploratory session {session_id.hex[:8]}",
            source_type=SourceType.MANUAL,
            source_ref=f"exploratory:{session_id}",
            environment=environment.key,
            project_id=project.id,
            environment_id=environment.id,
            risk_level=RiskLevel.MEDIUM,
            status=PlanStatus.READY,
            input_payload={"charter": payload.charter, "scope": payload.scope},
            generated_plan={"workflow": "exploratory_session", "sessionId": str(session_id)},
            metadata_json={"createdFor": "exploratory_session"},
            created_by=context.user.id,
        )
        self.db.add(plan)
        self.db.flush()
        execution = Execution(
            id=uuid4(),
            plan_id=plan.id,
            status=TaskStatus.RUNNING,
            stage=ExecutionStage.OBSERVE,
            environment=environment.key,
            triggered_by=context.user.id,
            trigger_source="exploratory_session",
            options={"timeboxMinutes": payload.timeboxMinutes, "manualTestSimulation": False},
            summary={"exploratory": "active"},
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(execution)
        self.db.flush()
        return plan, execution

    def _create_workflow_run_for_session(
        self,
        session: ExploratorySession,
        plan: TestPlan,
        execution: Execution,
        context: ServiceContext,
        *,
        audit_id: UUID,
    ) -> OrchestrationRun:
        envelope = {
            "runContext": {
                "runId": str(session.id),
                "requestId": context.request_id,
                "traceId": context.trace_id,
                "triggeredBy": str(context.user.id),
                "triggerSource": "exploratory_session",
                "queueMode": "inline",
                "attempt": 1,
                "startedAt": session.started_at.isoformat(),
            },
            "executionContext": {
                "executionId": str(execution.id),
                "planId": str(plan.id),
                "environment": execution.environment,
                "stage": ExecutionStage.OBSERVE.value,
                "domains": ["functional"],
                "options": execution.options,
                "strategies": ["exploratory"],
            },
            "artifactRefs": [],
            "findingRefs": [],
            "skillInvocationRefs": [],
            "policySnapshot": {
                "guardrailPolicyIds": ["exploratory.evidence_redaction"],
                "gatePolicyVersion": "v1",
            },
            "memorySnapshot": {"memoryIds": [], "namespaces": [], "summaryRef": None},
        }
        result_payload = {
            "exploratorySessionId": str(session.id),
            "exploratory": {
                "status": session.status,
                "charter": session.charter,
                "timeboxMinutes": session.timebox_minutes,
                "sessionId": str(session.id),
            },
            "auditRefs": [{"type": "audit", "id": str(audit_id)}],
        }
        workflow_run = OrchestrationRun(
            id=uuid4(),
            source="exploratory",
            trigger_type="exploratory_session",
            status=JobStatus.RUNNING,
            current_step="EXPLORATORY",
            request_id=context.request_id,
            trace_id=UUID(str(context.trace_id)),
            linked_plan_id=plan.id,
            linked_execution_id=execution.id,
            envelope_snapshot=envelope,
            result_payload=result_payload,
            started_at=session.started_at,
        )
        self.db.add(workflow_run)
        self.db.flush()
        self.db.add(
            OrchestrationCheckpoint(
                id=uuid4(),
                run_id=workflow_run.id,
                sequence_no=1,
                step_name="EXPLORATORY",
                execution_stage=ExecutionStage.OBSERVE.value,
                status=JobStatus.RUNNING,
                trace_id=UUID(str(context.trace_id)),
                execution_id=execution.id,
                envelope_snapshot=envelope,
                result_payload=result_payload,
                started_at=session.started_at,
                ended_at=None,
            )
        )
        self.db.flush()
        return workflow_run

    def _complete_workflow_run_for_session(
        self,
        session: ExploratorySession,
        context: ServiceContext,
        *,
        audit_id: UUID,
    ) -> None:
        workflow_run_id = session.metadata_json.get("workflowRunId")
        if not workflow_run_id:
            return
        workflow_run = self.db.get(OrchestrationRun, UUID(str(workflow_run_id)))
        if workflow_run is None:
            return
        workflow_run.status = JobStatus.COMPLETED
        workflow_run.current_step = "COMPLETED"
        workflow_run.ended_at = session.ended_at
        workflow_run.result_payload = {
            **dict(workflow_run.result_payload or {}),
            "exploratory": {
                **dict(dict(workflow_run.result_payload or {}).get("exploratory") or {}),
                "status": session.status,
                "candidateCount": self._candidate_count(session.id),
                "normalizedFindingCount": self._candidate_count(session.id, normalized=True),
                "endedAt": session.ended_at.isoformat() if session.ended_at else None,
            },
            "auditRefs": [
                *list(dict(workflow_run.result_payload or {}).get("auditRefs") or []),
                {"type": "audit", "id": str(audit_id)},
            ],
        }
        sequence_no = (
            self.db.scalar(
                select(OrchestrationCheckpoint.sequence_no)
                .where(OrchestrationCheckpoint.run_id == workflow_run.id)
                .order_by(OrchestrationCheckpoint.sequence_no.desc())
            )
            or 0
        ) + 1
        self.db.add(
            OrchestrationCheckpoint(
                id=uuid4(),
                run_id=workflow_run.id,
                sequence_no=sequence_no,
                step_name="EXPLORATORY",
                execution_stage=ExecutionStage.NORMALIZE.value,
                status=JobStatus.COMPLETED,
                trace_id=UUID(str(context.trace_id)),
                execution_id=session.backing_execution_id,
                envelope_snapshot=dict(workflow_run.envelope_snapshot or {}),
                result_payload=workflow_run.result_payload,
                started_at=session.ended_at,
                ended_at=session.ended_at,
            )
        )

    def _attach_note_evidence(
        self,
        session: ExploratorySession,
        note: ExploratorySessionNote,
        evidence_ref_ids: list[UUID],
    ) -> list[ExploratoryEvidenceRef]:
        if not evidence_ref_ids:
            return []
        rows = list(
            self.db.scalars(
                select(ExploratoryEvidenceRef).where(
                    ExploratoryEvidenceRef.id.in_(evidence_ref_ids),
                    ExploratoryEvidenceRef.session_id == session.id,
                )
            )
        )
        if len(rows) != len(set(evidence_ref_ids)):
            raise ValueError("one or more evidence refs were not found for this session")
        for row in rows:
            if row.note_id is not None and row.note_id != note.id:
                raise ValueError("one or more evidence refs are already attached to another note")
            row.note_id = note.id
        return rows

    def _normalize_image(
        self,
        *,
        filename: str,
        content_type: str | None,
        payload: bytes,
    ) -> tuple[bytes, str, str, int, int]:
        if not payload:
            raise ValueError("EXPLORATORY_IMAGE_INVALID: image is empty")
        if len(payload) > MAX_EXPLORATORY_IMAGE_BYTES:
            raise ValueError("EXPLORATORY_IMAGE_TOO_LARGE")
        extension = Path(filename or "").suffix.lower()
        expected_format = _IMAGE_EXTENSIONS.get(extension)
        if expected_format is None:
            raise ValueError("EXPLORATORY_IMAGE_UNSUPPORTED: use PNG, JPEG, or WebP")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(BytesIO(payload)) as source:
                    image_format = str(source.format or "").upper()
                    if image_format not in _IMAGE_FORMATS:
                        raise ValueError("EXPLORATORY_IMAGE_UNSUPPORTED: use PNG, JPEG, or WebP")
                    if image_format != expected_format:
                        raise ValueError(
                            "EXPLORATORY_IMAGE_INVALID: extension does not match image content"
                        )
                    if int(getattr(source, "n_frames", 1)) != 1:
                        raise ValueError(
                            "EXPLORATORY_IMAGE_UNSUPPORTED: animated images are not allowed"
                        )
                    width, height = source.size
                    if width <= 0 or height <= 0 or width * height > MAX_EXPLORATORY_IMAGE_PIXELS:
                        raise ValueError(
                            "EXPLORATORY_IMAGE_TOO_LARGE: image dimensions exceed policy"
                        )
                    source.load()
                    normalized_image = ImageOps.exif_transpose(source)
                    target_mode = (
                        "RGBA"
                        if "A" in normalized_image.getbands() and image_format != "JPEG"
                        else "RGB"
                    )
                    if normalized_image.mode != target_mode:
                        normalized_image = normalized_image.convert(target_mode)
                    output = BytesIO()
                    save_options: dict[str, object] = {"format": image_format}
                    if image_format == "PNG":
                        save_options["optimize"] = True
                    elif image_format in {"JPEG", "WEBP"}:
                        save_options["quality"] = 90
                    normalized_image.save(output, **save_options)
                    normalized = output.getvalue()
        except ValueError:
            raise
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            raise ValueError("EXPLORATORY_IMAGE_TOO_LARGE: image dimensions exceed policy") from exc
        except (UnidentifiedImageError, OSError) as exc:
            raise ValueError("EXPLORATORY_IMAGE_INVALID: image could not be decoded") from exc
        if len(normalized) > MAX_EXPLORATORY_IMAGE_BYTES:
            raise ValueError("EXPLORATORY_IMAGE_TOO_LARGE: normalized image exceeds policy")
        mime_type, canonical_extension = _IMAGE_FORMATS[image_format]
        supplied_mime = (content_type or "").split(";", 1)[0].strip().lower()
        if supplied_mime not in {"", "application/octet-stream", mime_type}:
            raise ValueError("EXPLORATORY_IMAGE_INVALID: mimeType does not match image content")
        return normalized, mime_type, canonical_extension, width, height

    @staticmethod
    def _safe_image_filename(filename: str, extension: str) -> str:
        stem = Path(filename or "screenshot").stem
        safe_stem = "".join(
            character if character.isalnum() or character in {"-", "_"} else "_"
            for character in stem
        )
        safe_stem = safe_stem.strip("._")[:80] or "screenshot"
        return f"{safe_stem}{extension}"

    def _create_evidence_ref(
        self,
        session: ExploratorySession,
        payload: ExploratoryEvidenceRefInput,
        context: ServiceContext,
        *,
        note_id: UUID | None = None,
        candidate_id: UUID | None = None,
    ) -> ExploratoryEvidenceRef:
        redaction_status = payload.redactionStatus or self._default_redaction_status(
            payload.evidenceType
        )
        artifact = ExecutionArtifact(
            id=uuid4(),
            execution_id=session.backing_execution_id,
            task_id=None,
            artifact_type=self._artifact_type(payload.evidenceType),
            uri=payload.ref,
            summary=payload.summary,
            redaction_status=redaction_status,
            redacted_uri=payload.ref if redaction_status == "redacted" else None,
            metadata_json={
                **payload.metadata,
                "sourceWorkflow": "exploratory_session",
                "sessionId": str(session.id),
                "referenceOnly": True,
                "uploadSupported": False,
            },
        )
        self.db.add(artifact)
        self.db.flush()
        evidence = ExploratoryEvidenceRef(
            id=uuid4(),
            session_id=session.id,
            note_id=note_id,
            candidate_id=candidate_id,
            artifact_id=artifact.id,
            evidence_type=payload.evidenceType,
            ref=payload.ref,
            summary=payload.summary,
            redaction_status=redaction_status,
            trace_id=UUID(str(context.trace_id)),
            metadata_json={
                **payload.metadata,
                "artifactType": artifact.artifact_type.value,
                "referenceOnly": True,
                "redactionGuardrail": "exploratory.evidence_redaction",
            },
            created_by=context.user.id,
        )
        self.db.add(evidence)
        self._record_evidence_guardrail(session, evidence, context)
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            "exploratory_session.evidence_ref.create",
            "exploratory_evidence_ref",
            str(evidence.id),
            context.request_id,
            context.trace_id,
            details={
                "sessionId": str(session.id),
                "artifactId": str(artifact.id),
                "redactionStatus": redaction_status,
            },
            execution_id=session.backing_execution_id,
        )
        evidence.metadata_json = {
            **evidence.metadata_json,
            "auditRefs": [{"type": "audit", "id": str(audit.id)}],
        }
        self.db.flush()
        return evidence

    def _attach_candidate_evidence(
        self,
        session: ExploratorySession,
        candidate: ExploratoryBugCandidate,
        payload: CreateBugCandidateRequest,
        context: ServiceContext,
    ) -> list[ExploratoryEvidenceRef]:
        evidence_rows: list[ExploratoryEvidenceRef] = []
        if payload.evidenceRefIds:
            rows = list(
                self.db.scalars(
                    select(ExploratoryEvidenceRef).where(
                        ExploratoryEvidenceRef.id.in_(payload.evidenceRefIds),
                        ExploratoryEvidenceRef.session_id == session.id,
                    )
                )
            )
            if len(rows) != len(set(payload.evidenceRefIds)):
                raise ValueError("one or more evidence refs were not found for this session")
            for row in rows:
                if row.candidate_id is not None and row.candidate_id != candidate.id:
                    raise ValueError(
                        "one or more evidence refs are already attached to another bug candidate"
                    )
                row.candidate_id = candidate.id
            evidence_rows.extend(rows)
        for evidence_input in payload.evidenceRefs:
            evidence_rows.append(
                self._create_evidence_ref(
                    session, evidence_input, context, candidate_id=candidate.id
                )
            )
        self.db.flush()
        return evidence_rows

    def _create_raw_finding(
        self,
        session: ExploratorySession,
        candidate: ExploratoryBugCandidate,
        evidence_rows: list[ExploratoryEvidenceRef],
    ) -> RawFindingRecord:
        artifact_ids_by_uri: dict[str, str] = {}
        evidence_payload: list[dict[str, object]] = []
        for row in evidence_rows:
            if row.artifact_id:
                artifact_ids_by_uri[row.ref] = str(row.artifact_id)
            evidence_payload.append(
                {
                    "type": "artifact_ref",
                    "ref": row.ref,
                    "artifactId": str(row.artifact_id) if row.artifact_id else None,
                    "evidenceRefId": str(row.id),
                    "redactionStatus": row.redaction_status,
                }
            )
        raw = RawFindingRecord(
            id=uuid4(),
            execution_id=session.backing_execution_id,
            task_id=None,
            source="manual",
            category=candidate.category,
            severity=candidate.severity,
            title=candidate.title,
            summary=candidate.summary,
            confidence=candidate.confidence,
            dedupe_key=f"exploratory:{session.id}:{candidate.id}",
            raw_ref=f"exploratory://sessions/{session.id}/candidates/{candidate.id}",
            location=candidate.location,
            evidence=evidence_payload,
            metadata_json={
                "sourceWorkflow": "exploratory_session",
                "sessionId": str(session.id),
                "candidateId": str(candidate.id),
                "projectId": str(session.project_id),
                "environmentId": str(session.environment_id),
                "artifactIdsByUri": artifact_ids_by_uri,
            },
        )
        self.db.add(raw)
        return raw

    def _create_traceability_links(
        self,
        session: ExploratorySession,
        raw: RawFindingRecord,
        finding_id: UUID,
        evidence_rows: list[ExploratoryEvidenceRef],
        confidence: float,
        context: ServiceContext,
    ) -> None:
        for evidence in evidence_rows:
            if evidence.artifact_id is None:
                continue
            existing = self.db.scalar(
                select(EvidenceRawFinding).where(
                    EvidenceRawFinding.evidence_artifact_id == evidence.artifact_id,
                    EvidenceRawFinding.raw_finding_id == raw.id,
                    EvidenceRawFinding.scope_id == str(session.id),
                )
            )
            if existing is None:
                self.db.add(
                    EvidenceRawFinding(
                        evidence_artifact_id=evidence.artifact_id,
                        raw_finding_id=raw.id,
                        relation_type="supports",
                        scope_id=str(session.id),
                        status=TraceabilityRelationStatus.SYSTEM_VERIFIED,
                        source=TraceabilityRelationSource.MANUAL,
                        confidence=Decimal(str(confidence)),
                        created_by=context.user.id,
                        validated_at=datetime.now(timezone.utc),
                        validated_by=context.user.id,
                        trace_id=UUID(str(context.trace_id)),
                        metadata_json={
                            "sourceWorkflow": "exploratory_session",
                            "sessionId": str(session.id),
                        },
                    )
                )
        existing_normalized = self.db.scalar(
            select(RawNormalizedFinding).where(
                RawNormalizedFinding.raw_finding_id == raw.id,
                RawNormalizedFinding.normalized_finding_id == finding_id,
                RawNormalizedFinding.scope_id == str(session.id),
            )
        )
        if existing_normalized is None:
            self.db.add(
                RawNormalizedFinding(
                    raw_finding_id=raw.id,
                    normalized_finding_id=finding_id,
                    normalization_method="exploratory_candidate_normalize",
                    dedupe_key=raw.dedupe_key,
                    relation_type="normalizes",
                    scope_id=str(session.id),
                    status=TraceabilityRelationStatus.SYSTEM_VERIFIED,
                    source=TraceabilityRelationSource.DETERMINISTIC_RULE,
                    confidence=Decimal("1.0000"),
                    created_by=context.user.id,
                    validated_at=datetime.now(timezone.utc),
                    validated_by=context.user.id,
                    trace_id=UUID(str(context.trace_id)),
                    metadata_json={
                        "sourceWorkflow": "exploratory_session",
                        "sessionId": str(session.id),
                    },
                )
            )

    def _record_evidence_guardrail(
        self, session: ExploratorySession, evidence: ExploratoryEvidenceRef, context: ServiceContext
    ) -> None:
        uploaded_image = bool(evidence.metadata_json.get("uploaded"))
        decision = (
            GuardrailDecisionType.WARN
            if evidence.redaction_status == "pending"
            else GuardrailDecisionType.ALLOW
        )
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                rule_id=(
                    "exploratory.evidence_image_upload"
                    if uploaded_image
                    else "exploratory.evidence_redaction"
                ),
                decision=decision,
                execution_id=session.backing_execution_id,
                trace_id=UUID(str(context.trace_id)),
                request_id=context.request_id,
                severity="medium" if decision == GuardrailDecisionType.WARN else "info",
                message=(
                    "exploratory image evidence sanitization state recorded"
                    if uploaded_image
                    else "exploratory evidence reference redaction state recorded"
                ),
                evidence=[{"type": "exploratory_evidence_ref", "ref": str(evidence.id)}],
                payload={
                    "resourceType": "exploratory_evidence_ref",
                    "resourceId": str(evidence.id),
                    "sessionId": str(session.id),
                    "redactionStatus": evidence.redaction_status,
                    "referenceOnly": not uploaded_image,
                    "uploadedImage": uploaded_image,
                    "uploadPolicyVersion": evidence.metadata_json.get("uploadPolicyVersion"),
                },
                metadata_json={"evidenceType": evidence.evidence_type},
            )
        )

    def _refresh_execution_summary(self, execution_id: UUID) -> None:
        execution = self.db.get(Execution, execution_id)
        if execution is None:
            return
        rows = list(self.db.scalars(select(Finding).where(Finding.execution_id == execution_id)))
        execution.summary = {
            **dict(execution.summary or {}),
            "exploratory": "active",
            "normalizedFindingCount": len(rows),
        }

    def _default_exploratory_charter_runtime(
        self,
        runtime_context,
        request: dict[str, object],
    ) -> dict[str, object]:
        raw_payload = request.get("payload")
        payload = dict(raw_payload) if isinstance(raw_payload, dict) else {}
        scope = [item for item in list(payload.get("scope") or []) if isinstance(item, dict)]
        focus_areas = [
            str(item.get("name") or item.get("title") or item.get("type") or "scoped-area")
            for item in scope[:10]
        ]
        if not focus_areas:
            focus_areas = ["primary user journey", "boundary behavior", "observable risks"]
        return self._projection_skill_result(
            result={
                "recommendedCharter": str(payload.get("charter") or ""),
                "focusAreas": focus_areas,
                "timeboxMinutes": int(payload.get("timeboxMinutes") or 0),
                "suggestionOnly": True,
            },
            confidence=0.8,
            evidence=[
                {"type": "exploratory_scope", "ref": str(payload.get("sessionId") or "pending")}
            ],
            metadata={
                "runtime": "managed-skill-runtime",
                "skillInvocationId": str(runtime_context.skill_invocation_id),
                "resolvedSkillId": runtime_context.skill_id,
            },
        )

    def _default_exploratory_assist_runtime(
        self,
        runtime_context,
        request: dict[str, object],
    ) -> dict[str, object]:
        raw_payload = request.get("payload")
        payload = dict(raw_payload) if isinstance(raw_payload, dict) else {}
        note_type = str(payload.get("noteType") or "note")
        suggestions = {
            "risk": ["capture corroborating evidence", "probe the nearest failure boundary"],
            "question": [
                "turn the question into a falsifiable observation",
                "record the answer as evidence",
            ],
            "observation": [
                "repeat with one controlled variable changed",
                "check adjacent user journeys",
            ],
        }.get(
            note_type,
            [
                "continue the charter with a new input partition",
                "record evidence before changing context",
            ],
        )
        return self._projection_skill_result(
            result={
                "nextStepSuggestions": suggestions,
                "basedOnNoteId": str(payload.get("noteId") or ""),
                "suggestionOnly": True,
            },
            confidence=0.75,
            evidence=[{"type": "exploratory_note", "ref": str(payload.get("noteId") or "")}],
            metadata={
                "runtime": "managed-skill-runtime",
                "skillInvocationId": str(runtime_context.skill_invocation_id),
                "resolvedSkillId": runtime_context.skill_id,
            },
        )

    @staticmethod
    def _projection_skill_result(
        *,
        result: dict[str, object],
        confidence: float,
        evidence: list[dict[str, object]],
        metadata: dict[str, object],
    ) -> dict[str, object]:
        return {
            "result": result,
            "confidence": confidence,
            "evidence": evidence,
            "artifactRefs": [],
            "rawFindingRefs": [],
            "findingCandidates": [],
            "metadata": metadata,
        }

    def _artifact_type(self, evidence_type: str) -> ArtifactType:
        mapping = {
            "screenshot": ArtifactType.SCREENSHOT,
            "log": ArtifactType.LOG,
            "console": ArtifactType.CONSOLE,
            "network": ArtifactType.NETWORK,
            "har": ArtifactType.HAR,
            "execution_artifact": ArtifactType.OTHER,
            "link": ArtifactType.OTHER,
            "other": ArtifactType.OTHER,
        }
        return mapping.get(evidence_type, ArtifactType.OTHER)

    def _default_redaction_status(self, evidence_type: str) -> str:
        if evidence_type in {"screenshot", "log", "console", "network", "har"}:
            return "redacted"
        return "not_required"

    def _authorize_project_contribution(
        self,
        project_id: UUID,
        environment_id: UUID,
        context: ServiceContext,
    ) -> ScopeContext:
        scope = self.scope_authorization.resolve_project(
            project_id,
            context,
            environment_id=environment_id,
        )
        if scope.membership_role not in {None, "owner", "admin", "member"}:
            raise ScopeAuthorizationError(
                "SCOPE_PROJECT_WRITE_FORBIDDEN",
                status_code=403,
                field="projectId",
            )
        return scope

    def _authorize_session_contribution(
        self,
        session: ExploratorySession,
        context: ServiceContext,
    ) -> None:
        scope = self._authorize_project_contribution(
            session.project_id,
            session.environment_id,
            context,
        )
        if scope.membership_role == "member" and session.tester_id != context.user.id:
            raise ScopeAuthorizationError(
                "SCOPE_EXPLORATORY_SESSION_WRITE_FORBIDDEN",
                status_code=403,
                field="sessionId",
            )

    def _require_active_session(
        self, session_id: UUID, context: ServiceContext
    ) -> ExploratorySession:
        session = self._require_session(session_id)
        self._authorize_session_contribution(session, context)
        if session.status != "active":
            raise ValueError("exploratory session is not active")
        return session

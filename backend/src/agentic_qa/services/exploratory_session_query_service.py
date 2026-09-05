# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    ExternalIssueLink,
    ExploratoryBugCandidate,
    ExploratoryEvidenceRef,
    ExploratorySession,
    ExploratorySessionNote,
    Finding,
    Project,
    ProjectEnvironment,
)
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.services.common import ServiceContext, paginate_query, paginate_result
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


class ExploratorySessionQueryService:
    """Project-scoped, read-only exploratory-session projection for OSS."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.scope_authorization = ScopeAuthorizationService(db)

    def list_sessions(
        self,
        page: int,
        page_size: int,
        *,
        context: ServiceContext,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
        status: str | None = None,
    ) -> dict[str, object]:
        statement = select(ExploratorySession).order_by(ExploratorySession.created_at.desc())
        if project_id is not None:
            self.scope_authorization.resolve_project(
                project_id,
                context,
                environment_id=environment_id,
            )
            statement = statement.where(ExploratorySession.project_id == project_id)
        elif environment_id is not None:
            environment = self.db.get(ProjectEnvironment, environment_id)
            if environment is None:
                raise ScopeAuthorizationError("SCOPE_ENVIRONMENT_NOT_FOUND")
            self.scope_authorization.resolve_project(
                environment.project_id,
                context,
                environment_id=environment_id,
            )
            statement = statement.where(ExploratorySession.project_id == environment.project_id)
        else:
            project_ids = self.scope_authorization.authorized_project_ids(context)
            if not project_ids:
                return paginate_result([], 0, page, page_size)
            statement = statement.where(ExploratorySession.project_id.in_(project_ids))
        if environment_id is not None:
            statement = statement.where(ExploratorySession.environment_id == environment_id)
        if status:
            statement = statement.where(ExploratorySession.status == status)
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result(
            [self.serialize_session(row, include_detail=False) for row in rows],
            total,
            page,
            page_size,
        )

    def get_session(self, session_id: UUID, context: ServiceContext) -> dict[str, object]:
        session = self._require_session(session_id)
        self._authorize_session(session, context)
        return self.serialize_session(session, include_detail=True)

    def get_report(self, session_id: UUID, context: ServiceContext) -> dict[str, object]:
        session = self._require_session(session_id)
        self._authorize_session(session, context)
        if session.report_snapshot:
            return session.report_snapshot
        return self._build_report(session)

    def serialize_session(self, session: ExploratorySession, *, include_detail: bool) -> dict[str, object]:
        project = self.db.get(Project, session.project_id)
        environment = self.db.get(ProjectEnvironment, session.environment_id)
        payload: dict[str, object] = {
            "id": str(session.id),
            "projectId": str(session.project_id),
            "projectName": project.name if project else None,
            "environmentId": str(session.environment_id),
            "environmentName": environment.name if environment else None,
            "backingPlanId": str(session.backing_plan_id),
            "backingExecutionId": str(session.backing_execution_id),
            "charter": session.charter,
            "scope": session.scope,
            "timeboxMinutes": session.timebox_minutes,
            "testerId": str(session.tester_id) if session.tester_id else None,
            "tester": session.tester_name,
            "status": session.status,
            "startedAt": session.started_at.isoformat(),
            "endedAt": session.ended_at.isoformat() if session.ended_at else None,
            "debrief": session.debrief,
            "traceId": str(session.trace_id) if session.trace_id else None,
            "replayRefs": session.replay_refs,
            "metadata": session.metadata_json,
            "noteCount": self._note_count(session.id),
            "evidenceCount": self._evidence_count(session.id),
            "candidateCount": self._candidate_count(session.id),
            "normalizedFindingCount": self._candidate_count(session.id, normalized=True),
            "createdAt": session.created_at.isoformat(),
            "updatedAt": session.updated_at.isoformat(),
        }
        if include_detail:
            payload.update(
                {
                    "notes": [self.serialize_note(row) for row in self._notes(session.id)],
                    "evidenceRefs": [
                        self.serialize_evidence_ref(row) for row in self._evidence_rows(session.id)
                    ],
                    "bugCandidates": [
                        self.serialize_candidate(row) for row in self._candidates(session.id)
                    ],
                    "report": session.report_snapshot or None,
                }
            )
        return payload

    @staticmethod
    def serialize_note(note: ExploratorySessionNote) -> dict[str, object]:
        return {
            "id": str(note.id),
            "sessionId": str(note.session_id),
            "noteType": note.note_type,
            "content": note.content,
            "evidenceRefs": note.evidence_refs,
            "traceId": str(note.trace_id) if note.trace_id else None,
            "replayRefs": note.replay_refs,
            "metadata": note.metadata_json,
            "createdBy": str(note.created_by) if note.created_by else None,
            "createdAt": note.created_at.isoformat(),
        }

    @staticmethod
    def serialize_evidence_ref(evidence: ExploratoryEvidenceRef) -> dict[str, object]:
        return {
            "id": str(evidence.id),
            "sessionId": str(evidence.session_id),
            "noteId": str(evidence.note_id) if evidence.note_id else None,
            "candidateId": str(evidence.candidate_id) if evidence.candidate_id else None,
            "artifactId": str(evidence.artifact_id) if evidence.artifact_id else None,
            "evidenceType": evidence.evidence_type,
            "ref": evidence.ref,
            "summary": evidence.summary,
            "redactionStatus": evidence.redaction_status,
            "traceId": str(evidence.trace_id) if evidence.trace_id else None,
            "metadata": evidence.metadata_json,
            "createdBy": str(evidence.created_by) if evidence.created_by else None,
            "createdAt": evidence.created_at.isoformat(),
        }

    def serialize_candidate(self, candidate: ExploratoryBugCandidate) -> dict[str, object]:
        finding = self.db.get(Finding, candidate.normalized_finding_id) if candidate.normalized_finding_id else None
        return {
            "id": str(candidate.id),
            "sessionId": str(candidate.session_id),
            "rawFindingId": str(candidate.raw_finding_id) if candidate.raw_finding_id else None,
            "normalizedFindingId": str(candidate.normalized_finding_id) if candidate.normalized_finding_id else None,
            "title": candidate.title,
            "summary": candidate.summary,
            "severity": candidate.severity,
            "category": candidate.category,
            "confidence": float(candidate.confidence),
            "location": candidate.location,
            "evidenceRefs": candidate.evidence_refs,
            "traceId": str(candidate.trace_id) if candidate.trace_id else None,
            "replayRefs": candidate.replay_refs,
            "status": candidate.status,
            "metadata": candidate.metadata_json,
            "finding": self._serialize_finding(finding) if finding else None,
            "createdAt": candidate.created_at.isoformat(),
            "updatedAt": candidate.updated_at.isoformat(),
        }

    def _serialize_finding(self, finding: Finding) -> dict[str, object]:
        validate_contract(
            "finding",
            {
                "id": str(finding.id),
                "source": finding.source.value,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "title": finding.title,
                "summary": finding.summary,
                "evidence": finding.evidence,
                "location": finding.location,
                "confidence": float(finding.confidence) if finding.confidence is not None else None,
                "dedupeKey": finding.dedupe_key,
                "rawRef": finding.raw_ref,
            },
        )
        link = self.db.scalar(
            select(ExternalIssueLink)
            .where(ExternalIssueLink.finding_id == finding.id)
            .order_by(ExternalIssueLink.updated_at.desc(), ExternalIssueLink.created_at.desc())
        )
        return {
            "id": str(finding.id),
            "executionId": str(finding.execution_id),
            "taskId": str(finding.task_id) if finding.task_id else None,
            "domain": finding.domain.value,
            "source": finding.source.value,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "category": finding.category.value,
            "title": finding.title,
            "summary": finding.summary,
            "description": finding.description,
            "evidenceRef": str(finding.evidence_ref) if finding.evidence_ref else None,
            "confidence": float(finding.confidence) if finding.confidence is not None else None,
            "dedupeKey": finding.dedupe_key,
            "rawRef": finding.raw_ref,
            "location": finding.location,
            "evidence": finding.evidence,
            "comment": finding.comment,
            "metadata": finding.metadata_json,
            "externalIssueLink": self._serialize_external_issue_link(link),
        }

    @staticmethod
    def _serialize_external_issue_link(link: ExternalIssueLink | None) -> dict[str, object] | None:
        if link is None:
            return None
        return {
            "id": str(link.id),
            "connectorName": link.connector_name,
            "externalIssueId": link.external_issue_id,
            "externalIssueKey": link.external_issue_key,
            "externalIssueUrl": link.external_issue_url,
            "externalStatus": link.external_status,
            "syncStatus": link.sync_status,
            "lastSyncedAt": link.last_synced_at.isoformat() if link.last_synced_at else None,
            "lastStatusSyncedAt": (
                link.last_status_synced_at.isoformat() if link.last_status_synced_at else None
            ),
            "evidenceRefs": link.evidence_refs,
            "replayRefs": link.replay_refs,
            "traceRefs": link.trace_refs,
            "auditRefs": link.audit_refs,
        }

    def _build_report(self, session: ExploratorySession) -> dict[str, object]:
        notes = [self.serialize_note(row) for row in self._notes(session.id)]
        evidence_refs = [self.serialize_evidence_ref(row) for row in self._evidence_rows(session.id)]
        candidates = [self.serialize_candidate(row) for row in self._candidates(session.id)]
        return {
            "schemaVersion": "phase8.exploratory-report.v1",
            "sessionId": str(session.id),
            "projectId": str(session.project_id),
            "environmentId": str(session.environment_id),
            "backingExecutionId": str(session.backing_execution_id),
            "charter": session.charter,
            "scope": session.scope,
            "timeboxMinutes": session.timebox_minutes,
            "tester": session.tester_name,
            "status": session.status,
            "startedAt": session.started_at.isoformat(),
            "endedAt": session.ended_at.isoformat() if session.ended_at else None,
            "debrief": session.debrief,
            "counts": {
                "notes": len(notes),
                "observations": len([item for item in notes if item["noteType"] == "observation"]),
                "risks": len([item for item in notes if item["noteType"] == "risk"]),
                "questions": len([item for item in notes if item["noteType"] == "question"]),
                "evidenceRefs": len(evidence_refs),
                "bugCandidates": len(candidates),
                "normalizedFindings": len(
                    [item for item in candidates if item["normalizedFindingId"]]
                ),
            },
            "notes": notes,
            "evidenceRefs": evidence_refs,
            "bugCandidates": candidates,
            "findingRefs": [
                {"type": "finding", "id": item["normalizedFindingId"]}
                for item in candidates
                if item["normalizedFindingId"]
            ],
            "traceRefs": [str(session.trace_id)] if session.trace_id else [],
            "replayRefs": session.replay_refs
            or self._replay_refs(session.backing_execution_id, session.id),
            "evidenceMode": "reference_only",
            "uploadsSupported": False,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }

    def _authorize_session(self, session: ExploratorySession, context: ServiceContext) -> None:
        self.scope_authorization.resolve_project(
            session.project_id,
            context,
            environment_id=session.environment_id,
        )

    def _require_session(self, session_id: UUID) -> ExploratorySession:
        session = self.db.get(ExploratorySession, session_id)
        if session is None:
            raise ValueError("exploratory session not found")
        return session

    def _notes(self, session_id: UUID) -> list[ExploratorySessionNote]:
        return list(
            self.db.scalars(
                select(ExploratorySessionNote)
                .where(ExploratorySessionNote.session_id == session_id)
                .order_by(ExploratorySessionNote.created_at.asc())
            )
        )

    def _evidence_rows(self, session_id: UUID) -> list[ExploratoryEvidenceRef]:
        return list(
            self.db.scalars(
                select(ExploratoryEvidenceRef)
                .where(ExploratoryEvidenceRef.session_id == session_id)
                .order_by(ExploratoryEvidenceRef.created_at.asc())
            )
        )

    def _candidates(self, session_id: UUID) -> list[ExploratoryBugCandidate]:
        return list(
            self.db.scalars(
                select(ExploratoryBugCandidate)
                .where(ExploratoryBugCandidate.session_id == session_id)
                .order_by(ExploratoryBugCandidate.created_at.asc())
            )
        )

    def _note_count(self, session_id: UUID) -> int:
        return len(self._notes(session_id))

    def _evidence_count(self, session_id: UUID) -> int:
        return len(self._evidence_rows(session_id))

    def _candidate_count(self, session_id: UUID, *, normalized: bool = False) -> int:
        rows = self._candidates(session_id)
        if normalized:
            rows = [row for row in rows if row.normalized_finding_id is not None]
        return len(rows)

    @staticmethod
    def _replay_refs(execution_id: UUID, session_id: UUID) -> list[dict[str, object]]:
        return [
            {"type": "execution_replay", "executionId": str(execution_id)},
            {"type": "exploratory_session", "id": str(session_id)},
        ]


__all__ = ["ExploratorySessionQueryService"]

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections import Counter
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    AdmissionRunRecord,
    ImprovementProposalRecord,
    LessonCandidateRecord,
)
from agentic_qa.schemas.governance import GovernanceAggregation, GovernanceReadiness
from agentic_qa.services.capability_service import CapabilityService
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.scope_service import ScopeAuthorizationService


MODULES: tuple[dict[str, object], ...] = (
    {"moduleId": "gate-policy", "route": "/gate-policies", "readCapability": "gate_policy.read", "governanceCapabilities": ["gate_policy.draft.write", "gate_policy.submit", "gate_policy.review", "gate_policy.lifecycle.manage", "gate_policy.simulate", "gate_policy.mode.manage", "gate_policy.activate", "gate_policy.rollback"]},
    {"moduleId": "timeline", "route": "/execution-explanations", "readCapability": "replay.read", "governanceCapabilities": []},
    {"moduleId": "evidence", "route": "/evidence-search", "readCapability": "evidence.read", "governanceCapabilities": ["evidence.query", "evidence.raw.read"]},
    {"moduleId": "ceg", "route": "/ceg", "readCapability": "graph.correction.read", "governanceCapabilities": ["graph.correction.propose", "graph.correction.validate", "graph.promotion.assess", "graph.promotion.promote", "graph.promotion.rollback"]},
    {"moduleId": "pr-context", "route": "/pr-contexts", "readCapability": "pr.read", "governanceCapabilities": ["match.review"]},
    {"moduleId": "pr-admission", "route": "/admission-runs", "readCapability": "admission.read", "governanceCapabilities": ["admission.review", "admission.retry", "admission.mode.manage", "enforce.manage", "ci.retry"]},
    {"moduleId": "lessons", "route": "/lessons", "readCapability": "lesson.read", "governanceCapabilities": ["lesson.feedback", "lesson.review", "lesson.promote"]},
    {"moduleId": "improvements", "route": "/improvement-proposals", "readCapability": "improvement.read", "governanceCapabilities": ["improvement.create", "improvement.review", "improvement.route"]},
    {"moduleId": "skill-catalog", "route": "/skill-runtime", "readCapability": "skills.catalog.read", "governanceCapabilities": ["capability_bindings.write", "capability_bindings.admin"]},
)


GRAPH_AUTONOMY_COMPONENTS = {
    "policy": True,
    "eligibility": True,
    "replay": True,
    "shadow": True,
    "killSwitch": True,
    "approval": True,
}


class GovernanceService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.scopes = ScopeAuthorizationService(db)

    def readiness(self, project_id: UUID, context: ServiceContext) -> dict[str, object]:
        scope = self.scopes.resolve_project(project_id, context)
        capabilities = set(context.user.capabilities)
        complete = all(GRAPH_AUTONOMY_COMPONENTS.values())
        configurable = complete and "graph.autonomy.configure" in capabilities
        edition, _effective, edition_projection = CapabilityService(
            self.db
        ).effective_access_projection_for_user(context.user.id, context.user.edition)
        # The request's already-resolved effective capabilities remain the
        # authorization source even when a unit-test context has no User row.
        edition_projection["edition"] = edition
        raw_effective_capabilities = edition_projection.get("effectiveCapabilities")
        effective_capabilities = (
            raw_effective_capabilities
            if isinstance(raw_effective_capabilities, list)
            else []
        )
        by_capability = {
            str(item["capability"]): item
            for item in effective_capabilities
            if isinstance(item, dict)
        }
        for capability, item in by_capability.items():
            item["granted"] = capability in capabilities

        modules: list[dict[str, object]] = []
        mutation_capabilities: set[str] = set()
        for definition in MODULES:
            read_capability = str(definition["readCapability"])
            raw_governance_capabilities = definition.get("governanceCapabilities")
            governance_capabilities = [
                str(item)
                for item in raw_governance_capabilities
            ] if isinstance(raw_governance_capabilities, list) else []
            mutation_capabilities.update(governance_capabilities)
            visible = read_capability in capabilities
            governance_available = bool(governance_capabilities) and all(
                item in capabilities for item in governance_capabilities
            )
            modules.append(
                {
                    **definition,
                    "workflowImplemented": True,
                    "visible": visible,
                    "governanceAvailable": governance_available,
                    "readOnly": visible and not governance_available,
                    "unavailableReason": None
                    if visible
                    else "CAPABILITY_NOT_GRANTED",
                }
            )

        unavailable_reasons: list[str] = []
        if not complete:
            unavailable_reasons.append("GRAPH_AUTONOMY_WORKFLOW_INCOMPLETE")
        if "graph.autonomy.configure" not in capabilities:
            unavailable_reasons.append("GRAPH_AUTONOMY_CONFIGURE_CAPABILITY_REQUIRED")
        payload = {
            "schemaVersion": "phase8.governance-readiness.v1",
            "scopeContext": scope.projection(),
            "editionProjection": edition_projection,
            "modules": modules,
            "graphAutonomy": {
                **GRAPH_AUTONOMY_COMPONENTS,
                "complete": complete,
                "configurable": configurable,
                "requiredCapability": "graph.autonomy.configure",
                "unavailableReasons": unavailable_reasons,
            },
            "basicReadOnly": not bool(capabilities.intersection(mutation_capabilities)),
            "directSkillExecution": False,
            "frontendAuthorizationBoundary": "ux_only",
            "backendAuthorizationBoundary": "service_api",
        }
        return GovernanceReadiness.model_validate(payload).model_dump(mode="json")

    def aggregation(self, project_id: UUID, context: ServiceContext) -> dict[str, object]:
        scope = self.scopes.resolve_project(project_id, context)
        projects, omitted = self.scopes.authorized_projects_in_workspace(scope, context)
        project_ids = [project.id for project in projects]
        if not project_ids:
            project_ids = [scope.project.id]

        lessons = list(
            self.db.scalars(
                select(LessonCandidateRecord).where(
                    LessonCandidateRecord.tenant_id == scope.tenant_id,
                    LessonCandidateRecord.workspace_id == scope.workspace_id,
                    LessonCandidateRecord.project_id.in_(project_ids),
                )
            )
        )
        improvements = list(
            self.db.scalars(
                select(ImprovementProposalRecord).where(
                    ImprovementProposalRecord.tenant_id == scope.tenant_id,
                    ImprovementProposalRecord.workspace_id == scope.workspace_id,
                    ImprovementProposalRecord.project_id.in_(project_ids),
                )
            )
        )
        admissions = list(
            self.db.scalars(
                select(AdmissionRunRecord).where(
                    AdmissionRunRecord.tenant_id == scope.tenant_id,
                    AdmissionRunRecord.workspace_id == scope.workspace_id,
                    AdmissionRunRecord.project_id.in_(project_ids),
                )
            )
        )
        payload = {
            "schemaVersion": "phase8.governance-aggregation.v1",
            "scopeContext": scope.projection(),
            "projectCount": len(project_ids),
            "omittedUnauthorizedProjectCount": omitted,
            "lessonTaxonomyCounts": dict(sorted(Counter(item.lesson_type for item in lessons).items())),
            "lessonStatusCounts": dict(sorted(Counter(item.status for item in lessons).items())),
            "improvementStatusCounts": dict(sorted(Counter(item.status for item in improvements).items())),
            "admissionModeCounts": dict(sorted(Counter(item.admission_mode for item in admissions).items())),
            "minimumVisibility": "aggregate_only",
            "rawEvidenceIncluded": False,
            "projectIdentifiersIncluded": False,
        }
        return GovernanceAggregation.model_validate(payload).model_dump(mode="json")

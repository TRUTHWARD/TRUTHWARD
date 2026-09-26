# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    CandidateGraphBuildRun,
    CanonicalExecutionGraph,
    CanonicalExecutionGraphVersion,
    CapabilityMappingRecord,
    ChangeSetRecord,
    CoverageProofBundleRecord,
    Execution,
    ExecutionTask,
    GraphCoverageSnapshot,
    ImpactResultRecord,
    RequirementIntakeDraft,
    RequirementIntakePreview,
    RequirementChangeSetRecord,
    RequirementVersion,
    SelectiveReplayPlanRecord,
    TestPlan,
    TraceabilitySnapshotRecord,
)
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


class CoverageReadinessError(ValueError):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.field = field


class CoverageReadinessService:
    """Explain which persisted facts exist before conditional coverage projections load.

    This service never creates Change Sets, Graphs, Impact Results, coverage facts,
    or Replay plans.  It reports server-derived counts and effective command
    availability so an empty Community page cannot be mistaken for a rendering
    failure or for missing form input.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def project_readiness(
        self,
        project_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        if "coverage.read" not in set(context.user.capabilities):
            raise CoverageReadinessError(
                "COVERAGE_READINESS_CAPABILITY_REQUIRED",
                status_code=403,
                field="coverage.read",
            )
        try:
            scope = ScopeAuthorizationService(self.db).resolve_project(project_id, context)
        except ScopeAuthorizationError as exc:
            raise CoverageReadinessError(
                "COVERAGE_READINESS_PROJECT_NOT_FOUND",
                status_code=exc.status_code,
                field=exc.field,
            ) from exc

        plan_requirement_ids = (
            select(TestPlan.requirement_version_id.label("requirement_version_id"))
            .where(
                TestPlan.project_id == project_id,
                TestPlan.requirement_version_id.is_not(None),
            )
            .distinct()
            .subquery()
        )
        plan_requirement_id_select = select(plan_requirement_ids.c.requirement_version_id)
        intake_requirement_ids = (
            select(
                RequirementIntakePreview.linked_requirement_version_id.label(
                    "requirement_version_id"
                )
            )
            .join(
                RequirementIntakeDraft,
                RequirementIntakeDraft.id == RequirementIntakePreview.draft_id,
            )
            .where(
                RequirementIntakeDraft.project_id == project_id,
                RequirementIntakePreview.linked_requirement_version_id.is_not(None),
            )
            .distinct()
            .subquery()
        )
        intake_requirement_id_select = select(intake_requirement_ids.c.requirement_version_id)
        project_requirement_versions = (
            select(RequirementVersion.id, RequirementVersion.source_ref)
            .where(
                or_(
                    RequirementVersion.id.in_(plan_requirement_id_select),
                    RequirementVersion.id.in_(intake_requirement_id_select),
                )
            )
            .distinct()
            .subquery()
        )
        project_requirement_id_select = select(project_requirement_versions.c.id)
        source_counts = Counter(
            self.db.scalars(select(project_requirement_versions.c.source_ref)).all()
        )

        counts = {
            "trackedRequirementVersions": self._count(project_requirement_id_select),
            "requirementSourcesWithHistory": sum(
                1 for count in source_counts.values() if count >= 2
            ),
            "testPlans": self._count(
                select(TestPlan.id).where(TestPlan.project_id == project_id)
            ),
            "executions": self._count(
                select(Execution.id)
                .join(TestPlan, TestPlan.id == Execution.plan_id)
                .where(TestPlan.project_id == project_id)
            ),
            "executionsWithTasks": self._count(
                select(Execution.id)
                .join(TestPlan, TestPlan.id == Execution.plan_id)
                .join(ExecutionTask, ExecutionTask.execution_id == Execution.id)
                .where(TestPlan.project_id == project_id)
                .distinct()
            ),
            "changeSets": self._scoped_count(ChangeSetRecord, scope, project_id),
            "candidateGraphBuilds": self._scoped_count(
                CandidateGraphBuildRun, scope, project_id
            ),
            "canonicalGraphs": self._scoped_count(
                CanonicalExecutionGraph, scope, project_id
            ),
            "graphVersions": self._scoped_count(
                CanonicalExecutionGraphVersion, scope, project_id
            ),
            "capabilityMappings": self._scoped_count(
                CapabilityMappingRecord, scope, project_id
            ),
            "coverageSnapshots": self._scoped_count(
                GraphCoverageSnapshot, scope, project_id
            ),
            "impactResults": self._scoped_count(ImpactResultRecord, scope, project_id),
            "selectiveReplayPlans": self._scoped_count(
                SelectiveReplayPlanRecord, scope, project_id
            ),
            "traceabilitySnapshots": self._count(
                select(TraceabilitySnapshotRecord.id).where(
                    TraceabilitySnapshotRecord.requirement_version_id.in_(
                        project_requirement_id_select
                    )
                )
            ),
            "proofBundles": self._count(
                select(CoverageProofBundleRecord.id).where(
                    CoverageProofBundleRecord.requirement_version_id.in_(
                        project_requirement_id_select
                    )
                )
            ),
        }
        freshness = self._freshness(
            scope,
            project_id,
            list(self.db.scalars(project_requirement_id_select)),
        )
        capabilities = set(context.user.capabilities)
        manual_scope_write = (
            scope.membership_role in {"owner", "admin"}
            or scope.access_source in {"platform_admin", "service_role"}
        )
        bounded_materialization = (
            "coverage.materialize" in capabilities and manual_scope_write
        )
        command_availability = {
            "analysisMaterialize": bounded_materialization,
            "candidateObserve": (
                "graph.candidate.observe" in capabilities
                and bounded_materialization
            ),
            "changeSetCreate": "change.create" in capabilities or bounded_materialization,
            "impactAnalyze": "impact.analyze" in capabilities or bounded_materialization,
            "replayPlanCreate": "replay.plan.create" in capabilities
            or bounded_materialization,
            "proofGenerate": bounded_materialization,
        }
        stages = [
            self._change_set_stage(counts, command_availability, freshness),
            self._impact_stage(counts, command_availability, freshness),
            self._replay_stage(counts, command_availability, freshness),
            self._proof_stage(counts, command_availability, freshness),
        ]
        return {
            "schemaVersion": "community.coverage-readiness.v1",
            "projectId": str(project_id),
            "serverDerived": True,
            "readOnly": True,
            "counts": counts,
            "commandAvailability": command_availability,
            "freshness": freshness,
            "stages": stages,
            "complete": all(stage["status"] == "ready" for stage in stages),
        }

    def _scoped_count(self, model: Any, scope: Any, project_id: UUID) -> int:
        return self._count(
            select(model.id).where(
                model.tenant_id == scope.tenant_id,
                model.workspace_id == scope.workspace_id,
                model.project_id == project_id,
            )
        )

    def _count(self, statement: Any) -> int:
        return int(self.db.scalar(select(func.count()).select_from(statement.subquery())) or 0)

    def _freshness(
        self,
        scope: Any,
        project_id: UUID,
        requirement_version_ids: list[UUID],
    ) -> dict[str, bool]:
        requirements = [
            item
            for item in (
                self.db.get(RequirementVersion, version_id)
                for version_id in requirement_version_ids
            )
            if item is not None
        ]
        latest_requirement = (
            max(
                requirements,
                key=lambda item: (item.created_at, item.version_no, str(item.id)),
            )
            if requirements
            else None
        )
        latest_change_set = None
        if latest_requirement is not None:
            latest_change_set = self.db.scalar(
                select(ChangeSetRecord)
                .join(
                    RequirementChangeSetRecord,
                    RequirementChangeSetRecord.change_set_id == ChangeSetRecord.id,
                )
                .where(
                    ChangeSetRecord.tenant_id == scope.tenant_id,
                    ChangeSetRecord.workspace_id == scope.workspace_id,
                    ChangeSetRecord.project_id == project_id,
                    RequirementChangeSetRecord.head_requirement_version_id
                    == latest_requirement.id,
                )
                .order_by(ChangeSetRecord.created_at.desc(), ChangeSetRecord.id.desc())
                .limit(1)
            )

        executions = list(
            self.db.scalars(
                select(Execution)
                .join(TestPlan, TestPlan.id == Execution.plan_id)
                .where(TestPlan.project_id == project_id)
                .order_by(Execution.created_at.desc(), Execution.id.desc())
            )
        )
        latest_execution = next(
            (
                execution
                for execution in executions
                if self.db.scalar(
                    select(ExecutionTask.id)
                    .where(ExecutionTask.execution_id == execution.id)
                    .limit(1)
                )
                is not None
            ),
            None,
        )
        graph_versions = list(
            self.db.scalars(
                select(CanonicalExecutionGraphVersion)
                .where(
                    CanonicalExecutionGraphVersion.tenant_id == scope.tenant_id,
                    CanonicalExecutionGraphVersion.workspace_id == scope.workspace_id,
                    CanonicalExecutionGraphVersion.project_id == project_id,
                )
                .order_by(
                    CanonicalExecutionGraphVersion.created_at.desc(),
                    CanonicalExecutionGraphVersion.id.desc(),
                )
            )
        )
        latest_graph_version = next(
            (
                version
                for version in graph_versions
                if latest_execution is not None
                and latest_requirement is not None
                and str(version.metadata_json.get("communityExecutionId") or "")
                == str(latest_execution.id)
                and str(version.metadata_json.get("requirementVersionId") or "")
                == str(latest_requirement.id)
            ),
            None,
        )
        latest_coverage = self.db.scalar(
            select(GraphCoverageSnapshot)
            .where(
                GraphCoverageSnapshot.tenant_id == scope.tenant_id,
                GraphCoverageSnapshot.workspace_id == scope.workspace_id,
                GraphCoverageSnapshot.project_id == project_id,
            )
            .order_by(
                GraphCoverageSnapshot.computed_at.desc(),
                GraphCoverageSnapshot.id.desc(),
            )
            .limit(1)
        )
        latest_impact = self.db.scalar(
            select(ImpactResultRecord)
            .where(
                ImpactResultRecord.tenant_id == scope.tenant_id,
                ImpactResultRecord.workspace_id == scope.workspace_id,
                ImpactResultRecord.project_id == project_id,
            )
            .order_by(ImpactResultRecord.created_at.desc(), ImpactResultRecord.id.desc())
            .limit(1)
        )
        latest_replay = self.db.scalar(
            select(SelectiveReplayPlanRecord)
            .where(
                SelectiveReplayPlanRecord.tenant_id == scope.tenant_id,
                SelectiveReplayPlanRecord.workspace_id == scope.workspace_id,
                SelectiveReplayPlanRecord.project_id == project_id,
            )
            .order_by(
                SelectiveReplayPlanRecord.created_at.desc(),
                SelectiveReplayPlanRecord.id.desc(),
            )
            .limit(1)
        )
        latest_proof = self.db.scalar(
            select(CoverageProofBundleRecord)
            .where(
                CoverageProofBundleRecord.requirement_version_id.in_(
                    requirement_version_ids or [UUID(int=0)]
                )
            )
            .order_by(
                CoverageProofBundleRecord.created_at.desc(),
                CoverageProofBundleRecord.id.desc(),
            )
            .limit(1)
        )
        replay_expires_at = latest_replay.expires_at if latest_replay else None
        if replay_expires_at is not None and replay_expires_at.tzinfo is None:
            replay_expires_at = replay_expires_at.replace(tzinfo=timezone.utc)
        coverage_fresh = bool(
            latest_coverage
            and latest_requirement
            and latest_execution
            and latest_graph_version
            and latest_coverage.requirement_version_id == latest_requirement.id
            and latest_coverage.execution_id == latest_execution.id
            and latest_coverage.graph_version_id == latest_graph_version.id
        )
        impact_fresh = bool(
            latest_impact
            and latest_change_set
            and latest_graph_version
            and str(latest_change_set.id) in set(latest_impact.change_set_ids)
            and latest_impact.graph_version_id == latest_graph_version.id
        )
        return {
            "changeSet": bool(latest_change_set),
            "graph": bool(latest_graph_version),
            "coverage": coverage_fresh,
            "impact": impact_fresh,
            "selectiveReplay": bool(
                latest_replay
                and impact_fresh
                and coverage_fresh
                and latest_execution
                and latest_replay.impact_result_id == latest_impact.id
                and latest_replay.coverage_snapshot_id == latest_coverage.id
                and latest_replay.base_execution_id == latest_execution.id
                and replay_expires_at is not None
                and replay_expires_at > datetime.now(timezone.utc)
            ),
            "proof": bool(
                latest_proof
                and latest_requirement
                and latest_proof.requirement_version_id == latest_requirement.id
                and coverage_fresh
            ),
        }

    @staticmethod
    def _issue(code: str, severity: str) -> dict[str, str]:
        return {"code": code, "severity": severity}

    def _change_set_stage(
        self,
        counts: dict[str, int],
        commands: dict[str, bool],
        freshness: dict[str, bool],
    ) -> dict[str, Any]:
        issues: list[dict[str, str]] = []
        if not counts["changeSets"]:
            if not counts["trackedRequirementVersions"]:
                issues.append(
                    self._issue("REQUIREMENT_VERSION_MISSING", "blocking")
                )
            if not commands["changeSetCreate"]:
                issues.append(self._issue("CHANGE_SET_GENERATION_UNAVAILABLE", "blocking"))
        elif not freshness["changeSet"]:
            issues.append(self._issue("CHANGE_SET_STALE", "blocking"))
        return self._stage(
            "change_set",
            counts["changeSets"],
            commands["changeSetCreate"],
            issues,
            "/requirement-intake",
            stale=bool(counts["changeSets"] and not freshness["changeSet"]),
        )

    def _impact_stage(
        self,
        counts: dict[str, int],
        commands: dict[str, bool],
        freshness: dict[str, bool],
    ) -> dict[str, Any]:
        issues: list[dict[str, str]] = []
        if not counts["impactResults"]:
            if not counts["changeSets"]:
                issues.append(self._issue("CHANGE_SET_MISSING", "blocking"))
            if not counts["graphVersions"]:
                issues.append(self._issue("EXECUTION_GRAPH_MISSING", "blocking"))
            if not counts["capabilityMappings"]:
                issues.append(self._issue("CAPABILITY_MAPPING_MISSING", "recommended"))
            if not commands["impactAnalyze"]:
                issues.append(self._issue("IMPACT_GENERATION_UNAVAILABLE", "blocking"))
        elif not freshness["impact"]:
            issues.append(self._issue("IMPACT_RESULT_STALE", "blocking"))
        return self._stage(
            "impact",
            counts["impactResults"],
            commands["impactAnalyze"],
            issues,
            "/impact-analysis",
            stale=bool(counts["impactResults"] and not freshness["impact"]),
        )

    def _replay_stage(
        self,
        counts: dict[str, int],
        commands: dict[str, bool],
        freshness: dict[str, bool],
    ) -> dict[str, Any]:
        issues: list[dict[str, str]] = []
        if not counts["selectiveReplayPlans"]:
            if not counts["impactResults"]:
                issues.append(self._issue("IMPACT_RESULT_MISSING", "blocking"))
            if not counts["executionsWithTasks"]:
                issues.append(self._issue("BASE_EXECUTION_MISSING", "blocking"))
            if not counts["coverageSnapshots"]:
                issues.append(self._issue("COVERAGE_SNAPSHOT_MISSING", "blocking"))
            if not commands["replayPlanCreate"]:
                issues.append(self._issue("REPLAY_GENERATION_UNAVAILABLE", "blocking"))
        elif not freshness["selectiveReplay"]:
            issues.append(self._issue("SELECTIVE_REPLAY_PLAN_STALE", "blocking"))
        return self._stage(
            "selective_replay",
            counts["selectiveReplayPlans"],
            commands["replayPlanCreate"],
            issues,
            "/selective-replay-plans",
            stale=bool(
                counts["selectiveReplayPlans"] and not freshness["selectiveReplay"]
            ),
        )

    def _proof_stage(
        self,
        counts: dict[str, int],
        commands: dict[str, bool],
        freshness: dict[str, bool],
    ) -> dict[str, Any]:
        issues: list[dict[str, str]] = []
        if not counts["proofBundles"]:
            if not counts["traceabilitySnapshots"]:
                issues.append(self._issue("TRACEABILITY_SNAPSHOT_MISSING", "blocking"))
            if not counts["coverageSnapshots"]:
                issues.append(self._issue("COVERAGE_SNAPSHOT_MISSING", "blocking"))
            if not commands["proofGenerate"]:
                issues.append(self._issue("PROOF_GENERATION_UNAVAILABLE", "blocking"))
        elif not freshness["proof"]:
            issues.append(self._issue("COVERAGE_PROOF_STALE", "blocking"))
        return self._stage(
            "proof",
            counts["proofBundles"],
            commands["proofGenerate"],
            issues,
            "/workflow",
            stale=bool(counts["proofBundles"] and not freshness["proof"]),
        )

    @staticmethod
    def _stage(
        stage_id: str,
        record_count: int,
        generation_available: bool,
        issues: list[dict[str, str]],
        next_route: str,
        *,
        stale: bool = False,
    ) -> dict[str, Any]:
        return {
            "id": stage_id,
            "status": "stale" if stale else "ready" if record_count else "blocked",
            "recordCount": record_count,
            "generationAvailable": generation_available,
            "issues": issues,
            "nextRoute": next_route,
        }


__all__ = ["CoverageReadinessError", "CoverageReadinessService"]

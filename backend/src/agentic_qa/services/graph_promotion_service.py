# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import (
    ApprovalStatus,
    ApprovalType,
    GraphSource,
    GraphStatus,
    GuardrailDecisionType,
    RiskLevel,
)
from agentic_qa.domain.models import (
    Approval,
    CandidateGraphBuildRun,
    CandidateGraphSourceMapping,
    CanonicalExecutionGraph,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
    CanonicalExecutionGraphVersion,
    CanonicalGraphPromotionRecord,
    CorrectionProposal,
    GatePolicySimulationRun,
    GraphCorrectionProposalRecord,
    GraphLearningPolicy,
    GraphLearningPolicyBinding,
    GraphLearningPolicyVersion,
    GraphPromotionEligibilityAssessment,
    GuardrailEvent,
    ProjectEnvironment,
    ReplayRepositoryEntry,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.operational_controls import operational_metrics
from agentic_qa.infra.settings import get_settings
from agentic_qa.infra.trace import ensure_trace, traced_operation
from agentic_qa.schemas.graph_promotion import (
    AssessGraphPromotionRequest,
    ConfigureGraphAutonomyRequest,
    CreateGraphCorrectionProposalRequest,
    CreateGraphLearningBindingRequest,
    CreateGraphLearningPolicyRequest,
    GraphPromotionResult,
    PauseGraphAutonomyRequest,
    PromoteGraphRequest,
    PromotionEligibilityAssessment,
    RequestGraphRollbackReviewRequest,
    RollbackGraphPromotionRequest,
    SubmitGraphPromotionReviewRequest,
    UpdateGraphCorrectionProposalRequest,
    ValidateGraphCorrectionRequest,
)
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
)
from agentic_qa.services.execution_graph_hash import (
    build_graph_topology_material,
    build_graph_version_content_hash,
)
from agentic_qa.services.execution_graph_repository import ExecutionGraphRepository
from agentic_qa.services.graph_staleness_service import GraphStalenessService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


DEFAULT_GRAPH_LEARNING_MODE = "human_supervised"
GRAPH_CORRECTION_VALIDATOR_VERSION = "graph-correction-validator.v1"
GRAPH_PROMOTION_SYSTEM_ACTOR = "system://controlled-graph-promotion"


def _controlled_autonomy_window_state(
    db: Session,
    *,
    binding: GraphLearningPolicyBinding | None,
    policy_document: dict[str, Any],
) -> dict[str, Any]:
    """Return persisted, bounded operational signals for one autonomy binding."""

    settings = get_settings()
    global_max = settings.controlled_autonomy_max_promotions_per_window
    policy_max = int(policy_document.get("maxAutoPromotionsPerWindow", global_max))
    maximum = max(1, min(global_max, policy_max))
    global_rollback_threshold = settings.controlled_autonomy_rollback_rate_threshold
    policy_rollback_threshold = float(
        policy_document.get("maxAutoPromotionRollbackRate", global_rollback_threshold)
    )
    rollback_threshold = max(0.0, min(global_rollback_threshold, policy_rollback_threshold))
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.controlled_autonomy_window_seconds
    )
    automatic_count = 0
    rollback_count = 0
    if binding is not None:
        automatic_count = int(
            db.scalar(
                select(func.count(CanonicalGraphPromotionRecord.id))
                .join(
                    GraphPromotionEligibilityAssessment,
                    GraphPromotionEligibilityAssessment.id
                    == CanonicalGraphPromotionRecord.assessment_id,
                )
                .where(
                    GraphPromotionEligibilityAssessment.binding_id == binding.id,
                    CanonicalGraphPromotionRecord.promotion_type
                    == "policy_approved_auto_promotion",
                    CanonicalGraphPromotionRecord.promoted_at >= cutoff,
                )
            )
            or 0
        )
        rollback_count = int(
            db.scalar(
                select(func.count(CanonicalGraphPromotionRecord.id))
                .join(
                    GraphPromotionEligibilityAssessment,
                    GraphPromotionEligibilityAssessment.id
                    == CanonicalGraphPromotionRecord.assessment_id,
                )
                .where(
                    GraphPromotionEligibilityAssessment.binding_id == binding.id,
                    CanonicalGraphPromotionRecord.promotion_type
                    == "human_approved_rollback",
                    CanonicalGraphPromotionRecord.promoted_at >= cutoff,
                )
            )
            or 0
        )
    rollback_rate = rollback_count / automatic_count if automatic_count else 0.0
    rate_sample_ready = (
        automatic_count
        >= settings.controlled_autonomy_minimum_promotions_for_rate_pause
    )
    return {
        "globalKillSwitch": settings.controlled_autonomy_global_kill_switch,
        "windowSeconds": settings.controlled_autonomy_window_seconds,
        "automaticPromotionCount": automatic_count,
        "maximumPromotions": maximum,
        "rollbackCount": rollback_count,
        "rollbackRate": rollback_rate,
        "rollbackRateThreshold": rollback_threshold,
        "rollbackRateSampleReady": rate_sample_ready,
        "minimumPromotionsForRatePause": (
            settings.controlled_autonomy_minimum_promotions_for_rate_pause
        ),
    }


class GraphPromotionError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


class GraphLearningPolicyResolver:
    """Deterministic environment > project resolver with a safe default."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def resolve(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        environment_id: UUID | None,
    ) -> tuple[str, GraphLearningPolicyBinding | None, GraphLearningPolicyVersion | None, str]:
        statement = select(GraphLearningPolicyBinding).where(
            GraphLearningPolicyBinding.tenant_id == tenant_id,
            GraphLearningPolicyBinding.workspace_id == workspace_id,
            GraphLearningPolicyBinding.project_id == project_id,
            GraphLearningPolicyBinding.status == "active",
        )
        bindings = list(self.db.scalars(statement))
        selected = next(
            (
                item
                for item in bindings
                if item.scope_type == "environment" and item.environment_id == environment_id
            ),
            None,
        )
        fallback_reason = "environment_binding"
        if selected is None:
            selected = next((item for item in bindings if item.scope_type == "project"), None)
            fallback_reason = "project_binding" if selected else "safe_builtin_default"
        if selected is None:
            return DEFAULT_GRAPH_LEARNING_MODE, None, None, fallback_reason
        version = self.db.get(GraphLearningPolicyVersion, selected.policy_version_id)
        if (
            version is None
            or version.tenant_id != tenant_id
            or version.workspace_id != workspace_id
            or version.project_id != project_id
            or version.status != "active"
            or version.content_hash != selected.policy_version_hash
        ):
            raise GraphPromotionError("GRAPH_LEARNING_POLICY_RESOLUTION_INVALID", status_code=409)
        return selected.learning_mode, selected, version, fallback_reason


class GraphPromotionEligibilityEvaluator:
    """Fail-closed evaluator consuming only persisted P12/Replay/Shadow facts."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def evaluate(
        self,
        *,
        proposal: GraphCorrectionProposalRecord,
        graph: CanonicalExecutionGraph,
        candidate: CanonicalExecutionGraphVersion,
        build: CandidateGraphBuildRun,
        mode: str,
        binding: GraphLearningPolicyBinding | None,
        policy: GraphLearningPolicyVersion | None,
        replay_ids: list[str],
        shadow_ids: list[UUID],
    ) -> tuple[list[dict[str, Any]], dict[str, Any], bool, bool, bool]:
        document = policy.policy_document if policy else {}
        summary = build.evidence_summary or {}
        builds = list(
            self.db.scalars(
                select(CandidateGraphBuildRun).where(
                    CandidateGraphBuildRun.tenant_id == proposal.tenant_id,
                    CandidateGraphBuildRun.workspace_id == proposal.workspace_id,
                    CandidateGraphBuildRun.graph_id == proposal.graph_id,
                    CandidateGraphBuildRun.semantic_path_hash == build.semantic_path_hash,
                    CandidateGraphBuildRun.status == "completed",
                )
            )
        )
        independent_by_source: dict[str, CandidateGraphBuildRun] = {}
        for item in sorted(builds, key=lambda row: (row.source_observed_at, row.id)):
            independent_by_source[item.source_identity_hash] = item
        independent = list(independent_by_source.values())
        derived_summary: dict[str, Any] = {
            "independentRunCount": len(independent),
            "successCount": sum(item.outcome == "success" for item in independent),
            "failureCount": sum(item.outcome == "failure" for item in independent),
            "distinctRevisionCount": len(
                {item.source_revision_hash for item in independent if item.source_revision_hash}
            ),
            "distinctEnvironmentCount": len({item.source_environment for item in independent}),
            "verificationCoverage": (
                sum(item.verified_action_count for item in independent)
                / sum(item.action_count for item in independent)
                if sum(item.action_count for item in independent)
                else 0.0
            ),
            "retryCount": sum(item.retry_count for item in independent),
            "coordinateClickCount": sum(item.coordinate_click_count for item in independent),
            "fallbackTypes": sorted(
                {value for item in independent for value in item.fallback_types}
            ),
        }
        time_windows = {
            self._aware(item.source_observed_at).date().isoformat() for item in independent
        }

        replays: list[ReplayRepositoryEntry] = []
        replay_unavailable = False
        for replay_id in replay_ids:
            replay_row = self.db.scalar(
                select(ReplayRepositoryEntry).where(ReplayRepositoryEntry.replay_id == replay_id)
            )
            if replay_row is None or str(replay_row.execution_id) not in {
                str(candidate_build.execution_id) for candidate_build in independent
            }:
                replay_unavailable = True
            else:
                replays.append(replay_row)
        shadows: list[GatePolicySimulationRun] = []
        shadow_unavailable = False
        for shadow_id in shadow_ids:
            shadow_row = self.db.get(GatePolicySimulationRun, shadow_id)
            if (
                shadow_row is None
                or shadow_row.tenant_id != proposal.tenant_id
                or shadow_row.workspace_id != proposal.workspace_id
                or shadow_row.project_id != proposal.project_id
                or shadow_row.run_type != "shadow"
            ):
                shadow_unavailable = True
            else:
                shadows.append(shadow_row)

        active_versions = list(
            self.db.scalars(
                select(CanonicalExecutionGraphVersion).where(
                    CanonicalExecutionGraphVersion.graph_id == graph.id,
                    CanonicalExecutionGraphVersion.status == GraphStatus.ACTIVE,
                    CanonicalExecutionGraphVersion.source == GraphSource.CANONICAL,
                    CanonicalExecutionGraphVersion.is_frozen.is_(True),
                )
            )
        )
        active_base = active_versions[0] if len(active_versions) == 1 else None
        max_confidence = self.db.scalar(
            select(func.min(CanonicalExecutionGraphPath.confidence)).where(
                CanonicalExecutionGraphPath.version_id == candidate.id
            )
        )
        source_mappings = list(
            self.db.scalars(
                select(CandidateGraphSourceMapping).where(
                    CandidateGraphSourceMapping.build_id.in_([item.id for item in independent])
                )
            )
        ) if independent else []
        evidence_ref_count = len(
            {
                (str(ref.get("type")), str(ref.get("ref")))
                for mapping in source_mappings
                for ref in mapping.evidence_refs
                if ref.get("ref")
            }
        )
        evidence_ref_count = max(evidence_ref_count, len(proposal.evidence_refs))
        persisted_refs_available = bool(independent) and all(
            ref.get("available") is True
            for item in independent
            for ref in item.observed_trace_snapshot.get("sourceEventRefs", [])
        )
        guardrail_block = bool(
            self.db.scalar(
                select(GuardrailEvent.id).where(
                    GuardrailEvent.trace_id.in_([item.trace_id for item in independent]),
                    GuardrailEvent.decision == GuardrailDecisionType.BLOCK,
                ).limit(1)
            )
        ) if independent else True

        checks: list[dict[str, Any]] = []

        def check(code: str, state: str, actual: Any, required: Any, refs: list[dict[str, Any]] | None = None) -> None:
            checks.append(
                {
                    "code": code,
                    "state": state,
                    "passed": state == "passed",
                    "actual": actual,
                    "required": required,
                    "evidenceRefs": refs or [],
                }
            )

        validation_valid = bool((proposal.validation_report.get("summary") or {}).get("valid"))
        check("GRAPH_ELIGIBILITY_VALIDATION_PASSED", "passed" if validation_valid else "failed", validation_valid, True)
        check("GRAPH_ELIGIBILITY_MODE_CONTROLLED_AUTONOMY", "passed" if mode == "controlled_autonomy" else "failed", mode, "controlled_autonomy")
        check("GRAPH_ELIGIBILITY_LOW_RISK", "passed" if proposal.risk_level == "low" else "failed", proposal.risk_level, "low")
        policy_ok = bool(binding and policy and not binding.autonomy_paused)
        check(
            "GRAPH_ELIGIBILITY_ACTIVE_POLICY_BINDING",
            "passed" if policy_ok else "unavailable" if binding is None else "failed",
            {"bindingActive": bool(binding), "policyActive": bool(policy), "autonomyPaused": bool(binding and binding.autonomy_paused)},
            {"active": True, "paused": False},
        )
        operational_state = _controlled_autonomy_window_state(
            self.db,
            binding=binding,
            policy_document=document,
        )
        global_enabled = not operational_state["globalKillSwitch"]
        check(
            "GRAPH_ELIGIBILITY_GLOBAL_AUTONOMY_ENABLED",
            "passed" if global_enabled else "failed",
            {"globalKillSwitch": operational_state["globalKillSwitch"]},
            {"globalKillSwitch": False},
        )
        within_quantity_limit = (
            operational_state["automaticPromotionCount"]
            < operational_state["maximumPromotions"]
        )
        check(
            "GRAPH_ELIGIBILITY_AUTONOMY_QUANTITY_LIMIT",
            "passed" if within_quantity_limit else "failed",
            {
                "windowSeconds": operational_state["windowSeconds"],
                "automaticPromotionCount": operational_state["automaticPromotionCount"],
            },
            {"maximumPromotions": operational_state["maximumPromotions"]},
        )
        rollback_rate_ok = (
            not operational_state["rollbackRateSampleReady"]
            or operational_state["rollbackRate"]
            < operational_state["rollbackRateThreshold"]
        )
        check(
            "GRAPH_ELIGIBILITY_AUTONOMY_ROLLBACK_RATE",
            "passed" if rollback_rate_ok else "failed",
            {
                "rollbackCount": operational_state["rollbackCount"],
                "automaticPromotionCount": operational_state["automaticPromotionCount"],
                "rollbackRate": operational_state["rollbackRate"],
                "sampleReady": operational_state["rollbackRateSampleReady"],
            },
            {
                "maximumRateExclusive": operational_state["rollbackRateThreshold"],
                "minimumPromotions": operational_state[
                    "minimumPromotionsForRatePause"
                ],
            },
        )

        min_success = int(document.get("minIndependentSuccesses", 3))
        summary_consistent = all(
            summary.get(key) == value
            for key, value in derived_summary.items()
        )
        check(
            "GRAPH_ELIGIBILITY_PERSISTED_AGGREGATE_CONSISTENT",
            "passed" if summary_consistent else "unknown",
            {key: summary.get(key) for key in derived_summary},
            derived_summary,
        )
        check("GRAPH_ELIGIBILITY_INDEPENDENT_SUCCESSES", "passed" if derived_summary["successCount"] >= min_success else "failed", derived_summary["successCount"], min_success)
        min_windows = int(document.get("minDistinctTimeWindows", 2))
        check("GRAPH_ELIGIBILITY_DISTINCT_TIME_WINDOWS", "passed" if len(time_windows) >= min_windows else "failed", len(time_windows), min_windows)
        min_revisions = int(document.get("minDistinctRevisions", 1))
        revision_count = int(derived_summary["distinctRevisionCount"])
        check("GRAPH_ELIGIBILITY_DISTINCT_REVISIONS", "passed" if revision_count >= min_revisions else "unknown" if revision_count == 0 else "failed", revision_count, min_revisions)
        min_environments = int(document.get("minDistinctEnvironments", 1))
        environment_count = int(derived_summary["distinctEnvironmentCount"])
        check("GRAPH_ELIGIBILITY_DISTINCT_ENVIRONMENTS", "passed" if environment_count >= min_environments else "failed", environment_count, min_environments)
        min_verification = float(document.get("minVerificationCoverage", 1.0))
        verification = float(derived_summary["verificationCoverage"])
        check("GRAPH_ELIGIBILITY_VERIFICATION_COVERAGE", "passed" if verification >= min_verification else "failed", verification, min_verification)
        no_unexplained = (
            int(derived_summary["retryCount"]) == 0
            and int(derived_summary["failureCount"]) == 0
            and all(item.outcome == "success" for item in independent)
            and not summary.get("flakySignals")
            and not summary.get("conflictRefs")
        )
        check("GRAPH_ELIGIBILITY_NO_UNEXPLAINED_FAILURES", "passed" if no_unexplained else "failed", {"retryCount": derived_summary["retryCount"], "failureCount": derived_summary["failureCount"], "flakySignals": summary.get("flakySignals", []), "conflicts": len(summary.get("conflictRefs", []))}, {"retryCount": 0, "failureCount": 0, "flakySignals": [], "conflicts": 0})
        allowed_fallbacks = set(document.get("allowedFallbackTypes") or [])
        observed_fallbacks = set(derived_summary["fallbackTypes"])
        candidate_paths = list(
            self.db.scalars(
                select(CanonicalExecutionGraphPath).where(
                    CanonicalExecutionGraphPath.version_id == candidate.id
                )
            )
        )
        candidate_nodes = list(
            self.db.scalars(
                select(CanonicalExecutionGraphNode).where(
                    CanonicalExecutionGraphNode.version_id == candidate.id
                )
            )
        )
        dangerous_action_markers = {"delete", "drop", "destroy", "merge", "release", "purge"}
        destructive_action = any(
            any(
                marker in str(node.attributes_json.get("actionType") or "").lower()
                or marker in node.semantic_key.lower()
                for marker in dangerous_action_markers
            )
            for node in candidate_nodes
        )
        connector_calls_present = any(
            item.observed_trace_snapshot.get("connectorCallRefs") for item in independent
        )
        safe_actions = (
            int(derived_summary["coordinateClickCount"]) == 0
            and observed_fallbacks <= allowed_fallbacks
            and all(path.risk_level == RiskLevel.LOW for path in candidate_paths)
            and not destructive_action
            and not connector_calls_present
            and persisted_refs_available
        )
        safe_state = "passed" if safe_actions else "unavailable" if not persisted_refs_available else "failed"
        check("GRAPH_ELIGIBILITY_SAFE_ACTIONS_ONLY", safe_state, {"coordinateClickCount": derived_summary["coordinateClickCount"], "fallbackTypes": sorted(observed_fallbacks), "allCandidatePathsLowRisk": all(path.risk_level == RiskLevel.LOW for path in candidate_paths), "destructiveAction": destructive_action, "connectorCallsPresent": connector_calls_present, "persistedRefsAvailable": persisted_refs_available}, {"coordinateClickCount": 0, "allowedFallbackTypes": sorted(allowed_fallbacks), "destructiveAction": False, "unapprovedExternalWrite": False, "persistedRefsAvailable": True})
        staleness_signal = GraphStalenessService(self.db).controlled_autonomy_signal(
            tenant_id=proposal.tenant_id,
            workspace_id=proposal.workspace_id,
            project_id=proposal.project_id,
            graph_version_id=candidate.id,
        )
        applicability = staleness_signal["status"]
        check(
            "GRAPH_ELIGIBILITY_APPLICABILITY_FRESH",
            "passed" if staleness_signal["eligible"] else "unknown" if applicability == "unknown" else "failed",
            {
                "status": applicability,
                "assessmentRef": staleness_signal["assessmentRef"],
                "assessmentHash": staleness_signal["assessmentHash"],
                "reasonCode": staleness_signal["reasonCode"],
            },
            {"status": "fresh", "evidenceComplete": True},
            ([{"type": "graph_staleness_assessment", "ref": staleness_signal["assessmentRef"], "contentHash": staleness_signal["assessmentHash"]}] if staleness_signal["assessmentRef"] else []),
        )
        replay_ok = bool(replay_ids) and not replay_unavailable and all(item.validity_status == "valid" and item.approval_state in {"approved", "not_required"} and item.redaction_status in {"redacted", "not_required"} for item in replays)
        check("GRAPH_ELIGIBILITY_REPLAY_ALL_PASSED", "passed" if replay_ok else "unavailable" if not replay_ids or replay_unavailable else "failed", {"requested": len(replay_ids), "resolved": len(replays), "valid": sum(item.validity_status == "valid" for item in replays)}, {"minimum": 1, "allValid": True}, [{"type": "replay", "ref": f"replay://repository/{item.replay_id}"} for item in replays])
        min_shadow = int(document.get("minShadowSamples", 3))
        shadow_samples = sum(item.completed_cases for item in shadows if item.status == "completed")
        shadow_ok = bool(shadow_ids) and not shadow_unavailable and all(item.status == "completed" and item.failed_cases == 0 and item.unavailable_cases == 0 for item in shadows) and shadow_samples >= min_shadow
        check("GRAPH_ELIGIBILITY_SHADOW_WINDOW_PASSED", "passed" if shadow_ok else "unavailable" if not shadow_ids or shadow_unavailable else "failed", {"runs": len(shadows), "samples": shadow_samples}, {"allCompleted": True, "minSamples": min_shadow}, [{"type": "shadow", "ref": f"gate-shadow://runs/{item.id}"} for item in shadows])
        min_confidence = float(document.get("minConfidence", 0.9))
        confidence = float(max_confidence or 0.0)
        min_evidence = int(document.get("minEvidenceRefs", 1))
        confidence_ok = confidence >= min_confidence and evidence_ref_count >= min_evidence
        check("GRAPH_ELIGIBILITY_CONFIDENCE_EVIDENCE_THRESHOLD", "passed" if confidence_ok else "failed", {"confidence": confidence, "evidenceRefCount": evidence_ref_count}, {"minConfidence": min_confidence, "minEvidenceRefs": min_evidence})
        check("GRAPH_ELIGIBILITY_NO_GUARDRAIL_BLOCK", "passed" if not guardrail_block else "failed", guardrail_block, False)
        candidate_bootstrap_base = (
            active_base is None
            and proposal.base_version_id == candidate.id
            and candidate.status == GraphStatus.CANDIDATE
            and candidate.source == GraphSource.CANDIDATE
            and not candidate.is_frozen
            and candidate.content_hash == proposal.base_version_hash
            and candidate.lock_version == proposal.base_version_lock_version
        )
        base_matches = bool(
            (
                active_base
                and active_base.id == proposal.base_version_id
                and active_base.content_hash == proposal.base_version_hash
                and active_base.lock_version == proposal.base_version_lock_version
            )
            or candidate_bootstrap_base
        )
        check("GRAPH_ELIGIBILITY_ACTIVE_BASE_UNCHANGED", "passed" if base_matches else "unavailable" if not active_base else "failed", {"activeVersionId": str(active_base.id) if active_base else None, "activeVersionHash": active_base.content_hash if active_base else None}, {"baseVersionId": str(proposal.base_version_id), "baseVersionHash": proposal.base_version_hash})

        automatic = all(item["passed"] for item in checks)
        eligible = validation_valid and mode != "learn_only"
        human_required = eligible and not automatic
        input_snapshot = {
            "candidateBuildId": str(build.id),
            "candidateEvidenceSummary": deepcopy(summary),
            "candidateVersionHash": candidate.content_hash,
            "baseVersionId": str(proposal.base_version_id),
            "baseVersionHash": proposal.base_version_hash,
            "replayIds": list(replay_ids),
            "shadowRunIds": [str(item) for item in shadow_ids],
            "mode": mode,
            "stalenessAssessmentRef": staleness_signal["assessmentRef"],
            "stalenessAssessmentHash": staleness_signal["assessmentHash"],
            "stalenessStatus": staleness_signal["status"],
            "operationalAutonomySnapshot": operational_state,
        }
        return checks, input_snapshot, eligible, automatic, human_required

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class GraphPromotionService:
    """P13 components inside the existing Service-owned CEG/CCG boundary."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = ExecutionGraphRepository(db)
        self.resolver = GraphLearningPolicyResolver(db)
        self.evaluator = GraphPromotionEligibilityEvaluator(db)
        self.guardrails = RuntimeGuardrailEngine(db)

    # -- Graph Correction -------------------------------------------------

    def create_proposal(
        self,
        project_id: UUID,
        payload: CreateGraphCorrectionProposalRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.correction.propose")
        scope = self._scope(project_id, context)
        ensure_trace(self.db, execution_id=None, root_span_name="ceg.promotion", trace_id=context.trace_id)
        existing = self.db.scalar(
            select(GraphCorrectionProposalRecord).where(
                GraphCorrectionProposalRecord.tenant_id == scope.tenant_id,
                GraphCorrectionProposalRecord.workspace_id == scope.workspace_id,
                GraphCorrectionProposalRecord.idempotency_key == payload.idempotencyKey,
            )
        )
        request_hash = canonical_hash(payload.model_dump(mode="json"))
        if existing:
            if existing.request_hash != request_hash:
                raise GraphPromotionError("GRAPH_CORRECTION_IDEMPOTENCY_CONFLICT")
            return self._proposal_projection(existing, deduplicated=True)
        graph, base, candidate, build = self._load_proposal_inputs(scope, payload)
        proposal_id = uuid4()
        created_at = datetime.now(timezone.utc)
        proposed_change = {
            "schemaVersion": "phase8.graph-correction-change.v1",
            "changeType": "graph_correction",
            "graphRef": {"type": "canonical_execution_graph", "id": str(graph.id)},
            "baseVersionRef": {"type": "ceg_version", "id": str(base.id)},
            "candidateVersionRef": {"type": "ceg_version", "id": str(candidate.id)},
            "patch": payload.patch.model_dump(mode="json"),
            "rationale": payload.rationaleCode,
            "riskLevel": payload.riskLevel,
            "evidenceRefs": payload.evidenceRefs,
            "metadata": {"candidateBuildId": str(build.id)},
        }
        ccg_contract = validate_contract(
            "correction-proposal",
            {
                "schemaVersion": "phase8.correction-proposal.v1",
                "correctionProposalId": str(proposal_id),
                "proposalType": "graph_correction",
                "proposedChange": proposed_change,
                "status": "draft",
                "requirementVersionId": None,
                "executionId": str(build.execution_id),
                "findingId": None,
                "attributionId": None,
                "riskLevel": payload.riskLevel,
                "requesterRef": {"type": "user", "id": str(context.user.id)},
                "approvalRefs": [],
                "evidenceRefs": payload.evidenceRefs,
                "traceRefs": [context.trace_id],
                "createdAt": created_at.isoformat(),
                "metadata": {"graphId": str(graph.id), "candidateBuildId": str(build.id)},
            },
        )
        ccg = CorrectionProposal(
            id=proposal_id,
            proposal_type="graph_correction",
            status="draft",
            proposed_change=proposed_change,
            requirement_version_id=None,
            execution_id=build.execution_id,
            finding_id=None,
            attribution_id=None,
            risk_level=RiskLevel(payload.riskLevel),
            requester_ref={"type": "user", "id": str(context.user.id)},
            requested_by=context.user.id,
            approval_refs=[],
            evidence_refs=payload.evidenceRefs,
            trace_refs=[context.trace_id],
            promotion_refs=[],
            contract_snapshot=ccg_contract,
            request_id=context.request_id,
            idempotency_key=f"graph-correction:{scope.tenant_id}:{scope.workspace_id}:{payload.idempotencyKey}"[:255],
            metadata_json={"graphId": str(graph.id), "candidateBuildId": str(build.id)},
        )
        record = GraphCorrectionProposalRecord(
            id=uuid4(),
            correction_proposal_id=ccg.id,
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=scope.project.id,
            environment_id=graph.environment_id,
            graph_id=graph.id,
            base_version_id=base.id,
            base_version_hash=base.content_hash,
            base_version_lock_version=base.lock_version,
            candidate_version_id=candidate.id,
            candidate_version_hash=candidate.content_hash,
            candidate_build_id=build.id,
            structured_patch=payload.patch.model_dump(mode="json"),
            patch_hash=canonical_hash(payload.patch.model_dump(mode="json")),
            rationale_code=payload.rationaleCode,
            risk_level=payload.riskLevel,
            status="draft",
            validation_report={},
            evidence_refs=payload.evidenceRefs,
            approval_refs=[],
            policy_decision_refs=[],
            audit_refs=[],
            rollback_refs=[],
            idempotency_key=payload.idempotencyKey,
            request_hash=request_hash,
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
            updated_by=context.user.id,
        )
        self.db.add_all([ccg, record])
        self.db.flush()
        record.audit_refs = [self._audit(context, "graph_correction.propose", "graph_correction_proposal", record.id, {"graphId": str(graph.id), "baseVersionId": str(base.id), "candidateVersionId": str(candidate.id), "patchHash": record.patch_hash})]
        self.db.commit()
        return self._proposal_projection(record)

    def update_proposal(
        self,
        project_id: UUID,
        proposal_id: UUID,
        payload: UpdateGraphCorrectionProposalRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.correction.propose")
        scope = self._scope(project_id, context)
        record = self._require_proposal(scope, proposal_id, for_update=True)
        if record.status != "draft":
            raise GraphPromotionError("GRAPH_CORRECTION_NOT_EDITABLE")
        self._require_lock(record.lock_version, payload.expectedLockVersion)
        record.structured_patch = payload.patch.model_dump(mode="json")
        record.patch_hash = canonical_hash(record.structured_patch)
        record.risk_level = payload.riskLevel
        record.rationale_code = payload.rationaleCode
        record.evidence_refs = payload.evidenceRefs
        record.updated_by = context.user.id
        record.audit_refs = [*record.audit_refs, self._audit(context, "graph_correction.update", "graph_correction_proposal", record.id, {"patchHash": record.patch_hash})][-128:]
        ccg = self.db.get(CorrectionProposal, record.correction_proposal_id)
        if ccg:
            ccg.proposed_change = {
                **ccg.proposed_change,
                "patch": record.structured_patch,
                "rationale": record.rationale_code,
                "riskLevel": record.risk_level,
                "evidenceRefs": record.evidence_refs,
            }
            ccg.risk_level = RiskLevel(record.risk_level)
            ccg.evidence_refs = record.evidence_refs
            ccg.contract_snapshot = validate_contract(
                "correction-proposal",
                {
                    **ccg.contract_snapshot,
                    "proposedChange": ccg.proposed_change,
                    "riskLevel": record.risk_level,
                    "evidenceRefs": record.evidence_refs,
                },
            )
        self.db.commit()
        return self._proposal_projection(record)

    def validate_proposal(
        self,
        project_id: UUID,
        proposal_id: UUID,
        payload: ValidateGraphCorrectionRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.correction.validate")
        scope = self._scope(project_id, context)
        record = self._require_proposal(scope, proposal_id, for_update=True)
        self._require_lock(record.lock_version, payload.expectedLockVersion)
        if record.status not in {"draft", "validated", "invalid"}:
            raise GraphPromotionError("GRAPH_CORRECTION_VALIDATION_STATE_INVALID")
        if record.validator_version and record.validator_version != payload.validatorVersion:
            raise GraphPromotionError("GRAPH_CORRECTION_VALIDATOR_VERSION_CHANGED")
        candidate = self._require_candidate(record)
        build = self._require_candidate_build(record)
        report = self._validate_patch(record, candidate, build, payload.validatorVersion)
        record.validation_report = report
        record.validation_hash = report["reportHash"]
        record.validator_version = payload.validatorVersion
        record.validated_at = datetime.now(timezone.utc)
        record.status = "validated" if report["summary"]["valid"] else "invalid"
        record.updated_by = context.user.id
        record.audit_refs = [*record.audit_refs, self._audit(context, "graph_correction.validate", "graph_correction_proposal", record.id, {"valid": report["summary"]["valid"], "reportHash": report["reportHash"], "reasonCodes": report["reasonCodes"]})][-128:]
        self.db.commit()
        return self._proposal_projection(record)

    def list_proposals(
        self, project_id: UUID, context: ServiceContext, *, graph_id: UUID | None = None
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.correction.read")
        scope = self._scope(project_id, context)
        statement = select(GraphCorrectionProposalRecord).where(
            GraphCorrectionProposalRecord.tenant_id == scope.tenant_id,
            GraphCorrectionProposalRecord.workspace_id == scope.workspace_id,
            GraphCorrectionProposalRecord.project_id == scope.project.id,
        )
        if graph_id:
            statement = statement.where(GraphCorrectionProposalRecord.graph_id == graph_id)
        rows = list(self.db.scalars(statement.order_by(GraphCorrectionProposalRecord.created_at.desc())))
        candidate_rows = list(
            self.db.scalars(
                select(CandidateGraphBuildRun)
                .where(
                    CandidateGraphBuildRun.tenant_id == scope.tenant_id,
                    CandidateGraphBuildRun.workspace_id == scope.workspace_id,
                    CandidateGraphBuildRun.project_id == scope.project.id,
                    CandidateGraphBuildRun.status == "completed",
                )
                .order_by(CandidateGraphBuildRun.source_observed_at.desc())
                .limit(100)
            )
        )
        candidate_intake: list[dict[str, Any]] = []
        for build in candidate_rows:
            candidate = self.db.get(CanonicalExecutionGraphVersion, build.candidate_version_id)
            graph = self.db.get(CanonicalExecutionGraph, build.graph_id)
            if (
                candidate is None
                or graph is None
                or candidate.status != GraphStatus.CANDIDATE
                or candidate.source != GraphSource.CANDIDATE
                or candidate.is_frozen
            ):
                continue
            active_versions = list(
                self.db.scalars(
                    select(CanonicalExecutionGraphVersion).where(
                        CanonicalExecutionGraphVersion.tenant_id == scope.tenant_id,
                        CanonicalExecutionGraphVersion.workspace_id == scope.workspace_id,
                        CanonicalExecutionGraphVersion.project_id == graph.project_id,
                        CanonicalExecutionGraphVersion.graph_id == graph.id,
                        CanonicalExecutionGraphVersion.status == GraphStatus.ACTIVE,
                        CanonicalExecutionGraphVersion.source == GraphSource.CANONICAL,
                        CanonicalExecutionGraphVersion.is_frozen.is_(True),
                    )
                )
            )
            active = active_versions[0] if len(active_versions) == 1 else None
            base = active or candidate
            material = self._topology_material(candidate)
            candidate_intake.append(
                {
                    "buildId": str(build.id),
                    "buildRef": build.build_ref,
                    "graphId": str(graph.id),
                    "baseVersionId": str(base.id),
                    "baseVersionHash": base.content_hash,
                    "baseVersionLockVersion": base.lock_version,
                    "candidateVersionId": str(candidate.id),
                    "candidateVersionHash": candidate.content_hash,
                    "candidateVersionLockVersion": candidate.lock_version,
                    "riskLevel": "high" if any(item.get("riskLevel") == "high" for bucket in material.values() for item in bucket.values()) else "medium" if any(item.get("riskLevel") == "medium" for bucket in material.values() for item in bucket.values()) else "low",
                    "targets": {
                        entity: [
                            {
                                "id": item["id"],
                                "stableKey": item["stableKey"],
                                "lockVersion": item["lockVersion"],
                                "summary": item.get("name") or (item.get("display") or {}).get("label") or item.get("edgeType") or item["stableKey"],
                                "value": item,
                            }
                            for item in bucket.values()
                        ]
                        for entity, bucket in material.items()
                    },
                    "allowedOperations": ["add", "update", "remove", "reorder"],
                    "authoritative": True,
                }
            )
        mode, binding, policy, fallback = self.resolver.resolve(
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=scope.project.id,
            environment_id=None,
        )
        return {
            "schemaVersion": "phase8.graph-correction-workspace.v1",
            "items": [self._proposal_projection(item) for item in rows],
            "candidateIntake": candidate_intake,
            "learningModeProjection": self._learning_projection(mode, binding, policy, fallback),
            "readOnly": "graph.correction.propose" not in context.user.capabilities,
            "authorizationBoundary": "backend_service_api",
            "frontendBoundary": "ux_only",
        }

    # -- policy and mode --------------------------------------------------

    def create_policy(
        self,
        project_id: UUID,
        payload: CreateGraphLearningPolicyRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.learning_policy.manage")
        scope = self._scope(project_id, context)
        ensure_trace(self.db, execution_id=None, root_span_name="ceg.learning-policy", trace_id=context.trace_id)
        acquire_transaction_advisory_lock(self.db, "graph-learning-policy", f"{scope.tenant_id}:{scope.workspace_id}:{project_id}:{payload.policyKey}")
        document = payload.model_dump(mode="json", exclude={"schemaVersion", "policyKey", "status", "idempotencyKey"})
        content_hash = canonical_hash(document)
        retry = self.db.scalar(select(GraphLearningPolicyVersion).where(GraphLearningPolicyVersion.tenant_id == scope.tenant_id, GraphLearningPolicyVersion.workspace_id == scope.workspace_id, GraphLearningPolicyVersion.idempotency_key == payload.idempotencyKey))
        if retry:
            if retry.request_hash != canonical_hash(payload.model_dump(mode="json")):
                raise GraphPromotionError("GRAPH_LEARNING_POLICY_IDEMPOTENCY_CONFLICT")
            return self._policy_projection(retry, deduplicated=True)
        policy = self.db.scalar(select(GraphLearningPolicy).where(GraphLearningPolicy.tenant_id == scope.tenant_id, GraphLearningPolicy.workspace_id == scope.workspace_id, GraphLearningPolicy.project_id == project_id, GraphLearningPolicy.policy_key == payload.policyKey))
        if policy is None:
            policy = GraphLearningPolicy(id=uuid4(), tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=project_id, policy_key=payload.policyKey, status=payload.status, created_by=context.user.id)
            self.db.add(policy)
            self.db.flush()
        max_version = int(self.db.scalar(select(func.max(GraphLearningPolicyVersion.version_number)).where(GraphLearningPolicyVersion.policy_id == policy.id)) or 0)
        version = GraphLearningPolicyVersion(id=uuid4(), policy_id=policy.id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=project_id, version_number=max_version + 1, status=payload.status, policy_document=document, content_hash=content_hash, idempotency_key=payload.idempotencyKey, request_hash=canonical_hash(payload.model_dump(mode="json")), audit_refs=[], trace_id=UUID(context.trace_id), created_by=context.user.id)
        self.db.add(version)
        self.db.flush()
        version.audit_refs = [self._audit(context, "graph_learning_policy.create_version", "graph_learning_policy_version", version.id, {"policyKey": policy.policy_key, "version": version.version_number, "contentHash": content_hash})]
        self.db.commit()
        return self._policy_projection(version)

    def bind_policy(
        self,
        project_id: UUID,
        payload: CreateGraphLearningBindingRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.learning_policy.manage")
        if payload.graphLearningMode == "controlled_autonomy":
            raise GraphPromotionError(
                "GRAPH_AUTONOMY_EXPLICIT_CONFIGURATION_REQUIRED",
                field="graphLearningMode",
            )
        scope = self._scope(project_id, context)
        ensure_trace(self.db, execution_id=None, root_span_name="ceg.learning-policy", trace_id=context.trace_id)
        version = self.db.get(GraphLearningPolicyVersion, payload.policyVersionId)
        if not version or version.tenant_id != scope.tenant_id or version.workspace_id != scope.workspace_id or version.project_id != project_id or version.status != "active" or version.content_hash != payload.policyVersionHash:
            raise GraphPromotionError("GRAPH_LEARNING_POLICY_VERSION_INVALID")
        environment = None
        scope_id = project_id
        if payload.environmentId:
            environment = self.db.scalar(select(ProjectEnvironment).where(ProjectEnvironment.id == payload.environmentId, ProjectEnvironment.project_id == project_id))
            if not environment:
                raise GraphPromotionError("GRAPH_LEARNING_POLICY_ENVIRONMENT_NOT_FOUND", status_code=404)
            scope_id = environment.id
        existing = self.db.scalar(select(GraphLearningPolicyBinding).where(GraphLearningPolicyBinding.tenant_id == scope.tenant_id, GraphLearningPolicyBinding.workspace_id == scope.workspace_id, GraphLearningPolicyBinding.project_id == project_id, GraphLearningPolicyBinding.scope_type == payload.scopeType, GraphLearningPolicyBinding.scope_id == scope_id))
        request_hash = canonical_hash(payload.model_dump(mode="json"))
        if existing:
            if existing.idempotency_key == payload.idempotencyKey and existing.request_hash == request_hash:
                return self._binding_projection(existing, deduplicated=True)
            raise GraphPromotionError("GRAPH_LEARNING_BINDING_SCOPE_CONFLICT")
        binding = GraphLearningPolicyBinding(id=uuid4(), tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=project_id, environment_id=environment.id if environment else None, scope_type=payload.scopeType, scope_id=scope_id, policy_version_id=version.id, policy_version_hash=version.content_hash, learning_mode=payload.graphLearningMode, status=payload.status, autonomy_paused=False, idempotency_key=payload.idempotencyKey, request_hash=request_hash, audit_refs=[], trace_id=UUID(context.trace_id), created_by=context.user.id)
        self.db.add(binding)
        self.db.flush()
        binding.audit_refs = [self._audit(context, "graph_learning_policy.bind", "graph_learning_policy_binding", binding.id, {"scopeType": binding.scope_type, "scopeId": str(binding.scope_id), "graphLearningMode": binding.learning_mode, "policyVersionHash": binding.policy_version_hash})]
        self.db.commit()
        return self._binding_projection(binding)

    def configure_autonomy_mode(
        self,
        project_id: UUID,
        binding_id: UUID,
        payload: ConfigureGraphAutonomyRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.autonomy.configure")
        scope = self._scope(project_id, context)
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="ceg.autonomy-configuration",
            trace_id=context.trace_id,
        )
        binding = self.db.scalar(
            select(GraphLearningPolicyBinding)
            .where(
                GraphLearningPolicyBinding.id == binding_id,
                GraphLearningPolicyBinding.tenant_id == scope.tenant_id,
                GraphLearningPolicyBinding.workspace_id == scope.workspace_id,
                GraphLearningPolicyBinding.project_id == project_id,
            )
            .with_for_update()
        )
        if not binding:
            raise GraphPromotionError("GRAPH_LEARNING_BINDING_NOT_FOUND", status_code=404)

        request_hash = canonical_hash(payload.model_dump(mode="json"))
        previous = next(
            (
                item
                for item in reversed(binding.audit_refs)
                if item.get("action") == "graph_autonomy.configure"
                and item.get("idempotencyKey") == payload.idempotencyKey
            ),
            None,
        )
        if previous is not None:
            if previous.get("requestHash") != request_hash:
                raise GraphPromotionError("GRAPH_AUTONOMY_IDEMPOTENCY_CONFLICT")
            return {
                "status": "configured",
                "productionApplied": binding.learning_mode == payload.targetMode,
                "approvalRequired": False,
                "binding": self._binding_projection(binding, deduplicated=True),
            }

        self._require_lock(binding.lock_version, payload.expectedLockVersion)
        self._require_autonomy_binding_ready(binding)
        if payload.targetMode == "controlled_autonomy":
            from agentic_qa.services.governance_service import GRAPH_AUTONOMY_COMPONENTS

            if not all(GRAPH_AUTONOMY_COMPONENTS.values()):
                raise GraphPromotionError("GRAPH_AUTONOMY_WORKFLOW_INCOMPLETE")
            approval = ApprovalService(self.db)._get_or_create_pending_approval(
                approval_type=ApprovalType.OTHER,
                resource_type="graph_autonomy_configuration",
                resource_id=f"{binding.id}:{payload.idempotencyKey}",
                summary=(
                    "Approval required before enabling controlled Graph autonomy "
                    f"for {binding.scope_type} scope {binding.scope_id}."
                ),
                payload={
                    "action": "graph_autonomy.configure",
                    "projectId": str(project_id),
                    "bindingId": str(binding.id),
                    "scopeType": binding.scope_type,
                    "scopeId": str(binding.scope_id),
                    "targetMode": payload.targetMode,
                    "expectedLockVersion": binding.lock_version,
                    "policyVersionId": str(binding.policy_version_id),
                    "policyVersionHash": binding.policy_version_hash,
                    "reasonCode": payload.reasonCode,
                    "idempotencyKey": payload.idempotencyKey,
                    "requestHash": request_hash,
                    "scopeDecisionRef": scope.decision_ref,
                },
                context=context,
                commit=False,
            )
            self._record_autonomy_guardrail(
                context,
                binding,
                decision="warn",
                reason="Controlled Graph autonomy requires explicit human Approval.",
            )
            self.db.commit()
            return {
                "status": "approval_pending",
                "productionApplied": False,
                "approvalRequired": True,
                "approval": ApprovalService(self.db).serialize_approval(approval),
                "binding": self._binding_projection(binding),
            }

        before = binding.learning_mode
        binding.learning_mode = payload.targetMode
        binding.autonomy_paused = False
        binding.pause_reason_code = None
        binding.paused_at = None
        guardrail_ref = self._record_autonomy_guardrail(
            context,
            binding,
            decision="allow",
            reason="Fail-safe Graph autonomy downgrade accepted.",
        )
        audit_ref = self._audit(
            context,
            "graph_autonomy.configure",
            "graph_learning_policy_binding",
            binding.id,
            {
                "beforeMode": before,
                "targetMode": payload.targetMode,
                "reasonCode": payload.reasonCode,
                "idempotencyKey": payload.idempotencyKey,
                "requestHash": request_hash,
                "approvalRequired": False,
                "guardrailRef": guardrail_ref,
            },
        )
        audit_ref.update(
            {"idempotencyKey": payload.idempotencyKey, "requestHash": request_hash}
        )
        binding.audit_refs = [*binding.audit_refs, audit_ref][-128:]
        self.db.commit()
        return {
            "status": "configured",
            "productionApplied": True,
            "approvalRequired": False,
            "binding": self._binding_projection(binding),
        }

    def execute_approved_autonomy_configuration(
        self,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.autonomy.configure")
        project_id = UUID(str(approval_payload["projectId"]))
        binding_id = UUID(str(approval_payload["bindingId"]))
        scope = self._scope(project_id, context)
        binding = self.db.scalar(
            select(GraphLearningPolicyBinding)
            .where(
                GraphLearningPolicyBinding.id == binding_id,
                GraphLearningPolicyBinding.tenant_id == scope.tenant_id,
                GraphLearningPolicyBinding.workspace_id == scope.workspace_id,
                GraphLearningPolicyBinding.project_id == project_id,
            )
            .with_for_update()
        )
        if not binding:
            raise GraphPromotionError("GRAPH_LEARNING_BINDING_NOT_FOUND", status_code=404)
        self._require_lock(
            binding.lock_version, int(str(approval_payload["expectedLockVersion"]))
        )
        self._require_autonomy_binding_ready(binding)
        if (
            str(binding.policy_version_id) != str(approval_payload["policyVersionId"])
            or binding.policy_version_hash != str(approval_payload["policyVersionHash"])
            or approval_payload.get("targetMode") != "controlled_autonomy"
        ):
            raise GraphPromotionError("GRAPH_AUTONOMY_APPROVAL_SNAPSHOT_STALE")
        from agentic_qa.services.governance_service import GRAPH_AUTONOMY_COMPONENTS

        if not all(GRAPH_AUTONOMY_COMPONENTS.values()):
            raise GraphPromotionError("GRAPH_AUTONOMY_WORKFLOW_INCOMPLETE")

        before = binding.learning_mode
        binding.learning_mode = "controlled_autonomy"
        binding.autonomy_paused = False
        binding.pause_reason_code = None
        binding.paused_at = None
        guardrail_ref = self._record_autonomy_guardrail(
            context,
            binding,
            decision="allow",
            reason="Approval-backed controlled Graph autonomy configuration revalidated.",
        )
        audit_ref = self._audit(
            context,
            "graph_autonomy.configure.approved",
            "graph_learning_policy_binding",
            binding.id,
            {
                "beforeMode": before,
                "targetMode": binding.learning_mode,
                "approvalId": str(approval_id),
                "reasonCode": str(approval_payload["reasonCode"]),
                "idempotencyKey": str(approval_payload["idempotencyKey"]),
                "requestHash": str(approval_payload["requestHash"]),
                "guardrailRef": guardrail_ref,
            },
        )
        audit_ref.update(
            {
                "idempotencyKey": str(approval_payload["idempotencyKey"]),
                "requestHash": str(approval_payload["requestHash"]),
            }
        )
        binding.audit_refs = [*binding.audit_refs, audit_ref][-128:]
        self.db.flush()
        return {
            "status": "configured",
            "productionApplied": True,
            "approvalRequired": True,
            "approvalId": str(approval_id),
            "binding": self._binding_projection(binding),
        }

    def set_autonomy_pause(
        self,
        project_id: UUID,
        binding_id: UUID,
        payload: PauseGraphAutonomyRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.autonomy.pause")
        scope = self._scope(project_id, context)
        binding = self.db.scalar(select(GraphLearningPolicyBinding).where(GraphLearningPolicyBinding.id == binding_id, GraphLearningPolicyBinding.tenant_id == scope.tenant_id, GraphLearningPolicyBinding.workspace_id == scope.workspace_id, GraphLearningPolicyBinding.project_id == project_id).with_for_update())
        if not binding:
            raise GraphPromotionError("GRAPH_LEARNING_BINDING_NOT_FOUND", status_code=404)
        self._require_lock(binding.lock_version, payload.expectedLockVersion)
        binding.autonomy_paused = payload.paused
        binding.pause_reason_code = payload.reasonCode if payload.paused else None
        binding.paused_at = datetime.now(timezone.utc) if payload.paused else None
        binding.audit_refs = [*binding.audit_refs, self._audit(context, "graph_autonomy.pause" if payload.paused else "graph_autonomy.resume", "graph_learning_policy_binding", binding.id, {"paused": payload.paused, "reasonCode": payload.reasonCode})][-128:]
        self.db.commit()
        return self._binding_projection(binding)

    # -- eligibility / approval / promotion ------------------------------

    def assess(
        self,
        project_id: UUID,
        proposal_id: UUID,
        payload: AssessGraphPromotionRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.promotion.assess")
        scope = self._scope(project_id, context)
        record = self._require_proposal(scope, proposal_id, for_update=True)
        self._require_lock(record.lock_version, payload.expectedProposalLockVersion)
        if record.status != "validated":
            raise GraphPromotionError("GRAPH_CORRECTION_NOT_VALIDATED")
        candidate = self._require_candidate(record)
        build = self._require_candidate_build(record)
        graph = self.db.get(CanonicalExecutionGraph, record.graph_id)
        if not graph:
            raise GraphPromotionError("GRAPH_NOT_FOUND", status_code=404)
        mode, binding, policy, _fallback = self.resolver.resolve(tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=scope.project.id, environment_id=record.environment_id)
        request_hash = canonical_hash(payload.model_dump(mode="json"))
        retry = self.db.scalar(select(GraphPromotionEligibilityAssessment).where(GraphPromotionEligibilityAssessment.tenant_id == scope.tenant_id, GraphPromotionEligibilityAssessment.workspace_id == scope.workspace_id, GraphPromotionEligibilityAssessment.proposal_id == record.id, GraphPromotionEligibilityAssessment.idempotency_key == payload.idempotencyKey))
        if retry:
            if retry.request_hash != request_hash:
                raise GraphPromotionError("GRAPH_ELIGIBILITY_IDEMPOTENCY_CONFLICT")
            return self._assessment_projection(retry, deduplicated=True)
        guardrail_ref = self._record_guardrail(context, record, decision="allow", reason="Service-owned Graph Promotion eligibility evaluation accepted persisted refs only.")
        checks, inputs, eligible, automatic, human_required = self.evaluator.evaluate(proposal=record, graph=graph, candidate=candidate, build=build, mode=mode, binding=binding, policy=policy, replay_ids=payload.evidence.replayRepositoryIds, shadow_ids=payload.evidence.shadowRunIds)
        reason_codes = [item["code"] for item in checks if not item["passed"]] or ["GRAPH_ELIGIBILITY_ALL_CHECKS_PASSED"]
        assessment_id = uuid4()
        evaluated_at = datetime.now(timezone.utc)
        snapshot_without_hash = {"assessmentId": str(assessment_id), "proposalId": str(record.id), "graphId": str(record.graph_id), "candidateVersionId": str(record.candidate_version_id), "baseVersionId": str(record.base_version_id), "learningMode": mode, "riskLevel": record.risk_level, "eligible": eligible, "automaticPromotionAllowed": automatic, "humanReviewRequired": human_required, "checks": checks, "reasonCodes": reason_codes, "policyVersionId": str(policy.id) if policy else None, "policyVersionHash": policy.content_hash if policy else canonical_hash({"mode": DEFAULT_GRAPH_LEARNING_MODE, "source": "safe_builtin_default"}), "bindingId": str(binding.id) if binding else None, "evaluatedAt": evaluated_at.isoformat()}
        eligibility_hash = canonical_hash(snapshot_without_hash)
        policy_ref = {"type": "policy_decision", "ref": f"policy-decision://graph-promotion/{assessment_id}", "decision": "auto_promotion_allowed" if automatic else "candidate_retained", "approvalRequired": human_required}
        audit_ref = self._audit(context, "graph_promotion.assess", "graph_promotion_eligibility", assessment_id, {"eligible": eligible, "automaticPromotionAllowed": automatic, "humanReviewRequired": human_required, "reasonCodes": reason_codes, "eligibilityHash": eligibility_hash})
        assessment = GraphPromotionEligibilityAssessment(id=assessment_id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=scope.project.id, proposal_id=record.id, graph_id=record.graph_id, candidate_version_id=record.candidate_version_id, base_version_id=record.base_version_id, learning_mode=mode, risk_level=record.risk_level, eligible=eligible, automatic_promotion_allowed=automatic, human_review_required=human_required, checks_snapshot=checks, reason_codes=reason_codes, input_snapshot=inputs, policy_version_id=policy.id if policy else None, policy_version_hash=snapshot_without_hash["policyVersionHash"], binding_id=binding.id if binding else None, eligibility_hash=eligibility_hash, idempotency_key=payload.idempotencyKey, request_hash=request_hash, policy_decision_refs=[policy_ref], guardrail_event_refs=[guardrail_ref], audit_refs=[audit_ref], trace_id=UUID(context.trace_id), evaluated_at=evaluated_at, evaluated_by=context.user.id)
        self.db.add(assessment)
        self.db.flush()
        record.latest_assessment_id = assessment.id
        record.policy_decision_refs = [policy_ref]
        self.db.flush()
        proposal_lock_version = record.lock_version
        self.db.commit()
        return {
            **self._assessment_projection(assessment),
            "proposalLockVersion": proposal_lock_version,
        }

    def submit_review(
        self,
        project_id: UUID,
        proposal_id: UUID,
        payload: SubmitGraphPromotionReviewRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.promotion.promote")
        scope = self._scope(project_id, context)
        record = self._require_proposal(scope, proposal_id, for_update=True)
        self._require_lock(record.lock_version, payload.expectedProposalLockVersion)
        assessment = self._require_assessment(scope, record, payload.assessmentId)
        if not assessment.eligible:
            raise GraphPromotionError("GRAPH_PROMOTION_NOT_ELIGIBLE")
        approval = ApprovalService(self.db)._get_or_create_pending_approval(approval_type=ApprovalType.OTHER, resource_type="canonical_graph_promotion", resource_id=f"{record.id}:{payload.idempotencyKey}", summary=f"Approval required before promoting Canonical Execution Graph proposal {record.id}.", payload={"action": "graph_promotion.review", "projectId": str(project_id), "proposalId": str(record.id), "assessmentId": str(assessment.id), "expectedProposalLockVersion": record.lock_version, "expectedBaseVersionId": str(record.base_version_id), "expectedBaseVersionHash": record.base_version_hash, "idempotencyKey": payload.idempotencyKey, "expiresAt": payload.expiresAt.isoformat() if payload.expiresAt else None, "comment": payload.comment, "requestedBy": str(context.user.id)}, context=context, commit=False)
        record.status = "pending_review"
        record.approval_refs = [{"type": "approval", "ref": f"approval://approvals/{approval.id}", "status": "pending"}]
        ccg = self.db.get(CorrectionProposal, record.correction_proposal_id)
        if ccg:
            ccg.status = "pending_approval"
            ccg.approval_refs = record.approval_refs
        self.db.commit()
        return {"approvalRequired": True, "approvalId": str(approval.id), "status": approval.status.value, "proposal": self._proposal_projection(record)}

    def request_rollback_review(
        self,
        project_id: UUID,
        graph_id: UUID,
        payload: RequestGraphRollbackReviewRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        """Create the mandatory human-review record for a canonical rollback."""

        self._require_capability(context, "graph.promotion.rollback")
        scope = self._scope(project_id, context)
        graph = self.repository.find_graph(
            scope.tenant_id, scope.workspace_id, project_id, graph_id, for_update=True
        )
        if not graph:
            raise GraphPromotionError("GRAPH_NOT_FOUND", status_code=404)
        active = self._active_version(scope, graph)
        if (
            not active
            or active.id != payload.expectedActiveVersionId
            or active.content_hash != payload.expectedActiveVersionHash
        ):
            raise GraphPromotionError("GRAPH_ROLLBACK_ACTIVE_VERSION_CHANGED")
        target = self.repository.find_version(
            scope.tenant_id,
            scope.workspace_id,
            project_id,
            graph.id,
            payload.rollbackTargetVersionId,
        )
        if (
            not target
            or not target.is_frozen
            or target.source != GraphSource.CANONICAL
            or target.status
            not in {GraphStatus.ACTIVE, GraphStatus.SUPERSEDED, GraphStatus.DEPRECATED}
        ):
            raise GraphPromotionError("GRAPH_ROLLBACK_TARGET_INVALID")
        approval = ApprovalService(self.db)._get_or_create_pending_approval(
            approval_type=ApprovalType.OTHER,
            resource_type="canonical_graph_rollback",
            resource_id=f"{graph.id}:{payload.idempotencyKey}",
            summary=f"Approval required before rolling back Canonical Execution Graph {graph.id}.",
            payload={
                "action": "graph_promotion.rollback_review",
                "projectId": str(project_id),
                "graphId": str(graph.id),
                "rollbackTargetVersionId": str(target.id),
                "expectedActiveVersionId": str(active.id),
                "expectedActiveVersionHash": active.content_hash,
                "reasonCode": payload.reasonCode,
                "idempotencyKey": payload.idempotencyKey,
                "expiresAt": payload.expiresAt.isoformat() if payload.expiresAt else None,
                "comment": payload.comment,
                "requestedBy": str(context.user.id),
            },
            context=context,
            commit=False,
        )
        self.db.commit()
        return {
            "approvalRequired": True,
            "approvalId": str(approval.id),
            "status": approval.status.value,
            "graphId": str(graph.id),
            "rollbackTargetVersionId": str(target.id),
        }

    def promote(
        self,
        project_id: UUID,
        proposal_id: UUID,
        payload: PromoteGraphRequest,
        context: ServiceContext,
        *,
        commit: bool = True,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.promotion.promote")
        scope = self._scope(project_id, context)
        acquire_transaction_advisory_lock(self.db, "canonical-graph-promotion", f"{scope.tenant_id}:{scope.workspace_id}:{proposal_id}")
        retry = self.db.scalar(select(CanonicalGraphPromotionRecord).where(CanonicalGraphPromotionRecord.tenant_id == scope.tenant_id, CanonicalGraphPromotionRecord.workspace_id == scope.workspace_id, CanonicalGraphPromotionRecord.idempotency_key == payload.idempotencyKey))
        request_hash = canonical_hash(payload.model_dump(mode="json"))
        if retry:
            if retry.request_hash != request_hash:
                raise GraphPromotionError("GRAPH_PROMOTION_IDEMPOTENCY_CONFLICT")
            return self._promotion_projection(retry, deduplicated=True)
        record = self._require_proposal(scope, proposal_id, for_update=True)
        if record.status not in {"validated", "pending_review"}:
            raise GraphPromotionError("GRAPH_PROMOTION_PROPOSAL_STATE_INVALID")
        self._require_lock(record.lock_version, payload.expectedProposalLockVersion)
        assessment = self._require_assessment(scope, record, payload.assessmentId)
        self._require_assessment_current(record, assessment)
        if not assessment.eligible:
            raise GraphPromotionError("GRAPH_PROMOTION_NOT_ELIGIBLE")
        graph = self.repository.find_graph(scope.tenant_id, scope.workspace_id, project_id, record.graph_id, for_update=True)
        if not graph:
            raise GraphPromotionError("GRAPH_NOT_FOUND", status_code=404)
        active = self._active_version(scope, graph)
        if payload.expectedBaseVersionId != record.base_version_id or payload.expectedBaseVersionHash != record.base_version_hash:
            raise GraphPromotionError("GRAPH_PROMOTION_BASE_REQUEST_MISMATCH")
        if active and (active.id != record.base_version_id or active.content_hash != record.base_version_hash or active.lock_version != record.base_version_lock_version):
            raise GraphPromotionError("GRAPH_PROMOTION_BASE_CHANGED")
        if not active:
            base = self.db.get(CanonicalExecutionGraphVersion, record.base_version_id)
            if (
                not base
                or base.graph_id != graph.id
                or base.status != GraphStatus.CANDIDATE
                or base.source != GraphSource.CANDIDATE
                or base.is_frozen
                or base.content_hash != record.base_version_hash
                or base.lock_version != record.base_version_lock_version
            ):
                raise GraphPromotionError("GRAPH_PROMOTION_ACTIVE_BASE_UNAVAILABLE")
        candidate = self._require_candidate(record)
        if candidate.content_hash != record.candidate_version_hash:
            raise GraphPromotionError("GRAPH_PROMOTION_CANDIDATE_CHANGED")
        approval_refs: list[dict[str, Any]] = []
        automatic = assessment.automatic_promotion_allowed and payload.approvalId is None
        if automatic:
            build = self.db.get(CandidateGraphBuildRun, record.candidate_build_id)
            if build is None:
                raise GraphPromotionError("GRAPH_PROMOTION_CANDIDATE_BUILD_UNAVAILABLE")
            mode, binding, policy, _fallback = self.resolver.resolve(
                tenant_id=scope.tenant_id,
                workspace_id=scope.workspace_id,
                project_id=project_id,
                environment_id=graph.environment_id,
            )
            if binding is not None:
                acquire_transaction_advisory_lock(
                    self.db,
                    "controlled-graph-autonomy-window",
                    str(binding.id),
                )
            current_checks, _current_inputs, current_eligible, current_automatic, _human_required = (
                self.evaluator.evaluate(
                    proposal=record,
                    graph=graph,
                    candidate=candidate,
                    build=build,
                    mode=mode,
                    binding=binding,
                    policy=policy,
                    replay_ids=list(assessment.input_snapshot.get("replayIds") or []),
                    shadow_ids=[
                        UUID(item)
                        for item in assessment.input_snapshot.get("shadowRunIds") or []
                    ],
                )
            )
            if (
                not current_eligible
                or not current_automatic
                or any(not item["passed"] for item in current_checks)
            ):
                operational_metrics.increment("graph.auto_promotion.eligibility_rejected")
                raise GraphPromotionError("GRAPH_PROMOTION_AUTOMATIC_ELIGIBILITY_CHANGED")
            promotion_type = "policy_approved_auto_promotion"
            actor_type = "system"
            actor_ref = GRAPH_PROMOTION_SYSTEM_ACTOR
            human_approval = False
        else:
            approval = self._approved_review(record, assessment, payload.approvalId)
            approval_refs = [{"type": "approval", "ref": f"approval://approvals/{approval.id}", "status": "approved", "decidedBy": str(approval.decided_by) if approval.decided_by else None}]
            promotion_type = "human_approved_promotion"
            actor_type = "human"
            actor_ref = f"user://users/{context.user.id}"
            human_approval = True
        guardrail_ref = self._record_guardrail(context, record, decision="allow", reason="Graph Promotion risk and immutable base were re-evaluated by Service.")
        with traced_operation(self.db, trace_id=context.trace_id, execution_id=None, root_span_name="ceg.promotion", span_name="ceg.canonical.promote", service_name="orchestrator-service", attributes={"proposalId": str(record.id), "graphId": str(graph.id), "promotionType": promotion_type, "humanApproval": human_approval, "baseVersionHash": record.base_version_hash, "candidateVersionHash": record.candidate_version_hash}, parent_span_id=context.parent_span_id):
            target = self._create_promoted_version(scope, graph, candidate, record, promotion_type, context, active=active)
            now = datetime.now(timezone.utc)
            promotion_id = uuid4()
            audit_ref = self._audit(context, "canonical_graph.promote", "canonical_graph_promotion", promotion_id, {"beforeVersionId": str(record.base_version_id), "beforeVersionHash": record.base_version_hash, "targetVersionId": str(target.id), "targetVersionHash": target.content_hash, "promotionType": promotion_type, "actorType": actor_type, "humanApproval": human_approval, "approvalRefs": approval_refs, "policyDecisionRefs": assessment.policy_decision_refs, "guardrailEventRefs": [guardrail_ref]})
            promotion = CanonicalGraphPromotionRecord(id=promotion_id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=project_id, graph_id=graph.id, proposal_id=record.id, assessment_id=assessment.id, before_version_id=record.base_version_id, before_version_hash=record.base_version_hash, candidate_version_id=candidate.id, target_version_id=target.id, target_version_hash=target.content_hash, promotion_type=promotion_type, actor_type=actor_type, actor_ref=actor_ref, human_approval=human_approval, approval_refs=approval_refs, policy_decision_refs=assessment.policy_decision_refs, eligibility_snapshot=self._assessment_projection(assessment), policy_version_id=assessment.policy_version_id, policy_version_hash=assessment.policy_version_hash, replay_refs=[{"type": "replay", "ref": f"replay://repository/{item}"} for item in assessment.input_snapshot.get("replayIds", [])], shadow_refs=[{"type": "shadow", "ref": f"gate-shadow://runs/{item}"} for item in assessment.input_snapshot.get("shadowRunIds", [])], audit_refs=[audit_ref], rollback_target_version_id=active.id if active else record.base_version_id, status="promoted", idempotency_key=payload.idempotencyKey, request_hash=request_hash, trace_id=UUID(context.trace_id), promoted_at=now, promoted_by=None if automatic else context.user.id)
            self.db.add(promotion)
            self.db.flush()
            record.status = "promoted"
            record.approval_refs = approval_refs
            record.policy_decision_refs = assessment.policy_decision_refs
            ccg = self.db.get(CorrectionProposal, record.correction_proposal_id)
            if ccg:
                ccg.status = "approved" if human_approval else "draft"
                ccg.approval_refs = approval_refs
                ccg.promotion_refs = [{"type": "canonical_graph_promotion", "id": str(promotion.id), "targetVersionId": str(target.id)}]
                ccg.promoted_at = now
        if commit:
            self.db.commit()
        if automatic:
            operational_metrics.increment("graph.auto_promotion.success")
        return self._promotion_projection(promotion)

    def rollback(
        self,
        project_id: UUID,
        graph_id: UUID,
        payload: RollbackGraphPromotionRequest,
        context: ServiceContext,
        *,
        commit: bool = True,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.promotion.rollback")
        scope = self._scope(project_id, context)
        acquire_transaction_advisory_lock(self.db, "canonical-graph-rollback", f"{scope.tenant_id}:{scope.workspace_id}:{graph_id}")
        retry = self.db.scalar(select(CanonicalGraphPromotionRecord).where(CanonicalGraphPromotionRecord.tenant_id == scope.tenant_id, CanonicalGraphPromotionRecord.workspace_id == scope.workspace_id, CanonicalGraphPromotionRecord.idempotency_key == payload.idempotencyKey))
        request_hash = canonical_hash(payload.model_dump(mode="json"))
        if retry:
            if retry.request_hash != request_hash:
                raise GraphPromotionError("GRAPH_ROLLBACK_IDEMPOTENCY_CONFLICT")
            return self._promotion_projection(retry, deduplicated=True)
        graph = self.repository.find_graph(scope.tenant_id, scope.workspace_id, project_id, graph_id, for_update=True)
        if not graph:
            raise GraphPromotionError("GRAPH_NOT_FOUND", status_code=404)
        active = self._active_version(scope, graph)
        if not active or active.id != payload.expectedActiveVersionId or active.content_hash != payload.expectedActiveVersionHash:
            raise GraphPromotionError("GRAPH_ROLLBACK_ACTIVE_VERSION_CHANGED")
        target = self.repository.find_version(scope.tenant_id, scope.workspace_id, project_id, graph.id, payload.rollbackTargetVersionId)
        if not target or not target.is_frozen or target.source != GraphSource.CANONICAL or target.status not in {GraphStatus.ACTIVE, GraphStatus.SUPERSEDED, GraphStatus.DEPRECATED}:
            raise GraphPromotionError("GRAPH_ROLLBACK_TARGET_INVALID")
        approval = self.db.get(Approval, payload.approvalId)
        if (
            not approval
            or approval.status != ApprovalStatus.APPROVED
            or approval.resource_type != "canonical_graph_rollback"
            or str(graph.id) not in approval.resource_id
            or str(approval.payload.get("graphId")) != str(graph.id)
            or str(approval.payload.get("rollbackTargetVersionId")) != str(target.id)
            or str(approval.payload.get("expectedActiveVersionId")) != str(active.id)
            or str(approval.payload.get("expectedActiveVersionHash")) != active.content_hash
            or str(approval.payload.get("reasonCode")) != payload.reasonCode
        ):
            raise GraphPromotionError("GRAPH_ROLLBACK_APPROVAL_INVALID")
        source_promotion = self.db.scalar(select(CanonicalGraphPromotionRecord).where(CanonicalGraphPromotionRecord.target_version_id == target.id))
        if not source_promotion:
            raise GraphPromotionError("GRAPH_ROLLBACK_TARGET_PROVENANCE_MISSING")
        proposal = self.db.get(GraphCorrectionProposalRecord, source_promotion.proposal_id)
        assessment = self.db.get(GraphPromotionEligibilityAssessment, source_promotion.assessment_id)
        if not proposal or not assessment:
            raise GraphPromotionError("GRAPH_ROLLBACK_TARGET_PROVENANCE_MISSING")
        active_promotion = self.db.scalar(
            select(CanonicalGraphPromotionRecord).where(
                CanonicalGraphPromotionRecord.target_version_id == active.id
            )
        )
        clone = self._clone_canonical_version(scope, graph, target, active, "human_approved_rollback", context)
        approval_refs = [{"type": "approval", "ref": f"approval://approvals/{approval.id}", "status": "approved"}]
        now = datetime.now(timezone.utc)
        promotion_id = uuid4()
        audit_ref = self._audit(context, "canonical_graph.rollback", "canonical_graph_promotion", promotion_id, {"beforeVersionId": str(active.id), "targetVersionId": str(clone.id), "rollbackSourceVersionId": str(target.id), "reasonCode": payload.reasonCode, "approvalRefs": approval_refs})
        promotion = CanonicalGraphPromotionRecord(id=promotion_id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=project_id, graph_id=graph.id, proposal_id=proposal.id, assessment_id=assessment.id, before_version_id=active.id, before_version_hash=active.content_hash, candidate_version_id=source_promotion.candidate_version_id, target_version_id=clone.id, target_version_hash=clone.content_hash, promotion_type="human_approved_rollback", actor_type="human", actor_ref=f"user://users/{context.user.id}", human_approval=True, approval_refs=approval_refs, policy_decision_refs=[], eligibility_snapshot={"rollbackReasonCode": payload.reasonCode, "sourcePromotionId": str(source_promotion.id)}, policy_version_id=assessment.policy_version_id, policy_version_hash=assessment.policy_version_hash, replay_refs=source_promotion.replay_refs, shadow_refs=source_promotion.shadow_refs, audit_refs=[audit_ref], rollback_target_version_id=target.id, status="rolled_back", idempotency_key=payload.idempotencyKey, request_hash=request_hash, trace_id=UUID(context.trace_id), promoted_at=now, promoted_by=context.user.id)
        if (
            active_promotion is not None
            and active_promotion.promotion_type == "policy_approved_auto_promotion"
        ):
            active_assessment = self.db.get(
                GraphPromotionEligibilityAssessment,
                active_promotion.assessment_id,
            )
            if active_assessment is not None:
                self._pause_autonomy_for_rollback_rate(
                    active_assessment,
                    now=now,
                    context=context,
                )
        self.db.add(promotion)
        self.db.flush()
        proposal.rollback_refs = [{"type": "canonical_graph_rollback", "id": str(promotion.id), "targetVersionId": str(clone.id)}]
        if commit:
            self.db.commit()
        if (
            active_promotion is not None
            and active_promotion.promotion_type == "policy_approved_auto_promotion"
        ):
            operational_metrics.increment("graph.auto_promotion.rollback")
        return self._promotion_projection(promotion)

    # -- internals --------------------------------------------------------

    def _pause_autonomy_for_rollback_rate(
        self,
        assessment: GraphPromotionEligibilityAssessment,
        *,
        now: datetime,
        context: ServiceContext,
    ) -> None:
        if assessment.binding_id is None:
            return
        acquire_transaction_advisory_lock(
            self.db,
            "controlled-graph-autonomy-window",
            str(assessment.binding_id),
        )
        binding = self.db.scalar(
            select(GraphLearningPolicyBinding)
            .where(GraphLearningPolicyBinding.id == assessment.binding_id)
            .with_for_update()
        )
        if binding is None or binding.autonomy_paused:
            return
        policy = self.db.get(GraphLearningPolicyVersion, binding.policy_version_id)
        state = _controlled_autonomy_window_state(
            self.db,
            binding=binding,
            policy_document=policy.policy_document if policy else {},
        )
        projected_rollback_count = int(state["rollbackCount"]) + 1
        automatic_count = int(state["automaticPromotionCount"])
        projected_rate = (
            projected_rollback_count / automatic_count if automatic_count else 1.0
        )
        if (
            automatic_count
            < int(state["minimumPromotionsForRatePause"])
            or projected_rate < float(state["rollbackRateThreshold"])
        ):
            return
        binding.autonomy_paused = True
        binding.pause_reason_code = "GRAPH_AUTONOMY_ROLLBACK_RATE_EXCEEDED"
        binding.paused_at = now
        audit_ref = self._audit(
            context,
            "graph_autonomy.auto_pause",
            "graph_learning_policy_binding",
            binding.id,
            {
                "reasonCode": binding.pause_reason_code,
                "windowSeconds": state["windowSeconds"],
                "automaticPromotionCount": automatic_count,
                "rollbackCount": projected_rollback_count,
                "rollbackRate": projected_rate,
                "rollbackRateThreshold": state["rollbackRateThreshold"],
            },
        )
        binding.audit_refs = [*list(binding.audit_refs or []), audit_ref]
        operational_metrics.increment("graph.auto_promotion.auto_suspension")

    def _validate_patch(self, record: GraphCorrectionProposalRecord, candidate: CanonicalExecutionGraphVersion, build: CandidateGraphBuildRun, validator_version: str) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        material = self._topology_material(candidate)
        if candidate.content_hash != record.candidate_version_hash:
            issues.append(self._issue("GRAPH_VALIDATION_CANDIDATE_HASH_MISMATCH", "conflict"))
        if not build.evidence_summary or not record.evidence_refs:
            issues.append(self._issue("GRAPH_VALIDATION_EVIDENCE_INCOMPLETE", "evidence"))
        if build.candidate_version_id != candidate.id:
            issues.append(self._issue("GRAPH_VALIDATION_PROVENANCE_MISMATCH", "provenance"))
        if candidate.applicability.get("status") not in {"fresh", "valid"}:
            issues.append(self._issue("GRAPH_VALIDATION_APPLICABILITY_NOT_FRESH", "applicability", severity="warning"))
        self._apply_patch_to_material(material, record.structured_patch, issues)
        self._validate_material(material, issues)
        valid = not any(item["blocking"] for item in issues)
        reason_codes = [item["code"] for item in issues] or ["GRAPH_VALIDATION_PASSED"]
        report = {"schemaVersion": "phase8.graph-correction-validation.v1", "proposalId": str(record.id), "baseVersionId": str(record.base_version_id), "baseVersionHash": record.base_version_hash, "candidateVersionId": str(candidate.id), "candidateVersionHash": candidate.content_hash, "patchHash": record.patch_hash, "validatorVersion": validator_version, "summary": {"valid": valid, "errorCount": sum(item["severity"] == "error" for item in issues), "warningCount": sum(item["severity"] == "warning" for item in issues)}, "checks": ["schema", "references", "path_connectivity", "scope", "provenance", "risk", "evidence", "applicability", "conflicts"], "issues": issues, "reasonCodes": reason_codes}
        report["reportHash"] = canonical_hash(report)
        return report

    @staticmethod
    def _issue(code: str, check: str, *, severity: str = "error", operation_id: str | None = None) -> dict[str, Any]:
        return {"code": code, "check": check, "severity": severity, "blocking": severity == "error", "operationId": operation_id}

    def _topology_material(self, version: CanonicalExecutionGraphVersion) -> dict[str, dict[str, dict[str, Any]]]:
        nodes = list(self.db.scalars(select(CanonicalExecutionGraphNode).where(CanonicalExecutionGraphNode.version_id == version.id)))
        edges = list(self.db.scalars(select(CanonicalExecutionGraphEdge).where(CanonicalExecutionGraphEdge.version_id == version.id)))
        paths = list(self.db.scalars(select(CanonicalExecutionGraphPath).where(CanonicalExecutionGraphPath.version_id == version.id)))
        steps = list(self.db.scalars(select(CanonicalExecutionGraphPathStep).where(CanonicalExecutionGraphPathStep.version_id == version.id)))
        steps_by_path: dict[UUID, list[CanonicalExecutionGraphPathStep]] = {}
        for step in steps:
            steps_by_path.setdefault(step.path_id, []).append(step)
        node_key = {item.id: item.semantic_key for item in nodes}
        edge_key = {item.id: item.client_key for item in edges}
        return {
            "node": {str(item.id): {"id": str(item.id), "stableKey": item.semantic_key, "clientKey": item.client_key, "nodeType": item.node_type, "display": deepcopy(item.display_metadata), "attributes": deepcopy(item.attributes_json), "externalRefs": deepcopy(item.external_refs), "riskLevel": item.risk_level, "confidence": float(item.confidence), "lockVersion": item.lock_version} for item in nodes},
            "edge": {str(item.id): {"id": str(item.id), "stableKey": item.client_key, "clientKey": item.client_key, "edgeType": item.edge_type, "sourceStableKey": node_key.get(item.source_node_id), "targetStableKey": node_key.get(item.target_node_id), "condition": deepcopy(item.condition_json), "riskLevel": item.risk_level, "reviewStatus": item.review_status, "confidence": float(item.confidence), "lockVersion": item.lock_version} for item in edges},
            "path": {str(item.id): {"id": str(item.id), "stableKey": item.path_key, "clientKey": item.client_key, "pathKey": item.path_key, "name": item.name, "description": item.description, "entryStableKey": node_key.get(item.entry_node_id), "exitStableKey": node_key.get(item.exit_node_id), "preconditions": deepcopy(item.preconditions), "postconditions": deepcopy(item.postconditions), "riskLevel": item.risk_level, "applicability": deepcopy(item.applicability), "evidenceRefs": deepcopy(item.evidence_refs), "confidence": float(item.confidence), "lockVersion": item.lock_version, "steps": [{"clientKey": step.client_key, "order": step.step_order, "nodeStableKey": node_key.get(step.node_id), "viaEdgeStableKey": edge_key.get(step.via_edge_id) if step.via_edge_id else None, "conditions": deepcopy(step.conditions), "evidenceRefs": deepcopy(step.evidence_refs)} for step in sorted(steps_by_path.get(item.id, []), key=lambda row: row.step_order)]} for item in paths},
        }

    def _apply_patch_to_material(self, material: dict[str, dict[str, dict[str, Any]]], patch: dict[str, Any], issues: list[dict[str, Any]]) -> None:
        allowed = {
            "node": {"clientKey", "nodeType", "display", "attributes", "externalRefs", "riskLevel", "confidence"},
            "edge": {"clientKey", "edgeType", "sourceStableKey", "targetStableKey", "condition", "riskLevel", "reviewStatus", "confidence"},
            "path": {"clientKey", "pathKey", "name", "description", "entryStableKey", "exitStableKey", "preconditions", "postconditions", "riskLevel", "applicability", "evidenceRefs", "confidence", "steps"},
        }
        for operation in patch.get("operations", []):
            entity = operation["entityType"]
            operation_id = operation["operationId"]
            bucket = material[entity]
            target_key = str(operation.get("targetId") or "")
            target = bucket.get(target_key)
            if operation["operation"] != "add" and target is None:
                issues.append(self._issue("GRAPH_VALIDATION_TARGET_NOT_FOUND", "references", operation_id=operation_id))
                continue
            if target and target["stableKey"] != operation["stableKey"]:
                issues.append(self._issue("GRAPH_VALIDATION_STABLE_ID_MISMATCH", "references", operation_id=operation_id))
                continue
            if target and target["lockVersion"] != operation.get("expectedLockVersion"):
                issues.append(self._issue("GRAPH_VALIDATION_TARGET_LOCK_CONFLICT", "conflict", operation_id=operation_id))
                continue
            value = deepcopy(operation.get("value") or {})
            if set(value) - allowed[entity]:
                issues.append(self._issue("GRAPH_VALIDATION_ATTRIBUTE_NOT_ALLOWED", "schema", operation_id=operation_id))
                continue
            if operation["operation"] == "add":
                if any(item["stableKey"] == operation["stableKey"] for item in bucket.values()):
                    issues.append(self._issue("GRAPH_VALIDATION_STABLE_ID_CONFLICT", "conflict", operation_id=operation_id))
                    continue
                required = {"node": {"nodeType", "display"}, "edge": {"edgeType", "sourceStableKey", "targetStableKey"}, "path": {"name", "entryStableKey", "exitStableKey", "steps"}}[entity]
                if not required <= set(value):
                    issues.append(self._issue("GRAPH_VALIDATION_ADD_FIELDS_MISSING", "schema", operation_id=operation_id))
                    continue
                bucket[f"add:{operation_id}"] = {"id": None, "stableKey": operation["stableKey"], "lockVersion": 1, **value}
            elif operation["operation"] == "remove":
                del bucket[target_key]
            elif operation["operation"] in {"update", "reorder"}:
                if operation["operation"] == "reorder" and set(value) != {"steps"}:
                    issues.append(self._issue("GRAPH_VALIDATION_REORDER_SHAPE_INVALID", "schema", operation_id=operation_id))
                    continue
                if target is None:
                    issues.append(
                        self._issue(
                            "GRAPH_VALIDATION_TARGET_NOT_FOUND",
                            "references",
                            operation_id=operation_id,
                        )
                    )
                    continue
                target.update(value)

    def _validate_material(self, material: dict[str, dict[str, dict[str, Any]]], issues: list[dict[str, Any]]) -> None:
        node_keys = {item["stableKey"] for item in material["node"].values()}
        if not node_keys:
            issues.append(self._issue("GRAPH_VALIDATION_EMPTY_GRAPH", "schema"))
        for edge in material["edge"].values():
            if edge.get("sourceStableKey") not in node_keys or edge.get("targetStableKey") not in node_keys:
                issues.append(self._issue("GRAPH_VALIDATION_EDGE_ENDPOINT_MISSING", "references"))
            if edge.get("sourceStableKey") == edge.get("targetStableKey"):
                issues.append(self._issue("GRAPH_VALIDATION_EDGE_SELF_LOOP", "references"))
        for path in material["path"].values():
            steps = path.get("steps") or []
            orders = [item.get("order") for item in steps]
            if not steps or orders != list(range(1, len(steps) + 1)):
                issues.append(self._issue("GRAPH_VALIDATION_PATH_ORDER_INVALID", "path_connectivity"))
                continue
            if path.get("entryStableKey") != steps[0].get("nodeStableKey") or path.get("exitStableKey") != steps[-1].get("nodeStableKey"):
                issues.append(self._issue("GRAPH_VALIDATION_PATH_BOUNDARY_MISMATCH", "path_connectivity"))
            for index, step in enumerate(steps):
                if step.get("nodeStableKey") not in node_keys:
                    issues.append(self._issue("GRAPH_VALIDATION_PATH_NODE_MISSING", "references"))
                if index == 0 and step.get("viaEdgeStableKey") is not None:
                    issues.append(self._issue("GRAPH_VALIDATION_PATH_FIRST_EDGE_INVALID", "path_connectivity"))
                if index > 0:
                    matching_edges = [
                        item
                        for item in material["edge"].values()
                        if item["stableKey"] == step.get("viaEdgeStableKey")
                    ]
                    matching_edge = matching_edges[0] if matching_edges else None
                    if not matching_edge or matching_edge["sourceStableKey"] != steps[index - 1].get("nodeStableKey") or matching_edge["targetStableKey"] != step.get("nodeStableKey"):
                        issues.append(self._issue("GRAPH_VALIDATION_PATH_DISCONNECTED", "path_connectivity"))
        referenced_nodes = {edge.get("sourceStableKey") for edge in material["edge"].values()} | {edge.get("targetStableKey") for edge in material["edge"].values()} | {step.get("nodeStableKey") for path in material["path"].values() for step in path.get("steps", [])}
        if not referenced_nodes <= node_keys:
            issues.append(self._issue("GRAPH_VALIDATION_REMOVED_NODE_STILL_REFERENCED", "references"))

    def _create_promoted_version(self, scope: Any, graph: CanonicalExecutionGraph, candidate: CanonicalExecutionGraphVersion, record: GraphCorrectionProposalRecord, promotion_type: str, context: ServiceContext, *, active: CanonicalExecutionGraphVersion | None) -> CanonicalExecutionGraphVersion:
        material = self._topology_material(candidate)
        issues: list[dict[str, Any]] = []
        self._apply_patch_to_material(material, record.structured_patch, issues)
        self._validate_material(material, issues)
        if any(item["blocking"] for item in issues):
            raise GraphPromotionError("GRAPH_PROMOTION_PATCH_REVALIDATION_FAILED")
        return self._persist_material_as_canonical(scope, graph, candidate, material, promotion_type, context, active=active)

    def _clone_canonical_version(self, scope: Any, graph: CanonicalExecutionGraph, source: CanonicalExecutionGraphVersion, active: CanonicalExecutionGraphVersion, promotion_type: str, context: ServiceContext) -> CanonicalExecutionGraphVersion:
        return self._persist_material_as_canonical(scope, graph, source, self._topology_material(source), promotion_type, context, active=active)

    def _persist_material_as_canonical(self, scope: Any, graph: CanonicalExecutionGraph, source: CanonicalExecutionGraphVersion, material: dict[str, dict[str, dict[str, Any]]], promotion_type: str, context: ServiceContext, *, active: CanonicalExecutionGraphVersion | None) -> CanonicalExecutionGraphVersion:
        now = datetime.now(timezone.utc)
        version_id = uuid4()
        version_number = self.repository.max_version_number(scope.tenant_id, scope.workspace_id, graph.id) + 1
        metadata = {"promotionType": promotion_type, "promotedFromVersionId": str(source.id), "immutableCanonical": True}
        version = CanonicalExecutionGraphVersion(id=version_id, graph_id=graph.id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=graph.project_id, environment_id=graph.environment_id, scope_type=graph.scope_type, scope_id=graph.scope_id, version_number=version_number, version_ref=f"ceg-version://versions/{version_id}", parent_version_id=active.id if active else source.id, status=GraphStatus.CANDIDATE, source=GraphSource.CANDIDATE, schema_version="ceg.v1", content_hash=canonical_hash({"pendingPromotionVersionId": str(version_id)}), source_refs=[{"type": "graph_version", "ref": source.version_ref, "contentHash": source.content_hash}], applicability=deepcopy(source.applicability), is_frozen=False, frozen_at=None, frozen_by=None, retention_policy="canonical-default", retention_until=None, retention_status="active", legal_hold=False, idempotency_key=f"graph-promotion:{version_id}", request_hash=canonical_hash({"sourceVersionId": str(source.id), "promotionType": promotion_type}), audit_refs=[], trace_id=UUID(context.trace_id), lock_version=1, created_by=context.user.id, updated_by=context.user.id, metadata_json={})
        self.db.add(version)
        self.db.flush()
        node_ids: dict[str, UUID] = {}
        nodes: list[CanonicalExecutionGraphNode] = []
        for item in material["node"].values():
            node_id = uuid4()
            node_ids[item["stableKey"]] = node_id
            node = CanonicalExecutionGraphNode(id=node_id, node_ref=f"ceg-node://versions/{version.id}/nodes/{node_id}", version_id=version.id, graph_id=graph.id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=graph.project_id, scope_id=graph.scope_id, client_key=item.get("clientKey") or f"promoted-node-{len(nodes)+1:04d}", semantic_key=item["stableKey"], node_type=item["nodeType"], display_metadata=deepcopy(item["display"]), attributes_json=deepcopy(item.get("attributes") or {}), external_refs=deepcopy(item.get("externalRefs") or []), risk_level=item.get("riskLevel", "low"), source="canonical", confidence=Decimal(str(item.get("confidence", 1.0))), request_hash=canonical_hash(item), audit_refs=[], trace_id=UUID(context.trace_id), created_by=context.user.id, updated_by=context.user.id)
            self.db.add(node)
            nodes.append(node)
        self.db.flush()
        edge_ids: dict[str, UUID] = {}
        edges: list[CanonicalExecutionGraphEdge] = []
        for item in material["edge"].values():
            edge_id = uuid4()
            edge_ids[item["stableKey"]] = edge_id
            edge = CanonicalExecutionGraphEdge(id=edge_id, edge_ref=f"ceg-edge://versions/{version.id}/edges/{edge_id}", version_id=version.id, graph_id=graph.id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=graph.project_id, scope_id=graph.scope_id, client_key=item.get("clientKey") or item["stableKey"], edge_type=item["edgeType"], source_node_id=node_ids[item["sourceStableKey"]], target_node_id=node_ids[item["targetStableKey"]], condition_json=deepcopy(item.get("condition") or {}), risk_level=item.get("riskLevel", "low"), review_status="approved" if item.get("reviewStatus") == "approved" else "not_required", source="canonical", confidence=Decimal(str(item.get("confidence", 1.0))), semantic_hash=canonical_hash({"edgeType": item["edgeType"], "source": item["sourceStableKey"], "target": item["targetStableKey"]}), request_hash=canonical_hash(item), audit_refs=[], trace_id=UUID(context.trace_id), created_by=context.user.id, updated_by=context.user.id)
            self.db.add(edge)
            edges.append(edge)
        self.db.flush()
        paths: list[CanonicalExecutionGraphPath] = []
        steps: list[CanonicalExecutionGraphPathStep] = []
        for item in material["path"].values():
            path_id = uuid4()
            path = CanonicalExecutionGraphPath(id=path_id, path_ref=f"ceg-path://versions/{version.id}/paths/{path_id}", version_id=version.id, graph_id=graph.id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=graph.project_id, scope_id=graph.scope_id, client_key=item.get("clientKey") or f"promoted-path-{len(paths)+1:04d}", path_key=item.get("pathKey") or item["stableKey"], name=item["name"], description=item.get("description"), entry_node_id=node_ids[item["entryStableKey"]], exit_node_id=node_ids[item["exitStableKey"]], preconditions=deepcopy(item.get("preconditions") or []), postconditions=deepcopy(item.get("postconditions") or []), risk_level=item.get("riskLevel", "low"), applicability=deepcopy(item.get("applicability") or {}), evidence_refs=deepcopy(item.get("evidenceRefs") or []), source="canonical", confidence=Decimal(str(item.get("confidence", 1.0))), request_hash=canonical_hash(item), audit_refs=[], trace_id=UUID(context.trace_id), created_by=context.user.id, updated_by=context.user.id)
            self.db.add(path)
            paths.append(path)
            self.db.flush()
            for step_item in item["steps"]:
                step_id = uuid4()
                step = CanonicalExecutionGraphPathStep(id=step_id, step_ref=f"ceg-step://versions/{version.id}/paths/{path.id}/steps/{step_id}", path_id=path.id, version_id=version.id, graph_id=graph.id, tenant_id=scope.tenant_id, workspace_id=scope.workspace_id, project_id=graph.project_id, scope_id=graph.scope_id, client_key=step_item["clientKey"], step_order=step_item["order"], node_id=node_ids[step_item["nodeStableKey"]], via_edge_id=edge_ids.get(step_item.get("viaEdgeStableKey")), conditions=deepcopy(step_item.get("conditions") or []), evidence_refs=deepcopy(step_item.get("evidenceRefs") or []), audit_refs=[], trace_id=UUID(context.trace_id), created_by=context.user.id, updated_by=context.user.id)
                self.db.add(step)
                steps.append(step)
        self.db.flush()
        topology = build_graph_topology_material(nodes=nodes, edges=edges, paths=paths, steps=steps)
        final_source_refs = [{"type": "graph_version", "ref": source.version_ref, "contentHash": source.content_hash}]
        final_hash = build_graph_version_content_hash(graph=graph, parent_version_id=version.parent_version_id, source="canonical", source_refs=final_source_refs, schema_version="ceg.v1", applicability=version.applicability, metadata=metadata, topology=topology)
        version.source = GraphSource.CANONICAL
        version.status = GraphStatus.ACTIVE
        version.content_hash = final_hash
        version.source_refs = final_source_refs
        version.metadata_json = metadata
        version.is_frozen = True
        version.frozen_at = now
        version.frozen_by = context.user.id
        if active:
            active.status = GraphStatus.SUPERSEDED
        graph.status = GraphStatus.ACTIVE
        graph.updated_by = context.user.id
        self.db.flush()
        return version

    def _active_version(self, scope: Any, graph: CanonicalExecutionGraph) -> CanonicalExecutionGraphVersion | None:
        rows = list(self.db.scalars(select(CanonicalExecutionGraphVersion).where(CanonicalExecutionGraphVersion.tenant_id == scope.tenant_id, CanonicalExecutionGraphVersion.workspace_id == scope.workspace_id, CanonicalExecutionGraphVersion.project_id == graph.project_id, CanonicalExecutionGraphVersion.graph_id == graph.id, CanonicalExecutionGraphVersion.status == GraphStatus.ACTIVE, CanonicalExecutionGraphVersion.source == GraphSource.CANONICAL, CanonicalExecutionGraphVersion.is_frozen.is_(True)).with_for_update()))
        if len(rows) > 1:
            raise GraphPromotionError("GRAPH_ACTIVE_VERSION_CONFLICT")
        return rows[0] if rows else None

    def _load_proposal_inputs(self, scope: Any, payload: CreateGraphCorrectionProposalRequest) -> tuple[CanonicalExecutionGraph, CanonicalExecutionGraphVersion, CanonicalExecutionGraphVersion, CandidateGraphBuildRun]:
        graph = self.repository.find_graph(scope.tenant_id, scope.workspace_id, scope.project.id, payload.graphId)
        if not graph:
            raise GraphPromotionError("GRAPH_NOT_FOUND", status_code=404)
        base = self.repository.find_version(scope.tenant_id, scope.workspace_id, scope.project.id, graph.id, payload.baseVersionId)
        candidate = self.repository.find_version(scope.tenant_id, scope.workspace_id, scope.project.id, graph.id, payload.candidateVersionId)
        build = self.db.get(CandidateGraphBuildRun, payload.candidateBuildId)
        if not base or base.content_hash != payload.baseVersionHash or base.lock_version != payload.baseVersionLockVersion:
            raise GraphPromotionError("GRAPH_CORRECTION_BASE_MISMATCH")
        if base.status == GraphStatus.ACTIVE and (base.source != GraphSource.CANONICAL or not base.is_frozen):
            raise GraphPromotionError("GRAPH_CORRECTION_BASE_INVALID")
        if base.status not in {GraphStatus.ACTIVE, GraphStatus.CANDIDATE}:
            raise GraphPromotionError("GRAPH_CORRECTION_BASE_SUPERSEDED")
        if not candidate or candidate.status != GraphStatus.CANDIDATE or candidate.source != GraphSource.CANDIDATE or candidate.is_frozen or candidate.content_hash != payload.candidateVersionHash:
            raise GraphPromotionError("GRAPH_CORRECTION_CANDIDATE_INVALID")
        if not build or build.candidate_version_id != candidate.id or build.graph_id != graph.id or build.project_id != scope.project.id:
            raise GraphPromotionError("GRAPH_CORRECTION_PROVENANCE_INVALID")
        return graph, base, candidate, build

    def _require_candidate(self, record: GraphCorrectionProposalRecord) -> CanonicalExecutionGraphVersion:
        candidate = self.db.get(CanonicalExecutionGraphVersion, record.candidate_version_id)
        if not candidate or candidate.graph_id != record.graph_id or candidate.project_id != record.project_id or candidate.status != GraphStatus.CANDIDATE or candidate.source != GraphSource.CANDIDATE or candidate.is_frozen:
            raise GraphPromotionError("GRAPH_PROMOTION_CANDIDATE_INVALID")
        return candidate

    def _require_candidate_build(self, record: GraphCorrectionProposalRecord) -> CandidateGraphBuildRun:
        build = self.db.get(CandidateGraphBuildRun, record.candidate_build_id)
        if not build or build.candidate_version_id != record.candidate_version_id or build.graph_id != record.graph_id:
            raise GraphPromotionError("GRAPH_PROMOTION_PROVENANCE_INVALID")
        return build

    def _require_proposal(self, scope: Any, proposal_id: UUID, *, for_update: bool = False) -> GraphCorrectionProposalRecord:
        statement = select(GraphCorrectionProposalRecord).where(GraphCorrectionProposalRecord.id == proposal_id, GraphCorrectionProposalRecord.tenant_id == scope.tenant_id, GraphCorrectionProposalRecord.workspace_id == scope.workspace_id, GraphCorrectionProposalRecord.project_id == scope.project.id)
        if for_update:
            statement = statement.with_for_update()
        record = self.db.scalar(statement)
        if not record:
            raise GraphPromotionError("GRAPH_CORRECTION_PROPOSAL_NOT_FOUND", status_code=404)
        return record

    def _require_assessment(self, scope: Any, record: GraphCorrectionProposalRecord, assessment_id: UUID) -> GraphPromotionEligibilityAssessment:
        assessment = self.db.scalar(select(GraphPromotionEligibilityAssessment).where(GraphPromotionEligibilityAssessment.id == assessment_id, GraphPromotionEligibilityAssessment.tenant_id == scope.tenant_id, GraphPromotionEligibilityAssessment.workspace_id == scope.workspace_id, GraphPromotionEligibilityAssessment.project_id == scope.project.id, GraphPromotionEligibilityAssessment.proposal_id == record.id))
        if not assessment:
            raise GraphPromotionError("GRAPH_PROMOTION_ASSESSMENT_NOT_FOUND", status_code=404)
        return assessment

    def _require_assessment_current(self, record: GraphCorrectionProposalRecord, assessment: GraphPromotionEligibilityAssessment) -> None:
        if record.latest_assessment_id != assessment.id or assessment.candidate_version_id != record.candidate_version_id or assessment.base_version_id != record.base_version_id:
            raise GraphPromotionError("GRAPH_PROMOTION_ASSESSMENT_STALE")
        if record.validation_hash != (record.validation_report or {}).get("reportHash"):
            raise GraphPromotionError("GRAPH_PROMOTION_VALIDATION_STALE")
        if assessment.policy_version_id:
            policy = self.db.get(GraphLearningPolicyVersion, assessment.policy_version_id)
            if not policy or policy.status != "active" or policy.content_hash != assessment.policy_version_hash:
                raise GraphPromotionError("GRAPH_PROMOTION_POLICY_STALE")
        if assessment.binding_id:
            binding = self.db.get(GraphLearningPolicyBinding, assessment.binding_id)
            if not binding or binding.status != "active" or binding.autonomy_paused:
                raise GraphPromotionError("GRAPH_PROMOTION_AUTONOMY_PAUSED")

    def _approved_review(self, record: GraphCorrectionProposalRecord, assessment: GraphPromotionEligibilityAssessment, approval_id: UUID | None) -> Approval:
        if approval_id is None:
            raise GraphPromotionError("GRAPH_PROMOTION_HUMAN_APPROVAL_REQUIRED")
        approval = self.db.get(Approval, approval_id)
        if not approval or approval.status != ApprovalStatus.APPROVED or approval.resource_type != "canonical_graph_promotion" or str(record.id) not in approval.resource_id or str(approval.payload.get("assessmentId")) != str(assessment.id):
            raise GraphPromotionError("GRAPH_PROMOTION_APPROVAL_INVALID")
        return approval

    def _scope(self, project_id: UUID, context: ServiceContext) -> Any:
        try:
            return ScopeAuthorizationService(self.db).resolve_project(project_id, context)
        except ScopeAuthorizationError as exc:
            raise GraphPromotionError(exc.code, status_code=exc.status_code, field=exc.field) from exc

    @staticmethod
    def _require_capability(context: ServiceContext, capability: str) -> None:
        if capability not in set(context.user.capabilities):
            raise GraphPromotionError("GRAPH_CAPABILITY_REQUIRED", status_code=403, field=capability)

    @staticmethod
    def _require_lock(actual: int, expected: int) -> None:
        if actual != expected:
            raise GraphPromotionError("GRAPH_LOCK_VERSION_CONFLICT")

    def _record_guardrail(self, context: ServiceContext, record: GraphCorrectionProposalRecord, *, decision: str, reason: str) -> dict[str, Any]:
        result = GuardrailResult(rule_id="graph.promotion.preflight.v1", decision=GuardrailDecision(decision), reason=reason, evidence=[f"ceg-version://versions/{record.candidate_version_id}"], metadata={"proposalId": str(record.id), "riskLevel": record.risk_level, "writesGate": False, "writesMemory": False})
        self.guardrails.record_result(GuardrailContext(trace_id=context.trace_id, request_id=context.request_id, actor_id=context.user.id, actor_roles=list(context.user.roles), resource_type="graph_correction_proposal", resource_id=str(record.id), payload={"riskLevel": record.risk_level, "candidateVersionId": str(record.candidate_version_id)}), result)
        self.db.flush()
        event = self.db.scalar(select(GuardrailEvent).where(GuardrailEvent.rule_id == result.rule_id, GuardrailEvent.trace_id == UUID(context.trace_id), GuardrailEvent.request_id == context.request_id).order_by(GuardrailEvent.created_at.desc()))
        if not event:
            raise GraphPromotionError("GRAPH_GUARDRAIL_AUDIT_MISSING", status_code=500)
        return {"type": "guardrail", "ref": f"guardrail://events/{event.id}", "decision": decision}

    def _record_autonomy_guardrail(
        self,
        context: ServiceContext,
        binding: GraphLearningPolicyBinding,
        *,
        decision: str,
        reason: str,
    ) -> dict[str, Any]:
        result = GuardrailResult(
            rule_id="graph.autonomy.configuration.v1",
            decision=GuardrailDecision(decision),
            reason=reason,
            evidence=[f"graph-learning-binding://bindings/{binding.id}"],
            metadata={
                "projectId": str(binding.project_id),
                "scopeType": binding.scope_type,
                "scopeId": str(binding.scope_id),
                "policyVersionHash": binding.policy_version_hash,
            },
        )
        self.guardrails.record_result(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=list(context.user.roles),
                resource_type="graph_learning_policy_binding",
                resource_id=str(binding.id),
                payload={
                    "projectId": str(binding.project_id),
                    "learningMode": binding.learning_mode,
                    "policyVersionHash": binding.policy_version_hash,
                },
            ),
            result,
        )
        self.db.flush()
        event = self.db.scalar(
            select(GuardrailEvent)
            .where(
                GuardrailEvent.rule_id == result.rule_id,
                GuardrailEvent.trace_id == UUID(context.trace_id),
                GuardrailEvent.request_id == context.request_id,
            )
            .order_by(GuardrailEvent.created_at.desc())
        )
        if not event:
            raise GraphPromotionError("GRAPH_GUARDRAIL_AUDIT_MISSING", status_code=500)
        return {
            "type": "guardrail",
            "ref": f"guardrail://events/{event.id}",
            "decision": decision,
        }

    def _require_autonomy_binding_ready(self, binding: GraphLearningPolicyBinding) -> None:
        if binding.status != "active":
            raise GraphPromotionError("GRAPH_AUTONOMY_BINDING_INACTIVE")
        version = self.db.get(GraphLearningPolicyVersion, binding.policy_version_id)
        if (
            not version
            or version.status != "active"
            or version.content_hash != binding.policy_version_hash
        ):
            raise GraphPromotionError("GRAPH_AUTONOMY_POLICY_STALE")

    def _audit(self, context: ServiceContext, action: str, resource_type: str, resource_id: UUID, details: dict[str, Any]) -> dict[str, Any]:
        audit = write_audit_log(self.db, context.user.id, action, resource_type, str(resource_id), context.request_id, context.trace_id, details=details)
        self.db.flush()
        return {"type": "audit", "ref": f"audit://records/{audit.id}", "action": action}

    def _proposal_projection(self, record: GraphCorrectionProposalRecord, *, deduplicated: bool = False) -> dict[str, Any]:
        assessment = self.db.get(GraphPromotionEligibilityAssessment, record.latest_assessment_id) if record.latest_assessment_id else None
        return {"schemaVersion": "phase8.graph-correction-proposal.v1", "proposalId": str(record.id), "correctionProposalId": str(record.correction_proposal_id), "projectId": str(record.project_id), "environmentId": str(record.environment_id) if record.environment_id else None, "graphId": str(record.graph_id), "baseVersionId": str(record.base_version_id), "baseVersionHash": record.base_version_hash, "baseVersionLockVersion": record.base_version_lock_version, "candidateVersionId": str(record.candidate_version_id), "candidateVersionHash": record.candidate_version_hash, "candidateBuildId": str(record.candidate_build_id), "patch": record.structured_patch, "patchHash": record.patch_hash, "riskLevel": record.risk_level, "rationaleCode": record.rationale_code, "status": record.status, "validationReport": record.validation_report or None, "eligibilityAssessment": self._assessment_projection(assessment) if assessment else None, "evidenceRefs": record.evidence_refs, "approvalRefs": record.approval_refs, "policyDecisionRefs": record.policy_decision_refs, "auditRefs": record.audit_refs, "rollbackRefs": record.rollback_refs, "lockVersion": record.lock_version, "readOnly": record.status != "draft", "deduplicated": deduplicated}

    def _assessment_projection(self, row: GraphPromotionEligibilityAssessment, *, deduplicated: bool = False) -> dict[str, Any]:
        payload = {"schemaVersion": "phase8.graph-promotion-eligibility.v1", "assessmentId": str(row.id), "proposalId": str(row.proposal_id), "graphId": str(row.graph_id), "candidateVersionId": str(row.candidate_version_id), "baseVersionId": str(row.base_version_id), "learningMode": row.learning_mode, "riskLevel": row.risk_level, "eligible": row.eligible, "automaticPromotionAllowed": row.automatic_promotion_allowed, "humanReviewRequired": row.human_review_required, "checks": row.checks_snapshot, "reasonCodes": row.reason_codes, "policyVersionId": str(row.policy_version_id) if row.policy_version_id else None, "policyVersionHash": row.policy_version_hash, "bindingId": str(row.binding_id) if row.binding_id else None, "eligibilityHash": row.eligibility_hash, "evaluatedAt": row.evaluated_at.isoformat()}
        PromotionEligibilityAssessment.model_validate(payload)
        return {**payload, "policyDecisionRefs": row.policy_decision_refs, "guardrailEventRefs": row.guardrail_event_refs, "auditRefs": row.audit_refs, "deduplicated": deduplicated}

    def _promotion_projection(self, row: CanonicalGraphPromotionRecord, *, deduplicated: bool = False) -> dict[str, Any]:
        payload = {"schemaVersion": "phase8.graph-promotion-result.v1", "promotionId": str(row.id), "proposalId": str(row.proposal_id), "graphId": str(row.graph_id), "beforeVersionId": str(row.before_version_id), "beforeVersionHash": row.before_version_hash, "targetVersionId": str(row.target_version_id), "targetVersionHash": row.target_version_hash, "promotionType": row.promotion_type, "actorType": row.actor_type, "actorRef": row.actor_ref, "humanApproval": row.human_approval, "approvalRefs": row.approval_refs, "policyDecisionRefs": row.policy_decision_refs, "assessmentId": str(row.assessment_id), "rollbackTargetVersionId": str(row.rollback_target_version_id) if row.rollback_target_version_id else None, "status": row.status, "promotedAt": row.promoted_at.isoformat(), "idempotencyKey": row.idempotency_key}
        GraphPromotionResult.model_validate(payload)
        return {**payload, "policyVersionId": str(row.policy_version_id) if row.policy_version_id else None, "policyVersionHash": row.policy_version_hash, "eligibilitySnapshot": row.eligibility_snapshot, "replayRefs": row.replay_refs, "shadowRefs": row.shadow_refs, "auditRefs": row.audit_refs, "deduplicated": deduplicated}

    @staticmethod
    def _policy_projection(row: GraphLearningPolicyVersion, *, deduplicated: bool = False) -> dict[str, Any]:
        return {"policyId": str(row.policy_id), "policyVersionId": str(row.id), "version": row.version_number, "status": row.status, "policyDocument": row.policy_document, "contentHash": row.content_hash, "lockVersion": row.lock_version, "auditRefs": row.audit_refs, "deduplicated": deduplicated}

    @staticmethod
    def _binding_projection(row: GraphLearningPolicyBinding, *, deduplicated: bool = False) -> dict[str, Any]:
        return {"bindingId": str(row.id), "projectId": str(row.project_id), "environmentId": str(row.environment_id) if row.environment_id else None, "scopeType": row.scope_type, "scopeId": str(row.scope_id), "policyVersionId": str(row.policy_version_id), "policyVersionHash": row.policy_version_hash, "graphLearningMode": row.learning_mode, "status": row.status, "autonomyPaused": row.autonomy_paused, "pauseReasonCode": row.pause_reason_code, "lockVersion": row.lock_version, "auditRefs": row.audit_refs, "deduplicated": deduplicated}

    @staticmethod
    def _learning_projection(mode: str, binding: GraphLearningPolicyBinding | None, policy: GraphLearningPolicyVersion | None, fallback: str) -> dict[str, Any]:
        return {"graphLearningMode": mode, "defaultMode": DEFAULT_GRAPH_LEARNING_MODE, "binding": GraphPromotionService._binding_projection(binding) if binding else None, "policy": GraphPromotionService._policy_projection(policy) if policy else None, "fallbackReason": fallback, "modeSemantics": {"learn_only": "candidate_collection_only_no_auto_promotion", "human_supervised": "approval_backed_promotion_required", "controlled_autonomy": "low_risk_all_checks_strictly_required"}}


__all__ = [
    "DEFAULT_GRAPH_LEARNING_MODE",
    "GraphLearningPolicyResolver",
    "GraphPromotionEligibilityEvaluator",
    "GraphPromotionError",
    "GraphPromotionService",
]

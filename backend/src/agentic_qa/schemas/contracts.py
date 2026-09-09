# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.schemas.candidate_graph import CandidateBuildRequest, CandidateBuildResult
from agentic_qa.schemas.admission import (
    AdmissionResultProjection,
    AdmissionRetryRequest,
    AdmissionReviewProjection,
    AdmissionReviewRequest,
    AdmissionRunProjection,
    AdmissionRunRequest,
    AdmissionStageProjection,
    AdmissionTimelineProjection,
    SandboxProfile,
    SmokePlan,
    SmokeResult,
    SmokeRun,
    StaticScanRequest,
    StaticScanResult,
)
from agentic_qa.schemas.change_sets import (
    CodeChangeSetContract,
    NormalizationIssueContract,
    RequirementChangeSetContract,
)
from agentic_qa.schemas.ci_writeback import (
    CIConclusion,
    CIWritebackRequest,
    CIWritebackRetryRequest,
    CIWritebackResult,
    EnforcementDecision,
    ExternalActionRef,
    LegacySkillDecisionFieldNotice,
    StaleRevisionResult,
)
from agentic_qa.schemas.ceg_projection import (
    EvidenceProjection,
    GraphSummaryProjection,
    NodeDetailProjection,
    PathProjection,
)
from agentic_qa.schemas.decision_timeline import TimelineProjection, TimelineQuery
from agentic_qa.schemas.evidence_query import (
    EvidenceIndexEntryContract,
    EvidenceIndexJobContract,
    EvidenceQueryRequestContract,
    EvidenceQueryResultContract,
)
from agentic_qa.schemas.execution_graph import CanonicalExecutionGraphContract
from agentic_qa.schemas.gate_policy import (
    GatePolicyContract,
    GatePolicyResolutionRequestContract,
    GatePolicyResolutionResultContract,
)
from agentic_qa.schemas.gate_evaluator import GateInputContract, GateResultContract
from agentic_qa.schemas.gate_policy_governance import (
    GatePolicyImportDraftSaveRequest,
    GatePolicyImportPreview,
    GatePolicyImportRequest,
    GatePolicyStructuredDiff,
    GatePolicyValidationIssue,
)
from agentic_qa.schemas.gate_policy_simulation import (
    ActivationRequest,
    ActivationResult,
    GateModeProjection,
    RollbackRequest,
    RollbackResult,
    RollbackTargetProjection,
    SimulationCaseDiff,
    SimulationRequest,
    SimulationRun,
    SimulationSummary,
)
from agentic_qa.schemas.graph_promotion import (
    CreateGraphCorrectionProposalRequest,
    CreateGraphLearningBindingRequest,
    CreateGraphLearningPolicyRequest,
    GraphPromotionResult,
    PromotionEligibilityAssessment,
)
from agentic_qa.schemas.graph_staleness import GraphStalenessAssessmentContract
from agentic_qa.schemas.impact_analysis import (
    CapabilityMappingContract,
    ImpactRequestContract,
    ImpactResultContract,
)
from agentic_qa.schemas.lessons import (
    FeedbackTaxonomyContract,
    LessonCandidateContract,
    LessonEvidenceContract,
    LessonReviewContract,
    PromotionResultContract,
)
from agentic_qa.schemas.improvement_proposals import (
    ImprovementEffectivenessResultContract,
    ImprovementProposalContract,
    ImprovementValidationResultContract,
)
from agentic_qa.schemas.selective_replay import (
    SelectiveReplayPlan,
    SelectiveReplayRequest,
)
from agentic_qa.schemas.scm_pr import (
    PRContext,
    PRRevision,
    RequirementMatch,
    RequirementMatchCandidate,
    RequirementMatchReason,
    RequirementMatchSnapshot,
    WebhookEnvelope,
)
from agentic_qa.schemas.graph_coverage import (
    GraphCoverageInput,
    GraphCoverageResult,
    TraceabilityProjection,
)
from agentic_qa.schemas.skills import SkillContextEnvelope


ContractName = Literal[
    "agent-output",
    "skill-result",
    "skill-context-envelope",
    "finding",
    "gate-policy",
    "gate-policy-resolution-request",
    "gate-policy-resolution-result",
    "gate-policy-import-request",
    "gate-policy-import-preview",
    "gate-policy-validation-issue",
    "gate-policy-structured-diff",
    "gate-policy-draft-save",
    "gate-policy-simulation-request",
    "gate-policy-simulation-run",
    "gate-policy-simulation-case-diff",
    "gate-policy-simulation-summary",
    "gate-policy-mode",
    "gate-policy-activation-request",
    "gate-policy-activation-result",
    "gate-policy-rollback-request",
    "gate-policy-rollback-result",
    "gate-policy-rollback-target",
    "gate-input",
    "gate-result",
    "replay-export",
    "replay-repository",
    "domain-event",
    "lifecycle-state",
    "license-capability-boundary",
    "capability-binding",
    "workflow-capability-graph",
    "structured-log-projection",
    "audit-log-projection",
    "decision-timeline-query",
    "decision-timeline",
    "evidence-index-entry",
    "evidence-index-job",
    "evidence-query-request",
    "evidence-query-result",
    "canonical-execution-graph",
    "candidate-build-request",
    "candidate-build-result",
    "requirement-change-set",
    "code-change-set",
    "normalization-issue",
    "capability-mapping",
    "impact-request",
    "impact-result",
    "selective-replay-request",
    "selective-replay-plan",
    "scm-webhook-envelope",
    "pr-revision",
    "pr-context",
    "requirement-match-reason",
    "requirement-match-candidate",
    "requirement-match",
    "requirement-match-snapshot",
    "sandbox-profile",
    "static-scan-request",
    "static-scan-result",
    "smoke-plan",
    "smoke-run",
    "smoke-result",
    "admission-run-request",
    "admission-run",
    "admission-stage",
    "admission-result",
    "admission-timeline",
    "admission-review-request",
    "admission-review",
    "admission-retry-request",
    "ci-conclusion",
    "enforcement-decision",
    "stale-revision-result",
    "external-action-ref",
    "legacy-skill-decision-field-notice",
    "ci-writeback-request",
    "ci-writeback-retry-request",
    "ci-writeback-result",
    "graph-correction-proposal",
    "graph-learning-policy",
    "graph-learning-binding",
    "graph-promotion-eligibility",
    "graph-promotion-result",
    "graph-staleness-assessment",
    "graph-traceability-projection",
    "graph-coverage-input",
    "graph-coverage-result",
    "ceg-graph-summary-projection",
    "ceg-path-projection",
    "ceg-node-detail-projection",
    "ceg-evidence-projection",
    "coverage-map",
    "test-knowledge-entry",
    "failure-attribution",
    "regression-plan",
    "requirement-version",
    "clarification",
    "test-asset",
    "asset-review",
    "execution-plan",
    "correction-record",
    "missing-link",
    "traceability-path",
    "coverage-summary",
    "coverage-matrix",
    "traceability-snapshot",
    "coverage-proof-bundle",
    "correction-proposal",
    "correction-application",
    "correction-validation",
    "rollback-record",
    "knowledge-promotion-record",
    "feedback-taxonomy",
    "lesson-evidence",
    "lesson-candidate",
    "lesson-review",
    "promotion-result",
    "improvement-proposal",
    "improvement-validation-result",
    "improvement-effectiveness-result",
    "locator-update",
    "assertion-update",
    "test-case-update",
    "test-step-update",
    "requirement-mapping-update",
    "execution-config-update",
    "generate-patch-suggestion",
]


class ContractValidationError(Exception):
    """Raised when a payload fails a canonical contract validation."""

    def __init__(self, contract_name: str, issues: list[str]) -> None:
        self.contract_name = contract_name
        self.issues = issues
        super().__init__(f"{contract_name} contract validation failed: {'; '.join(issues)}")


class AgentOutputContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str | dict[str, Any]] = Field(min_length=1)
    limitations: list[str]
    metadata: dict[str, Any]


class LicenseCapabilityBoundaryContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.license-capability-boundary.v1"]
    userId: str = Field(min_length=1)
    edition: Literal["basic", "community", "pro", "enterprise"]
    capabilities: list[str] = Field(min_length=1)
    inactiveCapabilities: list[str]
    authorizationBoundary: Literal["backend_service_api"]
    frontendBoundary: Literal["ux_only"]
    metadata: dict[str, Any]

    @model_validator(mode="after")
    def ensure_promotion_capability_boundary(self) -> "LicenseCapabilityBoundaryContract":
        capability_set = set(self.capabilities)
        if "knowledge.promote" in capability_set and "correction.promote" in capability_set:
            raise ValueError("knowledge.promote must not protect the same API as correction.promote")
        if "knowledge.promote" in capability_set:
            raise ValueError("knowledge.promote is reserved / inactive in the first implementation pass")
        if "knowledge.promote" not in set(self.inactiveCapabilities):
            raise ValueError("knowledge.promote must remain listed as inactive in the first implementation pass")
        return self


class CommunityBindingLifecycleContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policyVersion: str
    canEnable: bool
    canDisable: bool
    unavailableReason: str | None


class SkillActivationReadinessContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.skill-activation-readiness.v1"]
    candidate: bool
    skillVersionGovernanceStatus: str
    contractValidation: str
    datasetEvaluation: str
    shadowComparison: str
    evidenceReady: bool
    canRequestActivation: bool
    directExecutionAllowed: Literal[False]


class CapabilityBindingContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.capability-binding.v1"]
    stateHash: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$",
        json_schema_extra={"pattern": r"^sha256:[0-9a-f]{64}$"},
    )
    communityLifecycle: CommunityBindingLifecycleContract | None = None
    id: str = Field(min_length=1)
    extensionPointId: str = Field(min_length=1)
    skillId: str = Field(min_length=1)
    skillVersionId: str = Field(min_length=1)
    version: str = Field(min_length=1)
    manifestHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    scopeType: Literal["global", "workspace", "project", "environment", "stage", "domain"]
    scopeId: str | None
    projectId: str | None
    environment: str | None
    stage: str | None
    domain: str | None
    status: Literal["draft", "active", "disabled", "deprecated", "archived"]
    priority: int = Field(ge=0)
    bindingConfig: dict[str, Any]
    activationReadiness: SkillActivationReadinessContract
    pendingChange: dict[str, Any]
    approvalRefs: list[dict[str, Any]]
    guardrailEventRefs: list[dict[str, Any]]
    auditRefs: list[dict[str, Any]]
    approvalRequired: bool
    approvalEnvelope: dict[str, Any] | None
    createdAt: str
    updatedAt: str


class WorkflowCapabilityGraphNodeContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lifecycleStage: str = Field(min_length=1)
    extensionPointId: str = Field(min_length=1)
    label: str = Field(min_length=1)
    bindable: bool
    currentBindingSummary: dict[str, Any] | None
    requiredCapability: str | None
    requiredEdition: str | None
    unavailableReason: str | None


class WorkflowCapabilityGraphContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.workflow-capability-graph.v1"]
    nodes: list[WorkflowCapabilityGraphNodeContract] = Field(min_length=1)
    scope: dict[str, Any]


class AuditLogProjectionContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.audit-log-projection.v1"]
    generatedAt: str
    scope: dict[str, Any]
    filters: dict[str, Any]
    supportedFilters: list[str] = Field(min_length=1)
    summary: dict[str, Any]
    sourceCounts: dict[str, int]
    levelCounts: dict[str, int]
    resourceTypeCounts: dict[str, int]
    retentionProjection: dict[str, Any]
    items: list[dict[str, Any]]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    pageSize: int = Field(ge=1)
    evidenceOnly: bool
    writesDecision: bool
    capability: dict[str, Any]

    @model_validator(mode="after")
    def ensure_read_only_projection(self) -> "AuditLogProjectionContract":
        if self.evidenceOnly is not True:
            raise ValueError("audit-log-projection must be evidenceOnly")
        if self.writesDecision is not False:
            raise ValueError("audit-log-projection must not write decisions")
        if self.capability.get("required") != "audit.logs.read":
            raise ValueError("audit-log-projection must require audit.logs.read")
        if self.capability.get("authorizationBoundary") != "backend_service_api":
            raise ValueError("audit-log-projection authorization boundary must be backend_service_api")
        if self.capability.get("frontendBoundary") != "ux_only":
            raise ValueError("audit-log-projection frontend boundary must be ux_only")
        if self.retentionProjection.get("readOnly") is not True:
            raise ValueError("audit retention projection must remain read-only")
        if self.retentionProjection.get("destructiveActionsExposed") is not False:
            raise ValueError("audit retention projection must not expose destructive actions")
        return self


class StructuredLogProjectionContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.structured-log-projection.v1"]
    generatedAt: str
    scope: dict[str, Any]
    filters: dict[str, Any]
    supportedFilters: list[str] = Field(min_length=1)
    summary: dict[str, Any]
    sourceCounts: dict[str, int]
    levelCounts: dict[str, int]
    componentCounts: dict[str, int]
    serviceCounts: dict[str, int]
    resourceTypeCounts: dict[str, int]
    traceRefs: list[str]
    executionRefs: list[str]
    retentionProjection: dict[str, Any]
    items: list[dict[str, Any]]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    pageSize: int = Field(ge=1)
    evidenceOnly: bool
    writesDecision: bool
    capability: dict[str, Any]

    @model_validator(mode="after")
    def ensure_read_only_projection(self) -> "StructuredLogProjectionContract":
        if self.evidenceOnly is not True:
            raise ValueError("structured-log-projection must be evidenceOnly")
        if self.writesDecision is not False:
            raise ValueError("structured-log-projection must not write decisions")
        if self.capability.get("required") != "audit.logs.read":
            raise ValueError("structured-log-projection must require audit.logs.read")
        if self.capability.get("authorizationBoundary") != "backend_service_api":
            raise ValueError("structured-log-projection authorization boundary must be backend_service_api")
        if self.capability.get("frontendBoundary") != "ux_only":
            raise ValueError("structured-log-projection frontend boundary must be ux_only")
        if self.retentionProjection.get("readOnly") is not True:
            raise ValueError("structured log retention projection must remain read-only")
        if self.retentionProjection.get("destructiveActionsExposed") is not False:
            raise ValueError("structured log retention projection must not expose destructive actions")
        if "executionLogCount" not in self.summary or "auditLogCount" not in self.summary:
            raise ValueError("structured-log-projection summary must include source counts")
        return self


CANONICAL_EVIDENCE_TYPES = {
    "artifact_ref",
    "metric_ref",
    "log_ref",
    "trace_span_ref",
    "inline_fact",
    "external_ref",
    "screenshot",
    "dom_snapshot",
    "bounding_box",
    "semantic_target",
    "vision_output",
}
CANONICAL_LOCATION_KINDS = {
    "url_endpoint",
    "file",
    "selector",
    "dom_selector",
    "accessibility_node",
    "bounding_box",
    "screen_coordinate",
    "semantic_target",
    "network_resource",
    "command",
    "service",
    "unknown",
}
CANONICAL_LOCATION_TARGET_FIELDS = {
    "target",
    "file",
    "selector",
    "service",
    "command",
    "url",
    "endpoint",
    "path",
    "coordinates",
    "node",
    "boundingBox",
    "resource",
}


def _validate_canonical_evidence_and_location(
    *,
    evidence: list[dict[str, Any]],
    location: dict[str, Any],
) -> None:
    for index, item in enumerate(evidence):
        evidence_type = item.get("type")
        evidence_ref = item.get("ref")
        if not isinstance(evidence_type, str) or evidence_type not in CANONICAL_EVIDENCE_TYPES:
            raise ValueError(f"evidence[{index}].type must be a canonical evidence type")
        if not isinstance(evidence_ref, str) or not evidence_ref.strip():
            raise ValueError(f"evidence[{index}].ref must be a non-empty traceable reference")

    location_kind = location.get("kind")
    if not isinstance(location_kind, str) or location_kind not in CANONICAL_LOCATION_KINDS:
        raise ValueError("location.kind must be a canonical location kind")
    if not any(
        field_name in location and location[field_name] not in (None, "", [], {})
        for field_name in CANONICAL_LOCATION_TARGET_FIELDS
    ):
        raise ValueError("location must include at least one meaningful target field")


class SkillFindingCandidateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    evidence: list[dict[str, Any]] = Field(min_length=1)
    location: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    dedupeKey: str = Field(min_length=1)
    rawRef: str = Field(min_length=1)

    @model_validator(mode="after")
    def ensure_canonicalization_ready_candidate(self) -> "SkillFindingCandidateContract":
        _validate_canonical_evidence_and_location(evidence=self.evidence, location=self.location)
        return self


class SkillResultContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]]
    artifactRefs: list[dict[str, Any]]
    rawFindingRefs: list[dict[str, Any]]
    findingCandidates: list[SkillFindingCandidateContract]
    metadata: dict[str, Any]


class FindingContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    evidence: list[dict[str, Any]] = Field(min_length=1)
    location: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    dedupeKey: str = Field(min_length=1)
    rawRef: str = Field(min_length=1)

    @model_validator(mode="after")
    def ensure_evidence_backed_canonical_shape(self) -> "FindingContract":
        _validate_canonical_evidence_and_location(evidence=self.evidence, location=self.location)
        return self


class ReplayExportContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.replay-export.v1"]
    exportedAt: str
    requestId: str
    executionId: str
    traceRefs: list[str]
    storageRef: str | None
    exportArtifactRef: str | None
    exportHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    exportPayloadHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    redactionStatus: str
    auditRefs: list[dict[str, Any]]
    traceabilitySnapshotRef: str | None
    traceabilitySnapshotHash: str | None
    requirementScope: dict[str, Any] | None = None
    coverageSummarySnapshot: dict[str, Any] | None
    coverageMatrixSnapshotRef: str | None
    graphCoverageSnapshot: dict[str, Any] | None = None
    replay: dict[str, Any]
    auditLogs: list[dict[str, Any]]

    @model_validator(mode="after")
    def ensure_optional_traceability_hash_shape(self) -> "ReplayExportContract":
        if self.traceabilitySnapshotHash is not None and not re.match(r"^sha256:[a-f0-9]{64}$", self.traceabilitySnapshotHash):
            raise ValueError("traceabilitySnapshotHash must be null or sha256:<64 lowercase hex>")
        return self


class ReplayRepositorySectionContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sectionName: str = Field(min_length=1)
    storageRef: str = Field(min_length=1)
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    byteSize: int = Field(ge=0)
    compression: str
    redactionStatus: str


class ReplayRepositoryContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.replay-repository.v1"]
    replayId: str = Field(min_length=1)
    executionId: str = Field(min_length=1)
    frozenAt: str
    sourceReplayExportHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    manifestHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    payloadHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    storageAdapter: str
    redactionStatus: str
    validityStatus: Literal["valid", "invalid", "unknown"]
    approvalMode: Literal["always", "policy_only", "threshold"]
    approvalState: Literal["pending", "approved", "not_required", "rejected", "cancelled"]
    retentionState: dict[str, Any]
    summaryProjection: dict[str, Any]
    sectionIndex: list[ReplayRepositorySectionContract] = Field(min_length=1)
    auditRefs: list[dict[str, Any]]
    approvalRefs: list[dict[str, Any]]
    guardrailEventRefs: list[dict[str, Any]]
    manifest: dict[str, Any] | None = None


class DomainEventContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    eventId: str
    eventType: str
    schemaVersion: Literal["phase8.domain-event.v1"]
    traceId: str
    correlationRefs: dict[str, Any]
    occurredAt: str
    actorRef: dict[str, Any] | None
    sourceRef: dict[str, Any] | None
    payload: dict[str, Any]
    evidenceRefs: list[dict[str, Any]]
    replayRefs: list[dict[str, Any]]

    @model_validator(mode="after")
    def ensure_no_secret_payload(self) -> "DomainEventContract":
        for field_name in ("correlationRefs", "actorRef", "sourceRef", "payload", "evidenceRefs", "replayRefs"):
            if _contains_secret_marker(getattr(self, field_name)):
                raise ValueError(f"{field_name} must not contain secrets")
        return self


class LifecycleStateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.lifecycle-state.v1"]
    lifecycle: str
    state: str
    owner: str
    inputContract: dict[str, Any]
    outputContract: dict[str, Any]
    allowedTransitions: list[str]
    retryStrategy: dict[str, Any]
    blockStrategy: dict[str, Any]
    reviewStrategy: dict[str, Any]
    emittedDomainEvents: list[str]
    traceId: str | None
    evidenceRefs: list[dict[str, Any]]
    replayRefs: list[dict[str, Any]]


class CoverageMapContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.coverage-map.v1"]
    requirementCoverage: float = Field(ge=0.0, le=1.0)
    testPointCoverage: float = Field(ge=0.0, le=1.0)
    testCaseCoverage: float = Field(ge=0.0, le=1.0)
    executionCoverage: float = Field(ge=0.0, le=1.0)
    evidenceCoverage: float = Field(ge=0.0, le=1.0)
    regressionCoverage: float = Field(ge=0.0, le=1.0)
    uncoveredRequirements: list[dict[str, Any]]
    weakCoverageAreas: list[dict[str, Any]]
    duplicateCoverageAreas: list[dict[str, Any]]
    coverageConfidence: float = Field(ge=0.0, le=1.0)
    evidenceRefs: list[dict[str, Any]]
    metadata: dict[str, Any]


class TestKnowledgeEntryContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.test-knowledge-entry.v1"]
    knowledgeId: str
    knowledgeType: str
    status: str
    content: dict[str, Any]
    sourceRefs: list[dict[str, Any]] = Field(min_length=1)
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    traceRefs: list[str]
    replayRefs: list[dict[str, Any]]
    confidence: float = Field(ge=0.0, le=1.0)
    lifecycle: dict[str, Any]
    metadata: dict[str, Any]

    @model_validator(mode="after")
    def ensure_model_output_is_verified(self) -> "TestKnowledgeEntryContract":
        allowed_source_types = {
            "verified_evidence",
            "approved_correction",
            "validated_correction",
            "replay_validated_correction",
            "normalized_finding",
            "gate_decision",
            "replay_validated_artifact",
            "replay_validated_historical_artifact",
        }
        if self.metadata.get("unverifiedModelOutput") is True:
            raise ValueError("unverified model output must not be promoted into Test Knowledge")
        for source_ref in self.sourceRefs:
            if source_ref.get("type") == "model_output" and source_ref.get("verified") is not True:
                raise ValueError("model_output sourceRefs must be verified before Test Knowledge promotion")
            if source_ref.get("type") not in allowed_source_types:
                raise ValueError("Test Knowledge sourceRef type is not eligible for promotion")
            if not source_ref.get("id"):
                raise ValueError("Test Knowledge sourceRefs must contain an id")
        return self


class FailureAttributionContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.failure-attribution.v1"]
    executionId: str
    taskId: str | None
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str | dict[str, Any]] = Field(min_length=1)
    suspectedCause: str
    suggestedNextAction: str
    reviewRequired: bool
    metadata: dict[str, Any]


class RegressionPlanContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.regression-plan.v1"]
    baseRef: dict[str, Any]
    affectedCases: list[dict[str, Any]]
    recommendedRegressionSuite: list[dict[str, Any]]
    riskBasedPriority: list[dict[str, Any]]
    evidenceRefs: list[dict[str, Any]]
    replayRefs: list[dict[str, Any]]
    metadata: dict[str, Any]


class RequirementVersionContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.requirement-version.v1"]
    requirementVersionId: str
    sourceRef: str
    version: int = Field(ge=1)
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    document: str = Field(min_length=1)
    requirements: list[str]
    acceptanceCriteria: list[str]
    metadata: dict[str, Any]
    createdAt: str


class ClarificationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.clarification.v1"]
    clarificationId: str
    requirementVersionId: str
    question: str = Field(min_length=1)
    priority: Literal["P0", "P1", "P2"]
    status: Literal["open", "answered", "closed"]
    answer: str | None
    evidenceRefs: list[dict[str, Any]]
    metadata: dict[str, Any]


class TestAssetContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.test-asset.v1"]
    assetId: str
    requirementVersionId: str
    assetType: Literal["test_point", "test_case"]
    domain: str
    title: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    requirementRefs: list[str] = Field(min_length=1)
    status: Literal["draft", "reviewed", "approved", "invalidated"]
    evidenceRefs: list[dict[str, Any]]
    metadata: dict[str, Any]


class AssetReviewContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.asset-review.v1"]
    reviewId: str
    requirementVersionId: str
    planId: str
    status: Literal["approved", "needs_review", "rejected"]
    confidence: float = Field(ge=0.0, le=1.0)
    issues: list[dict[str, Any]]
    coverageMap: dict[str, Any]
    evidenceRefs: list[dict[str, Any]]
    metadata: dict[str, Any]


class ExecutionPlanContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.execution-plan.v1"]
    executionPlanId: str
    requirementVersionId: str
    testPlanId: str
    status: Literal["draft", "approved", "blocked"]
    riskLevel: Literal["low", "medium", "high"]
    approvalRequired: bool
    tasks: list[dict[str, Any]] = Field(min_length=1)
    assetRefs: list[dict[str, Any]] = Field(min_length=1)
    retryStrategy: dict[str, Any]
    replayRefs: list[dict[str, Any]]
    requirementScope: dict[str, Any]
    metadata: dict[str, Any]


class CorrectionRecordContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.correction-record.v1"]
    correctionId: str
    requirementVersionId: str
    executionId: str | None
    targetType: str
    targetId: str
    before: dict[str, Any]
    after: dict[str, Any]
    reason: str = Field(min_length=1)
    actorRef: dict[str, Any]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    affectedAssetRefs: list[dict[str, Any]]
    createdAt: str
    metadata: dict[str, Any]


class MissingLinkContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.missing-link.v1"]
    code: str
    fromType: str
    fromId: str
    expectedTargetType: str
    severity: str
    blocksCoverage: bool


class TraceabilityPathContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.traceability-path.v1"]
    sourceType: str
    sourceId: str
    upstreamPath: list[dict[str, Any]]
    downstreamPath: list[dict[str, Any]]
    relationStatus: list[dict[str, Any]]
    missingLinks: list[dict[str, Any]]
    staleLinks: list[dict[str, Any]]


class CoverageSummaryContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.coverage-summary.v1"]
    requirementVersionId: str
    scope: dict[str, Any]
    status: str
    reason: str | None
    requirementCoverage: float | None
    testPointCoverage: float | None
    testCaseCoverage: float | None
    evidenceCoverage: float | None
    findingTraceCoverage: float | None
    gateImpactCoverage: float | None
    missingLinks: list[dict[str, Any]]
    calculatedAt: str

    @model_validator(mode="after")
    def ensure_coverage_values_are_ratios_or_null(self) -> "CoverageSummaryContract":
        for field_name in (
            "requirementCoverage",
            "testPointCoverage",
            "testCaseCoverage",
            "evidenceCoverage",
            "findingTraceCoverage",
            "gateImpactCoverage",
        ):
            value = getattr(self, field_name)
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{field_name} must be null or between 0 and 1")
        return self


class CoverageMatrixContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.coverage-matrix.v1"]
    requirementVersionId: str
    summary: dict[str, Any]
    rows: list[dict[str, Any]]
    missingLinks: list[dict[str, Any]]
    status: str
    scope: dict[str, Any]
    calculatedAt: str
    pagination: dict[str, Any]
    filters: dict[str, Any]


class TraceabilitySnapshotContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.traceability-snapshot.v1"]
    traceabilitySnapshotRef: str
    traceabilitySnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    requirementScope: dict[str, Any] | None = None
    coverageSummarySnapshot: dict[str, Any]
    coverageMatrixSnapshotRef: str
    createdAt: str


class CoverageProofRelationRefContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table: str
    id: str
    status: Literal["confirmed", "system_verified"]
    source: str
    scopeId: str
    confidence: float = Field(ge=0.0, le=1.0)


class CoverageProofEdgeContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationRef: CoverageProofRelationRefContract
    sourceId: str
    targetId: str
    relationType: str
    frozenStatus: Literal["confirmed", "system_verified"]
    currentStatus: Literal["confirmed", "system_verified", "stale", "invalid", "missing", "superseded"]


class CoverageProofChainContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    testPointId: str | None
    testCaseId: str | None
    executionTaskId: str | None
    proofEdges: list[CoverageProofEdgeContract]
    evidenceArtifactRefs: list[dict[str, Any]]
    rawFindingRefs: list[dict[str, Any]]
    normalizedFindingRefs: list[dict[str, Any]]
    gateDecisionRef: str | None
    gateInputSnapshotRef: str | None
    policySnapshotRef: str | None
    approvalRefs: list[dict[str, Any]]
    traceRefs: list[str]
    auditRefs: list[dict[str, Any]]
    traceabilitySnapshotRef: str
    traceabilitySnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    coverageMatrixSnapshotRef: str
    coverageMatrixSnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    replayExportRef: str | None
    replayExportHash: str | None
    proofIssues: list[str]

    @model_validator(mode="after")
    def ensure_optional_replay_export_hash_shape(self) -> "CoverageProofChainContract":
        if self.replayExportHash is not None and not re.match(r"^sha256:[a-f0-9]{64}$", self.replayExportHash):
            raise ValueError("replayExportHash must be null or sha256:<64 lowercase hex>")
        return self


class CoverageProofBundleContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: str
    generatedAt: str
    requirementVersionId: str
    primaryRequirementVersionId: str | None = None
    requirementVersionIds: list[str] = Field(default_factory=list)
    requirementItemId: str
    requirementScope: dict[str, Any] | None = None
    coverageStatus: Literal["covered", "partial", "not_covered", "blocked", "not_applicable", "unknown"]
    proofStatus: Literal["valid", "stale", "broken", "superseded"]
    proofChain: list[CoverageProofChainContract]
    proofIssues: list[str]
    traceId: str | None

    @model_validator(mode="after")
    def ensure_not_covered_valid_semantics(self) -> "CoverageProofBundleContract":
        if self.schemaVersion not in {"phase8.coverage-proof-bundle.v1", "phase8.coverage-proof-bundle.v2"}:
            raise ValueError("schemaVersion must be a supported coverage-proof-bundle contract")
        if self.coverageStatus == "not_covered" and self.proofStatus == "broken" and not self.proofChain:
            raise ValueError("not_covered without a claimed proof chain must not be marked broken")
        return self


class ContractRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1)
    id: str = Field(min_length=1)


class ChangeDeltaContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    before: Any
    after: Any
    reason: str = Field(min_length=1)


class LocatorUpdateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.locator-update.v1"]
    changeType: Literal["locator_update"]
    targetRef: ContractRef
    beforeLocator: dict[str, Any]
    afterLocator: dict[str, Any]
    locatorStrategy: dict[str, Any]
    rationale: str = Field(min_length=1)
    riskLevel: Literal["low", "medium", "high"]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    metadata: dict[str, Any]


class AssertionUpdateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.assertion-update.v1"]
    changeType: Literal["assertion_update"]
    assertionRef: ContractRef
    beforeAssertion: dict[str, Any]
    afterAssertion: dict[str, Any]
    rationale: str = Field(min_length=1)
    riskLevel: Literal["low", "medium", "high"]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    metadata: dict[str, Any]


class TestCaseUpdateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.test-case-update.v1"]
    changeType: Literal["test_case_update"]
    testCaseRef: ContractRef
    changes: list[ChangeDeltaContract] = Field(min_length=1)
    rationale: str = Field(min_length=1)
    riskLevel: Literal["low", "medium", "high"]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    metadata: dict[str, Any]


class TestStepUpdateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.test-step-update.v1"]
    changeType: Literal["test_step_update"]
    testStepRef: ContractRef
    beforeStep: dict[str, Any]
    afterStep: dict[str, Any]
    rationale: str = Field(min_length=1)
    riskLevel: Literal["low", "medium", "high"]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    metadata: dict[str, Any]


class RequirementMappingUpdateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.requirement-mapping-update.v1"]
    changeType: Literal["requirement_mapping_update"]
    requirementRef: ContractRef
    assetRef: ContractRef
    beforeMapping: dict[str, Any] | None
    afterMapping: dict[str, Any]
    rationale: str = Field(min_length=1)
    riskLevel: Literal["low", "medium", "high"]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    metadata: dict[str, Any]


class ExecutionConfigUpdateContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.execution-config-update.v1"]
    changeType: Literal["execution_config_update"]
    configRef: ContractRef
    beforeConfig: dict[str, Any]
    afterConfig: dict[str, Any]
    rationale: str = Field(min_length=1)
    riskLevel: Literal["low", "medium", "high"]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    metadata: dict[str, Any]


class PatchSuggestionContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patchRef: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    diffRefs: list[dict[str, Any]]
    suggestedFiles: list[str]


class GeneratePatchSuggestionContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.generate-patch-suggestion.v1"]
    changeType: Literal["generate_patch_suggestion"]
    targetRef: ContractRef
    patchSuggestion: PatchSuggestionContract
    rationale: str = Field(min_length=1)
    riskLevel: Literal["low", "medium", "high"]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    metadata: dict[str, Any]

    @model_validator(mode="after")
    def ensure_suggest_only_patch_semantics(self) -> "GeneratePatchSuggestionContract":
        if _contains_forbidden_patch_semantics(self.model_dump(mode="json")):
            raise ValueError("generate_patch_suggestion must remain suggest_only and must not contain apply/applied/changed semantics")
        return self


class GraphCorrectionChangeContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.graph-correction-change.v1"]
    changeType: Literal["graph_correction"]
    graphRef: ContractRef
    baseVersionRef: ContractRef
    candidateVersionRef: ContractRef
    patch: dict[str, Any]
    rationale: str = Field(min_length=1)
    riskLevel: Literal["low", "medium", "high"]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    metadata: dict[str, Any]

    @model_validator(mode="after")
    def ensure_structured_patch(self) -> "GraphCorrectionChangeContract":
        operations = self.patch.get("operations")
        if not isinstance(operations, list) or not operations:
            raise ValueError("graph_correction requires structured operations")
        if any(not isinstance(item, dict) or not item.get("operationId") for item in operations):
            raise ValueError("graph_correction operations require stable operationId")
        return self


PROPOSED_CHANGE_MODELS: dict[str, type[BaseModel]] = {
    "locator_update": LocatorUpdateContract,
    "assertion_update": AssertionUpdateContract,
    "test_case_update": TestCaseUpdateContract,
    "test_step_update": TestStepUpdateContract,
    "requirement_mapping_update": RequirementMappingUpdateContract,
    "execution_config_update": ExecutionConfigUpdateContract,
    "generate_patch_suggestion": GeneratePatchSuggestionContract,
    "graph_correction": GraphCorrectionChangeContract,
}


class CorrectionProposalContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.correction-proposal.v1"]
    correctionProposalId: str
    proposalType: Literal[
        "locator_update",
        "assertion_update",
        "test_case_update",
        "test_step_update",
        "requirement_mapping_update",
        "execution_config_update",
        "generate_patch_suggestion",
        "graph_correction",
    ]
    proposedChange: dict[str, Any]
    status: Literal["draft", "pending_approval", "approved", "rejected", "cancelled", "expired"]
    requirementVersionId: str | None
    executionId: str | None
    findingId: str | None
    attributionId: str | None
    riskLevel: Literal["low", "medium", "high"]
    requesterRef: dict[str, Any]
    approvalRefs: list[dict[str, Any]]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    traceRefs: list[str]
    createdAt: str
    metadata: dict[str, Any]

    @model_validator(mode="after")
    def ensure_proposed_change_matches_proposal_type(self) -> "CorrectionProposalContract":
        change_type = self.proposedChange.get("changeType")
        if self.proposalType != change_type:
            raise ValueError("proposalType must equal proposedChange.changeType")
        change_model = PROPOSED_CHANGE_MODELS.get(self.proposalType)
        if change_model is None:
            raise ValueError("proposalType is not supported for Controlled Correction Governance")
        parsed_change = change_model.model_validate(self.proposedChange)
        self.proposedChange = parsed_change.model_dump(mode="json")
        return self


class CorrectionApplicationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.correction-application.v1"]
    correctionApplicationId: str
    correctionProposalId: str
    idempotencyKey: str
    requestId: str
    status: Literal["pending", "applying", "applied", "failed_to_apply"]
    appliedChangeRefs: list[dict[str, Any]]
    sideEffectRefs: list[dict[str, Any]]
    evidenceRefs: list[dict[str, Any]]
    traceRefs: list[str]
    startedAt: str | None
    finishedAt: str | None
    metadata: dict[str, Any]


class CorrectionValidationResultContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    originalFindingResolved: bool
    newBlockerIntroduced: bool
    assertionsPassed: bool
    coverageRegressed: bool
    riskWorsened: bool
    passed: bool
    failedReason: str | None
    evidenceRefs: list[dict[str, Any]]
    replayRefs: list[dict[str, Any]]

    @model_validator(mode="after")
    def ensure_validation_result_is_consistent(self) -> "CorrectionValidationResultContract":
        expected_passed = (
            self.originalFindingResolved
            and not self.newBlockerIntroduced
            and self.assertionsPassed
            and not self.coverageRegressed
            and not self.riskWorsened
        )
        if self.passed != expected_passed:
            raise ValueError("validation result passed must match selective replay validation conditions")
        if self.passed and self.failedReason is not None:
            raise ValueError("failedReason must be null when validation result passed")
        if self.passed and not self.evidenceRefs:
            raise ValueError("passed validation requires non-empty evidenceRefs")
        if self.passed and not self.replayRefs:
            raise ValueError("passed validation requires non-empty replayRefs")
        return self


class CorrectionValidationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.correction-validation.v1"]
    correctionValidationId: str
    correctionProposalId: str
    correctionApplicationId: str
    idempotencyKey: str
    requestId: str
    status: Literal["pending", "running", "validated", "validation_failed", "cancelled", "error"]
    result: CorrectionValidationResultContract
    traceRefs: list[str]
    startedAt: str | None
    finishedAt: str | None
    metadata: dict[str, Any]

    @model_validator(mode="after")
    def ensure_status_matches_result(self) -> "CorrectionValidationContract":
        if self.status == "validated" and self.result.passed is not True:
            raise ValueError("validated status requires result.passed true")
        if self.status == "validation_failed" and self.result.passed is not False:
            raise ValueError("validation_failed status requires result.passed false")
        if self.status == "validation_failed" and not self.result.failedReason:
            raise ValueError("failedReason is required when validation status is validation_failed")
        if self.status in {"pending", "running", "cancelled", "error"} and self.result.passed:
            raise ValueError(f"{self.status} status must not carry a passed validation result")
        return self


class RollbackRecordContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.rollback-record.v1"]
    rollbackRecordId: str
    correctionProposalId: str
    correctionApplicationId: str | None
    correctionValidationId: str | None
    idempotencyKey: str
    requestId: str
    status: Literal["rollback_not_required", "rolling_back", "rolled_back", "rollback_failed"]
    rollbackReason: str
    rollbackRefs: list[dict[str, Any]]
    evidenceRefs: list[dict[str, Any]]
    traceRefs: list[str]
    startedAt: str | None
    finishedAt: str | None
    metadata: dict[str, Any]


class KnowledgePromotionRecordContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["phase8.knowledge-promotion-record.v1"]
    knowledgePromotionId: str
    source: Literal["validated_correction", "replay_validated_correction"]
    sourceCorrectionId: str
    correctionValidationId: str
    replayValidationId: str | None
    replayValidationRef: dict[str, Any]
    coverageProofRef: dict[str, Any]
    knowledgeEntry: dict[str, Any]
    evidenceRefs: list[dict[str, Any]] = Field(min_length=1)
    replayRefs: list[dict[str, Any]] = Field(min_length=1)
    approvalRefs: list[dict[str, Any]]
    approvalState: Literal["satisfied", "not_required"]
    policySnapshot: dict[str, Any]
    auditRefs: list[dict[str, Any]]
    rollbackRef: dict[str, Any]
    supersedeRef: dict[str, Any]
    projectionState: Literal["skipped", "projected", "projection_failed", "retry"]
    projectionRefs: list[dict[str, Any]]
    status: Literal["pending", "promoted", "rejected", "rolled_back", "superseded"]
    promotedAt: str | None
    promotedBy: str | None
    traceId: str
    idempotencyKey: str | None
    requestId: str
    metadata: dict[str, Any]

    @model_validator(mode="after")
    def ensure_promotion_state_is_consistent(self) -> "KnowledgePromotionRecordContract":
        if self.status == "promoted":
            if self.promotedAt is None or self.promotedBy is None:
                raise ValueError("promoted Knowledge Promotion requires promotedAt and promotedBy")
            if self.rollbackRef:
                raise ValueError("promoted Knowledge Promotion must not carry rollbackRef")
            if self.supersedeRef:
                raise ValueError("promoted Knowledge Promotion must not carry supersedeRef")
        if self.status == "rolled_back" and not self.rollbackRef:
            raise ValueError("rolled_back Knowledge Promotion requires rollbackRef")
        if self.status == "superseded" and not self.supersedeRef:
            raise ValueError("superseded Knowledge Promotion requires supersedeRef")
        replay_status = self.replayValidationRef.get("status")
        replay_source = self.replayValidationRef.get("source")
        if replay_status != "passed":
            raise ValueError("replayValidationRef.status must be passed")
        if replay_source not in {"persisted_validation_record", "replay_export", "frozen_replay_snapshot"}:
            raise ValueError("replayValidationRef.source must be persisted or frozen")
        if not self.coverageProofRef.get("id"):
            raise ValueError("coverageProofRef.id is required")
        proof_status = self.coverageProofRef.get("proofStatus")
        if proof_status != "valid":
            raise ValueError("coverageProofRef.proofStatus must be valid")
        if self.coverageProofRef.get("source") != "persisted_record":
            raise ValueError("coverageProofRef.source must be persisted_record")
        if self.approvalState == "not_required" and self.policySnapshot.get("approvalState") != "not_required":
            raise ValueError("not_required approvalState requires policySnapshot.approvalState")
        if self.approvalState == "satisfied" and not self.approvalRefs:
            raise ValueError("satisfied approvalState requires approvalRefs")
        return self


CONTRACT_MODELS: dict[str, type[BaseModel]] = {
    "agent-output": AgentOutputContract,
    "skill-result": SkillResultContract,
    "skill-context-envelope": SkillContextEnvelope,
    "finding": FindingContract,
    "gate-policy": GatePolicyContract,
    "gate-policy-resolution-request": GatePolicyResolutionRequestContract,
    "gate-policy-resolution-result": GatePolicyResolutionResultContract,
    "gate-policy-import-request": GatePolicyImportRequest,
    "gate-policy-import-preview": GatePolicyImportPreview,
    "gate-policy-validation-issue": GatePolicyValidationIssue,
    "gate-policy-structured-diff": GatePolicyStructuredDiff,
    "gate-policy-draft-save": GatePolicyImportDraftSaveRequest,
    "gate-policy-simulation-request": SimulationRequest,
    "gate-policy-simulation-run": SimulationRun,
    "gate-policy-simulation-case-diff": SimulationCaseDiff,
    "gate-policy-simulation-summary": SimulationSummary,
    "gate-policy-mode": GateModeProjection,
    "gate-policy-activation-request": ActivationRequest,
    "gate-policy-activation-result": ActivationResult,
    "gate-policy-rollback-request": RollbackRequest,
    "gate-policy-rollback-result": RollbackResult,
    "gate-policy-rollback-target": RollbackTargetProjection,
    "gate-input": GateInputContract,
    "gate-result": GateResultContract,
    "replay-export": ReplayExportContract,
    "replay-repository": ReplayRepositoryContract,
    "domain-event": DomainEventContract,
    "lifecycle-state": LifecycleStateContract,
    "license-capability-boundary": LicenseCapabilityBoundaryContract,
    "capability-binding": CapabilityBindingContract,
    "workflow-capability-graph": WorkflowCapabilityGraphContract,
    "structured-log-projection": StructuredLogProjectionContract,
    "audit-log-projection": AuditLogProjectionContract,
    "decision-timeline-query": TimelineQuery,
    "decision-timeline": TimelineProjection,
    "evidence-index-entry": EvidenceIndexEntryContract,
    "evidence-index-job": EvidenceIndexJobContract,
    "evidence-query-request": EvidenceQueryRequestContract,
    "evidence-query-result": EvidenceQueryResultContract,
    "canonical-execution-graph": CanonicalExecutionGraphContract,
    "candidate-build-request": CandidateBuildRequest,
    "candidate-build-result": CandidateBuildResult,
    "requirement-change-set": RequirementChangeSetContract,
    "code-change-set": CodeChangeSetContract,
    "normalization-issue": NormalizationIssueContract,
    "capability-mapping": CapabilityMappingContract,
    "impact-request": ImpactRequestContract,
    "impact-result": ImpactResultContract,
    "selective-replay-request": SelectiveReplayRequest,
    "selective-replay-plan": SelectiveReplayPlan,
    "scm-webhook-envelope": WebhookEnvelope,
    "pr-revision": PRRevision,
    "pr-context": PRContext,
    "requirement-match-reason": RequirementMatchReason,
    "requirement-match-candidate": RequirementMatchCandidate,
    "requirement-match": RequirementMatch,
    "requirement-match-snapshot": RequirementMatchSnapshot,
    "sandbox-profile": SandboxProfile,
    "static-scan-request": StaticScanRequest,
    "static-scan-result": StaticScanResult,
    "smoke-plan": SmokePlan,
    "smoke-run": SmokeRun,
    "smoke-result": SmokeResult,
    "admission-run-request": AdmissionRunRequest,
    "admission-run": AdmissionRunProjection,
    "admission-stage": AdmissionStageProjection,
    "admission-result": AdmissionResultProjection,
    "admission-timeline": AdmissionTimelineProjection,
    "admission-review-request": AdmissionReviewRequest,
    "admission-review": AdmissionReviewProjection,
    "admission-retry-request": AdmissionRetryRequest,
    "ci-conclusion": CIConclusion,
    "enforcement-decision": EnforcementDecision,
    "stale-revision-result": StaleRevisionResult,
    "external-action-ref": ExternalActionRef,
    "legacy-skill-decision-field-notice": LegacySkillDecisionFieldNotice,
    "ci-writeback-request": CIWritebackRequest,
    "ci-writeback-retry-request": CIWritebackRetryRequest,
    "ci-writeback-result": CIWritebackResult,
    "graph-correction-proposal": CreateGraphCorrectionProposalRequest,
    "graph-learning-policy": CreateGraphLearningPolicyRequest,
    "graph-learning-binding": CreateGraphLearningBindingRequest,
    "graph-promotion-eligibility": PromotionEligibilityAssessment,
    "graph-promotion-result": GraphPromotionResult,
    "graph-staleness-assessment": GraphStalenessAssessmentContract,
    "graph-traceability-projection": TraceabilityProjection,
    "graph-coverage-input": GraphCoverageInput,
    "graph-coverage-result": GraphCoverageResult,
    "ceg-graph-summary-projection": GraphSummaryProjection,
    "ceg-path-projection": PathProjection,
    "ceg-node-detail-projection": NodeDetailProjection,
    "ceg-evidence-projection": EvidenceProjection,
    "coverage-map": CoverageMapContract,
    "test-knowledge-entry": TestKnowledgeEntryContract,
    "failure-attribution": FailureAttributionContract,
    "regression-plan": RegressionPlanContract,
    "requirement-version": RequirementVersionContract,
    "clarification": ClarificationContract,
    "test-asset": TestAssetContract,
    "asset-review": AssetReviewContract,
    "execution-plan": ExecutionPlanContract,
    "correction-record": CorrectionRecordContract,
    "missing-link": MissingLinkContract,
    "traceability-path": TraceabilityPathContract,
    "coverage-summary": CoverageSummaryContract,
    "coverage-matrix": CoverageMatrixContract,
    "traceability-snapshot": TraceabilitySnapshotContract,
    "coverage-proof-bundle": CoverageProofBundleContract,
    "correction-proposal": CorrectionProposalContract,
    "correction-application": CorrectionApplicationContract,
    "correction-validation": CorrectionValidationContract,
    "rollback-record": RollbackRecordContract,
    "knowledge-promotion-record": KnowledgePromotionRecordContract,
    "feedback-taxonomy": FeedbackTaxonomyContract,
    "lesson-evidence": LessonEvidenceContract,
    "lesson-candidate": LessonCandidateContract,
    "lesson-review": LessonReviewContract,
    "promotion-result": PromotionResultContract,
    "improvement-proposal": ImprovementProposalContract,
    "improvement-validation-result": ImprovementValidationResultContract,
    "improvement-effectiveness-result": ImprovementEffectivenessResultContract,
    "locator-update": LocatorUpdateContract,
    "assertion-update": AssertionUpdateContract,
    "test-case-update": TestCaseUpdateContract,
    "test-step-update": TestStepUpdateContract,
    "requirement-mapping-update": RequirementMappingUpdateContract,
    "execution-config-update": ExecutionConfigUpdateContract,
    "generate-patch-suggestion": GeneratePatchSuggestionContract,
}


def contract_schema_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "schemas" / "contracts"


def contract_schema_path(contract_name: str) -> Path:
    return contract_schema_dir() / f"{contract_name}.schema.json"


def load_contract_schema(contract_name: str) -> dict[str, Any]:
    path = contract_schema_path(contract_name)
    if not path.exists():
        raise ContractValidationError(contract_name, [f"missing schema file: {path}"])
    return json.loads(path.read_text(encoding="utf-8"))


def validate_contract(contract_name: ContractName, payload: dict[str, Any]) -> dict[str, Any]:
    schema = load_contract_schema(contract_name)
    _validate_payload_against_schema(contract_name, schema, payload)
    model = CONTRACT_MODELS[contract_name]
    try:
        parsed = model.model_validate(payload)
    except Exception as exc:
        raise ContractValidationError(contract_name, [str(exc)]) from exc
    return parsed.model_dump(mode="json")


def assert_contract_schema_consistency(contract_name: ContractName) -> None:
    schema = load_contract_schema(contract_name)
    model_schema = CONTRACT_MODELS[contract_name].model_json_schema()
    canonical_properties = set((schema.get("properties") or {}).keys())
    model_properties = set((model_schema.get("properties") or {}).keys())
    issues: list[str] = []

    if canonical_properties != model_properties:
        issues.append(
            "property drift: "
            f"schema-only={sorted(canonical_properties - model_properties)} "
            f"pydantic-only={sorted(model_properties - canonical_properties)}"
        )

    canonical_required = set(schema.get("required") or [])
    model_required = set(model_schema.get("required") or [])
    if canonical_required != model_required:
        issues.append(
            "required drift: "
            f"schema-only={sorted(canonical_required - model_required)} "
            f"pydantic-only={sorted(model_required - canonical_required)}"
        )

    if schema.get("additionalProperties") != model_schema.get("additionalProperties"):
        issues.append("root additionalProperties drift")

    for property_name in sorted(canonical_properties & model_properties):
        canonical_property = (schema.get("properties") or {}).get(property_name) or {}
        model_property = (model_schema.get("properties") or {}).get(property_name) or {}
        for keyword in ("type",):
            if keyword in canonical_property and keyword in model_property and canonical_property[keyword] != model_property[keyword]:
                issues.append(f"{property_name}.{keyword} drift")
        for keyword in ("minimum", "maximum", "minItems", "minLength", "const", "pattern"):
            if canonical_property.get(keyword) != model_property.get(keyword):
                issues.append(f"{property_name}.{keyword} drift")

    if issues:
        raise ContractValidationError(contract_name, issues)


def assert_all_contract_schemas_consistent() -> None:
    for contract_name in CONTRACT_MODELS:
        assert_contract_schema_consistency(contract_name)  # type: ignore[arg-type]


def _validate_payload_against_schema(contract_name: str, schema: dict[str, Any], payload: dict[str, Any]) -> None:
    issues: list[str] = []
    if not isinstance(payload, dict):
        issues.append("payload must be an object")
    else:
        required = schema.get("required") or []
        for field_name in required:
            if field_name not in payload:
                issues.append(f"missing required field: {field_name}")

        properties = schema.get("properties") or {}
        if schema.get("additionalProperties") is False:
            extra_fields = sorted(set(payload) - set(properties))
            if extra_fields:
                issues.append(f"unexpected fields: {extra_fields}")

        for field_name, field_schema in properties.items():
            if field_name in payload:
                issues.extend(_validate_json_schema_value(field_schema, payload[field_name], field_name))

    if issues:
        raise ContractValidationError(contract_name, issues)


def _validate_json_schema_value(schema: dict[str, Any], value: Any, path: str) -> list[str]:
    issues: list[str] = []
    expected_type = schema.get("type")
    if expected_type is not None and not _matches_json_type(value, expected_type):
        issues.append(f"{path} expected {expected_type}, got {_json_type_name(value)}")
        return issues

    if "enum" in schema and value not in schema["enum"]:
        issues.append(f"{path} must be one of {schema['enum']!r}")

    if "const" in schema and value != schema["const"]:
        issues.append(f"{path} must equal {schema['const']!r}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            issues.append(f"{path} is shorter than minLength {schema['minLength']}")
        if "pattern" in schema and not re.match(str(schema["pattern"]), value):
            issues.append(f"{path} does not match pattern {schema['pattern']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            issues.append(f"{path} is below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            issues.append(f"{path} is above maximum {schema['maximum']}")

    if isinstance(value, dict):
        properties = schema.get("properties") or {}
        for field_name in schema.get("required") or []:
            if field_name not in value:
                issues.append(f"{path}.{field_name} is required")
        if schema.get("additionalProperties") is False:
            extra_fields = sorted(set(value) - set(properties))
            if extra_fields:
                issues.append(f"{path} unexpected fields: {extra_fields}")
        for field_name, field_schema in properties.items():
            if field_name in value:
                issues.extend(_validate_json_schema_value(field_schema, value[field_name], f"{path}.{field_name}"))

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            issues.append(f"{path} has fewer than minItems {schema['minItems']}")
        if isinstance(schema.get("items"), dict):
            item_schema = schema["items"]
            for index, item in enumerate(value):
                issues.extend(_validate_json_schema_value(item_schema, item, f"{path}[{index}]"))

    return issues


def _contains_forbidden_patch_semantics(value: Any) -> bool:
    forbidden_keys = {
        "apply",
        "applyMode",
        "applied",
        "appliedRefs",
        "changed",
        "changedRefs",
        "changeApplied",
        "commitRef",
        "mergeRef",
    }
    if isinstance(value, dict):
        for key, item in value.items():
            if key in forbidden_keys:
                return True
            if _contains_forbidden_patch_semantics(item):
                return True
    if isinstance(value, list):
        return any(_contains_forbidden_patch_semantics(item) for item in value)
    return False


def _matches_json_type(value: Any, expected_type: str | list[str]) -> bool:
    expected = expected_type if isinstance(expected_type, list) else [expected_type]
    actual = _json_type_name(value)
    if actual == "integer" and "number" in expected:
        return True
    return actual in expected


def _json_type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _contains_secret_marker(value: Any) -> bool:
    secret_markers = ("secret", "password", "token", "api_key", "apikey", "credential")
    if isinstance(value, dict):
        for key, child in value.items():
            lowered_key = str(key).lower()
            if any(marker in lowered_key for marker in secret_markers):
                return True
            if _contains_secret_marker(child):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_marker(child) for child in value)
    return False

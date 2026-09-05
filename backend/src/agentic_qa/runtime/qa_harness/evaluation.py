# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_qa.runtime.qa_harness.context_builder import (
    canonical_content_hash,
    contains_unsafe_snapshot_material,
)


EvaluationTargetKind = Literal[
    "agent",
    "model_role",
    "skill",
    "extension",
    "profile",
    "harness_workflow",
]
MeasurementClass = Literal[
    "deterministic",
    "simulated",
    "loopback_contract",
    "local_actual",
    "external_actual",
]
EvaluationMetricName = Literal[
    "requirementCoverage",
    "duplicateCaseRate",
    "validCaseRate",
    "evidenceCitationValidity",
    "unsupportedClaimRate",
    "schemaFailureRate",
    "fallbackRate",
    "averageModelCalls",
    "averageTurns",
    "latencyMs",
    "tokenUsage",
    "costAmount",
    "reproducibility",
]

SkillEvaluationMetricDirection = Literal["higher_better", "lower_better"]


class _StrictEvaluationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvaluationScopeSnapshot(_StrictEvaluationModel):
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: str = Field(min_length=1, max_length=255)
    environmentId: str | None = Field(default=None, max_length=255)
    scopeHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_hash(self) -> "EvaluationScopeSnapshot":
        expected = canonical_content_hash(
            {
                "tenantId": self.tenantId,
                "workspaceId": self.workspaceId,
                "projectId": self.projectId,
                "environmentId": self.environmentId,
            }
        )
        if self.scopeHash != expected:
            raise ValueError("EVALUATION_SCOPE_HASH_MISMATCH")
        return self


class EvaluationFrozenReference(_StrictEvaluationModel):
    ref: str = Field(min_length=1, max_length=1000)
    refType: str = Field(min_length=1, max_length=120)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    scopeHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    trustBoundary: Literal["service_authorized", "frozen_untrusted"]
    redactionStatus: Literal["redacted", "not_required", "unavailable"]
    available: bool = True
    unavailableReason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_availability(self) -> "EvaluationFrozenReference":
        if not self.available and not self.unavailableReason:
            raise ValueError("unavailable Evaluation ref requires unavailableReason")
        if self.available and self.redactionStatus == "unavailable":
            raise ValueError("available Evaluation ref cannot be unavailable")
        if contains_unsafe_snapshot_material(self.model_dump(mode="json")):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        return self


class EvaluationFrozenSnapshot(_StrictEvaluationModel):
    snapshotRef: str = Field(min_length=1, max_length=1000)
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    schemaVersion: str = Field(min_length=1, max_length=120)
    scopeHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redactionStatus: Literal["redacted", "not_required"]
    sourceRefs: list[EvaluationFrozenReference] = Field(default_factory=list, max_length=500)
    limitations: list[str] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def validate_snapshot(self) -> "EvaluationFrozenSnapshot":
        if any(item.scopeHash != self.scopeHash for item in self.sourceRefs):
            raise ValueError("EVALUATION_CROSS_SCOPE_REFERENCE_BLOCKED")
        if contains_unsafe_snapshot_material(self.model_dump(mode="json")):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        return self


class EvaluationTargetReference(_StrictEvaluationModel):
    kind: EvaluationTargetKind
    ref: str = Field(min_length=1, max_length=1000)
    version: str = Field(min_length=1, max_length=120)
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    scopeHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def reject_unsafe_reference(self) -> "EvaluationTargetReference":
        if contains_unsafe_snapshot_material(self.model_dump(mode="json")):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        return self


class EvaluationRule(_StrictEvaluationModel):
    metricName: EvaluationMetricName
    operator: Literal["gte", "lte"]
    threshold: float = Field(ge=0.0)
    required: bool = True


class EvaluationInput(_StrictEvaluationModel):
    schemaVersion: Literal["phase8.harness-evaluation-input.v1"] = (
        "phase8.harness-evaluation-input.v1"
    )
    datasetId: str = Field(min_length=1, max_length=255)
    datasetVersion: str = Field(min_length=1, max_length=120)
    targetRef: EvaluationTargetReference
    baselineRef: EvaluationTargetReference | None = None
    candidateRef: EvaluationTargetReference | None = None
    frozenInputRefs: list[EvaluationFrozenReference] = Field(min_length=1, max_length=5000)
    scopeSnapshot: EvaluationScopeSnapshot
    policySnapshot: EvaluationFrozenSnapshot
    profileSnapshot: EvaluationFrozenSnapshot
    extensionSnapshot: EvaluationFrozenSnapshot
    promptSnapshot: EvaluationFrozenSnapshot
    modelRoleSnapshot: EvaluationFrozenSnapshot
    outputSnapshot: EvaluationFrozenSnapshot
    evaluationRules: list[EvaluationRule] = Field(default_factory=list, max_length=100)
    measurementClass: MeasurementClass

    @model_validator(mode="after")
    def validate_frozen_scope(self) -> "EvaluationInput":
        expected = self.scopeSnapshot.scopeHash
        scoped_values = [
            self.targetRef,
            self.baselineRef,
            self.candidateRef,
            self.policySnapshot,
            self.profileSnapshot,
            self.extensionSnapshot,
            self.promptSnapshot,
            self.modelRoleSnapshot,
            self.outputSnapshot,
            *self.frozenInputRefs,
        ]
        if any(item is not None and item.scopeHash != expected for item in scoped_values):
            raise ValueError("EVALUATION_CROSS_SCOPE_REFERENCE_BLOCKED")
        if self.baselineRef and self.baselineRef.kind != self.targetRef.kind:
            raise ValueError("EVALUATION_BASELINE_TARGET_KIND_MISMATCH")
        if self.candidateRef and self.candidateRef.kind != self.targetRef.kind:
            raise ValueError("EVALUATION_CANDIDATE_TARGET_KIND_MISMATCH")
        if contains_unsafe_snapshot_material(self.model_dump(mode="json")):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        return self


class EvaluationCaseMeasurement(_StrictEvaluationModel):
    caseId: str = Field(min_length=1, max_length=255)
    requirementsExpected: int = Field(default=0, ge=0)
    requirementsCovered: int = Field(default=0, ge=0)
    generatedCaseCount: int = Field(default=0, ge=0)
    duplicateCaseCount: int = Field(default=0, ge=0)
    validCaseCount: int = Field(default=0, ge=0)
    citationCount: int = Field(default=0, ge=0)
    validCitationCount: int = Field(default=0, ge=0)
    claimCount: int = Field(default=0, ge=0)
    unsupportedClaimCount: int = Field(default=0, ge=0)
    schemaFailureCount: int = Field(default=0, ge=0)
    fallbackCount: int = Field(default=0, ge=0)
    modelCalls: int = Field(default=0, ge=0)
    turns: int = Field(default=0, ge=0)
    latencyMs: float = Field(default=0.0, ge=0.0)
    tokenUsage: int = Field(default=0, ge=0)
    costAmount: float = Field(default=0.0, ge=0.0)
    reproducible: bool
    protocolActual: bool = False
    localActual: bool = False
    externalActual: bool = False
    semanticQualityMeasured: bool = False
    evidenceRefs: list[EvaluationFrozenReference] = Field(default_factory=list, max_length=500)
    artifactRefs: list[EvaluationFrozenReference] = Field(default_factory=list, max_length=500)
    modelInvocationRefs: list[EvaluationFrozenReference] = Field(default_factory=list, max_length=500)
    limitations: list[str] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def validate_counts(self) -> "EvaluationCaseMeasurement":
        if self.requirementsCovered > self.requirementsExpected:
            raise ValueError("requirementsCovered exceeds requirementsExpected")
        if self.duplicateCaseCount > self.generatedCaseCount:
            raise ValueError("duplicateCaseCount exceeds generatedCaseCount")
        if self.validCaseCount > self.generatedCaseCount:
            raise ValueError("validCaseCount exceeds generatedCaseCount")
        if self.validCitationCount > self.citationCount:
            raise ValueError("validCitationCount exceeds citationCount")
        if self.unsupportedClaimCount > self.claimCount:
            raise ValueError("unsupportedClaimCount exceeds claimCount")
        if self.fallbackCount > self.modelCalls:
            raise ValueError("fallbackCount exceeds modelCalls")
        if contains_unsafe_snapshot_material(
            {
                "references": [
                    item.model_dump(mode="json")
                    for item in [
                        *self.evidenceRefs,
                        *self.artifactRefs,
                        *self.modelInvocationRefs,
                    ]
                ],
                "limitations": self.limitations,
            }
        ):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        return self


class EvaluationMetrics(_StrictEvaluationModel):
    requirementCoverage: float = Field(ge=0.0, le=1.0)
    duplicateCaseRate: float = Field(ge=0.0, le=1.0)
    validCaseRate: float = Field(ge=0.0, le=1.0)
    evidenceCitationValidity: float = Field(ge=0.0, le=1.0)
    unsupportedClaimRate: float = Field(ge=0.0, le=1.0)
    schemaFailureRate: float = Field(ge=0.0, le=1.0)
    fallbackRate: float = Field(ge=0.0, le=1.0)
    averageModelCalls: float = Field(ge=0.0)
    averageTurns: float = Field(ge=0.0)
    latencyMs: float = Field(ge=0.0)
    tokenUsage: int = Field(ge=0)
    costAmount: float = Field(ge=0.0)
    reproducibility: float = Field(ge=0.0, le=1.0)


class EvaluationCaseResult(_StrictEvaluationModel):
    caseId: str
    status: Literal["completed", "partial", "failed"]
    metrics: EvaluationMetrics
    failureReasons: list[str] = Field(default_factory=list)
    evidenceRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    artifactRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    modelInvocationRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class EvaluationReproducibility(_StrictEvaluationModel):
    inputHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evaluatorVersion: Literal["controlled-qa-evaluator.v1"] = (
        "controlled-qa-evaluator.v1"
    )
    measurementClass: MeasurementClass
    deterministicAggregation: Literal[True] = True
    rerunComparable: bool
    wallClockExcludedFromResultHash: Literal[True] = True


class EvaluationResult(_StrictEvaluationModel):
    schemaVersion: Literal["phase8.harness-evaluation-result.v1"] = (
        "phase8.harness-evaluation-result.v1"
    )
    status: Literal["completed", "partial", "failed", "unavailable"]
    targetRef: EvaluationTargetReference
    metrics: EvaluationMetrics
    caseResults: list[EvaluationCaseResult]
    failureReasons: list[str] = Field(default_factory=list)
    evidenceRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    artifactRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    modelInvocationRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    profileSnapshot: EvaluationFrozenSnapshot
    extensionSnapshot: EvaluationFrozenSnapshot
    reproducibility: EvaluationReproducibility
    limitations: list[str] = Field(default_factory=list)
    resultHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_result_hash(self) -> "EvaluationResult":
        payload = self.model_dump(mode="json", exclude={"resultHash"})
        if contains_unsafe_snapshot_material(payload):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        if self.resultHash != canonical_content_hash(payload):
            raise ValueError("EVALUATION_RESULT_HASH_MISMATCH")
        return self


class SkillEvaluationMetricDefinition(_StrictEvaluationModel):
    """Platform-owned comparison rule for one extension-point metric.

    Skill implementations own how a metric is produced.  The Harness only
    validates its declared name, aggregates observations, and applies the
    frozen threshold/regression rule.
    """

    metricName: str = Field(pattern=r"^[a-z][A-Za-z0-9]{1,79}$")
    direction: SkillEvaluationMetricDirection
    threshold: float = Field(ge=0.0, le=1.0)
    maxRegression: float = Field(default=0.0, ge=0.0, le=1.0)
    required: bool = True


class SkillEvaluationObservation(_StrictEvaluationModel):
    caseId: str = Field(min_length=1, max_length=255)
    metrics: dict[str, float] = Field(default_factory=dict, max_length=100)
    outputContractValid: bool
    invocationRef: str = Field(min_length=1, max_length=1000)
    evidenceRefs: list[EvaluationFrozenReference] = Field(default_factory=list, max_length=500)
    artifactRefs: list[EvaluationFrozenReference] = Field(default_factory=list, max_length=500)
    limitations: list[str] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def validate_metrics_and_refs(self) -> "SkillEvaluationObservation":
        for name, value in self.metrics.items():
            if not name or len(name) > 80 or not 0.0 <= float(value) <= 1.0:
                raise ValueError("SKILL_EVALUATION_METRIC_INVALID")
        if contains_unsafe_snapshot_material(self.model_dump(mode="json")):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        return self


class SkillEvaluationMetricComparison(_StrictEvaluationModel):
    metricName: str
    direction: SkillEvaluationMetricDirection
    baselineValue: float = Field(ge=0.0, le=1.0)
    candidateValue: float = Field(ge=0.0, le=1.0)
    regression: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    maxRegression: float = Field(ge=0.0, le=1.0)
    passed: bool
    reasonCodes: list[str] = Field(default_factory=list)


class SkillVersionEvaluationInput(_StrictEvaluationModel):
    schemaVersion: Literal["phase8.skill-version-evaluation-input.v1"] = (
        "phase8.skill-version-evaluation-input.v1"
    )
    evaluationId: str = Field(min_length=1, max_length=255)
    extensionPointId: str = Field(min_length=1, max_length=160)
    datasetId: str = Field(min_length=1, max_length=255)
    datasetVersion: str = Field(min_length=1, max_length=120)
    baselineRef: EvaluationTargetReference
    candidateRef: EvaluationTargetReference
    frozenInputRefs: list[EvaluationFrozenReference] = Field(min_length=1, max_length=5000)
    scopeSnapshot: EvaluationScopeSnapshot
    measurementClass: MeasurementClass
    metricDefinitions: list[SkillEvaluationMetricDefinition] = Field(
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_frozen_comparison(self) -> "SkillVersionEvaluationInput":
        expected_scope = self.scopeSnapshot.scopeHash
        if self.baselineRef.kind != "skill" or self.candidateRef.kind != "skill":
            raise ValueError("SKILL_EVALUATION_TARGET_KIND_REQUIRED")
        if (
            self.baselineRef.scopeHash != expected_scope
            or self.candidateRef.scopeHash != expected_scope
            or any(item.scopeHash != expected_scope for item in self.frozenInputRefs)
        ):
            raise ValueError("EVALUATION_CROSS_SCOPE_REFERENCE_BLOCKED")
        metric_names = [item.metricName for item in self.metricDefinitions]
        if len(set(metric_names)) != len(metric_names):
            raise ValueError("SKILL_EVALUATION_METRIC_DUPLICATE")
        if contains_unsafe_snapshot_material(self.model_dump(mode="json")):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        return self


class SkillVersionEvaluationResult(_StrictEvaluationModel):
    schemaVersion: Literal["phase8.skill-version-evaluation-result.v1"] = (
        "phase8.skill-version-evaluation-result.v1"
    )
    evaluationId: str
    extensionPointId: str
    status: Literal["completed", "partial", "failed", "unavailable"]
    nonAuthoritative: Literal[True] = True
    activationEligible: bool
    baselineRef: EvaluationTargetReference
    candidateRef: EvaluationTargetReference
    caseCount: int = Field(ge=0)
    comparisons: list[SkillEvaluationMetricComparison]
    failureReasons: list[str] = Field(default_factory=list)
    evidenceRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    artifactRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    replayRefs: list[EvaluationFrozenReference] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    inputHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evaluatorVersion: Literal["controlled-skill-version-evaluator.v1"] = (
        "controlled-skill-version-evaluator.v1"
    )
    resultHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_result_hash(self) -> "SkillVersionEvaluationResult":
        payload = self.model_dump(mode="json", exclude={"resultHash"})
        if contains_unsafe_snapshot_material(payload):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        if self.resultHash != canonical_content_hash(payload):
            raise ValueError("EVALUATION_RESULT_HASH_MISMATCH")
        if self.activationEligible and self.status != "completed":
            raise ValueError("SKILL_EVALUATION_ELIGIBILITY_STATUS_INVALID")
        return self


@dataclass(frozen=True, slots=True)
class SkillEvaluationMetricRegistry:
    """Immutable platform registry; it never computes Skill-specific metrics."""

    _definitions: Mapping[str, tuple[SkillEvaluationMetricDefinition, ...]]

    def for_extension(self, extension_point_id: str) -> tuple[SkillEvaluationMetricDefinition, ...]:
        definitions = self._definitions.get(extension_point_id)
        if definitions is None:
            definitions = self._definitions["*"]
        return definitions

    def projection(self, extension_point_id: str) -> list[dict[str, object]]:
        return [
            item.model_dump(mode="json")
            for item in self.for_extension(extension_point_id)
        ]


def _metric(
    name: str,
    direction: SkillEvaluationMetricDirection,
    threshold: float,
    max_regression: float = 0.0,
) -> SkillEvaluationMetricDefinition:
    return SkillEvaluationMetricDefinition(
        metricName=name,
        direction=direction,
        threshold=threshold,
        maxRegression=max_regression,
    )


SKILL_EVALUATION_METRICS = SkillEvaluationMetricRegistry(
    MappingProxyType(
        {
            "PREPARE.test_plan": (
                _metric("requirementCoverage", "higher_better", 0.8, 0.02),
                _metric("evidenceCompleteness", "higher_better", 0.9, 0.02),
                _metric("schemaSuccessRate", "higher_better", 0.98, 0.0),
            ),
            "PREPARE.test_case": (
                _metric("coverage", "higher_better", 0.8, 0.02),
                _metric("executability", "higher_better", 0.9, 0.02),
                _metric("duplicateRate", "lower_better", 0.1, 0.02),
            ),
            "ANALYZE.finding_triage": (
                _metric("classificationAccuracy", "higher_better", 0.85, 0.02),
                _metric("lowConfidenceRate", "lower_better", 0.15, 0.02),
            ),
            "ANALYZE.performance_analysis": (
                _metric("regressionDetectionRate", "higher_better", 0.9, 0.02),
                _metric("evidenceCompleteness", "higher_better", 0.9, 0.02),
            ),
            "ANALYZE.security_analysis": (
                _metric("falseNegativeRate", "lower_better", 0.05, 0.0),
                _metric("falsePositiveRate", "lower_better", 0.15, 0.02),
                _metric("severityConsistency", "higher_better", 0.9, 0.02),
            ),
            "EXECUTE.automated_execution": (
                _metric("successRate", "higher_better", 0.95, 0.02),
                _metric("timeoutRate", "lower_better", 0.05, 0.0),
                _metric("stability", "higher_better", 0.95, 0.02),
                _metric("artifactCompleteness", "higher_better", 0.9, 0.02),
            ),
            "*": (
                _metric("schemaSuccessRate", "higher_better", 0.98, 0.0),
                _metric("evidenceCompleteness", "higher_better", 0.9, 0.02),
            ),
        }
    )
)


class QaEvaluationRunner:
    """Deterministic offline aggregation; never activates or mutates a target."""

    VERSION = "controlled-qa-evaluator.v1"
    SKILL_VERSION_EVALUATOR_VERSION = "controlled-skill-version-evaluator.v1"

    def compare_skill_versions(
        self,
        evaluation_input: SkillVersionEvaluationInput | dict[str, Any],
        *,
        baseline_observations: Sequence[SkillEvaluationObservation | dict[str, Any]],
        candidate_observations: Sequence[SkillEvaluationObservation | dict[str, Any]],
    ) -> SkillVersionEvaluationResult:
        """Compare exact baseline/candidate versions from the same frozen dataset.

        This is deliberately non-authoritative.  It produces activation
        eligibility evidence, never an authoritative governance or business
        mutation.
        """

        spec = (
            evaluation_input
            if isinstance(evaluation_input, SkillVersionEvaluationInput)
            else SkillVersionEvaluationInput.model_validate(evaluation_input)
        )
        baseline = self._skill_observations(baseline_observations)
        candidate = self._skill_observations(candidate_observations)
        if not baseline or not candidate:
            raise ValueError("EVALUATION_DATASET_EMPTY")
        baseline_ids = {item.caseId for item in baseline}
        candidate_ids = {item.caseId for item in candidate}
        if len(baseline_ids) != len(baseline) or len(candidate_ids) != len(candidate):
            raise ValueError("EVALUATION_CASE_ID_DUPLICATE")
        if baseline_ids != candidate_ids:
            raise ValueError("SKILL_EVALUATION_CASE_SET_MISMATCH")
        self._validate_skill_observation_scope(spec, [*baseline, *candidate])

        failure_reasons: list[str] = []
        comparisons: list[SkillEvaluationMetricComparison] = []
        for definition in sorted(spec.metricDefinitions, key=lambda item: item.metricName):
            missing_baseline = [
                item.caseId for item in baseline if definition.metricName not in item.metrics
            ]
            missing_candidate = [
                item.caseId for item in candidate if definition.metricName not in item.metrics
            ]
            if missing_baseline or missing_candidate:
                if definition.required:
                    failure_reasons.append(
                        f"SKILL_EVALUATION_METRIC_MISSING:{definition.metricName}"
                    )
                continue
            baseline_value = self._average_metric(baseline, definition.metricName)
            candidate_value = self._average_metric(candidate, definition.metricName)
            if definition.direction == "higher_better":
                regression = max(0.0, baseline_value - candidate_value)
                threshold_passed = candidate_value >= definition.threshold
            else:
                regression = max(0.0, candidate_value - baseline_value)
                threshold_passed = candidate_value <= definition.threshold
            reason_codes: list[str] = []
            if not threshold_passed:
                reason_codes.append(
                    f"SKILL_EVALUATION_THRESHOLD_FAILED:{definition.metricName}"
                )
            if regression > definition.maxRegression:
                reason_codes.append(
                    f"SKILL_EVALUATION_REGRESSION:{definition.metricName}"
                )
            failure_reasons.extend(reason_codes)
            comparisons.append(
                SkillEvaluationMetricComparison(
                    metricName=definition.metricName,
                    direction=definition.direction,
                    baselineValue=baseline_value,
                    candidateValue=candidate_value,
                    regression=round(regression, 8),
                    threshold=definition.threshold,
                    maxRegression=definition.maxRegression,
                    passed=not reason_codes,
                    reasonCodes=reason_codes,
                )
            )

        invalid_outputs = sorted(
            item.caseId for item in candidate if not item.outputContractValid
        )
        if invalid_outputs:
            failure_reasons.append("SKILL_EVALUATION_OUTPUT_CONTRACT_INVALID")
        limitations = list(
            dict.fromkeys(
                [
                    *self._measurement_limitations(spec.measurementClass),
                    *(value for item in [*baseline, *candidate] for value in item.limitations),
                ]
            )
        )
        observation_limitations = [
            value for item in [*baseline, *candidate] for value in item.limitations
        ]
        partial = bool(observation_limitations) or any(
            not ref.available
            for item in [*baseline, *candidate]
            for ref in [*item.evidenceRefs, *item.artifactRefs]
        )
        unique_evidence = self._unique_skill_refs(
            [*baseline, *candidate], "evidenceRefs"
        )
        unique_artifacts = self._unique_skill_refs(
            [*baseline, *candidate], "artifactRefs"
        )
        replay_refs = [
            item for item in spec.frozenInputRefs if item.refType in {"replay", "replay_case"}
        ]
        status: Literal["completed", "partial", "failed", "unavailable"]
        if failure_reasons:
            status = "failed"
        elif partial:
            status = "partial"
        else:
            status = "completed"
        result_payload: dict[str, Any] = {
            "schemaVersion": "phase8.skill-version-evaluation-result.v1",
            "evaluationId": spec.evaluationId,
            "extensionPointId": spec.extensionPointId,
            "status": status,
            "nonAuthoritative": True,
            "activationEligible": status == "completed",
            "baselineRef": spec.baselineRef.model_dump(mode="json"),
            "candidateRef": spec.candidateRef.model_dump(mode="json"),
            "caseCount": len(candidate),
            "comparisons": [item.model_dump(mode="json") for item in comparisons],
            "failureReasons": list(dict.fromkeys(failure_reasons)),
            "evidenceRefs": [item.model_dump(mode="json") for item in unique_evidence],
            "artifactRefs": [item.model_dump(mode="json") for item in unique_artifacts],
            "replayRefs": [item.model_dump(mode="json") for item in replay_refs],
            "limitations": limitations,
            "inputHash": canonical_content_hash(spec.model_dump(mode="json")),
            "evaluatorVersion": self.SKILL_VERSION_EVALUATOR_VERSION,
        }
        result_payload["resultHash"] = canonical_content_hash(result_payload)
        return SkillVersionEvaluationResult.model_validate(result_payload)

    def run(
        self,
        evaluation_input: EvaluationInput | dict[str, Any],
        measurements: list[EvaluationCaseMeasurement | dict[str, Any]],
    ) -> EvaluationResult:
        spec = (
            evaluation_input
            if isinstance(evaluation_input, EvaluationInput)
            else EvaluationInput.model_validate(evaluation_input)
        )
        cases = [
            item
            if isinstance(item, EvaluationCaseMeasurement)
            else EvaluationCaseMeasurement.model_validate(item)
            for item in measurements
        ]
        if not cases:
            raise ValueError("EVALUATION_DATASET_EMPTY")
        if len({item.caseId for item in cases}) != len(cases):
            raise ValueError("EVALUATION_CASE_ID_DUPLICATE")
        self._validate_measurement_class(spec.measurementClass, cases)
        for case in cases:
            all_refs = [*case.evidenceRefs, *case.artifactRefs, *case.modelInvocationRefs]
            if any(item.scopeHash != spec.scopeSnapshot.scopeHash for item in all_refs):
                raise ValueError("EVALUATION_CROSS_SCOPE_REFERENCE_BLOCKED")

        case_results: list[EvaluationCaseResult] = []
        for case in sorted(cases, key=lambda item: item.caseId):
            metrics = self._metrics([case])
            failures = self._rule_failures(metrics, spec.evaluationRules)
            partial = bool(case.limitations) or any(
                not item.available
                for item in [*case.evidenceRefs, *case.artifactRefs, *case.modelInvocationRefs]
            )
            case_results.append(
                EvaluationCaseResult(
                    caseId=case.caseId,
                    status="failed" if failures else "partial" if partial else "completed",
                    metrics=metrics,
                    failureReasons=failures,
                    evidenceRefs=case.evidenceRefs,
                    artifactRefs=case.artifactRefs,
                    modelInvocationRefs=case.modelInvocationRefs,
                    limitations=case.limitations,
                )
            )

        metrics = self._metrics(cases)
        aggregate_failures = self._rule_failures(metrics, spec.evaluationRules)
        limitations = self._measurement_limitations(spec.measurementClass)
        limitations.extend(
            item
            for case in case_results
            for item in case.limitations
            if item not in limitations
        )
        status: Literal["completed", "partial", "failed", "unavailable"]
        if aggregate_failures:
            status = "failed"
        elif any(case.status == "partial" for case in case_results):
            status = "partial"
        else:
            status = "completed"

        input_hash = canonical_content_hash(spec.model_dump(mode="json"))
        result_payload: dict[str, Any] = {
            "schemaVersion": "phase8.harness-evaluation-result.v1",
            "status": status,
            "targetRef": (spec.candidateRef or spec.targetRef).model_dump(mode="json"),
            "metrics": metrics.model_dump(mode="json"),
            "caseResults": [item.model_dump(mode="json") for item in case_results],
            "failureReasons": aggregate_failures,
            "evidenceRefs": [
                item.model_dump(mode="json")
                for item in self._unique_refs(cases, "evidenceRefs")
            ],
            "artifactRefs": [
                item.model_dump(mode="json")
                for item in self._unique_refs(cases, "artifactRefs")
            ],
            "modelInvocationRefs": [
                item.model_dump(mode="json")
                for item in self._unique_refs(cases, "modelInvocationRefs")
            ],
            "profileSnapshot": spec.profileSnapshot.model_dump(mode="json"),
            "extensionSnapshot": spec.extensionSnapshot.model_dump(mode="json"),
            "reproducibility": EvaluationReproducibility(
                inputHash=input_hash,
                measurementClass=spec.measurementClass,
                rerunComparable=all(case.reproducible for case in cases),
            ).model_dump(mode="json"),
            "limitations": limitations,
        }
        if contains_unsafe_snapshot_material(
            {
                "references": [
                    *result_payload["evidenceRefs"],
                    *result_payload["artifactRefs"],
                    *result_payload["modelInvocationRefs"],
                ],
                "limitations": result_payload["limitations"],
                "failureReasons": result_payload["failureReasons"],
            }
        ):
            raise ValueError("EVALUATION_SECRET_SCAN_BLOCKED")
        result_payload["resultHash"] = canonical_content_hash(result_payload)
        return EvaluationResult.model_validate(result_payload)

    @staticmethod
    def _validate_measurement_class(
        measurement_class: MeasurementClass,
        cases: list[EvaluationCaseMeasurement],
    ) -> None:
        if measurement_class == "loopback_contract":
            if any(not case.protocolActual or case.semanticQualityMeasured for case in cases):
                raise ValueError("LOOPBACK_CONTRACT_CANNOT_CLAIM_SEMANTIC_QUALITY")
        elif measurement_class == "local_actual":
            if any(not case.localActual or case.externalActual for case in cases):
                raise ValueError("LOCAL_ACTUAL_EVIDENCE_REQUIRED")
        elif measurement_class == "external_actual":
            if any(not case.externalActual or not case.evidenceRefs for case in cases):
                raise ValueError("EXTERNAL_ACTUAL_EVIDENCE_REQUIRED")
        elif measurement_class in {"deterministic", "simulated"}:
            if any(case.localActual or case.externalActual for case in cases):
                raise ValueError("SIMULATED_MEASUREMENT_CANNOT_CLAIM_ACTUAL")

    @staticmethod
    def _measurement_limitations(measurement_class: MeasurementClass) -> list[str]:
        if measurement_class == "loopback_contract":
            return ["LOOPBACK_DOES_NOT_MEASURE_REAL_PROVIDER_SEMANTIC_QUALITY"]
        if measurement_class in {"deterministic", "simulated"}:
            return ["REAL_PROVIDER_SEMANTIC_EVALUATION_NOT_MEASURED"]
        if measurement_class == "local_actual":
            return ["EXTERNAL_ACTUAL_NOT_MEASURED"]
        return []

    @classmethod
    def _metrics(cls, cases: list[EvaluationCaseMeasurement]) -> EvaluationMetrics:
        case_count = len(cases)
        expected = sum(item.requirementsExpected for item in cases)
        generated = sum(item.generatedCaseCount for item in cases)
        citations = sum(item.citationCount for item in cases)
        claims = sum(item.claimCount for item in cases)
        model_calls = sum(item.modelCalls for item in cases)
        return EvaluationMetrics(
            requirementCoverage=cls._ratio(
                sum(item.requirementsCovered for item in cases), expected
            ),
            duplicateCaseRate=cls._ratio(
                sum(item.duplicateCaseCount for item in cases), generated
            ),
            validCaseRate=cls._ratio(
                sum(item.validCaseCount for item in cases), generated
            ),
            evidenceCitationValidity=cls._ratio(
                sum(item.validCitationCount for item in cases), citations
            ),
            unsupportedClaimRate=cls._ratio(
                sum(item.unsupportedClaimCount for item in cases), claims
            ),
            schemaFailureRate=cls._ratio(
                sum(item.schemaFailureCount for item in cases), model_calls
            ),
            fallbackRate=cls._ratio(
                sum(item.fallbackCount for item in cases), model_calls
            ),
            averageModelCalls=sum(item.modelCalls for item in cases) / case_count,
            averageTurns=sum(item.turns for item in cases) / case_count,
            latencyMs=sum(item.latencyMs for item in cases) / case_count,
            tokenUsage=sum(item.tokenUsage for item in cases),
            costAmount=round(sum(item.costAmount for item in cases), 6),
            reproducibility=cls._ratio(
                sum(1 for item in cases if item.reproducible), case_count
            ),
        )

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        if denominator <= 0:
            return 0.0
        return round(numerator / denominator, 8)

    @staticmethod
    def _rule_failures(
        metrics: EvaluationMetrics,
        rules: list[EvaluationRule],
    ) -> list[str]:
        failures = []
        values = metrics.model_dump()
        for rule in sorted(
            (item for item in rules if item.required),
            key=lambda item: (item.metricName, item.operator, item.threshold),
        ):
            value = float(values[rule.metricName])
            passed = value >= rule.threshold if rule.operator == "gte" else value <= rule.threshold
            if not passed:
                failures.append(
                    f"RULE_FAILED:{rule.metricName}:{rule.operator}:{rule.threshold:g}"
                )
        return failures

    @staticmethod
    def _unique_refs(
        cases: list[EvaluationCaseMeasurement],
        field_name: Literal["evidenceRefs", "artifactRefs", "modelInvocationRefs"],
    ) -> list[EvaluationFrozenReference]:
        by_ref: dict[str, EvaluationFrozenReference] = {}
        for case in cases:
            for item in getattr(case, field_name):
                by_ref.setdefault(item.ref, item)
        return [by_ref[key] for key in sorted(by_ref)]

    @staticmethod
    def _skill_observations(
        values: Sequence[SkillEvaluationObservation | dict[str, Any]],
    ) -> list[SkillEvaluationObservation]:
        return [
            item
            if isinstance(item, SkillEvaluationObservation)
            else SkillEvaluationObservation.model_validate(item)
            for item in values
        ]

    @staticmethod
    def _average_metric(
        observations: list[SkillEvaluationObservation], metric_name: str
    ) -> float:
        return round(
            sum(float(item.metrics[metric_name]) for item in observations)
            / len(observations),
            8,
        )

    @staticmethod
    def _validate_skill_observation_scope(
        spec: SkillVersionEvaluationInput,
        observations: list[SkillEvaluationObservation],
    ) -> None:
        expected_scope = spec.scopeSnapshot.scopeHash
        if any(
            ref.scopeHash != expected_scope
            for item in observations
            for ref in [*item.evidenceRefs, *item.artifactRefs]
        ):
            raise ValueError("EVALUATION_CROSS_SCOPE_REFERENCE_BLOCKED")

    @staticmethod
    def _unique_skill_refs(
        observations: list[SkillEvaluationObservation],
        field_name: Literal["evidenceRefs", "artifactRefs"],
    ) -> list[EvaluationFrozenReference]:
        by_ref: dict[str, EvaluationFrozenReference] = {}
        for item in observations:
            for ref in getattr(item, field_name):
                by_ref.setdefault(ref.ref, ref)
        return [by_ref[key] for key in sorted(by_ref)]


def build_evaluation_scope_snapshot(
    *,
    tenant_id: str,
    workspace_id: str,
    project_id: str,
    environment_id: str | None = None,
) -> EvaluationScopeSnapshot:
    payload = {
        "tenantId": tenant_id,
        "workspaceId": workspace_id,
        "projectId": project_id,
        "environmentId": environment_id,
    }
    return EvaluationScopeSnapshot(
        tenantId=tenant_id,
        workspaceId=workspace_id,
        projectId=project_id,
        environmentId=environment_id,
        scopeHash=canonical_content_hash(payload),
    )


__all__ = [
    "EvaluationCaseMeasurement",
    "EvaluationCaseResult",
    "EvaluationFrozenReference",
    "EvaluationFrozenSnapshot",
    "EvaluationInput",
    "EvaluationMetricName",
    "EvaluationMetrics",
    "EvaluationReproducibility",
    "EvaluationResult",
    "EvaluationRule",
    "EvaluationScopeSnapshot",
    "EvaluationTargetKind",
    "EvaluationTargetReference",
    "MeasurementClass",
    "QaEvaluationRunner",
    "SKILL_EVALUATION_METRICS",
    "SkillEvaluationMetricComparison",
    "SkillEvaluationMetricDefinition",
    "SkillEvaluationMetricDirection",
    "SkillEvaluationMetricRegistry",
    "SkillEvaluationObservation",
    "SkillVersionEvaluationInput",
    "SkillVersionEvaluationResult",
    "build_evaluation_scope_snapshot",
]

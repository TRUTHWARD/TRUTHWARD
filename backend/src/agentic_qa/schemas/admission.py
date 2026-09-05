# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_qa.infra.redaction import contains_unsafe_control_characters, redact_sensitive_text


class _StrictAdmissionModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


AdmissionMode = Literal["observe", "shadow", "enforce"]


def _default_semgrep_tools() -> list[Literal["semgrep"]]:
    return ["semgrep"]
AdmissionReviewState = Literal[
    "not_requested",
    "pending",
    "approved",
    "rejected",
    "cancelled",
    "expired",
]
AdmissionStageStatus = Literal[
    "pending",
    "running",
    "completed",
    "partial",
    "failed",
    "skipped",
    "unavailable",
    "cancelled",
    "stale",
]


class AdmissionArtifactRef(_StrictAdmissionModel):
    type: str = Field(min_length=1, max_length=80)
    ref: str = Field(min_length=1, max_length=1200)
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    byteSize: int | None = Field(default=None, ge=0, le=2_147_483_647)
    redactionStatus: Literal["redacted", "not_required", "blocked"] = "not_required"

    @field_validator("ref")
    @classmethod
    def safe_ref(cls, value: str) -> str:
        if contains_unsafe_control_characters(value) or redact_sensitive_text(value) != value:
            raise ValueError("Admission refs must not contain control characters or sensitive values")
        return value


class SourceArchiveRef(_StrictAdmissionModel):
    storageRef: str = Field(min_length=1, max_length=1200)
    contentHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    headSha: str = Field(pattern=r"^[a-f0-9]{7,64}$")
    archiveFormat: Literal["tar"] = "tar"

    @field_validator("storageRef")
    @classmethod
    def controlled_storage_ref(cls, value: str) -> str:
        if not value.startswith("local://artifacts/"):
            raise ValueError("P21 source archives must use the configured Artifact Storage boundary")
        if contains_unsafe_control_characters(value) or redact_sensitive_text(value) != value:
            raise ValueError("source archive ref is unsafe")
        return value


class SandboxProfile(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.sandbox-profile.v1"] = "phase8.sandbox-profile.v1"
    profileId: str = Field(default="p21-default-deny-v1", min_length=1, max_length=120)
    engine: Literal["docker"] = "docker"
    networkMode: Literal["none", "allowlist"] = "none"
    networkAllowlist: list[str] = Field(default_factory=list, max_length=32)
    readOnlySource: Literal[True] = True
    readOnlyRootFilesystem: Literal[True] = True
    tmpfsMB: int = Field(default=128, ge=16, le=2048)
    cpuLimit: float = Field(default=1.0, gt=0.0, le=8.0)
    memoryMB: int = Field(default=512, ge=64, le=8192)
    pidsLimit: int = Field(default=128, ge=16, le=1024)
    timeoutSeconds: int = Field(default=300, ge=1, le=3600)
    secretRefs: list[str] = Field(default_factory=list, max_length=32)
    hostPathAccess: Literal[False] = False
    dockerSocketAccess: Literal[False] = False
    noNewPrivileges: Literal[True] = True
    dropAllCapabilities: Literal[True] = True
    cleanupRequired: Literal[True] = True

    @model_validator(mode="after")
    def deny_implicit_network_and_secrets(self) -> "SandboxProfile":
        if self.networkMode == "none" and self.networkAllowlist:
            raise ValueError("network allowlist requires networkMode=allowlist")
        if self.networkMode == "allowlist" and not self.networkAllowlist:
            raise ValueError("allowlist network mode requires at least one destination")
        for destination in self.networkAllowlist:
            if "://" in destination or "/" in destination or "\\" in destination:
                raise ValueError("network allowlist entries must be host names, not URLs or paths")
        for ref in self.secretRefs:
            if not ref.startswith(("secret://", "credential://", "env://")):
                raise ValueError("secretRefs must be opaque managed references")
        return self


class StaticScanRequest(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.static-scan-request.v1"]
    prContextVersionId: UUID
    sourceArtifactRef: SourceArchiveRef
    headSha: str = Field(pattern=r"^[a-f0-9]{7,64}$")
    tools: list[Literal["semgrep"]] = Field(default_factory=_default_semgrep_tools, min_length=1, max_length=4)
    sandboxProfile: SandboxProfile
    idempotencyKey: str = Field(min_length=8, max_length=255)

    @model_validator(mode="after")
    def source_matches_requested_revision(self) -> "StaticScanRequest":
        if self.sourceArtifactRef.headSha != self.headSha:
            raise ValueError("source archive headSha must match the frozen scan revision")
        return self


class AdmissionToolResult(_StrictAdmissionModel):
    tool: str = Field(min_length=1, max_length=80)
    toolVersion: str | None = Field(default=None, max_length=120)
    status: Literal["completed", "failed", "partial", "unavailable", "cancelled"]
    toolStatus: Literal[
        "ok",
        "findings_detected",
        "threshold_exceeded",
        "tool_error",
        "infra_error",
        "timeout",
        "partial",
        "cancelled",
    ]
    actualExecution: bool
    sandboxed: Literal[True] = True
    exitCode: int
    durationMs: int = Field(ge=0)
    unavailableReason: str | None = Field(default=None, max_length=500)
    artifactRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=1000)
    rawFindingRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=10000)


class StaticScanResult(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.static-scan-result.v1"]
    admissionRunId: UUID
    executionId: UUID
    status: Literal["completed", "failed", "partial", "unavailable", "cancelled"]
    headSha: str = Field(pattern=r"^[a-f0-9]{7,64}$")
    toolResults: list[AdmissionToolResult] = Field(min_length=1, max_length=16)
    artifactRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=1000)
    rawFindingRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=10000)
    findingCandidates: list[dict] = Field(default_factory=list, max_length=10000)
    normalizedFindingRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=10000)
    analyzeCompleted: bool
    normalizeCompleted: bool
    gateDecisionCreated: Literal[False] = False


class SmokeTestSpec(_StrictAdmissionModel):
    taskRef: str = Field(min_length=1, max_length=1000)
    recipe: Literal["python-unittest"]
    testModule: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]{0,254}$")
    selectedReasonCodes: list[str] = Field(min_length=1, max_length=16)
    estimatedSeconds: int = Field(ge=1, le=3600)


class UnsupportedSmokeTest(_StrictAdmissionModel):
    testRef: str = Field(min_length=1, max_length=1000)
    reasonCode: Literal[
        "SMOKE_NON_FUNCTIONAL_UNSUPPORTED",
        "SMOKE_TASK_REF_INVALID",
        "SMOKE_RUNNER_NOT_SANDBOXED",
        "SMOKE_SELECTOR_INVALID",
    ]


class SmokePlan(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.smoke-plan.v1"]
    selectiveReplayPlanId: UUID
    selectiveReplayPlanHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    headSha: str = Field(pattern=r"^[a-f0-9]{7,64}$")
    tests: list[SmokeTestSpec] = Field(default_factory=list, max_length=1000)
    unsupportedTests: list[UnsupportedSmokeTest] = Field(default_factory=list, max_length=10000)
    conservativeSelectionPreserved: Literal[True] = True

    @model_validator(mode="after")
    def every_selected_test_is_accounted_for(self) -> "SmokePlan":
        accounted = len(self.tests) + len(self.unsupportedTests)
        if accounted < 1:
            raise ValueError("smoke plan must contain an executable or explicitly unsupported selected test")
        return self


class SmokeRun(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.smoke-run.v1"]
    admissionRunId: UUID
    executionId: UUID
    status: Literal["queued", "running", "completed", "failed", "partial", "unavailable", "cancelled"]
    taskRefs: list[str] = Field(default_factory=list, max_length=1000)
    sandboxProfileHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    startedAt: datetime | None = None
    endedAt: datetime | None = None


class SmokeResult(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.smoke-result.v1"]
    admissionRunId: UUID
    executionId: UUID
    status: Literal["completed", "failed", "partial", "unavailable", "cancelled"]
    toolResults: list[AdmissionToolResult] = Field(default_factory=list, max_length=1000)
    artifactRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=1000)
    rawFindingRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=10000)
    findingCandidates: list[dict] = Field(default_factory=list, max_length=10000)
    normalizedFindingRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=10000)
    unsupportedTests: list[UnsupportedSmokeTest] = Field(default_factory=list, max_length=10000)
    flakyDetected: bool | None
    analyzeCompleted: bool
    normalizeCompleted: bool
    gateDecisionCreated: Literal[False] = False


class AdmissionRunRequest(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-run-request.v1", "phase8.admission-run-request.v2"]
    prContextVersionId: UUID
    selectiveReplayPlanId: UUID
    environmentId: UUID | None = None
    mode: AdmissionMode = "observe"
    sourceArtifactRef: SourceArchiveRef
    sandboxProfile: SandboxProfile = Field(default_factory=SandboxProfile)
    scanTools: list[Literal["semgrep"]] = Field(default_factory=_default_semgrep_tools, min_length=1, max_length=4)
    idempotencyKey: str = Field(min_length=8, max_length=255)


class AdmissionStageProjection(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-stage.v1"] = "phase8.admission-stage.v1"
    sequence: int = Field(ge=1, le=6)
    lifecycleStage: Literal["PREPARE", "EXECUTE", "OBSERVE", "ANALYZE", "NORMALIZE", "GATE"]
    status: AdmissionStageStatus
    reasonCode: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    startedAt: datetime | None = None
    endedAt: datetime | None = None
    traceRefs: list[str] = Field(default_factory=list, max_length=100)
    evidenceRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=10_000)
    summary: dict[str, Any] = Field(default_factory=dict, max_length=32)
    nonAuthoritative: bool = True

    @model_validator(mode="after")
    def require_reason_for_non_success(self) -> "AdmissionStageProjection":
        if self.status in {"partial", "failed", "skipped", "unavailable", "cancelled", "stale"} and not self.reasonCode:
            raise ValueError("non-success Admission stage status requires a ReasonCode")
        return self


class AdmissionShadowGateProjection(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-shadow-gate.v1"] = "phase8.admission-shadow-gate.v1"
    status: Literal["completed", "unavailable"]
    decision: Literal["pass", "warn", "fail", "blocked"] | None
    domainResults: list[dict[str, Any]] = Field(default_factory=list, max_length=3)
    reasonCodes: list[str] = Field(default_factory=list, max_length=1000)
    completeness: dict[str, Any] = Field(default_factory=dict, max_length=32)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    policyRef: AdmissionArtifactRef | None = None
    inputFingerprint: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    decisionSnapshotHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    evaluatorVersion: str | None = Field(default=None, max_length=120)
    evaluatedAt: datetime
    reasonCode: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    nonAuthoritative: Literal[True] = True
    gateDecisionCreated: Literal[False] = False
    ciWriteback: Literal[False] = False
    mergeBlocking: Literal[False] = False

    @model_validator(mode="after")
    def validate_availability(self) -> "AdmissionShadowGateProjection":
        if self.status == "completed" and self.decision is None:
            raise ValueError("completed shadow Gate requires a decision")
        if self.status == "unavailable" and not self.reasonCode:
            raise ValueError("unavailable shadow Gate requires a ReasonCode")
        return self


class AdmissionEnforceGateProjection(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-enforce-gate.v1"] = "phase8.admission-enforce-gate.v1"
    status: Literal["completed", "unavailable"]
    decision: Literal["pass", "warn", "fail", "blocked"] | None
    reasonCodes: list[str] = Field(default_factory=list, max_length=1000)
    gateDecisionId: UUID | None = None
    gateDecisionRef: str | None = Field(default=None, max_length=1200)
    inputFingerprint: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    decisionSnapshotHash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    evaluatorVersion: str | None = Field(default=None, max_length=120)
    evaluatedAt: datetime
    reasonCode: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    nonAuthoritative: Literal[False] = False
    gateDecisionCreated: bool

    @model_validator(mode="after")
    def validate_authoritative_gate(self) -> "AdmissionEnforceGateProjection":
        if self.status == "completed" and (
            self.decision is None or self.gateDecisionId is None or not self.gateDecisionCreated
        ):
            raise ValueError("completed Enforce Gate requires a persisted GateDecision")
        if self.status == "unavailable" and (not self.reasonCode or self.gateDecisionCreated):
            raise ValueError("unavailable Enforce Gate requires a ReasonCode and no GateDecision")
        return self


class AdmissionResultProjection(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-result.v2"] = "phase8.admission-result.v2"
    mode: AdmissionMode
    conclusion: Literal[
        "observed",
        "would_pass",
        "would_warn",
        "would_fail",
        "would_block",
        "passed",
        "warned",
        "failed",
        "blocked",
        "partial",
        "unavailable",
        "cancelled",
        "stale",
    ]
    reasonCodes: list[str] = Field(default_factory=list, max_length=1000)
    normalizedFindingRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=10_000)
    evidenceRefs: list[AdmissionArtifactRef] = Field(default_factory=list, max_length=10_000)
    shadowGate: AdmissionShadowGateProjection | None
    enforceGate: AdmissionEnforceGateProjection | None = None
    resultHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    nonAuthoritative: bool = True
    authoritativeAdmissionDecision: dict[str, Any] | None = None
    gateDecisionCreated: bool = False
    ciWriteback: bool = False
    mergeBlocking: bool = False

    @model_validator(mode="after")
    def validate_mode_authority(self) -> "AdmissionResultProjection":
        if self.mode == "enforce":
            if self.nonAuthoritative or self.shadowGate is not None:
                raise ValueError("Enforce Admission result must be authoritative")
            if self.conclusion in {"passed", "warned", "failed", "blocked"} and self.enforceGate is None:
                raise ValueError("authoritative Enforce conclusion requires an Enforce Gate projection")
        elif not self.nonAuthoritative or self.enforceGate is not None or self.gateDecisionCreated or self.mergeBlocking:
            raise ValueError("Observe and Shadow results must remain non-authoritative")
        if self.mergeBlocking and (self.mode != "enforce" or self.conclusion not in {"failed", "blocked"}):
            raise ValueError("only failed/blocked Enforce results may block merge")
        return self


class AdmissionReviewRequest(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-review-request.v1"] = "phase8.admission-review-request.v1"
    intent: Literal["acknowledge_evidence", "request_follow_up"]
    comment: str | None = Field(default=None, max_length=500)
    idempotencyKey: str = Field(min_length=8, max_length=255)


class AdmissionReviewProjection(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-review.v1"] = "phase8.admission-review.v1"
    admissionRunId: UUID
    state: AdmissionReviewState
    intent: Literal["acknowledge_evidence", "request_follow_up"] | None
    approvalRef: AdmissionArtifactRef | None
    requestedBy: str | None
    decidedBy: str | None
    requestedAt: datetime | None
    decidedAt: datetime | None
    commentPresent: bool
    effect: Literal["annotation_only"] = "annotation_only"
    mutatesCanonicalFinding: Literal[False] = False
    mutatesGateDecision: Literal[False] = False
    changesMergeState: Literal[False] = False
    readOnly: Literal[True] = True


class AdmissionRetryRequest(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-retry-request.v1"] = "phase8.admission-retry-request.v1"
    scope: Literal["failed_only", "all"] = "failed_only"


class AdmissionTimelineProjection(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-timeline.v1"] = "phase8.admission-timeline.v1"
    admissionRunId: UUID
    rootTraceRef: str = Field(min_length=1, max_length=1200)
    mode: AdmissionMode
    workflowVersion: str = Field(min_length=1, max_length=120)
    stages: list[AdmissionStageProjection] = Field(min_length=6, max_length=6)
    stageSnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    nonAuthoritative: bool = True
    readOnly: Literal[True] = True

    @model_validator(mode="after")
    def validate_fixed_lifecycle(self) -> "AdmissionTimelineProjection":
        expected = ["PREPARE", "EXECUTE", "OBSERVE", "ANALYZE", "NORMALIZE", "GATE"]
        if [stage.lifecycleStage for stage in self.stages] != expected:
            raise ValueError("Admission timeline must preserve the fixed lifecycle order")
        if [stage.sequence for stage in self.stages] != list(range(1, 7)):
            raise ValueError("Admission timeline stage sequence must be contiguous")
        expected_non_authoritative = self.mode != "enforce"
        if self.nonAuthoritative != expected_non_authoritative:
            raise ValueError("Admission timeline authority must match its mode")
        if any(stage.nonAuthoritative != expected_non_authoritative for stage in self.stages):
            raise ValueError("Admission stage authority must match its mode")
        return self


class AdmissionRunProjection(_StrictAdmissionModel):
    schemaVersion: Literal["phase8.admission-run.v3"]
    admissionRunId: UUID
    projectId: UUID
    repositoryRef: str = Field(min_length=1, max_length=1000)
    pullRequestNumber: int = Field(ge=1)
    prContextVersionId: UUID
    selectiveReplayPlanId: UUID
    executionId: UUID
    environmentId: UUID | None
    mode: AdmissionMode
    workflowVersion: str = Field(min_length=1, max_length=120)
    nonAuthoritative: bool = True
    status: Literal["queued", "running", "completed", "failed", "partial", "unavailable", "cancelled", "stale"]
    baseSha: str = Field(pattern=r"^[a-f0-9]{7,64}$")
    sourceHeadSha: str = Field(pattern=r"^[a-f0-9]{7,64}$")
    inputFingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    sandboxProfile: SandboxProfile
    staticScan: StaticScanResult | None
    smokePlan: SmokePlan
    smokeRun: SmokeRun
    smokeResult: SmokeResult | None
    requirementMatchRef: AdmissionArtifactRef | None
    impactResultRef: AdmissionArtifactRef | None
    changeSetRef: AdmissionArtifactRef | None
    selectiveReplayPlanRef: AdmissionArtifactRef
    stages: list[AdmissionStageProjection] = Field(min_length=6, max_length=6)
    stageSnapshotHash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    admissionResult: AdmissionResultProjection | None
    review: AdmissionReviewProjection
    retry: dict[str, Any]
    replaySnapshot: dict
    guardrailEventRefs: list[AdmissionArtifactRef]
    auditRefs: list[AdmissionArtifactRef]
    traceRefs: list[str]
    createdAt: datetime
    updatedAt: datetime
    rootTraceRef: str = Field(min_length=1, max_length=1200)
    readOnly: Literal[True] = True
    admissionDecision: dict[str, Any] | None = None
    gateDecisionCreated: bool = False
    ciWriteback: dict[str, Any] | None = None
    enforcementReadiness: dict[str, Any]
    frontendAuthoritative: Literal[False] = False


__all__ = [
    "AdmissionMode",
    "AdmissionEnforceGateProjection",
    "AdmissionResultProjection",
    "AdmissionRetryRequest",
    "AdmissionReviewProjection",
    "AdmissionReviewRequest",
    "AdmissionRunProjection",
    "AdmissionRunRequest",
    "AdmissionShadowGateProjection",
    "AdmissionStageProjection",
    "AdmissionTimelineProjection",
    "SandboxProfile",
    "SmokePlan",
    "SmokeResult",
    "SmokeRun",
    "SourceArchiveRef",
    "StaticScanRequest",
    "StaticScanResult",
]

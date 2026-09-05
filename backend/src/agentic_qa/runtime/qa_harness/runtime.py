# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import timedelta
from typing import Any, Protocol

from pydantic import ValidationError

from agentic_qa.runtime.qa_harness.context_builder import (
    AuthorizedContextBuilder,
    canonical_content_hash,
)
from agentic_qa.runtime.qa_harness.contracts import (
    AgentStepResult,
    HarnessContextBlock,
    HarnessEvidenceRef,
    HarnessRunContext,
    HarnessRunResult,
    HarnessRunSpec,
    Observation,
    SkillIntent,
)
from agentic_qa.runtime.qa_harness.loop_controller import (
    CancellationProbe,
    Clock,
    LoopController,
    utc_now,
)
from agentic_qa.runtime.qa_harness.observations import validate_service_observations
from agentic_qa.runtime.qa_harness.stop_reasons import (
    HarnessRunState,
    HarnessRunStatus,
    StopReason,
    TERMINAL_SERVICE_REASONS,
)
from agentic_qa.runtime.qa_harness.trajectory_events import TrajectoryRecorder, TrajectorySink


class AgentStepRuntime(Protocol):
    def __call__(
        self,
        spec: HarnessRunSpec,
        context: HarnessRunContext,
        blocks: list[HarnessContextBlock],
    ) -> AgentStepResult | dict[str, Any]: ...


class ServiceCapability(Protocol):
    def __call__(
        self,
        intent: SkillIntent,
        context: HarnessRunContext,
        blocks: list[HarnessContextBlock],
    ) -> Observation | list[Observation]: ...


class ServiceCapabilityError(RuntimeError):
    def __init__(self, reason_code: StopReason, message: str | None = None) -> None:
        super().__init__(message or reason_code.value)
        self.reason_code = reason_code


class QaHarnessRuntime:
    """Pure bounded loop; all business and persistence capabilities stay in Services."""

    def __init__(
        self,
        *,
        context_builder: AuthorizedContextBuilder,
        agent_runtime: AgentStepRuntime,
        service_capability: ServiceCapability,
        trajectory_sink: TrajectorySink | None = None,
        cancellation_probe: CancellationProbe | None = None,
        clock: Clock = utc_now,
    ) -> None:
        self.context_builder = context_builder
        self.agent_runtime = agent_runtime
        self.service_capability = service_capability
        self.trajectory_sink = trajectory_sink
        self.cancellation_probe = cancellation_probe or (lambda: False)
        self.clock = clock

    def run(self, spec: HarnessRunSpec | dict[str, Any]) -> HarnessRunResult:
        validated_spec = (
            spec if isinstance(spec, HarnessRunSpec) else HarnessRunSpec.model_validate(spec)
        )
        started_at = self.clock()
        context = HarnessRunContext(
            startedAt=started_at,
            deadlineAt=started_at + timedelta(seconds=validated_spec.timeoutSeconds),
            evidenceRefs=list(validated_spec.inputRefs),
        )
        profile_resolution = validated_spec.profileSnapshot.get(
            "extensionResolutionSnapshot"
        )
        profile_resolution = (
            profile_resolution if isinstance(profile_resolution, dict) else {}
        )
        profile_resolution_status = str(
            profile_resolution.get("resolutionStatus")
            or validated_spec.profileSnapshot.get("resolutionStatus")
            or "resolved"
        )
        if profile_resolution_status == "unavailable":
            raise ValueError("QA_PROFILE_RESOLUTION_UNAVAILABLE")
        if profile_resolution_status == "degraded":
            context.limitations = list(
                dict.fromkeys(
                    [
                        *[
                            str(item)
                            for item in profile_resolution.get("limitations", [])
                        ],
                        *[
                            str(item)
                            for item in profile_resolution.get("warnings", [])
                        ],
                    ]
                )
            )
        controller = LoopController(
            validated_spec,
            context,
            clock=self.clock,
            cancellation_probe=self.cancellation_probe,
        )
        trajectory = TrajectoryRecorder(validated_spec.runId, self.trajectory_sink)
        last_result: dict[str, Any] = {}
        degraded = profile_resolution_status == "degraded"
        while True:
            reason = controller.preflight(starting_turn=True)
            if reason is not None:
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=reason,
                    result=last_result,
                )
            trajectory.emit(
                turn=context.currentTurn,
                state=HarnessRunState.ASSEMBLE_CONTEXT,
                occurred_at=self.clock(),
                budget_snapshot=controller.budget_snapshot(),
            )
            try:
                blocks = self.context_builder.build(validated_spec, context)
            except (TypeError, ValueError, ValidationError) as exc:
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=StopReason.AGENT_OUTPUT_INVALID,
                    result=last_result,
                    limitation=f"CONTEXT_BUILD_FAILED:{type(exc).__name__}",
                )
            reason = controller.preflight()
            if reason is not None:
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=reason,
                    result=last_result,
                )
            context.currentTurn += 1
            trajectory.emit(
                turn=context.currentTurn,
                state=HarnessRunState.MODEL_STEP,
                occurred_at=self.clock(),
                budget_snapshot=controller.budget_snapshot(),
                agent_ref=str(
                    validated_spec.metadata.get("agentRef") or "agent-runtime://service-controlled"
                ),
            )
            try:
                raw_step = self.agent_runtime(validated_spec, context, blocks)
            except Exception as exc:  # callback failures must become stable terminal semantics
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=StopReason.SERVICE_CAPABILITY_FAILED,
                    result=last_result,
                    limitation=f"AGENT_RUNTIME_FAILED:{type(exc).__name__}",
                )
            trajectory.emit(
                turn=context.currentTurn,
                state=HarnessRunState.VALIDATE_AGENT_OUTPUT,
                occurred_at=self.clock(),
                budget_snapshot=controller.budget_snapshot(),
            )
            try:
                step = (
                    raw_step
                    if isinstance(raw_step, AgentStepResult)
                    else AgentStepResult.model_validate(raw_step)
                )
            except (TypeError, ValueError, ValidationError):
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=StopReason.AGENT_OUTPUT_INVALID,
                    result=last_result,
                )
            last_result = dict(step.result)
            context.evidenceRefs = self._merge_evidence(context.evidenceRefs, step.evidence)
            context.limitations = list(dict.fromkeys([*context.limitations, *step.limitations]))
            degraded = degraded or step.fallbackUsed or step.status == "degraded"
            if step.status in {"completed", "degraded"}:
                if "require_evidence" in validated_spec.stopConditions and not context.evidenceRefs:
                    return self._terminal(
                        spec=validated_spec,
                        context=context,
                        controller=controller,
                        trajectory=trajectory,
                        reason=StopReason.INSUFFICIENT_EVIDENCE,
                        result=last_result,
                    )
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=StopReason.COMPLETED_VALID_RESULT,
                    result=last_result,
                    force_degraded=degraded,
                    fallback_reason=step.fallbackReason,
                )
            if step.status == "needs_review":
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=StopReason.INSUFFICIENT_EVIDENCE,
                    result=last_result,
                    status=HarnessRunStatus.NEEDS_REVIEW,
                )
            if step.status in {"blocked", "failed"}:
                reason = self._reason_from_metadata(
                    step.metadata,
                    StopReason.SERVICE_CAPABILITY_FAILED,
                )
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=reason,
                    result=last_result,
                )
            intent = step.skillIntents[0]
            trajectory.emit(
                turn=context.currentTurn,
                state=HarnessRunState.RESOLVE_INTENT,
                occurred_at=self.clock(),
                budget_snapshot=controller.budget_snapshot(),
                skill_intent_ref=f"skill-intent://{validated_spec.runId}/{intent.intentId}",
            )
            reason = controller.validate_intent(intent)
            if reason is not None:
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=reason,
                    result=last_result,
                )
            reason = controller.preflight()
            if reason is not None:
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=reason,
                    result=last_result,
                )
            trajectory.emit(
                turn=context.currentTurn,
                state=HarnessRunState.AWAIT_SERVICE_CAPABILITY,
                occurred_at=self.clock(),
                budget_snapshot=controller.budget_snapshot(),
                skill_intent_ref=f"skill-intent://{validated_spec.runId}/{intent.intentId}",
            )
            try:
                raw_observations = self.service_capability(intent, context, blocks)
                observations = validate_service_observations(
                    raw_observations, intent_id=intent.intentId
                )
            except ServiceCapabilityError as exc:
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=exc.reason_code,
                    result=last_result,
                    limitation=str(exc),
                )
            except (TypeError, ValueError, ValidationError):
                return self._terminal(
                    spec=validated_spec,
                    context=context,
                    controller=controller,
                    trajectory=trajectory,
                    reason=StopReason.OBSERVATION_INVALID,
                    result=last_result,
                )
            for observation in observations:
                reason = controller.consume(observation.usage)
                if reason is not None:
                    return self._terminal(
                        spec=validated_spec,
                        context=context,
                        controller=controller,
                        trajectory=trajectory,
                        reason=reason,
                        result=last_result,
                    )
                context.observations.append(observation)
                context.evidenceRefs = self._merge_evidence(
                    context.evidenceRefs, observation.evidenceRefs
                )
                context.limitations = list(
                    dict.fromkeys([*context.limitations, *observation.limitations])
                )
                degraded = degraded or observation.status == "degraded"
                trajectory.emit(
                    turn=context.currentTurn,
                    state=HarnessRunState.OBSERVE,
                    occurred_at=self.clock(),
                    budget_snapshot=controller.budget_snapshot(),
                    model_invocation_ref=observation.modelInvocationRef,
                    skill_intent_ref=f"skill-intent://{validated_spec.runId}/{intent.intentId}",
                    skill_invocation_ref=observation.skillInvocationRef,
                    observation_refs=[observation.observationRef],
                    metadata={"kind": observation.kind, "status": observation.status},
                )
                if not observation.available:
                    reason = observation.reasonCode or StopReason.SERVICE_CAPABILITY_FAILED
                    if reason not in TERMINAL_SERVICE_REASONS:
                        reason = StopReason.SERVICE_CAPABILITY_FAILED
                    return self._terminal(
                        spec=validated_spec,
                        context=context,
                        controller=controller,
                        trajectory=trajectory,
                        reason=reason,
                        result=last_result,
                    )

    def _terminal(
        self,
        *,
        spec: HarnessRunSpec,
        context: HarnessRunContext,
        controller: LoopController,
        trajectory: TrajectoryRecorder,
        reason: StopReason,
        result: dict[str, Any],
        limitation: str | None = None,
        force_degraded: bool = False,
        fallback_reason: str | None = None,
        status: HarnessRunStatus | None = None,
    ) -> HarnessRunResult:
        if limitation:
            context.limitations = list(dict.fromkeys([*context.limitations, limitation]))
        resolved_status, state = self._terminal_status(reason, force_degraded, status)
        trajectory.emit(
            turn=context.currentTurn,
            state=state,
            occurred_at=self.clock(),
            budget_snapshot=controller.budget_snapshot(),
            stop_reason=reason,
        )
        frozen_refs = self._frozen_refs(spec, context)
        return HarnessRunResult(
            status=resolved_status,
            result=result,
            evidence=context.evidenceRefs,
            limitations=context.limitations,
            stopReason=reason,
            turnsUsed=context.currentTurn,
            modelCallsUsed=context.modelCallsUsed,
            skillInvocationsUsed=context.skillInvocationsUsed,
            toolCallsUsed=context.toolCallsUsed,
            trajectoryRefs=trajectory.refs,
            metadata={
                "runId": spec.runId,
                "workflow": spec.workflow,
                "lifecycleStage": spec.lifecycleStage,
                "runSpecHash": canonical_content_hash(spec.model_dump(mode="json")),
                "policySnapshotHash": canonical_content_hash(spec.policySnapshot),
                "profileSnapshotHash": canonical_content_hash(spec.profileSnapshot),
                "profileResolutionStatus": spec.profileSnapshot.get(
                    "resolutionStatus", "resolved"
                ),
                "fallbackUsed": force_degraded,
                "fallbackReason": fallback_reason,
                "frozenRefs": frozen_refs,
            },
        )

    @staticmethod
    def _terminal_status(
        reason: StopReason,
        degraded: bool,
        status: HarnessRunStatus | None,
    ) -> tuple[HarnessRunStatus, HarnessRunState]:
        if status is not None:
            return status, HarnessRunState.BLOCKED
        if reason == StopReason.COMPLETED_VALID_RESULT:
            if degraded:
                return HarnessRunStatus.DEGRADED, HarnessRunState.DEGRADED
            return HarnessRunStatus.COMPLETED, HarnessRunState.COMPLETE
        if reason == StopReason.CANCELLED:
            return HarnessRunStatus.CANCELLED, HarnessRunState.CANCELLED
        if reason in {
            StopReason.APPROVAL_REQUIRED,
            StopReason.BINDING_UNAVAILABLE,
            StopReason.CAPABILITY_UNAVAILABLE,
            StopReason.GUARDRAIL_BLOCKED,
            StopReason.INSUFFICIENT_EVIDENCE,
        }:
            return HarnessRunStatus.BLOCKED, HarnessRunState.BLOCKED
        if reason in {StopReason.MODEL_UNAVAILABLE, StopReason.MODEL_OUTPUT_INVALID}:
            return HarnessRunStatus.DEGRADED, HarnessRunState.DEGRADED
        return HarnessRunStatus.FAILED, HarnessRunState.FAILED

    @staticmethod
    def _merge_evidence(
        current: list[HarnessEvidenceRef],
        incoming: list[HarnessEvidenceRef],
    ) -> list[HarnessEvidenceRef]:
        merged: list[HarnessEvidenceRef] = []
        seen: set[str] = set()
        for item in [*current, *incoming]:
            key = f"{item.type}:{item.ref}:{item.contentHash or ''}"
            if key not in seen:
                seen.add(key)
                merged.append(item)
        return merged

    @staticmethod
    def _reason_from_metadata(metadata: dict[str, Any], default: StopReason) -> StopReason:
        value = metadata.get("reasonCode")
        try:
            return StopReason(str(value)) if value else default
        except ValueError:
            return default

    @staticmethod
    def _frozen_refs(spec: HarnessRunSpec, context: HarnessRunContext) -> dict[str, Any]:
        profile_resolution = spec.profileSnapshot.get("extensionResolutionSnapshot")
        profile_resolution = (
            profile_resolution if isinstance(profile_resolution, dict) else {}
        )
        actual_skill_refs = list(
            dict.fromkeys(
                observation.skillInvocationRef
                for observation in context.observations
                if observation.skillInvocationRef
            )
        )
        actual_model_refs = list(
            dict.fromkeys(
                observation.modelInvocationRef
                for observation in context.observations
                if observation.modelInvocationRef
            )
        )
        return {
            "inputRefs": [item.model_dump(mode="json") for item in spec.inputRefs],
            "policySnapshotHash": canonical_content_hash(spec.policySnapshot),
            "profileSnapshotHash": canonical_content_hash(spec.profileSnapshot),
            "profileSnapshot": spec.profileSnapshot,
            "extensionResolutionSnapshot": profile_resolution,
            "skillInvocationRefs": actual_skill_refs,
            "modelInvocationRefs": actual_model_refs,
            "resolvedSkillRefs": list(
                dict.fromkeys(
                    [
                        *[
                            str(item)
                            for item in profile_resolution.get("resolvedSkillRefs", [])
                        ],
                        *actual_skill_refs,
                    ]
                )
            ),
            "resolvedModelRefs": list(
                dict.fromkeys(
                    [
                        *[
                            str(item)
                            for item in profile_resolution.get("resolvedModelRefs", [])
                        ],
                        *actual_model_refs,
                    ]
                )
            ),
            "resolvedRunnerRefs": list(
                profile_resolution.get("resolvedRunnerRefs", [])
            ),
            "resolvedConnectorRefs": list(
                profile_resolution.get("resolvedConnectorRefs", [])
            ),
            "bindingRefs": list(profile_resolution.get("bindingRefs", [])),
            "fallbackReasons": list(
                profile_resolution.get("fallbackReasons", [])
            ),
            "compatibilityResults": list(
                profile_resolution.get("compatibilityResults", [])
            ),
            "agentRunRefs": list(
                dict.fromkeys(
                    observation.agentRunRef
                    for observation in context.observations
                    if observation.agentRunRef
                )
            ),
            "observationRefs": [observation.observationRef for observation in context.observations],
            "bindingResolutions": [
                observation.metadata["bindingResolution"]
                for observation in context.observations
                if isinstance(observation.metadata.get("bindingResolution"), dict)
            ],
            "fallbackRefs": [
                {
                    "observationRef": observation.observationRef,
                    "fallbackReason": observation.metadata.get("fallbackReason"),
                }
                for observation in context.observations
                if observation.status == "degraded"
            ],
        }


__all__ = [
    "AgentStepRuntime",
    "QaHarnessRuntime",
    "ServiceCapability",
    "ServiceCapabilityError",
]

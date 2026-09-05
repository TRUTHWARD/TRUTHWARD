# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping
from uuid import UUID

from agentic_qa.domain.models import ExecutionTask, SkillInvocation
from agentic_qa.runtime.qa_harness.context_builder import (
    validate_context_envelope,
    validate_safe_context_content,
)
from agentic_qa.tools.runner_protocols import (
    RunnerAdapter,
    RunnerExecutionRequest,
    RunnerExecutionResult,
    RunnerLogRecord,
    utcnow,
    validate_runner_execution_result,
)
from agentic_qa.tools.runner_registry import RunnerRegistry
from agentic_qa.services.extension_point_contracts import EXTENSION_POINT_CONTRACTS
from agentic_qa.services.skill_execution_policy import SkillInvocationExecutionError
from agentic_qa.services.community_skill_policy import (
    COMMUNITY_REGRESSION_ADAPTER,
    COMMUNITY_REGRESSION_EXTENSION,
    project_regression_view,
)


@dataclass(frozen=True, slots=True)
class SkillRuntimeContext:
    skill_invocation_id: UUID
    skill_id: str | None
    extension_point_id: str | None
    source_workflow: str | None
    resolution_snapshot: dict[str, object]
    policy_snapshot: dict[str, object]
    skill_version_id: UUID | None = None
    version: str | None = None
    manifest_hash: str | None = None
    runtime_adapter: str | None = None
    runtime_result_kind: str | None = None
    authorized_context: dict[str, object] | None = None
    deadline_at: datetime | None = None
    cancellation_probe: Callable[[], bool] | None = None
    clock: Callable[[], datetime] = utcnow

    @classmethod
    def from_invocation(
        cls,
        invocation: SkillInvocation,
        *,
        cancellation_probe: Callable[[], bool] | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> "SkillRuntimeContext":
        resolution = dict(invocation.resolution_snapshot or {})
        input_snapshot = dict(invocation.input_snapshot or {})
        policy_snapshot = dict(invocation.policy_snapshot or {})
        execution_policy = policy_snapshot.get("skillInvocationExecutionPolicy")
        execution_policy = execution_policy if isinstance(execution_policy, dict) else {}
        raw_deadline = execution_policy.get("deadlineAt")
        deadline_at: datetime | None = None
        if isinstance(raw_deadline, str):
            parsed = datetime.fromisoformat(raw_deadline.replace("Z", "+00:00"))
            deadline_at = (
                parsed.replace(tzinfo=timezone.utc)
                if parsed.tzinfo is None
                else parsed.astimezone(timezone.utc)
            )
        authorized_context = input_snapshot.get("authorizedContextEnvelope")
        if authorized_context is not None:
            authorized_context = validate_context_envelope(authorized_context)
        return cls(
            skill_invocation_id=invocation.id,
            skill_id=str(resolution.get("skillId") or resolution.get("resolvedSkillId") or ""),
            extension_point_id=invocation.extension_point_id,
            source_workflow=invocation.source_workflow,
            resolution_snapshot=resolution,
            policy_snapshot=policy_snapshot,
            skill_version_id=invocation.skill_version_id,
            version=str(resolution.get("version") or "") or None,
            manifest_hash=str(resolution.get("manifestHash") or "") or None,
            runtime_adapter=str(resolution.get("runtimeAdapter") or "") or None,
            runtime_result_kind=str(resolution.get("runtimeResultKind") or "") or None,
            authorized_context=authorized_context,
            deadline_at=deadline_at,
            cancellation_probe=cancellation_probe,
            clock=clock,
        )

    def cancellation_requested(self) -> bool:
        return bool(self.cancellation_probe and self.cancellation_probe())

    def checkpoint(self) -> None:
        if self.cancellation_requested():
            raise SkillInvocationExecutionError(
                "SKILL_INVOCATION_CANCELLED",
                status="cancelled",
            )
        if self.deadline_at is not None and self.clock() >= self.deadline_at:
            raise SkillInvocationExecutionError(
                "SKILL_INVOCATION_DEADLINE_EXCEEDED",
                status="timed_out",
            )

    def remaining_seconds(self) -> float | None:
        if self.deadline_at is None:
            return None
        return max(0.0, (self.deadline_at - self.clock()).total_seconds())


ManagedSkillRuntimeHandler = Callable[
    [SkillRuntimeContext, dict[str, object], Mapping[str, object]],
    object,
]


@dataclass(frozen=True, slots=True)
class ManagedSkillRuntimeAdapter:
    adapter_id: str
    result_kind: str
    handler: ManagedSkillRuntimeHandler
    extension_points: frozenset[str] | None = None


class ManagedSkillRuntimeRegistry:
    """Version-frozen dispatch boundary for replaceable Skill implementations.

    Domain Services provide narrowly scoped in-memory capabilities. Runtime
    adapters never receive a DB session and cannot make the binding decision.
    The adapter selected by the resolved SkillVersion is the implementation
    that actually runs; an unavailable or incompatible adapter fails closed.
    """

    def __init__(self, adapters: list[ManagedSkillRuntimeAdapter] | None = None) -> None:
        self._adapters: dict[str, ManagedSkillRuntimeAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: ManagedSkillRuntimeAdapter, *, replace: bool = False) -> None:
        adapter_id = adapter.adapter_id.strip()
        if not adapter_id:
            raise ValueError("managed Skill runtime adapter id is required")
        if adapter_id in self._adapters and not replace:
            raise ValueError(f"managed Skill runtime adapter already registered: {adapter_id}")
        self._adapters[adapter_id] = adapter

    def validate(
        self,
        *,
        adapter_id: str | None,
        result_kind: str | None,
        extension_point_id: str | None,
    ) -> ManagedSkillRuntimeAdapter:
        if not adapter_id:
            raise ValueError("skill version has no managed runtime adapter")
        try:
            adapter = self._adapters[adapter_id]
        except KeyError as exc:
            raise ValueError(f"managed Skill runtime adapter is not registered: {adapter_id}") from exc
        if not result_kind or adapter.result_kind != result_kind:
            raise ValueError(
                "managed Skill runtime result kind is incompatible: "
                f"expected {adapter.result_kind}, got {result_kind or 'missing'}"
            )
        if adapter.extension_points is None and extension_point_id is not None:
            raise ValueError(
                f"managed Skill runtime adapter {adapter_id} is direct-only and cannot bind extension point {extension_point_id}"
            )
        if adapter.extension_points is not None and (
            extension_point_id is None or extension_point_id not in adapter.extension_points
        ):
            raise ValueError(
                f"managed Skill runtime adapter {adapter_id} is not allowed for extension point {extension_point_id or 'direct'}"
            )
        return adapter

    def dispatch(
        self,
        runtime_context: SkillRuntimeContext,
        request: dict[str, object],
        *,
        capabilities: Mapping[str, object] | None = None,
    ) -> object:
        adapter = self.validate(
            adapter_id=runtime_context.runtime_adapter,
            result_kind=runtime_context.runtime_result_kind,
            extension_point_id=runtime_context.extension_point_id,
        )
        safe_capabilities: dict[str, object] = {}
        for key, value in (capabilities or {}).items():
            if not isinstance(key, str):
                raise ValueError("managed Skill runtime capability keys must be strings")
            if callable(value):
                safe_capabilities[key] = value
                continue
            try:
                safe_value, _, _ = validate_safe_context_content(value)
            except ValueError as exc:
                raise ValueError(
                    f"managed Skill runtime capability contains unsafe object: {key}"
                ) from exc
            safe_capabilities[key] = safe_value
        runtime_context.checkpoint()
        return adapter.handler(runtime_context, dict(request), safe_capabilities)

    def list_adapters(self) -> list[dict[str, object]]:
        return [
            {
                "adapterId": adapter.adapter_id,
                "resultKind": adapter.result_kind,
                "extensionPoints": sorted(adapter.extension_points) if adapter.extension_points is not None else None,
            }
            for adapter in sorted(self._adapters.values(), key=lambda item: item.adapter_id)
        ]


def _service_capability_adapter(
    runtime_context: SkillRuntimeContext,
    request: dict[str, object],
    capabilities: Mapping[str, object],
) -> object:
    executor = capabilities.get("execute")
    if not callable(executor):
        raise ValueError(
            f"managed Skill runtime capability is unavailable for {runtime_context.runtime_adapter}"
        )
    return executor(runtime_context, request)


def _community_regression_adapter(
    runtime_context: SkillRuntimeContext,
    request: dict[str, object],
    capabilities: Mapping[str, object],
) -> object:
    result = _service_capability_adapter(runtime_context, request, capabilities)
    if not isinstance(result, dict) or not isinstance(result.get("result"), dict):
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_RESULT_INVALID")
    profile = runtime_context.resolution_snapshot.get("communityProfile")
    if not isinstance(profile, dict):
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_PROFILE_MISSING")
    payload = dict(result["result"])
    plan = payload.get("regressionPlan")
    if not isinstance(plan, dict):
        raise ValueError("COMMUNITY_SKILL_PRESENTATION_PLAN_MISSING")
    payload["regressionPlan"] = project_regression_view(plan, profile)
    return {**result, "result": payload}


def build_managed_skill_runtime_registry(
    extra_adapters: list[ManagedSkillRuntimeAdapter] | None = None,
) -> ManagedSkillRuntimeRegistry:
    registry = ManagedSkillRuntimeRegistry(
        [
            ManagedSkillRuntimeAdapter(
                adapter_id=COMMUNITY_REGRESSION_ADAPTER,
                result_kind="skill_result",
                handler=_community_regression_adapter,
                extension_points=frozenset({COMMUNITY_REGRESSION_EXTENSION}),
            ),
            ManagedSkillRuntimeAdapter(
                adapter_id="service.agent.v1",
                result_kind="agent_result",
                handler=_service_capability_adapter,
                extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_runtime_adapter(
                    "service.agent.v1"
                ),
            ),
            ManagedSkillRuntimeAdapter(
                adapter_id="service.projection.v1",
                result_kind="skill_result",
                handler=_service_capability_adapter,
                extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_runtime_adapter(
                    "service.projection.v1"
                ),
            ),
            ManagedSkillRuntimeAdapter(
                adapter_id="execution.runner.v1",
                result_kind="runner_result",
                handler=_service_capability_adapter,
                extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_runtime_adapter(
                    "execution.runner.v1"
                ),
            ),
            ManagedSkillRuntimeAdapter(
                adapter_id="execution.manual.v1",
                result_kind="skill_result",
                handler=_service_capability_adapter,
                extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_runtime_adapter(
                    "execution.manual.v1"
                ),
            ),
            ManagedSkillRuntimeAdapter(
                adapter_id="integration.registry.v1",
                result_kind="integration_result",
                handler=_service_capability_adapter,
                extension_points=None,
            ),
        ]
    )
    for adapter in extra_adapters or []:
        registry.register(adapter)
    return registry


class CapabilityGateway:
    """Managed runtime boundary for Skill-owned capability requests."""

    def __init__(self, runner_registry: RunnerRegistry | None = None) -> None:
        self.runner_registry = runner_registry or RunnerRegistry()

    def runner_for_visual_capture(self, runner_id: str) -> RunnerAdapter:
        return self.runner_registry.get(runner_id)

    def default_timeout_seconds(self, runner_id: str) -> int:
        return int(self.runner_registry.get(runner_id).default_timeout_seconds)

    def run_execution_task(self, runtime_context: SkillRuntimeContext, request: RunnerExecutionRequest) -> RunnerExecutionResult:
        if runtime_context.extension_point_id != "EXECUTE.automated_execution":
            raise ValueError("managed execution runtime only runs automated execution extension points")
        if runtime_context.runtime_result_kind != "runner_result":
            raise ValueError("resolved skill runtime is not allowed to return runner results")
        runner = self.runner_registry.get(request.runner_id)
        if runtime_context.deadline_at is not None:
            request.deadline_at = min(
                item
                for item in (request.deadline_at, runtime_context.deadline_at)
                if item is not None
            )
            remaining_seconds = runtime_context.remaining_seconds()
            if remaining_seconds is not None and remaining_seconds > 0:
                request.timeout_seconds = min(
                    request.timeout_seconds,
                    max(1, int(remaining_seconds + 0.999)),
                )
        if runtime_context.cancellation_requested():
            ended_at = utcnow()
            result = RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=request.runner_id,
                domain=request.domain,
                status="cancelled",
                tool_status="cancelled",
                exit_code=-1,
                timed_out=False,
                started_at=ended_at,
                ended_at=ended_at,
                duration_ms=0,
                logs=[RunnerLogRecord(level="warn", message="runner dispatch cancelled by managed Skill policy")],
                error="runner dispatch cancelled by managed Skill policy",
                metadata={"executionMode": "managed_cancellation"},
            )
        elif request.deadline_at is not None and utcnow() >= request.deadline_at:
            ended_at = utcnow()
            result = RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=request.runner_id,
                domain=request.domain,
                status="failed",
                tool_status="timeout",
                exit_code=-1,
                timed_out=True,
                started_at=ended_at,
                ended_at=ended_at,
                duration_ms=0,
                logs=[
                    RunnerLogRecord(
                        level="error",
                        message="runner deadline elapsed before managed execution",
                        context={"deadlineAt": request.deadline_at.isoformat()},
                    )
                ],
                error="runner deadline elapsed before managed execution",
                metadata={"executionMode": "managed_deadline"},
            )
        else:
            result = runner.run(request)
        validate_runner_execution_result(
            result,
            request=request,
            require_terminal=True,
        )
        result.metadata = {
            **result.metadata,
            "runtime": "managed-execution-runtime",
            "skillInvocationId": str(runtime_context.skill_invocation_id),
            "resolvedSkillId": runtime_context.skill_id,
            "extensionPointId": runtime_context.extension_point_id,
        }
        return result

    def propose_manual_simulation(
        self,
        runtime_context: SkillRuntimeContext,
        task: ExecutionTask,
        dispatch_plan: dict[str, object],
    ) -> dict[str, object]:
        if runtime_context.extension_point_id != "EXECUTE.manual_simulation":
            raise ValueError("manual simulation runtime only handles manual simulation extension points")
        if runtime_context.runtime_result_kind != "skill_result":
            raise ValueError("resolved skill runtime is not allowed to propose manual simulation actions")
        raw_semantic_action = task.config.get("semanticAction")
        semantic_action: dict[str, object] = (
            dict(raw_semantic_action) if isinstance(raw_semantic_action, dict) else {}
        )
        action_type = str(semantic_action.get("actionType") or "assert_visible")
        action_id = str(semantic_action.get("actionId") or f"manual_{task.id}")
        semantic_target = semantic_action.get("semanticTarget")
        target_hints = semantic_action.get("targetHints")
        locator_strategy = semantic_action.get("locatorStrategy")
        fallback_policy = semantic_action.get("fallbackPolicy")
        assertion_intent = semantic_action.get("assertionIntent")
        policy_refs = semantic_action.get("policyRefs")
        return {
            "result": {
                "semanticActions": [
                    {
                        "schemaVersion": "phase7.v1",
                        "actionId": action_id,
                        "actionType": action_type,
                        "semanticTarget": (
                            dict(semantic_target)
                            if isinstance(semantic_target, dict)
                            else {"taskType": task.task_type}
                        ),
                        "targetHints": (
                            dict(target_hints) if isinstance(target_hints, dict) else {}
                        ),
                        "locatorStrategy": (
                            dict(locator_strategy)
                            if isinstance(locator_strategy, dict)
                            else {}
                        ),
                        "fallbackPolicy": (
                            dict(fallback_policy)
                            if isinstance(fallback_policy, dict)
                            else {"allowCoordinateClick": False}
                        ),
                        "assertionIntent": (
                            dict(assertion_intent)
                            if isinstance(assertion_intent, dict)
                            else {}
                        ),
                        "riskLevel": str(semantic_action.get("riskLevel") or "low"),
                        "policyRefs": (
                            list(policy_refs) if isinstance(policy_refs, list) else []
                        ),
                    }
                ],
                "executionConstraints": {
                    "runnerRef": task.runner,
                    "taskType": task.task_type,
                    "domain": task.domain.value,
                    "dispatchPlan": dispatch_plan,
                },
                "manualTestIntent": {
                    "taskId": str(task.id),
                    "createdAt": datetime.now(timezone.utc).isoformat(),
                },
            },
            "confidence": 0.8,
            "evidence": [{"type": "execution_task", "ref": str(task.id)}],
            "artifactRefs": [],
            "rawFindingRefs": [],
            "findingCandidates": [],
            "metadata": {
                "runtime": "capability-gateway",
                "executionMode": "manual_simulation",
                "skillInvocationId": str(runtime_context.skill_invocation_id),
                "resolvedSkillId": runtime_context.skill_id,
                "extensionPointId": runtime_context.extension_point_id,
            },
        }

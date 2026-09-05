# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import json
from threading import Lock
from time import sleep
from typing import Callable, Iterator, Mapping

from agentic_qa.agents.base import AgentResult
from agentic_qa.infra.managed_http import ManagedHttpRequestError
from agentic_qa.infra.settings import Settings, get_settings
from agentic_qa.tools.runner_protocols import RunnerExecutionResult


Clock = Callable[[], datetime]
CancellationProbe = Callable[[], bool]
Waiter = Callable[[float], None]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SkillInvocationReasonCode(StrEnum):
    DEADLINE_EXCEEDED = "SKILL_INVOCATION_DEADLINE_EXCEEDED"
    ADAPTER_TIMEOUT = "SKILL_ADAPTER_TIMEOUT"
    CANCELLED = "SKILL_INVOCATION_CANCELLED"
    LATE_RESULT_REJECTED = "SKILL_INVOCATION_LATE_RESULT_REJECTED"
    TRANSIENT_DEPENDENCY = "SKILL_ADAPTER_TRANSIENT_DEPENDENCY"
    PROVIDER_RATE_LIMITED = "SKILL_PROVIDER_RATE_LIMITED"
    PROVIDER_UNAVAILABLE = "SKILL_PROVIDER_TEMPORARILY_UNAVAILABLE"
    RETRY_EXHAUSTED = "SKILL_RETRY_EXHAUSTED"
    INPUT_INVALID = "SKILL_INPUT_INVALID"
    INPUT_TOO_LARGE = "SKILL_INPUT_TOO_LARGE"
    OUTPUT_SCHEMA_INVALID = "SKILL_OUTPUT_SCHEMA_INVALID"
    OUTPUT_TOO_LARGE = "SKILL_OUTPUT_TOO_LARGE"
    MANIFEST_HASH_MISMATCH = "SKILL_MANIFEST_HASH_MISMATCH"
    RUNTIME_ADAPTER_UNREGISTERED = "SKILL_RUNTIME_ADAPTER_UNREGISTERED"
    SCOPE_DENIED = "SKILL_SCOPE_DENIED"
    CAPABILITY_DENIED = "SKILL_CAPABILITY_DENIED"
    APPROVAL_REQUIRED = "SKILL_APPROVAL_REQUIRED"
    GUARDRAIL_BLOCKED = "SKILL_GUARDRAIL_BLOCKED"
    SECRET_SCAN_FAILED = "SKILL_SECRET_SCAN_FAILED"
    NON_IDEMPOTENT_RETRY_FORBIDDEN = "SKILL_NON_IDEMPOTENT_RETRY_FORBIDDEN"
    EXTERNAL_WRITE_OUTCOME_UNKNOWN = "SKILL_EXTERNAL_WRITE_OUTCOME_UNKNOWN"
    GLOBAL_KILL_SWITCH = "SKILL_GLOBAL_KILL_SWITCH_ACTIVE"
    BINDING_KILL_SWITCH = "SKILL_BINDING_KILL_SWITCH_ACTIVE"
    TENANT_QUOTA_EXCEEDED = "SKILL_TENANT_QUOTA_EXCEEDED"
    PROJECT_QUOTA_EXCEEDED = "SKILL_PROJECT_QUOTA_EXCEEDED"
    BINDING_CONCURRENCY_EXCEEDED = "SKILL_BINDING_CONCURRENCY_EXCEEDED"
    INVOCATION_BUDGET_EXHAUSTED = "SKILL_INVOCATION_BUDGET_EXHAUSTED"
    CIRCUIT_OPEN = "SKILL_ADAPTER_CIRCUIT_OPEN"
    FALLBACK_USED = "SKILL_GOVERNED_FALLBACK_USED"
    FALLBACK_NOT_ALLOWED = "SKILL_FALLBACK_NOT_ALLOWED"
    FALLBACK_FAILED = "SKILL_FALLBACK_FAILED"
    CONTEXT_UNAVAILABLE = "SKILL_CONTEXT_REQUIRED_UNAVAILABLE"
    ADAPTER_FAILED = "SKILL_ADAPTER_FAILED"


STABLE_INVOCATION_STATUSES = frozenset(
    {
        "completed",
        "degraded",
        "unavailable",
        "cancelled",
        "timed_out",
        "blocked",
        "invalid_output",
        "failed",
    }
)

RETRYABLE_REASON_CODES = frozenset(
    {
        SkillInvocationReasonCode.ADAPTER_TIMEOUT.value,
        SkillInvocationReasonCode.TRANSIENT_DEPENDENCY.value,
        SkillInvocationReasonCode.PROVIDER_RATE_LIMITED.value,
        SkillInvocationReasonCode.PROVIDER_UNAVAILABLE.value,
    }
)


class SkillInvocationExecutionError(RuntimeError):
    def __init__(
        self,
        reason_code: str | SkillInvocationReasonCode,
        *,
        status: str,
        message: str | None = None,
        retryable: bool = False,
    ) -> None:
        if status not in STABLE_INVOCATION_STATUSES:
            raise ValueError(f"unsupported Skill Invocation status: {status}")
        self.reason_code = (
            reason_code.value
            if isinstance(reason_code, SkillInvocationReasonCode)
            else str(reason_code)
        )
        self.status = status
        self.retryable = retryable
        super().__init__(message or self.reason_code)


class SkillAdapterTransientError(SkillInvocationExecutionError):
    def __init__(
        self,
        message: str = "managed Skill adapter dependency is temporarily unavailable",
        *,
        reason_code: str | SkillInvocationReasonCode = SkillInvocationReasonCode.TRANSIENT_DEPENDENCY,
    ) -> None:
        super().__init__(
            reason_code,
            status="unavailable",
            message=message,
            retryable=True,
        )


@dataclass(frozen=True, slots=True)
class RetryClassification:
    reason_code: str
    status: str
    retryable: bool
    counts_toward_circuit: bool


@dataclass(frozen=True, slots=True)
class SkillInvocationExecutionPolicy:
    schema_version: str
    frozen_at: datetime
    timeout_seconds: float
    deadline_at: datetime
    cancellation_mode: str
    reject_late_results: bool
    max_attempts: int
    retryable_reason_codes: tuple[str, ...]
    mutation: bool
    idempotent: bool
    external_write: bool
    max_input_bytes: int
    max_output_bytes: int
    max_model_calls: int
    max_tool_calls: int
    max_skill_calls: int
    expected_model_calls: int
    expected_tool_calls: int
    expected_skill_calls: int
    max_tokens: int | None
    max_cost_usd: float | None
    metering_available: bool
    concurrency_key: str
    tenant_key: str | None
    project_key: str | None
    binding_key: str | None
    tenant_concurrency_limit: int
    project_concurrency_limit: int
    binding_concurrency_limit: int
    global_kill_switch: bool
    binding_kill_switch: bool
    binding_kill_switch_reason: str | None
    fallback_allowed: bool
    fallback_reason_codes: tuple[str, ...]
    fallback_target: dict[str, object] | None
    risk_classification: str
    approval_required: bool
    approval_satisfied: bool
    adapter_id: str
    adapter_version: str | None
    circuit_failure_threshold: int
    circuit_recovery_seconds: float
    cooperative_cancellation: bool
    authority_sources: tuple[str, ...]

    def snapshot(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "frozenAt": self.frozen_at.isoformat(),
            "timeoutSeconds": self.timeout_seconds,
            "deadlineAt": self.deadline_at.isoformat(),
            "cancellationPolicy": {
                "mode": self.cancellation_mode,
                "rejectLateResults": self.reject_late_results,
                "cooperativeOnlyForSynchronousAdapters": self.cooperative_cancellation,
                "physicalTerminationGuaranteed": False,
            },
            "maxAttempts": self.max_attempts,
            "retryableReasonCodes": list(self.retryable_reason_codes),
            "mutation": self.mutation,
            "idempotent": self.idempotent,
            "externalWrite": self.external_write,
            "maxInputBytes": self.max_input_bytes,
            "maxOutputBytes": self.max_output_bytes,
            "budget": {
                "maxModelCalls": self.max_model_calls,
                "maxToolCalls": self.max_tool_calls,
                "maxSkillCalls": self.max_skill_calls,
                "expectedModelCalls": self.expected_model_calls,
                "expectedToolCalls": self.expected_tool_calls,
                "expectedSkillCalls": self.expected_skill_calls,
                "maxTokens": self.max_tokens,
                "maxCostUsd": self.max_cost_usd,
                "meteringAvailable": self.metering_available,
            },
            "concurrencyKey": self.concurrency_key,
            "quota": {
                "tenantKey": self.tenant_key,
                "projectKey": self.project_key,
                "bindingKey": self.binding_key,
                "tenantConcurrencyLimit": self.tenant_concurrency_limit,
                "projectConcurrencyLimit": self.project_concurrency_limit,
                "bindingConcurrencyLimit": self.binding_concurrency_limit,
            },
            "killSwitchSnapshot": {
                "globalActive": self.global_kill_switch,
                "bindingActive": self.binding_kill_switch,
                "bindingReason": self.binding_kill_switch_reason,
                "priority": ["global", "binding", "guardrail", "approval", "quota", "health"],
            },
            "fallbackPolicy": {
                "allowed": self.fallback_allowed,
                "reasonCodes": list(self.fallback_reason_codes),
                "target": self.fallback_target,
            },
            "riskClassification": self.risk_classification,
            "approval": {
                "required": self.approval_required,
                "satisfied": self.approval_satisfied,
            },
            "adapterHealth": {
                "adapterId": self.adapter_id,
                "adapterVersion": self.adapter_version,
                "failureThreshold": self.circuit_failure_threshold,
                "recoverySeconds": self.circuit_recovery_seconds,
                "scope": "process_local",
            },
            "idempotency": {
                "requiredForAutomaticRetry": True,
                "effective": self.idempotent,
            },
            "authoritySources": list(self.authority_sources),
        }


@dataclass(slots=True)
class _CircuitState:
    state: str = "closed"
    consecutive_failures: int = 0
    opened_at: datetime | None = None
    half_open_probe_active: bool = False


@dataclass(slots=True)
class _LocalReliabilityState:
    lock: Lock = field(default_factory=Lock)
    active: dict[str, int] = field(default_factory=dict)
    circuits: dict[str, _CircuitState] = field(default_factory=dict)


class SkillRetryClassifier:
    _NON_RETRYABLE_NAME_TOKENS = {
        "ContractValidationError": SkillInvocationReasonCode.OUTPUT_SCHEMA_INVALID,
        "ExtensionPointContractError": SkillInvocationReasonCode.INPUT_INVALID,
        "ScopeAuthorizationError": SkillInvocationReasonCode.SCOPE_DENIED,
        "SkillContextUnavailableError": SkillInvocationReasonCode.CONTEXT_UNAVAILABLE,
        "GuardrailViolationError": SkillInvocationReasonCode.GUARDRAIL_BLOCKED,
        "IdempotencyConflictError": SkillInvocationReasonCode.INPUT_INVALID,
    }

    def classify(self, error: BaseException) -> RetryClassification:
        if isinstance(error, SkillInvocationExecutionError):
            return RetryClassification(
                reason_code=error.reason_code,
                status=error.status,
                retryable=error.retryable,
                counts_toward_circuit=error.retryable,
            )
        if isinstance(error, ManagedHttpRequestError):
            if error.status_code == 429:
                reason = SkillInvocationReasonCode.PROVIDER_RATE_LIMITED
            elif error.status_code in {500, 502, 503, 504}:
                reason = SkillInvocationReasonCode.PROVIDER_UNAVAILABLE
            elif error.kind == "timeout":
                reason = SkillInvocationReasonCode.ADAPTER_TIMEOUT
            else:
                return RetryClassification(
                    SkillInvocationReasonCode.ADAPTER_FAILED.value,
                    "failed",
                    False,
                    False,
                )
            return RetryClassification(reason.value, "unavailable", True, True)
        if isinstance(error, TimeoutError):
            return RetryClassification(
                SkillInvocationReasonCode.ADAPTER_TIMEOUT.value,
                "timed_out",
                True,
                True,
            )
        if isinstance(error, ConnectionError):
            return RetryClassification(
                SkillInvocationReasonCode.TRANSIENT_DEPENDENCY.value,
                "unavailable",
                True,
                True,
            )
        if isinstance(error, PermissionError):
            return RetryClassification(
                SkillInvocationReasonCode.CAPABILITY_DENIED.value,
                "blocked",
                False,
                False,
            )
        class_name = type(error).__name__
        mapped = self._NON_RETRYABLE_NAME_TOKENS.get(class_name)
        if mapped is not None:
            status = "invalid_output" if mapped == SkillInvocationReasonCode.OUTPUT_SCHEMA_INVALID else (
                "unavailable" if mapped == SkillInvocationReasonCode.CONTEXT_UNAVAILABLE else "blocked"
            )
            return RetryClassification(mapped.value, status, False, False)
        normalized = str(error).upper()
        if "APPROVAL" in normalized:
            return RetryClassification(
                SkillInvocationReasonCode.APPROVAL_REQUIRED.value,
                "blocked",
                False,
                False,
            )
        if "SECRET" in normalized and ("SCAN" in normalized or "SENSITIVE" in normalized):
            return RetryClassification(
                SkillInvocationReasonCode.SECRET_SCAN_FAILED.value,
                "blocked",
                False,
                False,
            )
        if "MANIFEST" in normalized and "HASH" in normalized:
            return RetryClassification(
                SkillInvocationReasonCode.MANIFEST_HASH_MISMATCH.value,
                "blocked",
                False,
                False,
            )
        if "RUNTIME ADAPTER" in normalized and "REGISTER" in normalized:
            return RetryClassification(
                SkillInvocationReasonCode.RUNTIME_ADAPTER_UNREGISTERED.value,
                "unavailable",
                False,
                False,
            )
        if "SCHEMA" in normalized or "MALFORMED" in normalized or "INVALID" in normalized:
            return RetryClassification(
                SkillInvocationReasonCode.OUTPUT_SCHEMA_INVALID.value,
                "invalid_output",
                False,
                False,
            )
        return RetryClassification(
            SkillInvocationReasonCode.ADAPTER_FAILED.value,
            "failed",
            False,
            True,
        )

    def classify_result(self, result: object) -> RetryClassification | None:
        if isinstance(result, AgentResult):
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            fallback_reason = str(
                metadata.get("fallbackReason")
                or metadata.get("modelFailureReason")
                or ""
            ).upper()
            model_status = str(metadata.get("modelStatus") or "").lower()
            if (
                "MODEL_PROVIDER_HTTP_ERROR" in fallback_reason
                or "MODEL_PROVIDER_FAILURE" in fallback_reason
                or model_status in {"unavailable", "temporarily_unavailable"}
            ):
                return RetryClassification(
                    SkillInvocationReasonCode.PROVIDER_UNAVAILABLE.value,
                    "unavailable",
                    True,
                    True,
                )
        if not isinstance(result, RunnerExecutionResult):
            return None
        if result.status == "cancelled":
            return RetryClassification(
                SkillInvocationReasonCode.CANCELLED.value,
                "cancelled",
                False,
                False,
            )
        if result.status != "failed":
            return None
        if result.tool_status == "infra_error":
            return RetryClassification(
                SkillInvocationReasonCode.TRANSIENT_DEPENDENCY.value,
                "unavailable",
                True,
                True,
            )
        if result.tool_status == "timeout":
            return RetryClassification(
                SkillInvocationReasonCode.ADAPTER_TIMEOUT.value,
                "timed_out",
                True,
                True,
            )
        return RetryClassification(
            SkillInvocationReasonCode.ADAPTER_FAILED.value,
            "failed",
            False,
            True,
        )


class SkillInvocationReliabilityRuntime:
    """Process-local reliability controls for the existing managed Skill boundary.

    This object does not claim distributed coordination. Active counters and
    circuit state are intentionally lost on restart and are not shared between
    workers. Persistent idempotency remains owned by the existing database row
    and transaction/advisory-lock path in SkillService.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        clock: Clock = utc_now,
        waiter: Waiter = sleep,
        classifier: SkillRetryClassifier | None = None,
        state: _LocalReliabilityState | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.clock = clock
        self.waiter = waiter
        self.classifier = classifier or SkillRetryClassifier()
        self._state = state or _LocalReliabilityState()

    @staticmethod
    def json_size(value: object) -> int:
        return len(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        )

    def build_policy(
        self,
        *,
        extension_point_id: str,
        execution_constraints: Mapping[str, object],
        risk_profile: Mapping[str, object],
        approval_policy: Mapping[str, object],
        binding_config: Mapping[str, object],
        resolution: Mapping[str, object],
        scope: Mapping[str, object],
        idempotency_key: str | None,
        caller_policy_snapshot: Mapping[str, object],
        approval_refs: list[dict[str, object]],
        deadline_at: datetime | None,
        timeout_seconds: float | None,
        fallback_target: dict[str, object] | None,
    ) -> SkillInvocationExecutionPolicy:
        now = self._aware(self.clock())
        binding_policy = binding_config.get("executionPolicy")
        binding_policy = binding_policy if isinstance(binding_policy, dict) else {}
        parent_budget = caller_policy_snapshot.get("parentBudget")
        parent_budget = parent_budget if isinstance(parent_budget, dict) else {}

        configured_timeout = self._positive_float(
            binding_policy.get("timeoutSeconds"),
            self.settings.skill_invocation_timeout_seconds,
        )
        effective_timeout = min(
            self.settings.skill_invocation_timeout_seconds,
            configured_timeout,
            self._positive_float(timeout_seconds, self.settings.skill_invocation_timeout_seconds),
        )
        computed_deadline = now + timedelta(seconds=effective_timeout)
        if deadline_at is not None:
            computed_deadline = min(computed_deadline, self._aware(deadline_at))

        mutation = bool(execution_constraints.get("mutation", False))
        external_write = bool(execution_constraints.get("externalWrite", False))
        idempotent = bool(execution_constraints.get("idempotent", not mutation))
        risk = str(risk_profile.get("level") or execution_constraints.get("riskLevel") or "low").lower()
        if risk not in {"low", "medium", "high"}:
            risk = "high"
        approval_required = bool(approval_policy.get("required") or risk == "high")
        approval_satisfied = self._approval_satisfied(approval_refs)

        platform_attempts = self.settings.skill_invocation_max_attempts
        binding_attempts = self._positive_int(binding_policy.get("maxAttempts"), platform_attempts)
        max_attempts = min(platform_attempts, binding_attempts)
        if mutation or external_write or not idempotent or risk in {"medium", "high"}:
            max_attempts = 1

        max_model_calls = self._budget_limit(
            self.settings.skill_invocation_max_model_calls,
            parent_budget.get("remainingModelCalls"),
        )
        max_tool_calls = self._budget_limit(
            self.settings.skill_invocation_max_tool_calls,
            parent_budget.get("remainingToolCalls"),
        )
        max_skill_calls = self._budget_limit(
            self.settings.skill_invocation_max_skill_calls,
            parent_budget.get("remainingSkillInvocations"),
        )
        expected_model_calls = (
            self._positive_int(execution_constraints.get("expectedModelCalls"), 1)
            if str(resolution.get("runtimeResultKind")) == "agent_result"
            else 0
        )
        expected_tool_calls = 1 if str(resolution.get("runtimeResultKind")) == "runner_result" else 0
        if expected_model_calls:
            max_attempts = min(max_attempts, max_model_calls // expected_model_calls)
        if expected_tool_calls:
            max_attempts = min(max_attempts, max_tool_calls)
        max_attempts = min(max_attempts, max_skill_calls)
        max_attempts = max(1, max_attempts)

        kill_switch = binding_config.get("killSwitch")
        kill_switch = kill_switch if isinstance(kill_switch, dict) else {}
        binding_kill_switch = bool(kill_switch.get("active", False))
        fallback_config = binding_policy.get("fallback")
        fallback_config = fallback_config if isinstance(fallback_config, dict) else {}
        fallback_allowed = bool(
            fallback_config.get("allowed", False)
            and fallback_target
            and max_skill_calls > max_attempts
            and risk == "low"
            and not mutation
            and not external_write
            and idempotent
        )

        tenant_key = self._scope_key(scope, "tenantId")
        project_key = self._scope_key(scope, "projectId")
        binding_id = str(resolution.get("bindingId") or "").strip() or None
        binding_key = f"binding:{binding_id}" if binding_id else None
        adapter_id = str(resolution.get("runtimeAdapter") or "unavailable")
        concurrency_parts = [
            extension_point_id,
            tenant_key or "tenant:none",
            project_key or "project:none",
            binding_key or "binding:default",
        ]
        return SkillInvocationExecutionPolicy(
            schema_version="skill-invocation-execution-policy.v1",
            frozen_at=now,
            timeout_seconds=effective_timeout,
            deadline_at=computed_deadline,
            cancellation_mode="cooperative",
            reject_late_results=True,
            max_attempts=max_attempts,
            retryable_reason_codes=tuple(sorted(RETRYABLE_REASON_CODES)),
            mutation=mutation,
            idempotent=idempotent,
            external_write=external_write,
            max_input_bytes=min(
                self.settings.skill_invocation_max_input_bytes,
                self._positive_int(
                    binding_policy.get("maxInputBytes"),
                    self.settings.skill_invocation_max_input_bytes,
                ),
            ),
            max_output_bytes=min(
                self.settings.skill_invocation_max_output_bytes,
                self._positive_int(
                    binding_policy.get("maxOutputBytes"),
                    self.settings.skill_invocation_max_output_bytes,
                ),
            ),
            max_model_calls=max_model_calls,
            max_tool_calls=max_tool_calls,
            max_skill_calls=max_skill_calls,
            expected_model_calls=expected_model_calls,
            expected_tool_calls=expected_tool_calls,
            expected_skill_calls=1,
            max_tokens=self._optional_budget(parent_budget.get("remainingTokens")),
            max_cost_usd=self._optional_float(parent_budget.get("remainingCostUsd")),
            metering_available=bool(
                parent_budget.get("remainingTokens") is not None
                or parent_budget.get("remainingCostUsd") is not None
            ),
            concurrency_key="|".join(concurrency_parts),
            tenant_key=tenant_key,
            project_key=project_key,
            binding_key=binding_key,
            tenant_concurrency_limit=min(
                self.settings.skill_invocation_tenant_concurrency_limit,
                self._positive_int(
                    binding_policy.get("tenantConcurrencyLimit"),
                    self.settings.skill_invocation_tenant_concurrency_limit,
                ),
            ),
            project_concurrency_limit=min(
                self.settings.skill_invocation_project_concurrency_limit,
                self._positive_int(
                    binding_policy.get("projectConcurrencyLimit"),
                    self.settings.skill_invocation_project_concurrency_limit,
                ),
            ),
            binding_concurrency_limit=min(
                self.settings.skill_invocation_binding_concurrency_limit,
                self._positive_int(
                    binding_policy.get("bindingConcurrencyLimit"),
                    self.settings.skill_invocation_binding_concurrency_limit,
                ),
            ),
            global_kill_switch=bool(self.settings.skill_invocation_global_kill_switch),
            binding_kill_switch=binding_kill_switch,
            binding_kill_switch_reason=(
                str(kill_switch.get("reason") or "binding disabled by platform operator")
                if binding_kill_switch
                else None
            ),
            fallback_allowed=fallback_allowed,
            fallback_reason_codes=tuple(sorted(RETRYABLE_REASON_CODES)),
            fallback_target=fallback_target if fallback_allowed else None,
            risk_classification=risk,
            approval_required=approval_required,
            approval_satisfied=approval_satisfied,
            adapter_id=adapter_id,
            adapter_version=str(resolution.get("version") or "") or None,
            circuit_failure_threshold=min(
                self.settings.skill_invocation_circuit_failure_threshold,
                self._positive_int(
                    binding_policy.get("circuitFailureThreshold"),
                    self.settings.skill_invocation_circuit_failure_threshold,
                ),
            ),
            circuit_recovery_seconds=min(
                self.settings.skill_invocation_circuit_recovery_seconds,
                self._non_negative_float(
                    binding_policy.get("circuitRecoverySeconds"),
                    self.settings.skill_invocation_circuit_recovery_seconds,
                ),
            ),
            cooperative_cancellation=True,
            authority_sources=(
                "platform_settings",
                "extension_point_contract",
                "resolved_skill_manifest",
                "capability_binding_config",
                "guardrail_and_approval_state",
                "parent_workflow_budget",
            ),
        )

    def preflight(
        self,
        policy: SkillInvocationExecutionPolicy,
        *,
        cancellation_probe: CancellationProbe,
        input_size: int,
    ) -> None:
        if policy.global_kill_switch:
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.GLOBAL_KILL_SWITCH,
                status="blocked",
            )
        if policy.binding_kill_switch:
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.BINDING_KILL_SWITCH,
                status="blocked",
                message=policy.binding_kill_switch_reason,
            )
        if policy.approval_required and not policy.approval_satisfied:
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.APPROVAL_REQUIRED,
                status="blocked",
            )
        if (
            policy.max_skill_calls < policy.expected_skill_calls
            or policy.max_model_calls < policy.expected_model_calls
            or policy.max_tool_calls < policy.expected_tool_calls
        ):
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.INVOCATION_BUDGET_EXHAUSTED,
                status="blocked",
            )
        if input_size > policy.max_input_bytes:
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.INPUT_TOO_LARGE,
                status="blocked",
            )
        self.checkpoint(policy, cancellation_probe=cancellation_probe, phase="pre_execution")

    def checkpoint(
        self,
        policy: SkillInvocationExecutionPolicy,
        *,
        cancellation_probe: CancellationProbe,
        phase: str,
    ) -> None:
        if cancellation_probe():
            reason = (
                SkillInvocationReasonCode.LATE_RESULT_REJECTED
                if phase == "result_acceptance"
                else SkillInvocationReasonCode.CANCELLED
            )
            raise SkillInvocationExecutionError(reason, status="cancelled")
        if self._aware(self.clock()) >= policy.deadline_at:
            reason = (
                SkillInvocationReasonCode.ADAPTER_TIMEOUT
                if phase == "result_acceptance"
                else SkillInvocationReasonCode.DEADLINE_EXCEEDED
            )
            raise SkillInvocationExecutionError(reason, status="timed_out")

    @contextmanager
    def lease(self, policy: SkillInvocationExecutionPolicy) -> Iterator[None]:
        keys_and_limits = [
            (policy.tenant_key, policy.tenant_concurrency_limit, SkillInvocationReasonCode.TENANT_QUOTA_EXCEEDED),
            (policy.project_key, policy.project_concurrency_limit, SkillInvocationReasonCode.PROJECT_QUOTA_EXCEEDED),
            (policy.binding_key, policy.binding_concurrency_limit, SkillInvocationReasonCode.BINDING_CONCURRENCY_EXCEEDED),
        ]
        acquired: list[str] = []
        with self._state.lock:
            for key, limit, reason in keys_and_limits:
                if key is None:
                    continue
                if self._state.active.get(key, 0) >= limit:
                    raise SkillInvocationExecutionError(reason, status="blocked")
            for key, _, _ in keys_and_limits:
                if key is None:
                    continue
                self._state.active[key] = self._state.active.get(key, 0) + 1
                acquired.append(key)
        try:
            yield
        finally:
            with self._state.lock:
                for key in acquired:
                    next_count = self._state.active.get(key, 0) - 1
                    if next_count <= 0:
                        self._state.active.pop(key, None)
                    else:
                        self._state.active[key] = next_count

    def before_adapter(
        self,
        adapter_id: str,
        policy: SkillInvocationExecutionPolicy,
    ) -> str:
        now = self._aware(self.clock())
        with self._state.lock:
            state = self._state.circuits.setdefault(adapter_id, _CircuitState())
            if state.state == "open":
                ready_at = (state.opened_at or now) + timedelta(seconds=policy.circuit_recovery_seconds)
                if now < ready_at or state.half_open_probe_active:
                    raise SkillInvocationExecutionError(
                        SkillInvocationReasonCode.CIRCUIT_OPEN,
                        status="unavailable",
                    )
                state.state = "half_open"
                state.half_open_probe_active = True
                return "half_open"
            if state.state == "half_open" and state.half_open_probe_active:
                raise SkillInvocationExecutionError(
                    SkillInvocationReasonCode.CIRCUIT_OPEN,
                    status="unavailable",
                )
            return state.state

    def adapter_succeeded(self, adapter_id: str) -> None:
        with self._state.lock:
            state = self._state.circuits.setdefault(adapter_id, _CircuitState())
            state.state = "closed"
            state.consecutive_failures = 0
            state.opened_at = None
            state.half_open_probe_active = False

    def adapter_failed(
        self,
        adapter_id: str,
        policy: SkillInvocationExecutionPolicy,
        *,
        counts_toward_circuit: bool,
    ) -> str:
        with self._state.lock:
            state = self._state.circuits.setdefault(adapter_id, _CircuitState())
            if not counts_toward_circuit:
                if state.state == "half_open":
                    state.half_open_probe_active = False
                return state.state
            state.consecutive_failures += 1
            if state.state == "half_open" or state.consecutive_failures >= policy.circuit_failure_threshold:
                state.state = "open"
                state.opened_at = self._aware(self.clock())
                state.half_open_probe_active = False
            return state.state

    def circuit_snapshot(self, adapter_id: str) -> dict[str, object]:
        with self._state.lock:
            state = self._state.circuits.get(adapter_id, _CircuitState())
            return {
                "adapterId": adapter_id,
                "state": state.state,
                "consecutiveFailures": state.consecutive_failures,
                "openedAt": state.opened_at.isoformat() if state.opened_at else None,
                "scope": "process_local",
            }

    def retry_allowed(
        self,
        policy: SkillInvocationExecutionPolicy,
        classification: RetryClassification,
        *,
        attempt: int,
    ) -> bool:
        return bool(
            classification.retryable
            and classification.reason_code in policy.retryable_reason_codes
            and attempt < policy.max_attempts
            and policy.idempotent
            and not policy.mutation
            and not policy.external_write
            and policy.risk_classification == "low"
        )

    @staticmethod
    def backoff_seconds(attempt: int, reason_code: str) -> float:
        base = 0.05 if reason_code != SkillInvocationReasonCode.PROVIDER_RATE_LIMITED.value else 0.1
        return min(base * (2 ** max(0, attempt - 1)), 1.0)

    def wait_for_retry(
        self,
        policy: SkillInvocationExecutionPolicy,
        *,
        delay_seconds: float,
        cancellation_probe: CancellationProbe,
    ) -> None:
        remaining = (policy.deadline_at - self._aware(self.clock())).total_seconds()
        if remaining <= 0 or delay_seconds >= remaining:
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.DEADLINE_EXCEEDED,
                status="timed_out",
            )
        self.checkpoint(policy, cancellation_probe=cancellation_probe, phase="backoff")
        self.waiter(delay_seconds)
        self.checkpoint(policy, cancellation_probe=cancellation_probe, phase="backoff")

    @staticmethod
    def _approval_satisfied(refs: list[dict[str, object]]) -> bool:
        for ref in refs:
            decision = str(ref.get("decision") or ref.get("status") or "").lower()
            if decision in {"approved", "allow", "satisfied"}:
                return True
        return False

    @staticmethod
    def _scope_key(scope: Mapping[str, object], key: str) -> str | None:
        value = scope.get(key)
        if value is None or not str(value).strip():
            return None
        return f"{key}:{value}"

    @staticmethod
    def _positive_int(value: object, default: int) -> int:
        if not isinstance(value, (int, float, str)):
            return int(default)
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return int(default)
        return parsed if parsed > 0 else int(default)

    @staticmethod
    def _positive_float(value: object, default: float) -> float:
        if not isinstance(value, (int, float, str)):
            return float(default)
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return float(default)
        return parsed if parsed > 0 else float(default)

    @staticmethod
    def _non_negative_float(value: object, default: float) -> float:
        if not isinstance(value, (int, float, str)):
            return float(default)
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return float(default)
        return parsed if parsed >= 0 else float(default)

    @staticmethod
    def _optional_budget(value: object) -> int | None:
        if value is None:
            return None
        if not isinstance(value, (int, float, str)):
            return None
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _optional_float(value: object) -> float | None:
        if value is None:
            return None
        if not isinstance(value, (int, float, str)):
            return None
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _budget_limit(platform_limit: int, inherited: object, *, minimum: int = 0) -> int:
        if not isinstance(inherited, (int, float, str)):
            inherited = platform_limit
        try:
            inherited_limit = int(inherited)
        except (TypeError, ValueError):
            inherited_limit = platform_limit
        return max(minimum, min(platform_limit, max(0, inherited_limit)))

    @staticmethod
    def _aware(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


_DEFAULT_RUNTIME: SkillInvocationReliabilityRuntime | None = None
_DEFAULT_RUNTIME_LOCK = Lock()


def get_skill_invocation_reliability_runtime() -> SkillInvocationReliabilityRuntime:
    global _DEFAULT_RUNTIME
    with _DEFAULT_RUNTIME_LOCK:
        if _DEFAULT_RUNTIME is None:
            _DEFAULT_RUNTIME = SkillInvocationReliabilityRuntime()
        return _DEFAULT_RUNTIME


__all__ = [
    "CancellationProbe",
    "SkillAdapterTransientError",
    "SkillInvocationExecutionError",
    "SkillInvocationExecutionPolicy",
    "SkillInvocationReasonCode",
    "SkillInvocationReliabilityRuntime",
    "SkillRetryClassifier",
    "STABLE_INVOCATION_STATUSES",
    "get_skill_invocation_reliability_runtime",
]

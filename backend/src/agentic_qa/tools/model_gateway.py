# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ValidationError
from sqlalchemy import case, select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import HealthStatus, ModelRole, ProviderType, RiskLevel
from agentic_qa.domain.models import Execution, Model, ModelInvocation, ModelRoleBinding, TestPlan
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime import PromptSafetyGuard, RuntimeGuardrailEngine
from agentic_qa.infra.redaction import contains_sensitive_material, redact_sensitive_data, redact_sensitive_text
from agentic_qa.schemas.contracts import ContractValidationError, validate_contract
from agentic_qa.tools.model_adapters import build_adapter


_MODEL_OUTPUT_INJECTION_PATTERN = re.compile(
    r"(?is)(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system)\s+"
    r"(?:instructions?|rules?)|reveal\s+(?:the\s+)?system\s+prompt|<\s*/?\s*(?:system|assistant)\b"
)
_TRANSPORT_OUTPUT_KEYS = {
    "attempts",
    "content",
    "errorCode",
    "inputKeys",
    "mode",
    "model",
    "promptEcho",
    "provider",
}


class ModelOutputNormalizationError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


class ModelGatewayTool:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.guardrail_engine = RuntimeGuardrailEngine(db)
        self.prompt_safety_guard = PromptSafetyGuard()

    def select_model(
        self,
        risk_level: RiskLevel,
        role: ModelRole,
        provider: ProviderType | None = None,
        *,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
    ) -> Model | None:
        statement = (
            select(Model)
            .join(ModelRoleBinding, Model.id == ModelRoleBinding.model_id)
            .where(Model.enabled.is_(True))
            .where(ModelRoleBinding.enabled.is_(True))
            .where(ModelRoleBinding.role == role)
            .where(Model.health_status.in_([HealthStatus.HEALTHY, HealthStatus.UNKNOWN, HealthStatus.DEGRADED]))
        )
        statement = self._scope_statement(statement, project_id=project_id, environment_id=environment_id)
        if environment_id is not None:
            statement = statement.order_by(
                case((Model.environment_id == environment_id, 1), else_=0).desc(),
                ModelRoleBinding.weight.desc(),
                Model.priority.desc(),
            )
        else:
            statement = statement.order_by(ModelRoleBinding.weight.desc(), Model.priority.desc())
        if provider is not None:
            statement = statement.where(Model.provider == provider)
        models = list(self.db.scalars(statement))
        if not models:
            fallback_statement = (
                select(Model)
                .where(Model.enabled.is_(True))
                .where(Model.health_status.in_([HealthStatus.HEALTHY, HealthStatus.UNKNOWN, HealthStatus.DEGRADED]))
            )
            fallback_statement = self._scope_statement(
                fallback_statement,
                project_id=project_id,
                environment_id=environment_id,
            )
            if environment_id is not None:
                fallback_statement = fallback_statement.order_by(
                    case((Model.environment_id == environment_id, 1), else_=0).desc(),
                    Model.priority.desc(),
                )
            else:
                fallback_statement = fallback_statement.order_by(Model.priority.desc())
            if provider is not None:
                fallback_statement = fallback_statement.where(Model.provider == provider)
            models = list(self.db.scalars(fallback_statement))
            if not models:
                return None
        if risk_level == RiskLevel.HIGH and role == ModelRole.CHALLENGER and len(models) > 1:
            return models[1]
        return models[0]

    @staticmethod
    def _scope_statement(statement, *, project_id: UUID | None, environment_id: UUID | None):
        if project_id is None:
            return statement.where(Model.project_id.is_(None))
        statement = statement.where(Model.project_id == project_id)
        if environment_id is None:
            return statement.where(Model.environment_id.is_(None))
        return statement.where(
            (Model.environment_id == environment_id) | Model.environment_id.is_(None)
        )

    def _resolve_invocation_scope(
        self,
        payload: dict[str, object],
        *,
        execution_id: UUID | None,
        project_id: UUID | None,
        environment_id: UUID | None,
    ) -> tuple[UUID | None, UUID | None]:
        resolved_project = project_id or self._uuid_or_none(payload.get("projectId"))
        resolved_environment = environment_id or self._uuid_or_none(payload.get("environmentId"))
        if resolved_project is not None or execution_id is None:
            return resolved_project, resolved_environment
        plan = self.db.scalar(
            select(TestPlan)
            .join(Execution, Execution.plan_id == TestPlan.id)
            .where(Execution.id == execution_id)
        )
        if plan is None:
            return None, None
        return plan.project_id, plan.environment_id

    @staticmethod
    def _uuid_or_none(value: object) -> UUID | None:
        if value is None:
            return None
        try:
            return UUID(str(value))
        except ValueError:
            return None

    def invoke_structured(
        self,
        trace_id: UUID | None,
        execution_id: UUID | None,
        role: ModelRole,
        prompt: str,
        payload: dict[str, object],
        provider: ProviderType | None = None,
        request_id: str | None = None,
        timeout_seconds: float | None = None,
        max_provider_retries: int | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
    ) -> dict[str, object]:
        """Compatibility entrypoint backed by the canonical JSON boundary."""

        return self.invoke_json(
            trace_id=trace_id,
            execution_id=execution_id,
            role=role,
            prompt=prompt,
            payload=payload,
            provider=provider,
            request_id=request_id,
            timeout_seconds=timeout_seconds,
            max_provider_retries=max_provider_retries,
            project_id=project_id,
            environment_id=environment_id,
        )

    def invoke_json(
        self,
        trace_id: UUID | None,
        execution_id: UUID | None,
        role: ModelRole,
        prompt: str,
        payload: dict[str, object],
        validator: object | None = None,
        schema_ref: str | None = None,
        provider: ProviderType | None = None,
        request_id: str | None = None,
        timeout_seconds: float | None = None,
        max_provider_retries: int | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
    ) -> dict[str, object]:
        """Invoke a provider and normalize its content into one validated object.

        Provider adapters may return a JSON string in ``content``. That string
        is parsed only here; callers consume only the canonical ``output``.
        """

        if validator is not None and schema_ref is not None:
            raise ValueError("validator and schema_ref are mutually exclusive")
        sanitized_prompt, sanitized_payload, guardrail_result = self.prompt_safety_guard.sanitize_prompt_and_payload(prompt, payload)
        self.guardrail_engine.record_result(
            GuardrailContext(
                trace_id=trace_id,
                request_id=request_id,
                actor_id=None,
                actor_roles=[],
                resource_type="model_invocation",
                resource_id=str(execution_id) if execution_id else role.value,
                execution_id=execution_id,
                payload={"prompt": prompt, "payload": payload, "role": role.value},
            ),
            guardrail_result,
        )
        input_injection_detected = bool(
            _MODEL_OUTPUT_INJECTION_PATTERN.search(
                f"{sanitized_prompt}\n{json.dumps(sanitized_payload, ensure_ascii=False, sort_keys=True)}"
            )
        )
        if input_injection_detected:
            self.guardrail_engine.record_result(
                GuardrailContext(
                    trace_id=trace_id,
                    request_id=request_id,
                    actor_id=None,
                    actor_roles=[],
                    resource_type="model_invocation",
                    resource_id=str(execution_id) if execution_id else role.value,
                    execution_id=execution_id,
                    payload={"role": role.value, "promptInjectionSuspected": True},
                ),
                GuardrailResult(
                    rule_id="prompt_safety.prompt_injection_blocked",
                    decision=GuardrailDecision.BLOCK,
                    reason="prompt-injection instructions were blocked before model invocation",
                    evidence=["prompt injection pattern detected"],
                    metadata={"role": role.value},
                ),
            )
        effective_risk = RiskLevel.HIGH if role in {ModelRole.CHALLENGER, ModelRole.JUDGE} else RiskLevel.MEDIUM
        project_id, environment_id = self._resolve_invocation_scope(
            payload,
            execution_id=execution_id,
            project_id=project_id,
            environment_id=environment_id,
        )
        selected_model = self.select_model(
            effective_risk,
            role,
            provider=provider,
            project_id=project_id,
            environment_id=environment_id,
        )
        adapter_payload: dict[str, Any]
        latency_ms: int
        prompt_tokens: int | None
        completion_tokens: int | None
        total_tokens: int | None
        error_message: str | None
        cost_amount: float | None
        if input_injection_detected:
            adapter_payload = {
                "provider": selected_model.provider.value if selected_model is not None else "stub",
                "mode": "live" if selected_model is not None else "stub",
                "errorCode": "MODEL_INPUT_PROMPT_INJECTION_BLOCKED",
            }
            latency_ms = 0
            prompt_tokens = None
            completion_tokens = None
            total_tokens = None
            adapter_success = False
            error_message = "prompt-injection instructions were blocked before provider invocation"
            cost_amount = 0.0
        elif selected_model is None:
            adapter_payload = {
                "provider": "stub",
                "mode": "stub",
                "promptEcho": sanitized_prompt[:200],
            }
            latency_ms = 0
            prompt_tokens = max(len(sanitized_prompt) // 4, 1)
            completion_tokens = 0
            total_tokens = prompt_tokens + completion_tokens
            adapter_success = False
            error_message = "MODEL_NOT_CONFIGURED"
            cost_amount = 0.0
        else:
            try:
                adapter_response = build_adapter(selected_model).invoke(
                    sanitized_prompt,
                    sanitized_payload,
                    timeout_seconds=timeout_seconds,
                    max_retries=max_provider_retries,
                )
            except Exception as exc:  # adapters must not prevent invocation evidence persistence
                adapter_payload = {
                    "provider": selected_model.provider.value,
                    "mode": "live",
                    "errorCode": "MODEL_ADAPTER_FAILURE",
                }
                latency_ms = 0
                prompt_tokens = None
                completion_tokens = None
                total_tokens = None
                adapter_success = False
                error_message = redact_sensitive_text(str(exc))
                cost_amount = 0.0
            else:
                adapter_payload = dict(adapter_response.payload)
                latency_ms = adapter_response.latency_ms
                prompt_tokens = adapter_response.prompt_tokens
                completion_tokens = adapter_response.completion_tokens
                total_tokens = adapter_response.total_tokens
                adapter_success = adapter_response.success
                error_message = adapter_response.error_message
                cost_amount = adapter_response.cost_amount

        provider_name = str(
            adapter_payload.get("provider")
            or (selected_model.provider.value if selected_model is not None else "stub")
        )
        mode = "stub" if str(adapter_payload.get("mode") or "live") == "stub" else "live"
        status = "failed"
        output: dict[str, Any] = {}
        limitations: list[str] = []
        fallback_used = False
        fallback_reason: str | None = None
        normalized_error = redact_sensitive_text(str(error_message)) if error_message else None

        if input_injection_detected:
            status = "invalid"
            limitations.append("MODEL_INPUT_PROMPT_INJECTION_BLOCKED")
        elif mode == "stub":
            status = "degraded"
            fallback_used = True
            fallback_reason = "MODEL_PROVIDER_FAILURE" if normalized_error and normalized_error != "MODEL_NOT_CONFIGURED" else "MODEL_STUB_USED"
            limitations.append("MODEL_NOT_CONFIGURED" if selected_model is None else fallback_reason)
        elif not adapter_success:
            status = "failed"
            limitations.append(str(adapter_payload.get("errorCode") or "MODEL_PROVIDER_FAILURE"))
        else:
            try:
                candidate = self._normalize_semantic_output(adapter_payload)
                _, sanitized_output, output_guardrail = self.prompt_safety_guard.sanitize_prompt_and_payload("", candidate)
                self.guardrail_engine.record_result(
                    GuardrailContext(
                        trace_id=trace_id,
                        request_id=request_id,
                        actor_id=None,
                        actor_roles=[],
                        resource_type="model_output",
                        resource_id=str(execution_id) if execution_id else role.value,
                        execution_id=execution_id,
                        payload={"output": candidate, "role": role.value},
                    ),
                    output_guardrail,
                )
                if sanitized_output != candidate:
                    limitations.append("MODEL_OUTPUT_REDACTED")
                if contains_sensitive_material(sanitized_output):
                    raise ModelOutputNormalizationError(
                        "MODEL_OUTPUT_SECRET_SCAN_BLOCKED",
                        "model output failed the final Secret scan",
                    )
                if _MODEL_OUTPUT_INJECTION_PATTERN.search(
                    json.dumps(sanitized_output, ensure_ascii=False, sort_keys=True)
                ):
                    self.guardrail_engine.record_result(
                        GuardrailContext(
                            trace_id=trace_id,
                            request_id=request_id,
                            actor_id=None,
                            actor_roles=[],
                            resource_type="model_output",
                            resource_id=str(execution_id) if execution_id else role.value,
                            execution_id=execution_id,
                            payload={"role": role.value, "promptInjectionSuspected": True},
                        ),
                        GuardrailResult(
                            rule_id="prompt_safety.model_output_injection_blocked",
                            decision=GuardrailDecision.BLOCK,
                            reason="prompt-injection instructions in model output were blocked",
                            evidence=["model output prompt injection pattern detected"],
                            metadata={"role": role.value},
                        ),
                    )
                    raise ModelOutputNormalizationError(
                        "MODEL_OUTPUT_PROMPT_INJECTION_BLOCKED",
                        "model output contained prompt-injection instructions",
                    )
                output = self._validate_output(sanitized_output, validator=validator, schema_ref=schema_ref)
                status = "completed"
                normalized_error = None
            except ModelOutputNormalizationError as exc:
                status = "invalid"
                output = {}
                normalized_error = redact_sensitive_text(str(exc))
                limitations.append(exc.reason_code)

        invocation_id = uuid4()
        response: dict[str, object] = {
            "modelInvocationId": str(invocation_id),
            "modelId": str(selected_model.id) if selected_model else None,
            "modelName": selected_model.model_name if selected_model else None,
            "role": role.value,
            "provider": provider_name,
            "mode": mode,
            "status": status,
            "output": redact_sensitive_data(output),
            "success": status == "completed",
            "limitations": list(dict.fromkeys(limitations)),
            "fallbackUsed": fallback_used,
            "fallbackReason": fallback_reason,
            "latencyMs": latency_ms,
            "promptTokens": prompt_tokens,
            "completionTokens": completion_tokens,
            "totalTokens": total_tokens,
            "costAmount": cost_amount,
            "errorMessage": normalized_error,
        }
        self.db.add(
            ModelInvocation(
                id=invocation_id,
                model_id=selected_model.id if selected_model else None,
                trace_id=trace_id,
                execution_id=execution_id,
                request_summary=sanitized_prompt[:200],
                request_payload=sanitized_payload,
                response_payload=response,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                latency_ms=latency_ms,
                cost_amount=cost_amount,
                currency="USD",
                success=status == "completed",
                error_message=normalized_error,
            )
        )
        return response

    def probe_model(
        self,
        model: Model,
        *,
        timeout_seconds: float = 5.0,
    ) -> dict[str, object]:
        """Run a bounded live probe through the provider-owned gateway boundary."""

        try:
            response = build_adapter(model).invoke(
                "Return a JSON object with an ok boolean.",
                {"taskType": "model.health_check"},
                timeout_seconds=timeout_seconds,
                max_retries=0,
            )
        except Exception as exc:
            return {
                "success": False,
                "mode": "live",
                "latencyMs": 0,
                "error": redact_sensitive_text(str(exc)),
            }
        return {
            "success": response.success and response.payload.get("mode") == "live",
            "mode": str(response.payload.get("mode") or "live"),
            "latencyMs": response.latency_ms,
            "error": redact_sensitive_text(response.error_message) if response.error_message else None,
        }

    def _normalize_semantic_output(self, adapter_payload: dict[str, Any]) -> dict[str, Any]:
        if "content" in adapter_payload:
            raw_content = adapter_payload.get("content")
            if not isinstance(raw_content, str):
                raise ModelOutputNormalizationError(
                    "MODEL_OUTPUT_NOT_JSON",
                    "provider content must be a JSON string",
                )
            try:
                parsed = json.loads(raw_content)
            except json.JSONDecodeError as exc:
                raise ModelOutputNormalizationError(
                    "MODEL_OUTPUT_MALFORMED_JSON",
                    "provider content was not valid JSON",
                ) from exc
            if not isinstance(parsed, dict):
                raise ModelOutputNormalizationError(
                    "MODEL_OUTPUT_NOT_OBJECT",
                    "provider JSON output must be an object",
                )
            if "output" in parsed:
                wrapped = parsed.get("output")
                if not isinstance(wrapped, dict):
                    raise ModelOutputNormalizationError(
                        "MODEL_OUTPUT_NOT_OBJECT",
                        "provider output wrapper must contain an object",
                    )
                return wrapped
            return parsed

        direct_output = adapter_payload.get("output")
        if direct_output is not None:
            if not isinstance(direct_output, dict):
                raise ModelOutputNormalizationError(
                    "MODEL_OUTPUT_NOT_OBJECT",
                    "adapter output must be an object",
                )
            return direct_output

        legacy_output = {
            key: value
            for key, value in adapter_payload.items()
            if key not in _TRANSPORT_OUTPUT_KEYS
        }
        if legacy_output:
            return legacy_output
        raise ModelOutputNormalizationError(
            "MODEL_OUTPUT_MISSING",
            "provider response did not contain structured output",
        )

    def _validate_output(
        self,
        output: dict[str, Any],
        *,
        validator: object | None,
        schema_ref: str | None,
    ) -> dict[str, Any]:
        try:
            if schema_ref is not None:
                return validate_contract(schema_ref, output)  # type: ignore[arg-type]
            if validator is None:
                return output
            if isinstance(validator, type) and issubclass(validator, BaseModel):
                return validator.model_validate(output).model_dump(mode="json")
            validate_python = getattr(validator, "validate_python", None)
            if callable(validate_python):
                validated = validate_python(output)
            elif callable(validator):
                validated = validator(output)
            else:
                raise TypeError("validator must be a Pydantic model, TypeAdapter, or callable")
            if isinstance(validated, BaseModel):
                return validated.model_dump(mode="json")
            if isinstance(validated, dict):
                return validated
            raise TypeError("validator must return an object")
        except (ContractValidationError, ValidationError, TypeError, ValueError) as exc:
            raise ModelOutputNormalizationError(
                "MODEL_OUTPUT_SCHEMA_INVALID",
                "provider JSON output failed schema validation",
            ) from exc

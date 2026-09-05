# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
from time import perf_counter
from typing import Any

from agentic_qa.domain.enums import ProviderType
from agentic_qa.domain.models import Model
from agentic_qa.infra.credentials import CredentialResolver
from agentic_qa.infra.managed_http import ManagedHttpRequestError, managed_http_request
from agentic_qa.infra.settings import get_settings


@dataclass(slots=True)
class AdapterResponse:
    payload: dict[str, Any]
    latency_ms: int
    success: bool
    error_message: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    cost_amount: float | None = None


class ModelAdapter(ABC):
    def __init__(self, model: Model) -> None:
        self.model = model
        self.settings = get_settings()

    @abstractmethod
    def invoke(
        self,
        prompt: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
    ) -> AdapterResponse:
        raise NotImplementedError

    def health_check(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "details": {
                "provider": self.model.provider.value,
                "model": self.model.model_name,
            },
        }

    def _timeout_seconds(self, override: float | None = None) -> float:
        configured_value = self.model.config.get("timeoutSeconds")
        if configured_value is None:
            configured_value = float(self.model.config.get("timeoutMs", 15000)) / 1000
        configured = max(float(configured_value), 0.001)
        return configured if override is None else min(configured, max(override, 0.001))

    def _max_retries(self, override: int | None = None) -> int:
        configured = max(int(self.model.config.get("maxRetries", 2)), 0)
        return configured if override is None else min(configured, max(override, 0))

    def _failure_response(
        self,
        *,
        started: float,
        error_code: str,
        error_message: str,
        attempts: int,
    ) -> AdapterResponse:
        return AdapterResponse(
            payload={
                "provider": self.model.provider.value,
                "mode": "live",
                "content": "{}",
                "errorCode": error_code,
                "attempts": attempts,
            },
            latency_ms=int((perf_counter() - started) * 1000),
            success=False,
            error_message=error_message,
            cost_amount=0.0,
        )


class StubAdapter(ModelAdapter):
    def invoke(
        self,
        prompt: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
    ) -> AdapterResponse:
        del timeout_seconds, max_retries
        started = perf_counter()
        # The stub keeps the orchestration path testable even when no real
        # provider credentials or local model runtime are available.
        response = {
            "provider": self.model.provider.value,
            "mode": "stub",
            "model": self.model.model_name,
            "promptEcho": prompt[:200],
            "inputKeys": sorted(payload.keys()),
        }
        latency_ms = int((perf_counter() - started) * 1000)
        prompt_tokens = max(len(prompt) // 4, 1)
        completion_tokens = 32
        return AdapterResponse(
            payload=response,
            latency_ms=latency_ms,
            success=True,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            cost_amount=0.0,
        )


class OpenAICompatibleAdapter(ModelAdapter):
    def invoke(
        self,
        prompt: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
    ) -> AdapterResponse:
        api_key = self._api_key()
        if self.model.api_key_ref and self.model.api_key_ref.lower().startswith("env://") and not api_key:
            return self._failure_response(
                started=perf_counter(),
                error_code="MODEL_CREDENTIAL_UNAVAILABLE",
                error_message="configured model credential reference is unavailable",
                attempts=0,
            )
        if not api_key:
            return StubAdapter(self.model).invoke(prompt, payload)

        base_url = (self.model.base_url or self.settings.openai_base_url).rstrip("/")
        started = perf_counter()
        try:
            response = managed_http_request(
                "POST",
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json_body={
                    "model": self.model.model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Return compact structured JSON only.",
                        },
                        {
                            "role": "user",
                            "content": f"{prompt}\n\nInput:\n{payload}",
                        },
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": self.model.config.get("temperature", 0.2),
                },
                timeout_seconds=self._timeout_seconds(timeout_seconds),
                max_retries=self._max_retries(max_retries),
            )
            body = json.loads(response.text)
            if not isinstance(body, dict):
                raise ValueError("model response must be a JSON object")
            choices = body.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                raise ValueError("model response did not include a choice")
            choice = choices[0]
            usage = body.get("usage", {})
            latency_ms = int((perf_counter() - started) * 1000)
            return AdapterResponse(
                payload={
                    "provider": self.model.provider.value,
                    "mode": "live",
                    "content": choice.get("message", {}).get("content", "{}"),
                    "attempts": response.attempts,
                },
                latency_ms=latency_ms,
                success=True,
                prompt_tokens=usage.get("prompt_tokens") if isinstance(usage, dict) else None,
                completion_tokens=usage.get("completion_tokens") if isinstance(usage, dict) else None,
                total_tokens=usage.get("total_tokens") if isinstance(usage, dict) else None,
                cost_amount=0.0,
            )
        except ManagedHttpRequestError as exc:
            return self._failure_response(
                started=started,
                error_code="MODEL_PROVIDER_HTTP_ERROR",
                error_message=exc.summary,
                attempts=exc.attempts,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            return self._failure_response(
                started=started,
                error_code="MODEL_PROVIDER_MALFORMED_RESPONSE",
                error_message=str(exc),
                attempts=1,
            )

    def _api_key(self) -> str | None:
        if self.model.api_key_ref:
            runtime = CredentialResolver().runtime_credentials_for_binding(
                {"credentialRef": self.model.api_key_ref},
                prefer_credential=True,
            )
            if runtime.get("token"):
                return str(runtime["token"])
        return self.settings.openai_api_key


class OllamaAdapter(ModelAdapter):
    def invoke(
        self,
        prompt: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
    ) -> AdapterResponse:
        base_url = (self.model.base_url or self.settings.ollama_base_url).rstrip("/")
        started = perf_counter()
        try:
            response = managed_http_request(
                "POST",
                f"{base_url}/api/generate",
                json_body={
                    "model": self.model.model_name or self.settings.ollama_model,
                    "prompt": f"{prompt}\n\nInput:\n{payload}",
                    "format": "json",
                    "stream": False,
                },
                timeout_seconds=self._timeout_seconds(timeout_seconds),
                max_retries=self._max_retries(max_retries),
            )
            body = json.loads(response.text)
            if not isinstance(body, dict) or "response" not in body:
                raise ValueError("model response did not include response content")
            latency_ms = int((perf_counter() - started) * 1000)
            return AdapterResponse(
                payload={
                    "provider": self.model.provider.value,
                    "mode": "live",
                    "content": body.get("response", "{}"),
                    "attempts": response.attempts,
                },
                latency_ms=latency_ms,
                success=True,
                prompt_tokens=None,
                completion_tokens=None,
                total_tokens=None,
                cost_amount=0.0,
            )
        except ManagedHttpRequestError as exc:
            if not self.model.base_url:
                fallback = StubAdapter(self.model).invoke(prompt, payload)
                fallback.error_message = exc.summary
                return fallback
            return self._failure_response(
                started=started,
                error_code="MODEL_PROVIDER_HTTP_ERROR",
                error_message=exc.summary,
                attempts=exc.attempts,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            if not self.model.base_url:
                fallback = StubAdapter(self.model).invoke(prompt, payload)
                fallback.error_message = str(exc)
                return fallback
            return self._failure_response(
                started=started,
                error_code="MODEL_PROVIDER_MALFORMED_RESPONSE",
                error_message=str(exc),
                attempts=1,
            )


def build_adapter(model: Model) -> ModelAdapter:
    # Keep provider routing centralized here so services never need provider-
    # specific branching logic.
    if model.provider in {
        ProviderType.OPENAI,
        ProviderType.OPENAI_COMPATIBLE,
        ProviderType.CUSTOM,
        ProviderType.ANTHROPIC,
    }:
        return OpenAICompatibleAdapter(model)
    if model.provider in {ProviderType.OLLAMA, ProviderType.VLLM}:
        return OllamaAdapter(model)
    return StubAdapter(model)

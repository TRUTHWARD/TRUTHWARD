# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.infra.redaction import redact_sensitive_text


REDACTION = "[REDACTED]"
SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "password",
    "secret",
    "token",
}


class PromptSafetyGuard(RuntimeGuardrail):
    """Redact obviously sensitive values before prompts or memory are persisted."""

    rule_id = "prompt_safety.redact_sensitive_material"

    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        _, _, result = self.sanitize_prompt_and_payload(
            str(context.payload.get("prompt", "")),
            context.payload.get("payload", {}),
        )
        return result

    def sanitize_prompt_and_payload(
        self,
        prompt: str,
        payload: dict[str, Any],
    ) -> tuple[str, dict[str, Any], GuardrailResult]:
        sanitized_prompt, prompt_hits = self._sanitize_text(prompt)
        sanitized_payload, payload_hits = self._sanitize_value(payload, "")
        return self._build_result(sanitized_prompt, sanitized_payload, prompt_hits + payload_hits)

    def sanitize_text_and_metadata(
        self,
        text: str,
        metadata: dict[str, Any],
    ) -> tuple[str, dict[str, Any], GuardrailResult]:
        sanitized_text, text_hits = self._sanitize_text(text)
        sanitized_metadata, metadata_hits = self._sanitize_value(metadata, "metadata")
        return self._build_result(sanitized_text, sanitized_metadata, text_hits + metadata_hits)

    def _build_result(
        self,
        sanitized_text: str,
        sanitized_payload: dict[str, Any],
        hits: list[str],
    ) -> tuple[str, dict[str, Any], GuardrailResult]:
        if hits:
            return (
                sanitized_text,
                sanitized_payload,
                GuardrailResult(
                    rule_id=self.rule_id,
                    decision=GuardrailDecision.WARN,
                    reason="sensitive values were redacted before downstream processing",
                    evidence=hits,
                    metadata={"redactions": len(hits)},
                ),
            )
        return (
            sanitized_text,
            sanitized_payload,
            GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.ALLOW,
                reason="no sensitive prompt material detected",
                evidence=["no redaction required"],
                metadata={"redactions": 0},
            ),
        )

    def _sanitize_value(self, value: Any, path: str) -> tuple[Any, list[str]]:
        if isinstance(value, dict):
            sanitized: dict[str, Any] = {}
            hits: list[str] = []
            for key, item in value.items():
                raw_key = str(key)
                safe_key = redact_sensitive_text(raw_key)
                current_path = f"{path}.{safe_key}" if path else safe_key
                if raw_key.lower() in SENSITIVE_KEYS:
                    sanitized[safe_key] = REDACTION
                    hits.append(current_path)
                    continue
                sanitized_item, item_hits = self._sanitize_value(item, current_path)
                sanitized[safe_key] = sanitized_item
                hits.extend(item_hits)
            return sanitized, hits
        if isinstance(value, list):
            sanitized_list: list[Any] = []
            list_hits: list[str] = []
            for index, item in enumerate(value):
                sanitized_item, item_hits = self._sanitize_value(item, f"{path}[{index}]")
                sanitized_list.append(sanitized_item)
                list_hits.extend(item_hits)
            return sanitized_list, list_hits
        if isinstance(value, str):
            sanitized_text, text_hits = self._sanitize_text(value)
            normalized_hits = [path or "text"] if text_hits else []
            return sanitized_text, normalized_hits
        return value, []

    def _sanitize_text(self, text: str) -> tuple[str, list[str]]:
        if not text:
            return text, []
        sanitized = redact_sensitive_text(text)
        if sanitized == text:
            return text, []
        return sanitized, ["sensitive_text"]

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
import math
import re
from copy import deepcopy
from dataclasses import dataclass

from agentic_qa.infra.redaction import contains_sensitive_material, redact_sensitive_data

from agentic_qa.runtime.qa_harness.contracts import (
    HarnessContextBlock,
    HarnessRunContext,
    HarnessRunSpec,
)


_FORBIDDEN_KEYS = {
    "authorization",
    "cookie",
    "credential",
    "credentialref",
    "password",
    "rawconnectorconfig",
    "rawproviderresponse",
    "secret",
    "secretref",
    "token",
}
_UNSAFE_SNAPSHOT_VALUE = re.compile(
    r"(?i)(?:\bBearer\s+[A-Za-z0-9._~+/=-]{6,}|"
    r"(?:ghp_|github_pat_|sk-|xoxb-|xoxp-|glpat-)[A-Za-z0-9._-]{6,}|"
    r"(?:vault|cred|credential|secret|mcp-secret)://[^\s\"'<>]+|"
    r"[?&](?:access[_-]?token|api[_-]?key|token|password|secret|credential)=[^&#\s]+)"
)

AUTHORIZED_CONTEXT_SCHEMA_VERSION = "phase8.skill-context-envelope.v1"
AUTHORIZED_CONTEXT_REDACTION_POLICY_VERSION = "phase8.authorized-context.v1"
MAX_CONTEXT_DEPTH = 20
MAX_CONTEXT_NODES = 20_000
MAX_CONTEXT_BYTES = 262_144
MAX_CONTEXT_TOKENS = 65_536


@dataclass(frozen=True, slots=True)
class SafeContextProjection:
    content: object
    content_hash: str
    redaction_status: str
    byte_size: int
    estimated_tokens: int


def canonical_content_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _normalized_key(value: object) -> str:
    return "".join(character for character in str(value).lower() if character.isalnum())


def contains_unsafe_snapshot_material(value: object, *, key: str | None = None) -> bool:
    """Conservative, dependency-free scanner for frozen internal snapshots."""

    normalized = _normalized_key(key or "")
    if key and (
        normalized in _FORBIDDEN_KEYS
        or normalized.endswith("secret")
        or normalized.endswith("token")
    ):
        return not (value is None or value == "" or value == "[REDACTED]")
    if isinstance(value, dict):
        return any(
            contains_unsafe_snapshot_material(item, key=str(item_key))
            for item_key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(contains_unsafe_snapshot_material(item) for item in value)
    return (
        isinstance(value, str)
        and _UNSAFE_SNAPSHOT_VALUE.search(value.replace("[REDACTED]", "")) is not None
    )


def _strict_json_clone(
    value: object,
    *,
    max_depth: int,
    max_nodes: int,
    depth: int = 0,
    nodes: list[int] | None = None,
    active: set[int] | None = None,
) -> object:
    if depth > max_depth:
        raise ValueError("context exceeds maximum depth")
    counter = nodes if nodes is not None else [0]
    counter[0] += 1
    if counter[0] > max_nodes:
        raise ValueError("context exceeds maximum node count")
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("context contains non-finite number")
        return value
    seen = active if active is not None else set()
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in seen:
            raise ValueError("context contains circular value")
        seen.add(identity)
        try:
            return [
                _strict_json_clone(
                    item,
                    max_depth=max_depth,
                    max_nodes=max_nodes,
                    depth=depth + 1,
                    nodes=counter,
                    active=seen,
                )
                for item in value
            ]
        finally:
            seen.remove(identity)
    if isinstance(value, dict):
        identity = id(value)
        if identity in seen:
            raise ValueError("context contains circular value")
        seen.add(identity)
        try:
            result: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("context object keys must be strings")
                result[key] = _strict_json_clone(
                    item,
                    max_depth=max_depth,
                    max_nodes=max_nodes,
                    depth=depth + 1,
                    nodes=counter,
                    active=seen,
                )
            return result
        finally:
            seen.remove(identity)
    raise ValueError(f"context contains non-JSON value: {type(value).__name__}")


def _encoded_context(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("context is not canonical JSON") from exc


def validate_safe_context_content(
    value: object,
    *,
    max_depth: int = MAX_CONTEXT_DEPTH,
    max_nodes: int = MAX_CONTEXT_NODES,
    max_bytes: int = MAX_CONTEXT_BYTES,
    max_tokens: int = MAX_CONTEXT_TOKENS,
) -> tuple[object, int, int]:
    """Validate already-projected JSON with the shared Harness/Skill rules."""

    cloned = _strict_json_clone(
        value,
        max_depth=min(max_depth, MAX_CONTEXT_DEPTH),
        max_nodes=min(max_nodes, MAX_CONTEXT_NODES),
    )
    encoded = _encoded_context(cloned)
    if len(encoded) > min(max_bytes, MAX_CONTEXT_BYTES):
        raise ValueError("context exceeds maximum byte size")
    estimated_tokens = (len(encoded) + 3) // 4
    if estimated_tokens > min(max_tokens, MAX_CONTEXT_TOKENS):
        raise ValueError("context exceeds maximum token budget")
    if contains_sensitive_material(cloned) or contains_unsafe_snapshot_material(cloned):
        raise ValueError("context failed the final Secret scan")
    return cloned, len(encoded), estimated_tokens


def project_safe_context_content(
    value: object,
    *,
    max_depth: int = MAX_CONTEXT_DEPTH,
    max_nodes: int = MAX_CONTEXT_NODES,
    max_bytes: int = MAX_CONTEXT_BYTES,
    max_tokens: int = MAX_CONTEXT_TOKENS,
) -> SafeContextProjection:
    """Create a redacted, canonical, bounded projection from strict JSON input."""

    raw = _strict_json_clone(
        value,
        max_depth=min(max_depth, MAX_CONTEXT_DEPTH),
        max_nodes=min(max_nodes, MAX_CONTEXT_NODES),
    )
    projected = redact_sensitive_data(raw)
    safe, byte_size, estimated_tokens = validate_safe_context_content(
        projected,
        max_depth=max_depth,
        max_nodes=max_nodes,
        max_bytes=max_bytes,
        max_tokens=max_tokens,
    )
    return SafeContextProjection(
        content=safe,
        content_hash=canonical_content_hash(safe),
        redaction_status="redacted" if safe != raw else "not_required",
        byte_size=byte_size,
        estimated_tokens=estimated_tokens,
    )


def validate_context_block(block: HarnessContextBlock) -> HarnessContextBlock:
    validated = HarnessContextBlock.model_validate(block.model_dump(mode="python"))
    validate_safe_context_content(validated.scopeSnapshot)
    validate_safe_context_content(validated.freshness)
    validate_safe_context_content([item.model_dump(mode="json") for item in validated.evidenceRefs])
    if not validated.available:
        if validated.contentHash != canonical_content_hash(None):
            raise ValueError(f"unavailable context hash mismatch: {validated.sourceRef}")
        return validated
    safe_content, _, _ = validate_safe_context_content(validated.content)
    if canonical_content_hash(safe_content) != validated.contentHash:
        raise ValueError(f"context content hash mismatch: {validated.sourceRef}")
    return validated


def context_envelope_hash(payload: dict[str, object]) -> str:
    return canonical_content_hash({key: value for key, value in payload.items() if key != "envelopeHash"})


def validate_context_envelope(payload: object) -> dict[str, object]:
    """Validate a frozen Skill Context Envelope without DB or Service access."""

    # Local import avoids making the shared projection module depend on its
    # envelope schema at module-import time.
    from agentic_qa.schemas.skills import SkillContextEnvelope

    safe, _, _ = validate_safe_context_content(payload)
    if not isinstance(safe, dict):
        raise ValueError("Skill Context Envelope must be an object")
    if safe.get("schemaVersion") != AUTHORIZED_CONTEXT_SCHEMA_VERSION:
        raise ValueError("Skill Context Envelope schemaVersion is unsupported")
    blocks = safe.get("blocks")
    if not isinstance(blocks, list):
        raise ValueError("Skill Context Envelope blocks must be a list")
    for item in blocks:
        if not isinstance(item, dict):
            raise ValueError("Skill Context Envelope block must be an object")
        validate_context_block(HarnessContextBlock.model_validate(item))
    envelope_hash = safe.get("envelopeHash")
    if not isinstance(envelope_hash, str) or context_envelope_hash(safe) != envelope_hash:
        raise ValueError("Skill Context Envelope hash mismatch")
    return SkillContextEnvelope.model_validate(safe).model_dump(mode="json")


class AuthorizedContextBuilder:
    """Build model-facing context only from Service-authorized safe blocks."""

    def __init__(self, blocks: list[HarnessContextBlock]) -> None:
        self._blocks = [HarnessContextBlock.model_validate(block.model_dump()) for block in blocks]

    def build(self, spec: HarnessRunSpec, context: HarnessRunContext) -> list[HarnessContextBlock]:
        del spec
        blocks = [validate_context_block(block) for block in self._blocks]
        for observation in context.observations:
            content = {
                "kind": observation.kind,
                "status": observation.status,
                "result": deepcopy(observation.result),
                "evidenceRefs": [item.model_dump() for item in observation.evidenceRefs],
                "limitations": list(observation.limitations),
                "reasonCode": observation.reasonCode.value if observation.reasonCode else None,
                "metadata": deepcopy(observation.metadata),
            }
            blocks.append(
                HarnessContextBlock(
                    sourceRef=observation.observationRef,
                    sourceType=f"observation:{observation.kind}",
                    sourceVersion=observation.observationId,
                    scopeSnapshot={},
                    freshness={"status": "service_observation"},
                    trustBoundary="service_observation",
                    contentHash=canonical_content_hash(content if observation.available else None),
                    redactionStatus=(
                        observation.redactionStatus if observation.available else "unavailable"
                    ),
                    redactionPolicyVersion=AUTHORIZED_CONTEXT_REDACTION_POLICY_VERSION,
                    available=observation.available,
                    unavailableReason=(
                        observation.reasonCode.value if observation.reasonCode else None
                    ),
                    evidenceRefs=observation.evidenceRefs,
                    limitations=observation.limitations,
                    content=content if observation.available else None,
                )
            )
        return [validate_context_block(block) for block in blocks]


__all__ = [
    "AuthorizedContextBuilder",
    "AUTHORIZED_CONTEXT_REDACTION_POLICY_VERSION",
    "AUTHORIZED_CONTEXT_SCHEMA_VERSION",
    "MAX_CONTEXT_BYTES",
    "MAX_CONTEXT_DEPTH",
    "MAX_CONTEXT_NODES",
    "MAX_CONTEXT_TOKENS",
    "SafeContextProjection",
    "canonical_content_hash",
    "contains_unsafe_snapshot_material",
    "context_envelope_hash",
    "project_safe_context_content",
    "validate_context_block",
    "validate_context_envelope",
    "validate_safe_context_content",
]

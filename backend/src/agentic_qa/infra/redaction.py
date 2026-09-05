# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any


PLAINTEXT_SECRET_PREFIXES = ("ghp_", "github_pat_", "sk-", "xoxb-", "xoxp-", "glpat-", "eyJ")
REFERENCE_KEYS = {"secretref", "credentialref", "apikeyref"}
SENSITIVE_KEY_FRAGMENTS = (
    "apikey",
    "accesstoken",
    "authorization",
    "clientsecret",
    "cookie",
    "credential",
    "dsn",
    "headers",
    "keymaterial",
    "passphrase",
    "passwd",
    "password",
    "privatekey",
    "refreshtoken",
    "secretvalue",
    "session",
    "token",
    "tokenvalue",
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)([\"']?(?:password|passwd|pwd|token|credential|secret|api[_ -]?key|"
    r"access[_ -]?token|refresh[_ -]?token|client[_ -]?secret)[\"']?|"
    r"密码|口令|凭据|密钥|令牌)\s*([:=：])\s*([\"']?[^\s,;，；}\]]+)"
)
BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}")
PREFIXED_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:ghp_|github_pat_|sk-|xoxb-|xoxp-|glpat-)[A-Za-z0-9._-]{6,}"
)
JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"
)
EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)
PHONE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?"
    r"\d{3}[\s.-]\d{3}[\s.-]\d{4}(?![A-Za-z0-9_-])"
)
NATIONAL_ID_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:\d{3}-\d{2}-\d{4}|\d{17}[\dXx])"
    r"(?![A-Za-z0-9_-])"
)
URL_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@"
)
SENSITIVE_QUERY_PATTERN = re.compile(
    r"(?i)([?&](?:access[_-]?token|refresh[_-]?token|api[_-]?key|token|password|"
    r"secret|credential|client[_-]?secret)=)[^&#\s]+"
)
CREDENTIAL_REFERENCE_PATTERN = re.compile(
    r"(?i)\b(?:vault|cred|credential|secret|aws-sm|gcp-sm|azure-kv|env|mcp-secret)://[^\s\"'<>]+"
)
REDACTION = "[REDACTED]"


def normalize_sensitive_key(value: str) -> str:
    """Normalize snake/camel/kebab/case variants before key classification."""

    return re.sub(r"[^a-z0-9]", "", value.casefold())


def is_sensitive_key(value: str) -> bool:
    normalized = normalize_sensitive_key(value)
    return normalized in REFERENCE_KEYS or any(
        fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS
    )


def mask_reference(value: str) -> str:
    # A partially masked reference can still be resolvable and can preserve a
    # caller's unique canary in its final path segment. References therefore
    # use the same non-reversible marker as credential material.
    return REDACTION


def redact_sensitive_text(value: str) -> str:
    """Remove synthetic/real-looking secret and PII material from free text."""

    stripped = value.strip()
    if len(stripped) <= 65_536 and stripped[:1] in {"{", "["}:
        try:
            decoded = json.loads(stripped)
        except (json.JSONDecodeError, TypeError, ValueError):
            decoded = None
        if isinstance(decoded, (dict, list)):
            return json.dumps(
                redact_sensitive_data(decoded),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )

    redacted = SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION}",
        value,
    )
    for pattern in (
        BEARER_TOKEN_PATTERN,
        PREFIXED_SECRET_PATTERN,
        JWT_PATTERN,
        EMAIL_PATTERN,
        PHONE_PATTERN,
        NATIONAL_ID_PATTERN,
        CREDENTIAL_REFERENCE_PATTERN,
    ):
        redacted = pattern.sub(REDACTION, redacted)
    redacted = URL_CREDENTIAL_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTION}@", redacted)
    redacted = SENSITIVE_QUERY_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTION}", redacted)
    return redacted


def contains_unsafe_control_characters(value: str) -> bool:
    """Return true for controls that are unsafe in persisted text or paths."""

    return any(
        character not in {"\t", "\n", "\r"}
        and unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    )


def redact_sensitive_data(value: Any, *, key: str | None = None) -> Any:
    key_normalized = normalize_sensitive_key(key or "")
    if key and is_sensitive_key(key):
        if value is None or value == "" or isinstance(value, bool):
            return value
        return REDACTION
    if isinstance(value, dict):
        return {
            redact_sensitive_text(item_key): redact_sensitive_data(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, str):
        if key_normalized in REFERENCE_KEYS:
            return mask_reference(value)
        if value.startswith(PLAINTEXT_SECRET_PREFIXES):
            return REDACTION
        return redact_sensitive_text(value)
    return value


def contains_sensitive_material(value: Any, *, key: str | None = None) -> bool:
    """Conservatively scan a payload before persistence or external output."""

    if key and is_sensitive_key(key):
        return not (value is None or value == "" or value == REDACTION)
    if isinstance(value, dict):
        return any(
            contains_sensitive_material(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(contains_sensitive_material(item) for item in value)
    if not isinstance(value, str):
        return False
    if value == REDACTION:
        return False
    # Redaction markers intentionally remain in otherwise useful structured
    # text (for example ``?access_token=[REDACTED]``).  Scan the residual text
    # so a successfully redacted value does not fail the final persistence
    # backstop merely because the original key shape is still visible.
    residual = value.replace(REDACTION, "")
    return any(
        pattern.search(residual) is not None
        for pattern in (
            BEARER_TOKEN_PATTERN,
            PREFIXED_SECRET_PATTERN,
            JWT_PATTERN,
            SECRET_ASSIGNMENT_PATTERN,
            URL_CREDENTIAL_PATTERN,
            SENSITIVE_QUERY_PATTERN,
            CREDENTIAL_REFERENCE_PATTERN,
        )
    )

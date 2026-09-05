# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any


class CredentialReferenceError(ValueError):
    """Raised when a connector credential reference looks unsafe."""


@dataclass(frozen=True, slots=True)
class ResolvedCredentialReference:
    ref: str
    scheme: str
    scope: dict[str, Any]


class CredentialResolver:
    """Validate credential references without materializing secret values."""

    allowed_secret_schemes = {
        "vault",
        "cred",
        "credential",
        "secret",
        "aws-sm",
        "gcp-sm",
        "azure-kv",
        "env",
        "mcp-secret",
    }
    plaintext_prefixes = ("ghp_", "github_pat_", "sk-", "xoxb-", "xoxp-", "glpat-", "eyJ")

    def validate_reference(self, ref: str, *, field_name: str, scope: dict[str, Any] | None = None) -> ResolvedCredentialReference:
        normalized = (ref or "").strip()
        if not normalized:
            raise CredentialReferenceError(f"{field_name} must not be blank")
        if normalized.startswith(self.plaintext_prefixes) or "://" not in normalized:
            raise CredentialReferenceError(f"{field_name} must be a credential reference, not a plaintext secret")
        scheme = normalized.split("://", 1)[0].lower()
        if scheme not in self.allowed_secret_schemes:
            raise CredentialReferenceError(f"{field_name} uses unsupported credential reference scheme '{scheme}'")
        return ResolvedCredentialReference(ref=normalized, scheme=scheme, scope=dict(scope or {}))

    def validate_binding(
        self,
        *,
        connector_name: str,
        secret_ref: str,
        credential_ref: str | None,
        scope: dict[str, Any],
    ) -> dict[str, Any]:
        secret = self.validate_reference(secret_ref, field_name="secretRef", scope=scope)
        credential = (
            self.validate_reference(credential_ref, field_name="credentialRef", scope=scope)
            if credential_ref
            else None
        )
        return {
            "connectorName": connector_name,
            "secretRef": secret.ref,
            "secretScheme": secret.scheme,
            "credentialRef": credential.ref if credential else None,
            "credentialScheme": credential.scheme if credential else None,
            "scope": dict(scope),
            "resolverVersion": "phase8.v1",
        }

    def runtime_credentials_for_binding(
        self,
        binding_snapshot: dict[str, Any],
        *,
        prefer_credential: bool = False,
    ) -> dict[str, Any]:
        """Materialize in-memory runtime credentials for supported local refs.

        This method intentionally supports only `env://NAME` references. Secret
        values are returned to the managed connector runtime and must never be
        persisted in DB snapshots, logs, replay payloads, or frontend state.
        """

        credentials: dict[str, Any] = {}
        ref_keys = ("credentialRef",) if prefer_credential else ("secretRef", "credentialRef")
        for ref_key in ref_keys:
            ref = str(binding_snapshot.get(ref_key) or "").strip()
            if not ref.lower().startswith("env://"):
                continue
            env_name = ref.split("://", 1)[1].strip()
            if not env_name:
                continue
            value = os.environ.get(env_name)
            if value:
                credentials.setdefault("token", value)
        return credentials

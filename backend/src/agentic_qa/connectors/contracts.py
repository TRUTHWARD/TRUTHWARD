# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ConnectorCapability:
    name: str
    read_only: bool = True
    risk_level: str = "low"


@dataclass(frozen=True, slots=True)
class ConnectorRuntimeContract:
    connector_name: str
    protocol: str
    capabilities: list[ConnectorCapability] = field(default_factory=list)
    credential_schemes: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ConnectorOperationRequest:
    connector_name: str
    operation: str
    payload: dict[str, Any] = field(default_factory=dict)
    binding_snapshot: dict[str, Any] = field(default_factory=dict)
    runtime_credentials: dict[str, Any] = field(default_factory=dict)
    trace_id: str | None = None
    skill_invocation_id: str | None = None


@dataclass(frozen=True, slots=True)
class ConnectorOperationResult:
    succeeded: bool
    data: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[dict[str, Any]] = field(default_factory=list)
    connector_call_ref: str | None = None
    errors: list[str] = field(default_factory=list)


class ConnectorRuntime(Protocol):
    contract: ConnectorRuntimeContract

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        ...

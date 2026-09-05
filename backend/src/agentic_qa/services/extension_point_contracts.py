# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from agentic_qa.agents.base import AgentResult
from agentic_qa.tools.runner_protocols import RunnerExecutionResult


SKILL_REQUEST_SCHEMA: Mapping[str, object] = MappingProxyType(
    {
        "type": "object",
        "required": ("operation", "payload"),
        "properties": {
            "operation": {"type": "string", "minLength": 1},
            "payload": {"type": "object"},
        },
    }
)

SKILL_RESULT_REQUIRED_FIELDS = frozenset(
    {
        "result",
        "confidence",
        "evidence",
        "artifactRefs",
        "rawFindingRefs",
        "findingCandidates",
        "metadata",
    }
)


class ExtensionPointContractError(ValueError):
    """Raised when an extension point is unknown or violates its authority contract."""


@dataclass(frozen=True, slots=True)
class ExtensionPointContract:
    extension_point_id: str
    lifecycle_stage: str
    label: str
    bindable: bool
    default_skill_id: str | None
    input_schema_ref: str | None
    output_schema_ref: str | None
    allowed_runtime_result_kinds: frozenset[str]
    required_capability: str | None
    unavailable_reason: str | None
    allow_fallback: bool
    default_runtime_adapter: str | None = None
    allowed_execution_modes: frozenset[str] = frozenset({"synchronous"})
    execution_constraints: Mapping[str, object] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def workflow_projection(self) -> dict[str, object]:
        return {
            "lifecycleStage": self.lifecycle_stage,
            "extensionPointId": self.extension_point_id,
            "label": self.label,
            "bindable": self.bindable,
            "requiredCapability": self.required_capability,
            "unavailableReason": self.unavailable_reason,
        }


class ExtensionPointContractRegistry:
    """Code authority for bindable and permanently non-bindable workflow nodes."""

    def __init__(self, contracts: tuple[ExtensionPointContract, ...]) -> None:
        by_id: dict[str, ExtensionPointContract] = {}
        for contract in contracts:
            if contract.extension_point_id in by_id:
                raise ValueError(f"duplicate extension point contract: {contract.extension_point_id}")
            if contract.bindable:
                if not contract.default_skill_id:
                    raise ValueError(f"bindable extension point has no default Skill: {contract.extension_point_id}")
                if not contract.input_schema_ref or not contract.output_schema_ref:
                    raise ValueError(f"bindable extension point has no schema contract: {contract.extension_point_id}")
                if not contract.allowed_runtime_result_kinds:
                    raise ValueError(f"bindable extension point has no runtime result kind: {contract.extension_point_id}")
                if not contract.default_runtime_adapter:
                    raise ValueError(f"bindable extension point has no default runtime adapter: {contract.extension_point_id}")
            elif contract.default_skill_id is not None or contract.allow_fallback:
                raise ValueError(f"non-bindable extension point cannot have a default or fallback: {contract.extension_point_id}")
            by_id[contract.extension_point_id] = contract
        self._contracts = MappingProxyType(by_id)

    def get(self, extension_point_id: str) -> ExtensionPointContract | None:
        return self._contracts.get(extension_point_id)

    def require(self, extension_point_id: str) -> ExtensionPointContract:
        contract = self.get(extension_point_id)
        if contract is None:
            raise ExtensionPointContractError(f"UNKNOWN_EXTENSION_POINT: {extension_point_id}")
        return contract

    def require_bindable(self, extension_point_id: str) -> ExtensionPointContract:
        contract = self.require(extension_point_id)
        if not contract.bindable:
            reason = contract.unavailable_reason or "permanently non-bindable"
            raise ExtensionPointContractError(
                f"EXTENSION_POINT_NOT_BINDABLE: {extension_point_id} ({reason})"
            )
        return contract

    def all(self) -> tuple[ExtensionPointContract, ...]:
        return tuple(self._contracts.values())

    def bindable(self) -> tuple[ExtensionPointContract, ...]:
        return tuple(item for item in self._contracts.values() if item.bindable)

    def workflow_nodes(self) -> tuple[dict[str, object], ...]:
        return tuple(item.workflow_projection() for item in self._contracts.values())

    def default_bindings(self) -> dict[str, str]:
        return {
            item.extension_point_id: str(item.default_skill_id)
            for item in self.bindable()
        }

    def default_runtime_contracts_by_skill(self) -> dict[str, dict[str, str]]:
        return {
            str(item.default_skill_id): {
                "runtimeAdapter": str(item.default_runtime_adapter),
                "runtimeResultKind": next(iter(item.allowed_runtime_result_kinds)),
            }
            for item in self.bindable()
        }

    def extension_points_for_runtime_adapter(self, adapter_id: str) -> frozenset[str]:
        return frozenset(
            item.extension_point_id
            for item in self.bindable()
            if item.default_runtime_adapter == adapter_id
        )

    def extension_points_for_default_skill(self, skill_id: str) -> list[str]:
        return [
            item.extension_point_id
            for item in self.bindable()
            if item.default_skill_id == skill_id
        ]

    def validate_request(
        self,
        extension_point_id: str,
        request: dict[str, object],
        *,
        execution_mode: str,
    ) -> ExtensionPointContract:
        contract = self.require_bindable(extension_point_id)
        if execution_mode not in contract.allowed_execution_modes:
            raise ExtensionPointContractError(
                f"EXTENSION_POINT_EXECUTION_MODE_INCOMPATIBLE: {extension_point_id} ({execution_mode})"
            )
        if not isinstance(request, dict):
            raise ExtensionPointContractError(
                f"EXTENSION_POINT_INPUT_INVALID: {extension_point_id} request must be an object"
            )
        operation = request.get("operation")
        if not isinstance(operation, str) or not operation.strip():
            raise ExtensionPointContractError(
                f"EXTENSION_POINT_INPUT_INVALID: {extension_point_id} operation must be a non-empty string"
            )
        if not isinstance(request.get("payload"), dict):
            raise ExtensionPointContractError(
                f"EXTENSION_POINT_INPUT_INVALID: {extension_point_id} payload must be an object"
            )
        return contract

    def validate_version_contract(
        self,
        extension_point_id: str,
        *,
        input_schema: object,
        output_schema: object,
        compatibility: object,
    ) -> ExtensionPointContract:
        contract = self.require_bindable(extension_point_id)
        if not isinstance(input_schema, dict) or not input_schema:
            raise ExtensionPointContractError("skill input schema must be a non-empty object")
        if not isinstance(output_schema, dict):
            raise ExtensionPointContractError("skill output schema must be an object")
        if not isinstance(compatibility, dict):
            raise ExtensionPointContractError("skill compatibility must be an object")
        if compatibility.get("input") != contract.input_schema_ref:
            raise ExtensionPointContractError(
                f"skill input schema is not compatible with {contract.input_schema_ref}"
            )
        if compatibility.get("output") != contract.output_schema_ref:
            raise ExtensionPointContractError(
                f"skill output schema is not compatible with {contract.output_schema_ref}"
            )
        if not SKILL_RESULT_REQUIRED_FIELDS.issubset(output_schema):
            raise ExtensionPointContractError("skill output schema is not compatible with skill-result schema")
        runtime_result_kind = str(compatibility.get("runtimeResultKind") or "")
        if runtime_result_kind and runtime_result_kind not in contract.allowed_runtime_result_kinds:
            raise ExtensionPointContractError(
                "managed Skill runtime result kind is incompatible with extension point: "
                f"{extension_point_id} does not allow {runtime_result_kind}"
            )
        return contract

    def validate_runtime_result(
        self,
        extension_point_id: str,
        *,
        runtime_result_kind: str | None,
        runtime_result: object,
    ) -> None:
        contract = self.require_bindable(extension_point_id)
        if runtime_result_kind not in contract.allowed_runtime_result_kinds:
            raise ExtensionPointContractError(
                "managed Skill runtime result kind is incompatible with extension point: "
                f"{extension_point_id} does not allow {runtime_result_kind or 'missing'}"
            )
        compatible = {
            "agent_result": isinstance(runtime_result, AgentResult),
            "runner_result": isinstance(runtime_result, RunnerExecutionResult),
            "skill_result": isinstance(runtime_result, dict),
        }.get(str(runtime_result_kind), False)
        if not compatible:
            raise ExtensionPointContractError(
                "managed Skill runtime returned an incompatible result: "
                f"expected {runtime_result_kind}, got {type(runtime_result).__name__}"
            )


def _bindable(
    extension_point_id: str,
    lifecycle_stage: str,
    label: str,
    default_skill_id: str,
    runtime_adapter: str,
    runtime_result_kind: str,
    *,
    execution_modes: frozenset[str] = frozenset({"synchronous"}),
    execution_constraints: Mapping[str, object] = MappingProxyType({}),
) -> ExtensionPointContract:
    governed_execution_constraints = MappingProxyType(
        {
            "mutation": False,
            "externalWrite": False,
            "idempotent": True,
            **dict(execution_constraints),
        }
    )
    return ExtensionPointContract(
        extension_point_id=extension_point_id,
        lifecycle_stage=lifecycle_stage,
        label=label,
        bindable=True,
        default_skill_id=default_skill_id,
        input_schema_ref="skill-request.v1",
        output_schema_ref="skill-result.v1",
        allowed_runtime_result_kinds=frozenset({runtime_result_kind}),
        required_capability="capability_bindings.write",
        unavailable_reason=None,
        allow_fallback=True,
        default_runtime_adapter=runtime_adapter,
        allowed_execution_modes=execution_modes,
        execution_constraints=governed_execution_constraints,
    )


def _non_bindable(
    extension_point_id: str,
    lifecycle_stage: str,
    label: str,
    unavailable_reason: str,
) -> ExtensionPointContract:
    return ExtensionPointContract(
        extension_point_id=extension_point_id,
        lifecycle_stage=lifecycle_stage,
        label=label,
        bindable=False,
        default_skill_id=None,
        input_schema_ref=None,
        output_schema_ref=None,
        allowed_runtime_result_kinds=frozenset(),
        required_capability=None,
        unavailable_reason=unavailable_reason,
        allow_fallback=False,
        default_runtime_adapter=None,
        allowed_execution_modes=frozenset(),
    )


EXTENSION_POINT_CONTRACTS = ExtensionPointContractRegistry(
    (
        _bindable("PREPARE.test_plan", "PREPARE", "Test Plan Generation", "test-plan-generation", "service.agent.v1", "agent_result"),
        _bindable("PREPARE.test_case", "PREPARE", "Test Case Generation", "test-case-generation", "service.agent.v1", "agent_result"),
        _bindable("PREPARE.exploratory_charter", "PREPARE", "Exploratory Charter", "exploratory-charter-generation", "service.projection.v1", "skill_result"),
        _bindable("PREPARE.regression_scope", "PREPARE", "Regression Scope", "regression-scope-recommendation", "service.projection.v1", "skill_result"),
        _bindable(
            "EXECUTE.automated_execution",
            "EXECUTE",
            "Automated Execution",
            "execution-runner",
            "execution.runner.v1",
            "runner_result",
            execution_modes=frozenset({"managed_task"}),
            execution_constraints=MappingProxyType(
                {
                    "queueOwnedBy": "ExecutionService",
                    "preservesCancellation": True,
                    "preservesSandbox": True,
                    "mutation": True,
                    "externalWrite": False,
                    "idempotent": False,
                }
            ),
        ),
        _bindable("EXECUTE.manual_simulation", "EXECUTE", "Manual Simulation", "manual-test-simulation", "execution.manual.v1", "skill_result", execution_modes=frozenset({"managed_task"})),
        _bindable("EXECUTE.exploratory_assist", "EXECUTE", "Exploratory Assist", "exploratory-assist", "service.projection.v1", "skill_result"),
        _non_bindable("OBSERVE", "OBSERVE", "Observe", "execution-owned observation"),
        _bindable(
            "ANALYZE.finding_triage",
            "ANALYZE",
            "Finding Triage",
            "finding-triage",
            "service.agent.v1",
            "agent_result",
            execution_constraints=MappingProxyType({"expectedModelCalls": 2}),
        ),
        _bindable(
            "ANALYZE.performance_analysis",
            "ANALYZE",
            "Performance Analysis",
            "performance-analysis",
            "service.agent.v1",
            "agent_result",
            execution_constraints=MappingProxyType({"expectedModelCalls": 2}),
        ),
        _bindable(
            "ANALYZE.security_analysis",
            "ANALYZE",
            "Security Analysis",
            "security-analysis",
            "service.agent.v1",
            "agent_result",
            execution_constraints=MappingProxyType({"expectedModelCalls": 2}),
        ),
        _non_bindable("NORMALIZE", "NORMALIZE", "Normalize Findings", "service-owned canonicalization"),
        _non_bindable("GATE.decision_write", "GATE", "Gate Decision Write", "service-owned governance decision"),
        _non_bindable("Memory promotion", "GOVERNANCE", "Memory Promotion", "memory promotion rules"),
        _non_bindable("Approval decision", "GOVERNANCE", "Approval Decision", "approval flow"),
        _non_bindable("Provider routing", "ROUTING", "Provider Routing", "model-gateway routing policy"),
        _non_bindable("Visual Grounding", "EXECUTE", "Visual Grounding", "execution-service internal capability"),
    )
)


__all__ = [
    "EXTENSION_POINT_CONTRACTS",
    "ExtensionPointContract",
    "ExtensionPointContractError",
    "ExtensionPointContractRegistry",
    "SKILL_REQUEST_SCHEMA",
    "SKILL_RESULT_REQUIRED_FIELDS",
]

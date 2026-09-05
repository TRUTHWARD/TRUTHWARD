# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any, Callable, Mapping
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from agentic_qa.agents.base import AgentResult
from agentic_qa.domain.enums import ApprovalStatus, GuardrailDecisionType
from agentic_qa.domain.models import (
    Approval,
    AuditLog,
    CapabilityBinding,
    Execution,
    GuardrailEvent,
    GuardrailPolicy,
    Skill,
    SkillConnectorBinding,
    SkillInvocation,
    SkillInvocationEvent,
    SkillVersion,
    TestPlan,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.artifact_storage import (
    ArtifactStorageAdapter,
    artifact_storage_adapter,
)
from agentic_qa.infra.credentials import CredentialResolver
from agentic_qa.infra.redaction import redact_sensitive_data, redact_sensitive_text
from agentic_qa.infra.safe_projection import ConnectorBindingSafeProjectionBuilder
from agentic_qa.infra.trace import ensure_trace, traced_operation
from agentic_qa.runtime.qa_harness import (
    EvaluationFrozenReference,
    EvaluationTargetReference,
    MeasurementClass,
    QaEvaluationRunner,
    SKILL_EVALUATION_METRICS,
    SkillEvaluationObservation,
    SkillVersionEvaluationInput,
    build_evaluation_scope_snapshot,
)
from agentic_qa.runtime.qa_harness.context_builder import (
    canonical_content_hash,
    contains_unsafe_snapshot_material,
    project_safe_context_content,
)
from agentic_qa.runtime.qa_harness.contracts import BudgetSnapshot
from agentic_qa.runtime.qa_harness.stop_reasons import HarnessRunState
from agentic_qa.runtime.qa_harness.trajectory_events import TrajectoryRecorder
from agentic_qa.schemas.skills import (
    CapabilityBindingRequest,
    CapabilityBindingUpdateRequest,
    CommunityBindingLifecycleRequest,
    ConnectorBindingRequest,
    ConnectorBindingUpdateRequest,
    SkillInvocationRequest,
)
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.services.common import (
    IdempotencyConflictError,
    ServiceContext,
    acquire_transaction_advisory_lock,
    paginate_query,
    paginate_result,
)
from agentic_qa.services.approval_service import ApprovalService
from agentic_qa.services.community_skill_policy import (
    COMMUNITY_ENABLEMENT_POLICY,
    COMMUNITY_REGRESSION_ADAPTER,
    COMMUNITY_REGRESSION_EXTENSION,
    presentation_conformance,
    validate_community_presentation_manifest,
)
from agentic_qa.services.authorized_skill_context import (
    AuthorizedSkillContextBuilder,
    SkillContextUnavailableError,
)
from agentic_qa.services.scope_service import (
    ScopeAuthorizationError,
    ScopeAuthorizationService,
)
from agentic_qa.services.skill_activation_governance import (
    SkillActivationValidationReport,
    SkillShadowComparisonReport,
    SkillVersionActivationValidator,
    manifest_snapshot_hash,
)
from agentic_qa.services.extension_point_contracts import (
    EXTENSION_POINT_CONTRACTS,
)
from agentic_qa.services.skill_runtime import (
    ManagedSkillRuntimeRegistry,
    SkillRuntimeContext,
    build_managed_skill_runtime_registry,
)
from agentic_qa.services.skill_execution_policy import (
    CancellationProbe,
    SkillInvocationExecutionError,
    SkillInvocationExecutionPolicy,
    SkillInvocationReasonCode,
    SkillInvocationReliabilityRuntime,
    STABLE_INVOCATION_STATUSES,
    get_skill_invocation_reliability_runtime,
)
from agentic_qa.tools.runner_protocols import RunnerExecutionResult
from agentic_qa.skills.integrations import (
    IntegrationEvidenceRef,
    IntegrationSkillInput,
    IntegrationSkillRegistry,
    IntegrationSkillResult,
    build_integration_skill_registry,
)


# Compatibility exports. The code authority is ExtensionPointContractRegistry.
DEFAULT_EXTENSION_POINT_BINDINGS: dict[str, str] = EXTENSION_POINT_CONTRACTS.default_bindings()
WORKFLOW_EXTENSION_POINTS: tuple[dict[str, object], ...] = EXTENSION_POINT_CONTRACTS.workflow_nodes()

BINDING_STATUSES = {"draft", "active", "disabled", "deprecated", "archived"}
BINDING_SCOPE_TYPES = {"global", "workspace", "project", "environment", "stage", "domain"}
BINDING_SCOPE_SPECIFICITY = {
    "environment": 60,
    "project": 50,
    "workspace": 40,
    "stage": 30,
    "domain": 20,
    "global": 10,
}

# The existing database check constraint predates the reliability result
# vocabulary. Keep its storage values migration-free while exposing the
# authoritative effective status through the output/event/API projection.
INVOCATION_STORAGE_STATUS = {
    "degraded": "completed",
    "unavailable": "failed",
    "timed_out": "failed",
}


def _skill_result_output_schema() -> dict[str, str]:
    return {
        "result": "dict",
        "confidence": "float",
        "evidence": "list",
        "artifactRefs": "list",
        "rawFindingRefs": "list",
        "findingCandidates": "list",
        "metadata": "dict",
    }


def _core_manifest(
    *,
    skill_id: str,
    display_name: str,
    extension_points: list[str],
    operations: list[str],
    risk_level: str = "low",
    allowed_tools: list[str] | None = None,
    allowed_connectors: list[str] | None = None,
) -> dict[str, object]:
    return {
        "skillId": skill_id,
        "displayName": display_name,
        "version": "1.0.0",
        "capabilities": {"category": "core", "operations": operations},
        "inputSchema": {"request": "dict", "contextRefs": "list", "constraints": "dict"},
        "outputSchema": _skill_result_output_schema(),
        "allowedTools": allowed_tools or [],
        "allowedConnectors": allowed_connectors or [],
        "riskProfile": {"level": risk_level},
        "approvalPolicy": {"required": risk_level == "high"},
        "dataAccessPolicy": {"writeDb": False, "writeMemory": False, "writeGate": False},
        "replayPolicy": {"freezeManifest": True, "freezeInputOutput": True, "freezeResolution": True},
        "extensionPoints": extension_points,
        "compatibility": {"input": "skill-request.v1", "output": "skill-result.v1"},
    }


BUILTIN_SKILL_MANIFESTS: dict[str, dict[str, object]] = {
    "integration-intake": {
        "skillId": "integration-intake",
        "displayName": "Integration Intake",
        "version": "1.0.0",
        "capabilities": {"category": "integration", "operations": ["normalize_pr_trigger", "normalize_requirement_document"]},
        "inputSchema": {"operation": "str", "payload": "dict", "metadata": "dict"},
        "outputSchema": _skill_result_output_schema(),
        "allowedTools": [],
        "allowedConnectors": [
            "git",
            "github",
            "mock-scm",
            "mock-requirement-docs",
            "lark-requirement-docs",
            "zentao-requirement-docs",
            "mcp",
            "enterprise-api",
        ],
        "riskProfile": {"level": "low"},
        "approvalPolicy": {"required": False},
        "dataAccessPolicy": {"writeDb": False, "writeMemory": False, "writeGate": False},
        "replayPolicy": {"freezeManifest": True, "freezeInputOutput": True},
        "extensionPoints": [],
        "compatibility": {"input": "integration-skill-input.v1", "output": "skill-result.v1"},
    },
    "scm-pr-workflow": {
        "skillId": "scm-pr-workflow",
        "displayName": "SCM PR Workflow",
        "version": "1.0.0",
        "capabilities": {"category": "integration", "operations": ["build_pr_context"]},
        "inputSchema": {"operation": "str", "payload": "dict", "metadata": "dict"},
        "outputSchema": _skill_result_output_schema(),
        "allowedTools": [],
        "allowedConnectors": ["git", "github", "mock-scm", "mcp", "enterprise-api"],
        "riskProfile": {"level": "low"},
        "approvalPolicy": {"required": False},
        "dataAccessPolicy": {"writeDb": False, "writeMemory": False, "writeGate": False},
        "replayPolicy": {"freezeManifest": True, "freezeInputOutput": True},
        "extensionPoints": [],
        "compatibility": {"input": "integration-skill-input.v1", "output": "skill-result.v1"},
    },
    "ci-gate": {
        "skillId": "ci-gate",
        "displayName": "CI Evidence Adapter",
        "version": "2.0.0",
        "capabilities": {"category": "integration", "operations": ["build_ci_evidence"]},
        "inputSchema": {"operation": "str", "payload": "dict", "metadata": "dict"},
        "outputSchema": _skill_result_output_schema(),
        "allowedTools": [],
        "allowedConnectors": ["ci", "github", "mock-scm", "mcp", "enterprise-api"],
        "riskProfile": {"level": "low", "gateWrite": False, "ciDecision": False},
        "approvalPolicy": {"required": False},
        "dataAccessPolicy": {"writeDb": False, "writeMemory": False, "writeGate": False},
        "replayPolicy": {
            "freezeManifest": True,
            "freezeInputOutput": True,
            "legacyVersion": "1.0.0",
            "legacyDecisionFields": ["shouldMerge", "exitCode"],
            "legacyDecisionFieldsAuthoritative": False,
        },
        "extensionPoints": [],
        "compatibility": {
            "input": "integration-skill-input.v1",
            "output": "skill-result.v1",
            "decisionOwner": "domain-service",
        },
    },
    "test-plan-generation": _core_manifest(
        skill_id="test-plan-generation",
        display_name="Test Plan Generation",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("test-plan-generation"),
        operations=["generate_test_plan"],
    ),
    "test-case-generation": _core_manifest(
        skill_id="test-case-generation",
        display_name="Test Case Generation",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("test-case-generation"),
        operations=["generate_test_cases"],
    ),
    "exploratory-charter-generation": _core_manifest(
        skill_id="exploratory-charter-generation",
        display_name="Exploratory Charter Generation",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("exploratory-charter-generation"),
        operations=["recommend_exploratory_charter"],
    ),
    "regression-scope-recommendation": _core_manifest(
        skill_id="regression-scope-recommendation",
        display_name="Regression Scope Recommendation",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("regression-scope-recommendation"),
        operations=["recommend_regression_scope"],
    ),
    "execution-runner": _core_manifest(
        skill_id="execution-runner",
        display_name="Execution Runner",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("execution-runner"),
        operations=["execute_task"],
        risk_level="medium",
        allowed_tools=["playwright", "k6", "zap", "semgrep", "nuclei", "sandbox-semgrep", "sandbox-python-unittest"],
    ),
    "manual-test-simulation": _core_manifest(
        skill_id="manual-test-simulation",
        display_name="Manual Test Simulation",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("manual-test-simulation"),
        operations=["propose_semantic_actions"],
    ),
    "exploratory-assist": _core_manifest(
        skill_id="exploratory-assist",
        display_name="Exploratory Assist",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("exploratory-assist"),
        operations=["suggest_exploratory_next_steps"],
    ),
    "finding-triage": _core_manifest(
        skill_id="finding-triage",
        display_name="Finding Triage",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("finding-triage"),
        operations=["triage_findings"],
    ),
    "performance-analysis": _core_manifest(
        skill_id="performance-analysis",
        display_name="Performance Analysis",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("performance-analysis"),
        operations=["analyze_performance"],
    ),
    "security-analysis": _core_manifest(
        skill_id="security-analysis",
        display_name="Security Analysis",
        extension_points=EXTENSION_POINT_CONTRACTS.extension_points_for_default_skill("security-analysis"),
        operations=["analyze_security"],
    ),
}


BUILTIN_SKILL_RUNTIME_CONTRACTS: dict[str, dict[str, str]] = {
    "integration-intake": {"runtimeAdapter": "integration.registry.v1", "runtimeResultKind": "integration_result"},
    "scm-pr-workflow": {"runtimeAdapter": "integration.registry.v1", "runtimeResultKind": "integration_result"},
    "ci-gate": {"runtimeAdapter": "integration.registry.v1", "runtimeResultKind": "integration_result"},
    **EXTENSION_POINT_CONTRACTS.default_runtime_contracts_by_skill(),
}


@dataclass(frozen=True, slots=True)
class ExtensionInvocationCompletion:
    output_snapshot: dict[str, object]
    artifact_refs: list[dict[str, object]] = field(default_factory=list)
    tool_call_refs: list[dict[str, object]] = field(default_factory=list)
    connector_call_refs: list[dict[str, object]] = field(default_factory=list)
    status: str = "completed"
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class ExtensionInvocationResult:
    runtime_result: object
    invocation_id: UUID
    status: str
    invocation_projection: dict[str, object]
    deduplicated: bool = False


class SkillService:
    def __init__(
        self,
        db: Session,
        skill_registry: IntegrationSkillRegistry | None = None,
        credential_resolver: CredentialResolver | None = None,
        connector_snapshot_builder: ConnectorBindingSafeProjectionBuilder | None = None,
        runtime_registry: ManagedSkillRuntimeRegistry | None = None,
        authorized_context_builder: AuthorizedSkillContextBuilder | None = None,
        reliability_runtime: SkillInvocationReliabilityRuntime | None = None,
        artifact_storage: ArtifactStorageAdapter | None = None,
    ) -> None:
        self.db = db
        self.skill_registry = skill_registry or build_integration_skill_registry()
        self.credential_resolver = credential_resolver or CredentialResolver()
        self.connector_snapshot_builder = connector_snapshot_builder or ConnectorBindingSafeProjectionBuilder()
        self.runtime_registry = runtime_registry or build_managed_skill_runtime_registry()
        self.authorized_context_builder = authorized_context_builder or AuthorizedSkillContextBuilder(
            db,
            connector_snapshot_builder=self.connector_snapshot_builder,
        )
        self.extension_point_contracts = EXTENSION_POINT_CONTRACTS
        self.reliability_runtime = (
            reliability_runtime or get_skill_invocation_reliability_runtime()
        )
        self.artifact_storage = artifact_storage or artifact_storage_adapter()
        self.activation_validator = SkillVersionActivationValidator(
            runtime_registry=self.runtime_registry,
            extension_point_contracts=self.extension_point_contracts,
        )
        self._extension_failures_pending_reconciliation: dict[
            UUID, tuple[str, str, str]
        ] = {}
        self._active_execution_policies: dict[UUID, SkillInvocationExecutionPolicy] = {}
        self._execution_outcomes: dict[UUID, dict[str, object]] = {}

    def list_skills(self, page: int, page_size: int) -> dict[str, object]:
        self.ensure_builtin_skills()
        statement = select(Skill).order_by(Skill.skill_id.asc())
        rows, total = paginate_query(self.db, statement, page, page_size)
        latest_versions = {skill.id: self._latest_version(skill.id) for skill in rows}
        items = [
            self.serialize_skill(skill, latest_versions.get(skill.id))
            for skill in rows
        ]
        return paginate_result(items, total, page, page_size)

    def get_skill(self, skill_id: str) -> dict[str, object]:
        self.ensure_builtin_skills()
        skill = self._require_skill(skill_id)
        return self.serialize_skill(skill, self._latest_version(skill.id))

    def register_trusted_local_manifest(
        self,
        manifest: dict[str, object],
        *,
        source_name: str,
        context: ServiceContext,
    ) -> dict[str, object]:
        """Register a data-only Community manifest for an existing managed adapter.

        This boundary deliberately does not load Python, JavaScript, binaries, or
        remote URLs. A manifest can select only a runtime adapter already compiled
        into the Service and allowed by an existing Extension Point contract.
        """
        self._require_governance_capability(context, "community_skills.manage")
        compatibility_value = manifest.get("compatibility")
        if isinstance(compatibility_value, dict) and compatibility_value.get("runtimeAdapter") == COMMUNITY_REGRESSION_ADAPTER:
            validate_community_presentation_manifest(manifest)
        required = {
            "skillId", "displayName", "version", "capabilities", "inputSchema",
            "outputSchema", "allowedTools", "allowedConnectors", "riskProfile",
            "approvalPolicy", "dataAccessPolicy", "replayPolicy", "extensionPoints",
            "compatibility",
        }
        if required - set(manifest):
            raise ValueError("COMMUNITY_SKILL_MANIFEST_INCOMPLETE")
        skill_id = str(manifest.get("skillId") or "")
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,127}", skill_id) is None:
            raise ValueError("COMMUNITY_SKILL_ID_INVALID")
        if manifest.get("allowedTools") != [] or manifest.get("allowedConnectors") != []:
            raise ValueError("COMMUNITY_SKILL_EXTERNAL_CAPABILITIES_FORBIDDEN")
        risk_profile = manifest.get("riskProfile")
        if not isinstance(risk_profile, dict) or str(risk_profile.get("level") or "").lower() != "low":
            raise ValueError("COMMUNITY_SKILL_LOW_RISK_REQUIRED")
        approval_policy = manifest.get("approvalPolicy")
        if not isinstance(approval_policy, dict) or bool(approval_policy.get("required")):
            raise ValueError("COMMUNITY_SKILL_MANIFEST_APPROVAL_POLICY_INVALID")
        data_policy = manifest.get("dataAccessPolicy")
        if not isinstance(data_policy, dict) or any(
            bool(data_policy.get(key))
            for key in ("writeDb", "writeMemory", "writeGate", "externalWrite")
        ):
            raise ValueError("COMMUNITY_SKILL_READ_ONLY_DATA_POLICY_REQUIRED")
        extension_points = manifest.get("extensionPoints")
        compatibility = manifest.get("compatibility")
        input_schema = manifest.get("inputSchema")
        output_schema = manifest.get("outputSchema")
        if not isinstance(extension_points, list) or not extension_points:
            raise ValueError("COMMUNITY_SKILL_EXTENSION_POINT_REQUIRED")
        if not isinstance(compatibility, dict):
            raise ValueError("COMMUNITY_SKILL_COMPATIBILITY_INVALID")
        adapter_id = str(compatibility.get("runtimeAdapter") or "")
        result_kind = str(compatibility.get("runtimeResultKind") or "")
        for extension_point in extension_points:
            extension_point_id = str(extension_point)
            self.extension_point_contracts.validate_version_contract(
                extension_point_id,
                input_schema=input_schema,
                output_schema=output_schema,
                compatibility=compatibility,
            )
            self.runtime_registry.validate(
                adapter_id=adapter_id,
                result_kind=result_kind,
                extension_point_id=extension_point_id,
            )
        snapshot = self._manifest_snapshot(manifest)
        manifest_hash = self._manifest_hash(snapshot)
        version_name = str(manifest.get("version") or "")
        if not version_name or len(version_name) > 64:
            raise ValueError("COMMUNITY_SKILL_VERSION_INVALID")
        skill = self.db.scalar(select(Skill).where(Skill.skill_id == skill_id))
        if skill is None:
            skill = Skill(
                id=uuid4(),
                skill_id=skill_id,
                display_name=str(manifest.get("displayName") or skill_id)[:255],
                status="active",
            )
            self.db.add(skill)
            self.db.flush()
        conflicting = self.db.scalar(
            select(SkillVersion).where(
                SkillVersion.skill_ref_id == skill.id,
                SkillVersion.version == version_name,
            )
        )
        if conflicting is not None:
            if conflicting.manifest_hash != manifest_hash:
                raise ValueError("COMMUNITY_SKILL_VERSION_IMMUTABLE_CONFLICT")
            return {
                **self.serialize_skill(skill, conflicting),
                "skillVersionId": str(conflicting.id),
                "deduplicated": True,
            }
        version = SkillVersion(
            id=uuid4(),
            skill_ref_id=skill.id,
            version=version_name,
            manifest_hash=manifest_hash,
            manifest_snapshot=snapshot,
            capabilities=dict(manifest["capabilities"]),
            input_schema=dict(manifest["inputSchema"]),
            output_schema=dict(manifest["outputSchema"]),
            allowed_tools=[],
            allowed_connectors=[],
            risk_profile=dict(risk_profile),
            approval_policy=dict(approval_policy),
            data_access_policy=dict(data_policy),
            replay_policy=dict(manifest["replayPolicy"]),
            extension_points=[str(item) for item in extension_points],
            compatibility=dict(compatibility),
            governance_status="active",
        )
        self.db.add(version)
        self.db.flush()
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            "community_skill.manifest.register",
            "skill_version",
            str(version.id),
            context.request_id,
            context.trace_id,
            details={
                "skillId": skill_id,
                "version": version_name,
                "manifestHash": manifest_hash,
                "sourceName": source_name,
                "runtimeAdapter": adapter_id,
                "extensionPoints": version.extension_points,
                "codeLoaded": False,
            },
        )
        self.db.commit()
        return {
            **self.serialize_skill(skill, version),
            "skillVersionId": str(version.id),
            "deduplicated": False,
            "auditRefs": [{"type": "audit_log", "id": str(audit.id)}],
        }

    def create_manifest_proposal(
        self,
        *,
        base_skill_version_id: UUID,
        expected_manifest_hash: str,
        manifest: dict[str, object],
        context: ServiceContext,
    ) -> dict[str, object]:
        """Create an immutable, non-invocable Skill Version proposal.

        Activation remains owned by the existing Skill/Capability Binding
        governance flow. This method never changes the active Skill or a
        Capability Binding.
        """
        if "custom_skills.manage" not in set(context.user.capabilities):
            raise ValueError("custom_skills.manage capability required")
        base = self.db.get(SkillVersion, base_skill_version_id)
        if base is None or base.manifest_hash != expected_manifest_hash:
            raise ValueError("SKILL_PROPOSAL_BASE_VERSION_CHANGED")
        skill = self.db.get(Skill, base.skill_ref_id)
        if skill is None or skill.status in {"archived", "deprecated"}:
            raise ValueError("SKILL_PROPOSAL_TARGET_UNAVAILABLE")
        required = {
            "skillId",
            "version",
            "capabilities",
            "inputSchema",
            "outputSchema",
            "allowedTools",
            "allowedConnectors",
            "riskProfile",
            "approvalPolicy",
            "dataAccessPolicy",
            "replayPolicy",
        }
        if required - set(manifest):
            raise ValueError("SKILL_PROPOSAL_MANIFEST_INCOMPLETE")
        if str(manifest.get("skillId")) != skill.skill_id:
            raise ValueError("SKILL_PROPOSAL_SKILL_ID_CHANGED")
        snapshot = self._manifest_snapshot(manifest)
        mapping_fields: dict[str, dict[str, object]] = {}
        for field_name in (
            "capabilities",
            "inputSchema",
            "outputSchema",
            "riskProfile",
            "approvalPolicy",
            "dataAccessPolicy",
            "replayPolicy",
            "compatibility",
        ):
            value = snapshot.get(field_name)
            if not isinstance(value, dict):
                raise ValueError(f"SKILL_PROPOSAL_MANIFEST_{field_name.upper()}_INVALID")
            mapping_fields[field_name] = value
        list_fields: dict[str, list[object]] = {}
        for field_name in ("allowedTools", "allowedConnectors", "extensionPoints"):
            value = snapshot.get(field_name)
            if not isinstance(value, list):
                raise ValueError(f"SKILL_PROPOSAL_MANIFEST_{field_name.upper()}_INVALID")
            list_fields[field_name] = value
        base_scope = dict(base.manifest_snapshot.get("dataAccessPolicy") or {}).get("scope")
        proposed_scope = mapping_fields["dataAccessPolicy"].get("scope")
        if not isinstance(base_scope, dict) or proposed_scope != base_scope:
            raise ValueError("SKILL_PROPOSAL_SCOPE_CHANGE_FORBIDDEN")
        manifest_hash = self._manifest_hash(snapshot)
        proposed_version = str(snapshot["version"])
        existing = self.db.scalar(
            select(SkillVersion).where(
                SkillVersion.skill_ref_id == skill.id,
                SkillVersion.version == proposed_version,
                SkillVersion.governance_status == "draft",
            )
        )
        if existing is not None:
            if existing.manifest_hash != manifest_hash:
                raise ValueError("SKILL_PROPOSAL_VERSION_CONFLICT")
            return {
                **self.serialize_skill(skill, existing),
                "skillVersionId": str(existing.id),
                "governanceStatus": "draft",
                "activatesSkill": False,
                "deduplicated": True,
            }
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="skill.manifest-proposal",
            trace_id=context.trace_id,
        )
        proposed = SkillVersion(
            id=uuid4(),
            skill_ref_id=skill.id,
            version=proposed_version,
            manifest_hash=manifest_hash,
            manifest_snapshot=snapshot,
            capabilities=mapping_fields["capabilities"],
            input_schema=mapping_fields["inputSchema"],
            output_schema=mapping_fields["outputSchema"],
            allowed_tools=[str(item) for item in list_fields["allowedTools"]],
            allowed_connectors=[str(item) for item in list_fields["allowedConnectors"]],
            risk_profile=mapping_fields["riskProfile"],
            approval_policy=mapping_fields["approvalPolicy"],
            data_access_policy=mapping_fields["dataAccessPolicy"],
            replay_policy=mapping_fields["replayPolicy"],
            extension_points=[str(item) for item in list_fields["extensionPoints"]],
            compatibility=mapping_fields["compatibility"],
            governance_status="draft",
        )
        self.db.add(proposed)
        self.db.flush()
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            "skill.manifest_proposal.create",
            "skill_version",
            str(proposed.id),
            context.request_id,
            context.trace_id,
            details={
                "skillId": skill.skill_id,
                "baseSkillVersionId": str(base.id),
                "baseManifestHash": base.manifest_hash,
                "proposedManifestHash": manifest_hash,
                "governanceStatus": "draft",
                "activatesSkill": False,
            },
        )
        self.db.commit()
        return {
            **self.serialize_skill(skill, proposed),
            "skillVersionId": str(proposed.id),
            "governanceStatus": "draft",
            "activatesSkill": False,
            "auditRefs": [{"type": "audit", "id": str(audit.id)}],
            "deduplicated": False,
        }

    def validate_skill_version_activation(
        self,
        *,
        binding_id: UUID,
        context: ServiceContext,
        scope: dict[str, object] | None = None,
        context_sources: Mapping[str, object] | None = None,
        commit: bool = True,
    ) -> dict[str, object]:
        """Validate and persist auditable activation evidence for one draft Binding."""

        binding = self._require_capability_binding(binding_id)
        version = self._require_bound_skill_version(binding)
        report = self._build_activation_validation_report(
            binding=binding,
            version=version,
            context=context,
            scope=scope or {},
            context_sources=context_sources,
        )
        report_projection = self._persist_binding_governance_report(
            binding=binding,
            version=version,
            report_kind="contractValidation",
            report=report.model_dump(mode="json"),
            context=context,
            status="passed" if report.passed else "failed",
        )
        if commit:
            self.db.commit()
            self.db.refresh(binding)
        return report_projection

    def record_skill_version_evaluation(
        self,
        *,
        binding_id: UUID,
        evaluation_input: SkillVersionEvaluationInput | dict[str, object],
        baseline_observations: Sequence[
            SkillEvaluationObservation | dict[str, object]
        ],
        candidate_observations: Sequence[
            SkillEvaluationObservation | dict[str, object]
        ],
        context: ServiceContext,
        commit: bool = True,
    ) -> dict[str, object]:
        """Persist a Harness comparison already measured through managed invocations."""

        self._require_governance_capability(context, "capability_bindings.write")
        binding = self._require_capability_binding(binding_id)
        version = self._require_bound_skill_version(binding)
        spec = (
            evaluation_input
            if isinstance(evaluation_input, SkillVersionEvaluationInput)
            else SkillVersionEvaluationInput.model_validate(evaluation_input)
        )
        if spec.extensionPointId != binding.extension_point_id:
            raise ValueError("SKILL_EVALUATION_EXTENSION_POINT_CHANGED")
        if str(spec.candidateRef.ref).removeprefix("skill-version://") != str(version.id):
            raise ValueError("SKILL_EVALUATION_CANDIDATE_VERSION_CHANGED")
        if spec.candidateRef.contentHash != version.manifest_hash:
            raise ValueError("SKILL_EVALUATION_CANDIDATE_MANIFEST_CHANGED")
        result = QaEvaluationRunner().compare_skill_versions(
            spec,
            baseline_observations=baseline_observations,
            candidate_observations=candidate_observations,
        )
        projection = self._persist_binding_governance_report(
            binding=binding,
            version=version,
            report_kind="datasetEvaluation",
            report=result.model_dump(mode="json"),
            context=context,
            status=result.status,
        )
        if commit:
            self.db.commit()
            self.db.refresh(binding)
        return projection

    def run_skill_version_evaluation(
        self,
        *,
        binding_id: UUID,
        dataset_id: str,
        dataset_version: str,
        cases: list[dict[str, object]],
        context: ServiceContext,
        scope: dict[str, object] | None = None,
        capabilities_by_case: Mapping[str, Mapping[str, object]] | None = None,
        context_sources_by_case: Mapping[str, Mapping[str, object]] | None = None,
        approval_refs: list[dict[str, object]] | None = None,
        measurement_class: MeasurementClass = "loopback_contract",
    ) -> dict[str, object]:
        """Execute baseline and candidate exact versions against one frozen dataset."""

        self._require_governance_capability(context, "capability_bindings.write")
        if not cases:
            raise ValueError("EVALUATION_DATASET_EMPTY")
        binding = self._require_capability_binding(binding_id)
        candidate = self._require_bound_skill_version(binding)
        effective_scope = self._authorize_binding_scope(binding, context, scope or {})
        baseline_resolution = self.resolve_binding(
            binding.extension_point_id,
            scope=effective_scope,
        )
        baseline = self.db.get(
            SkillVersion,
            UUID(str(baseline_resolution["skillVersionId"])),
        )
        if baseline is None:
            raise ValueError("SKILL_EVALUATION_BASELINE_UNAVAILABLE")
        scope_snapshot = build_evaluation_scope_snapshot(
            tenant_id=str(effective_scope.get("tenantId") or "local-tenant"),
            workspace_id=str(effective_scope.get("workspaceId") or "local-workspace"),
            project_id=str(effective_scope.get("projectId") or "platform-scope"),
            environment_id=(
                str(effective_scope["environmentId"])
                if effective_scope.get("environmentId")
                else None
            ),
        )
        frozen_input_refs = [
            self._evaluation_dataset_reference(case, scope_snapshot.scopeHash)
            for case in cases
        ]
        evaluation_id = uuid4()
        spec = SkillVersionEvaluationInput(
            evaluationId=str(evaluation_id),
            extensionPointId=binding.extension_point_id,
            datasetId=dataset_id,
            datasetVersion=dataset_version,
            baselineRef=self._evaluation_target_reference(
                baseline,
                scope_snapshot.scopeHash,
            ),
            candidateRef=self._evaluation_target_reference(
                candidate,
                scope_snapshot.scopeHash,
            ),
            frozenInputRefs=frozen_input_refs,
            scopeSnapshot=scope_snapshot,
            measurementClass=measurement_class,
            metricDefinitions=list(
                SKILL_EVALUATION_METRICS.for_extension(binding.extension_point_id)
            ),
        )
        baseline_observations: list[SkillEvaluationObservation] = []
        candidate_observations: list[SkillEvaluationObservation] = []
        seen_case_ids: set[str] = set()
        for index, case in enumerate(cases):
            case_id = str(case.get("caseId") or "").strip()
            if not case_id or case_id in seen_case_ids:
                raise ValueError("EVALUATION_CASE_ID_DUPLICATE")
            seen_case_ids.add(case_id)
            request = case.get("request")
            if not isinstance(request, dict):
                raise ValueError("SKILL_EVALUATION_CASE_REQUEST_INVALID")
            capabilities = dict((capabilities_by_case or {}).get(case_id) or {})
            sources = dict((context_sources_by_case or {}).get(case_id) or {})
            baseline_observations.append(
                self._invoke_skill_evaluation_case(
                    evaluation_id=evaluation_id,
                    case_id=case_id,
                    request=request,
                    version=baseline,
                    binding_id=(
                        UUID(str(baseline_resolution["bindingId"]))
                        if baseline_resolution.get("bindingId")
                        else None
                    ),
                    mode="evaluation_baseline",
                    extension_point_id=binding.extension_point_id,
                    context=context,
                    scope=effective_scope,
                    capabilities=capabilities,
                    context_sources=sources,
                    approval_refs=approval_refs or [],
                    frozen_input_ref=frozen_input_refs[index],
                )
            )
            candidate_observations.append(
                self._invoke_skill_evaluation_case(
                    evaluation_id=evaluation_id,
                    case_id=case_id,
                    request=request,
                    version=candidate,
                    binding_id=binding.id,
                    mode="evaluation_candidate",
                    extension_point_id=binding.extension_point_id,
                    context=context,
                    scope=effective_scope,
                    capabilities=capabilities,
                    context_sources=sources,
                    approval_refs=approval_refs or [],
                    frozen_input_ref=frozen_input_refs[index],
                )
            )
        return self.record_skill_version_evaluation(
            binding_id=binding.id,
            evaluation_input=spec,
            baseline_observations=baseline_observations,
            candidate_observations=candidate_observations,
            context=context,
        )

    def run_candidate_binding_shadow(
        self,
        *,
        binding_id: UUID,
        cases: list[dict[str, object]],
        context: ServiceContext,
        scope: dict[str, object] | None = None,
        authoritative_capabilities_by_case: Mapping[str, Mapping[str, object]] | None = None,
        shadow_capabilities_by_case: Mapping[str, Mapping[str, object]] | None = None,
        context_sources_by_case: Mapping[str, Mapping[str, object]] | None = None,
        approval_refs: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        """Run an internal, non-authoritative candidate shadow beside live resolution."""

        self._require_governance_capability(context, "capability_bindings.write")
        if not cases:
            raise ValueError("SKILL_SHADOW_DATASET_EMPTY")
        binding = self._require_capability_binding(binding_id)
        candidate = self._require_bound_skill_version(binding)
        effective_scope = self._authorize_binding_scope(binding, context, scope or {})
        baseline_resolution = self.resolve_binding(
            binding.extension_point_id,
            scope=effective_scope,
        )
        baseline = self.db.get(
            SkillVersion,
            UUID(str(baseline_resolution["skillVersionId"])),
        )
        if baseline is None:
            raise ValueError("SKILL_SHADOW_BASELINE_UNAVAILABLE")
        contract = self.extension_point_contracts.require_bindable(
            binding.extension_point_id
        )
        mutation_blocked = bool(
            contract.execution_constraints.get("mutation")
            or contract.execution_constraints.get("externalWrite")
            or candidate.data_access_policy.get("writeDb")
            or candidate.data_access_policy.get("writeMemory")
            or candidate.data_access_policy.get("writeGate")
            or candidate.risk_profile.get("mutation")
            or candidate.risk_profile.get("externalWrite")
        )
        official_projections: list[dict[str, object]] = []
        candidate_projections: list[dict[str, object]] = []
        failure_reasons: list[str] = []
        seen_case_ids: set[str] = set()
        for case in cases:
            case_id = str(case.get("caseId") or "").strip()
            request = case.get("request")
            if not case_id or case_id in seen_case_ids or not isinstance(request, dict):
                raise ValueError("SKILL_SHADOW_CASE_INVALID")
            seen_case_ids.add(case_id)
            sources = dict((context_sources_by_case or {}).get(case_id) or {})
            official = self.invoke_extension(
                extension_point_id=binding.extension_point_id,
                request=request,
                context=context,
                scope=effective_scope,
                source_workflow="skill-binding-shadow-authoritative",
                approval_refs=approval_refs or [],
                idempotency_key=f"skill-shadow:{binding.id}:official:{case_id}:{uuid4()}",
                capabilities=dict(
                    (authoritative_capabilities_by_case or {}).get(case_id) or {}
                ),
                execution_mode=next(iter(contract.allowed_execution_modes)),
                context_sources=sources,
                result_transformer=self._governance_output_snapshot,
                resolution_metadata={
                    "shadowPairBindingId": str(binding.id),
                    "shadowRole": "authoritative",
                    "nonAuthoritative": False,
                },
            )
            official_projections.append(official.invocation_projection)
            if mutation_blocked:
                failure_reasons.append("SKILL_SHADOW_MUTATION_FORBIDDEN")
                continue
            try:
                shadow = self.invoke_extension(
                    extension_point_id=binding.extension_point_id,
                    request=request,
                    context=context,
                    scope=effective_scope,
                    source_workflow="skill-binding-shadow-candidate",
                    approval_refs=approval_refs or [],
                    idempotency_key=f"skill-shadow:{binding.id}:candidate:{case_id}:{uuid4()}",
                    capabilities=dict(
                        (shadow_capabilities_by_case or {}).get(case_id) or {}
                    ),
                    execution_mode=next(iter(contract.allowed_execution_modes)),
                    context_sources=sources,
                    result_transformer=self._governance_output_snapshot,
                    result_validator=self._validate_shadow_runtime_result,
                    governance_skill_version_id=candidate.id,
                    governance_binding_id=binding.id,
                    governance_mode="shadow_candidate",
                    resolution_metadata={
                        "shadowPairBindingId": str(binding.id),
                        "shadowRole": "candidate",
                        "nonAuthoritative": True,
                    },
                )
            except Exception as exc:
                failure_reasons.append(
                    f"SKILL_SHADOW_CANDIDATE_FAILED:{redact_sensitive_text(str(exc))}"
                )
                continue
            candidate_projections.append(shadow.invocation_projection)

        policy = binding.binding_config.get("activationPolicy")
        policy = policy if isinstance(policy, dict) else {}
        minimum_samples = max(1, int(policy.get("shadowMinimumSamples") or 1))
        if len(candidate_projections) < minimum_samples:
            failure_reasons.append("SKILL_SHADOW_MINIMUM_SAMPLES_NOT_MET")
        status = (
            "blocked"
            if mutation_blocked
            else "failed"
            if failure_reasons
            else "completed"
        )
        report_payload: dict[str, Any] = {
            "schemaVersion": "phase8.skill-binding-shadow.v1",
            "shadowId": uuid4(),
            "bindingId": binding.id,
            "extensionPointId": binding.extension_point_id,
            "nonAuthoritative": True,
            "status": status,
            "activationEligible": status == "completed",
            "baselineSkillVersionId": baseline.id,
            "baselineManifestHash": baseline.manifest_hash,
            "candidateSkillVersionId": candidate.id,
            "candidateManifestHash": candidate.manifest_hash,
            "adapter": self._runtime_projection(candidate),
            "sampleCount": len(candidate_projections),
            "minimumRequiredSamples": minimum_samples,
            "authoritativeInvocationRefs": [
                f"skill-invocation://{item['id']}" for item in official_projections
            ],
            "candidateInvocationRefs": [
                f"skill-invocation://{item['id']}" for item in candidate_projections
            ],
            "evidenceRefs": [],
            "failureReasons": list(dict.fromkeys(failure_reasons)),
            "limitations": [
                "SHADOW_RESULT_NON_AUTHORITATIVE",
                "SHADOW_DOES_NOT_WRITE_GATE_MEMORY_OR_CANONICAL_FINDINGS",
            ],
            "scope": effective_scope,
            "evaluatedAt": datetime.now(timezone.utc),
        }
        draft_report = SkillShadowComparisonReport.model_construct(
            **report_payload,
            reportHash="sha256:" + "0" * 64,
        )
        report_payload["reportHash"] = canonical_content_hash(
            draft_report.model_dump(mode="json", exclude={"reportHash"})
        )
        report = SkillShadowComparisonReport.model_validate(report_payload)
        projection = self._persist_binding_governance_report(
            binding=binding,
            version=candidate,
            report_kind="shadowComparison",
            report=report.model_dump(mode="json"),
            context=context,
            status=report.status,
        )
        self.db.commit()
        return {
            "schemaVersion": "phase8.skill-shadow-execution.v1",
            "authoritativeResults": official_projections,
            "candidateResults": candidate_projections,
            "shadow": projection,
            "nonAuthoritative": True,
        }

    def request_binding_rollback(
        self,
        *,
        binding_id: UUID,
        stable_skill_version_id: UUID,
        reason_code: str,
        context: ServiceContext,
        scope: dict[str, object] | None = None,
        automatic: bool = False,
    ) -> dict[str, object]:
        """Request or apply a governed resolution rollback without rewriting history."""

        self._require_governance_capability(context, "capability_bindings.admin")
        binding = self._require_capability_binding(binding_id)
        self._ensure_no_pending_capability_binding_change(binding)
        current = self._binding_snapshot(binding)
        stable = self.db.get(SkillVersion, stable_skill_version_id)
        if stable is None or stable.governance_status != "active":
            raise ValueError("SKILL_ROLLBACK_STABLE_VERSION_UNAVAILABLE")
        self._validate_binding_compatibility(binding.extension_point_id, stable)
        effective_scope = self._authorize_binding_scope(binding, context, scope or {})
        self._ensure_skill_governance_kill_switch_clear(binding, automatic=automatic)
        proposed = self._binding_snapshot_from_fields(
            extension_point_id=binding.extension_point_id,
            skill_version_id=stable.id,
            scope_type=binding.scope_type,
            scope_id=binding.scope_id,
            project_id=binding.project_id,
            environment=binding.environment,
            stage=binding.stage,
            domain=binding.domain,
            status="active",
            priority=binding.priority,
            binding_config={
                **dict(binding.binding_config or {}),
                "rollbackSourceBindingId": str(binding.id),
                "rollbackReasonCode": reason_code,
            },
        )
        risk_level = str(stable.risk_profile.get("level") or "high").lower()
        if automatic:
            autonomy = binding.binding_config.get("controlledAutonomy")
            autonomy = autonomy if isinstance(autonomy, dict) else {}
            if risk_level != "low" or not bool(autonomy.get("enabled")):
                return self.suggest_binding_rollback(
                    binding_id=binding.id,
                    stable_skill_version_id=stable.id,
                    reason_code=reason_code,
                    context=context,
                    scope=effective_scope,
                )
        risk = {
            "highRisk": risk_level in {"medium", "high"} or not automatic,
            "requiresApproval": risk_level in {"medium", "high"} or not automatic,
            "riskLevel": risk_level,
            "reasons": ["binding_rollback", reason_code],
        }
        if risk["requiresApproval"]:
            result = self._request_capability_binding_lifecycle_approval(
                binding=binding,
                operation="rollback",
                proposed=proposed,
                current=current,
                risk=risk,
                context=context,
            )
            binding.pending_change = {
                **dict(binding.pending_change or {}),
                "expectedBindingStateHash": self._binding_state_hash(binding),
                "scope": effective_scope,
                "reasonCode": reason_code,
                "automatic": automatic,
            }
            self.db.commit()
            return {
                **self.serialize_capability_binding(binding),
                "approvalRequired": True,
                "approvalEnvelope": result["approvalEnvelope"],
            }
        replacement = self._apply_binding_rollback(
            binding=binding,
            proposed=proposed,
            context=context,
            approval_id=None,
            reason_code=reason_code,
            automatic=True,
        )
        self.db.commit()
        return replacement

    def suggest_binding_rollback(
        self,
        *,
        binding_id: UUID,
        stable_skill_version_id: UUID,
        reason_code: str,
        context: ServiceContext,
        scope: dict[str, object] | None = None,
    ) -> dict[str, object]:
        binding = self._require_capability_binding(binding_id)
        stable = self.db.get(SkillVersion, stable_skill_version_id)
        if stable is None:
            raise ValueError("SKILL_ROLLBACK_STABLE_VERSION_UNAVAILABLE")
        projection = {
            "schemaVersion": "phase8.skill-binding-rollback-suggestion.v1",
            "bindingId": str(binding.id),
            "currentSkillVersionId": str(binding.skill_version_id),
            "stableSkillVersionId": str(stable.id),
            "stableManifestHash": stable.manifest_hash,
            "reasonCode": reason_code,
            "scope": scope or {},
            "automaticExecution": False,
            "productionApplied": False,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        persisted = self._persist_binding_governance_report(
            binding=binding,
            version=stable,
            report_kind="rollbackSuggestion",
            report=projection,
            context=context,
            status="suggested",
        )
        self.db.commit()
        return persisted

    def workflow_capability_graph(
        self,
        scope: dict[str, object] | None = None,
        *,
        edition: str | None = None,
    ) -> dict[str, object]:
        self.ensure_builtin_skills()
        nodes: list[dict[str, object]] = []
        for node in WORKFLOW_EXTENSION_POINTS:
            extension_point_id = str(node["extensionPointId"])
            bindable = bool(node["bindable"])
            current_binding_summary = None
            if bindable:
                resolved = self.resolve_binding(extension_point_id, scope=scope or {})
                current_binding_summary = {
                    "skillId": resolved["skillId"],
                    "skillVersionId": resolved["skillVersionId"],
                    "version": resolved["version"],
                    "manifestHash": resolved["manifestHash"],
                    "runtimeAdapter": resolved["runtimeAdapter"],
                    "runtimeResultKind": resolved["runtimeResultKind"],
                    "runtimeAvailable": True,
                    "bindingId": resolved["bindingId"],
                    "source": resolved["source"],
                    "fallbackReason": resolved["fallbackReason"],
                }
            nodes.append(
                {
                    "lifecycleStage": node["lifecycleStage"],
                    "extensionPointId": extension_point_id,
                    "label": node["label"],
                    "bindable": bindable,
                    "currentBindingSummary": current_binding_summary,
                    "requiredCapability": node.get("requiredCapability"),
                    "requiredEdition": (
                        "community" if bindable and edition == "community"
                        else "enterprise" if bindable
                        else None
                    ),
                    "unavailableReason": node.get("unavailableReason"),
                }
            )
        return {"schemaVersion": "phase8.workflow-capability-graph.v1", "nodes": nodes, "scope": scope or {}}

    def list_capability_bindings(
        self,
        page: int,
        page_size: int,
        *,
        extension_point_id: str | None = None,
        status: str | None = None,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        statement = select(CapabilityBinding).order_by(CapabilityBinding.created_at.desc())
        if context is not None and context.user.edition == "community":
            project_ids = {
                str(item) for item in ScopeAuthorizationService(self.db).authorized_project_ids(context)
            }
            statement = statement.where(CapabilityBinding.project_id.in_(project_ids))
        if extension_point_id:
            statement = statement.where(CapabilityBinding.extension_point_id == extension_point_id)
        if status:
            statement = statement.where(CapabilityBinding.status == status)
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result([self.serialize_capability_binding(row) for row in rows], total, page, page_size)

    def create_capability_binding(
        self,
        payload: CapabilityBindingRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self.ensure_builtin_skills()
        self._authorize_community_binding_payload(payload, context)
        if context.user.edition == "community" and payload.status != "draft":
            raise ValueError("COMMUNITY_SKILL_CREATE_DRAFT_REQUIRED")
        self._validate_binding_status(payload.status)
        self._validate_scope_type(payload.scopeType)
        self._validate_user_binding_config(payload.bindingConfig)
        version = self._require_skill_version(payload.skillId, payload.version, payload.manifestHash)
        self._validate_binding_compatibility(payload.extensionPointId, version)
        effective_status = "draft" if payload.status == "active" else payload.status
        binding = CapabilityBinding(
            id=uuid4(),
            extension_point_id=payload.extensionPointId,
            skill_version_id=version.id,
            scope_type=payload.scopeType,
            scope_id=payload.scopeId,
            project_id=payload.projectId,
            environment=payload.environment,
            stage=payload.stage,
            domain=payload.domain,
            status=effective_status,
            priority=payload.priority,
            binding_config=payload.bindingConfig,
            created_by=context.user.id,
            updated_by=context.user.id,
        )
        self.db.add(binding)
        self.db.flush()
        proposed = self._binding_snapshot_from_fields(
            extension_point_id=payload.extensionPointId,
            skill_version_id=version.id,
            scope_type=payload.scopeType,
            scope_id=payload.scopeId,
            project_id=payload.projectId,
            environment=payload.environment,
            stage=payload.stage,
            domain=payload.domain,
            status=payload.status,
            priority=payload.priority,
            binding_config=payload.bindingConfig,
        )
        risk = self._binding_change_risk(None, proposed, target_version=version)
        if risk["highRisk"]:
            approval_result = self._request_capability_binding_lifecycle_approval(
                binding=binding,
                operation="create",
                proposed=proposed,
                current=None,
                risk=risk,
                context=context,
            )
            self.db.commit()
            self.db.refresh(binding)
            return {
                **self.serialize_capability_binding(binding),
                "approvalRequired": True,
                "approvalEnvelope": approval_result["approvalEnvelope"],
            }

        self._record_capability_binding_lifecycle_refs(
            binding=binding,
            operation="create",
            proposed=proposed,
            current=None,
            risk=risk,
            decision=GuardrailDecisionType.ALLOW,
            context=context,
            audit_action="capability_binding.create",
        )
        self.db.commit()
        self.db.refresh(binding)
        return self.serialize_capability_binding(binding)

    def update_capability_binding(
        self,
        binding_id: UUID,
        payload: CapabilityBindingUpdateRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        binding = self.db.get(CapabilityBinding, binding_id)
        if binding is None:
            raise ValueError("capability binding not found")
        self._authorize_community_existing_binding(binding, context)
        if context.user.edition == "community":
            raise ValueError("COMMUNITY_SKILL_EXPLICIT_LIFECYCLE_REQUIRED")
        self._ensure_no_pending_capability_binding_change(binding)
        if payload.bindingConfig is not None:
            self._validate_user_binding_config(payload.bindingConfig)
        current = self._binding_snapshot(binding)
        target_version = self._target_binding_version(binding, payload)
        proposed = self._proposed_binding_snapshot(binding, payload, target_version)
        self._validate_binding_status(str(proposed["status"]))
        self._validate_scope_type(str(proposed["scopeType"]))
        self._validate_binding_compatibility(str(proposed["extensionPointId"]), target_version)
        risk = self._binding_change_risk(current, proposed, target_version=target_version)
        if risk["highRisk"]:
            approval_result = self._request_capability_binding_lifecycle_approval(
                binding=binding,
                operation="update",
                proposed=proposed,
                current=current,
                risk=risk,
                context=context,
            )
            self.db.commit()
            self.db.refresh(binding)
            return {
                **self.serialize_capability_binding(binding),
                "approvalRequired": True,
                "approvalEnvelope": approval_result["approvalEnvelope"],
            }

        self._apply_capability_binding_snapshot(binding, proposed, context)
        self._record_capability_binding_lifecycle_refs(
            binding=binding,
            operation="update",
            proposed=proposed,
            current=current,
            risk=risk,
            decision=GuardrailDecisionType.ALLOW,
            context=context,
            audit_action="capability_binding.update",
        )
        self.db.commit()
        self.db.refresh(binding)
        return self.serialize_capability_binding(binding)

    def community_binding_lifecycle(
        self,
        binding_id: UUID,
        payload: CommunityBindingLifecycleRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_governance_capability(context, "community_skills.manage")
        self._require_governance_capability(context, "capability_bindings.write")
        binding = self._require_capability_binding(binding_id)
        self._authorize_binding_scope(binding, context, {})
        if binding.scope_type not in {"project", "environment"} or not binding.project_id:
            raise ValueError("COMMUNITY_SKILL_PROJECT_SCOPE_REQUIRED")
        scope_key = f"{binding.project_id}:{binding.scope_type}:{binding.environment}:{binding.extension_point_id}"
        acquire_transaction_advisory_lock(self.db, "community-binding", scope_key)
        self.db.refresh(binding)
        self._authorize_binding_scope(binding, context, {})
        request_hash = canonical_content_hash(payload.model_dump())
        receipt = dict((binding.pending_change or {}).get("communityLifecycle") or {})
        if receipt.get("idempotencyKey") == payload.idempotencyKey:
            if receipt.get("requestHash") != request_hash:
                raise IdempotencyConflictError("COMMUNITY_SKILL_IDEMPOTENCY_CONFLICT")
            return {**self.serialize_capability_binding(binding), "deduplicated": True}
        if payload.expectedStateHash != self._binding_state_hash(binding):
            raise IdempotencyConflictError("SKILL_BINDING_CONCURRENT_MODIFICATION")
        if binding.status not in {"draft", "active", "disabled"}:
            raise ValueError("COMMUNITY_SKILL_BINDING_STATE_INVALID")
        self._ensure_no_pending_capability_binding_change(binding)
        current = self._binding_snapshot(binding)
        target_status = "active" if payload.action == "enable" else "disabled"
        evidence: dict[str, object] = {"policyVersion": COMMUNITY_ENABLEMENT_POLICY}
        if payload.action == "enable":
            version = self._require_bound_skill_version(binding)
            profile = self._validate_community_enablement_target(binding, version)
            self._ensure_skill_governance_kill_switch_clear(binding, automatic=False)
            report = self._build_activation_validation_report(
                binding=binding, version=version, context=context, scope={},
            )
            if not report.passed:
                raise ValueError("COMMUNITY_SKILL_VALIDATION_FAILED:" + ",".join(report.failures))
            active = self.db.scalars(select(CapabilityBinding).where(
                CapabilityBinding.project_id == binding.project_id,
                CapabilityBinding.extension_point_id == binding.extension_point_id,
                CapabilityBinding.scope_type == binding.scope_type,
                CapabilityBinding.environment == binding.environment,
                CapabilityBinding.status == "active",
                CapabilityBinding.id != binding.id,
            )).first()
            if active is not None:
                raise IdempotencyConflictError("COMMUNITY_SKILL_ACTIVE_BINDING_CONFLICT")
            conformance = presentation_conformance(profile)
            evidence.update({
                "manifestHash": version.manifest_hash,
                "validationReportHash": report.reportHash,
                "validationReport": report.model_dump(mode="json"),
                "conformanceHash": canonical_content_hash(conformance),
                "fixtureVersion": conformance["fixtureVersion"],
                "presentationOnly": True,
            })
        elif not (binding.binding_config or {}).get("communityEnablement"):
            # Existing Community drafts may also be safely disabled.
            evidence["presentationOnly"] = False
        binding.status = target_status
        binding.updated_by = context.user.id
        binding.binding_config = {
            **dict(binding.binding_config or {}),
            "communityEnablement": {**evidence, "revision": str(uuid4())},
        }
        binding.pending_change = {"communityLifecycle": {
            "idempotencyKey": payload.idempotencyKey, "requestHash": request_hash,
        }}
        self._record_capability_binding_lifecycle_refs(
            binding=binding, operation=payload.action,
            proposed=self._binding_snapshot(binding), current=current,
            risk={"riskLevel": "low", "reasons": [COMMUNITY_ENABLEMENT_POLICY]},
            decision=GuardrailDecisionType.ALLOW, context=context,
            audit_action=f"community_skill.binding.{payload.action}",
        )
        self.db.commit()
        return self.serialize_capability_binding(binding)

    def _validate_community_enablement_target(
        self, binding: CapabilityBinding, version: SkillVersion,
    ) -> dict[str, object]:
        if binding.extension_point_id != COMMUNITY_REGRESSION_EXTENSION:
            raise ValueError("COMMUNITY_SKILL_EXTENSION_NOT_ENABLEABLE")
        if binding.stage is not None or binding.domain is not None:
            raise ValueError("COMMUNITY_SKILL_EXTRA_SCOPE_FORBIDDEN")
        expected_scope_id = binding.project_id if binding.scope_type == "project" else binding.environment
        if binding.scope_id not in {None, expected_scope_id}:
            raise ValueError("COMMUNITY_SKILL_SCOPE_ID_CONFLICT")
        if binding.scope_type == "project" and binding.environment is not None:
            raise ValueError("COMMUNITY_SKILL_SCOPE_ID_CONFLICT")
        if set(binding.binding_config or {}) - {"communityEnablement", "killSwitch"}:
            raise ValueError("COMMUNITY_SKILL_BINDING_CONFIG_FORBIDDEN")
        if version.governance_status != "active" or manifest_snapshot_hash(version.manifest_snapshot) != version.manifest_hash:
            raise ValueError("COMMUNITY_SKILL_VERSION_OR_HASH_INVALID")
        registered = self.db.scalar(select(AuditLog.id).where(
            AuditLog.action == "community_skill.manifest.register",
            AuditLog.resource_type == "skill_version",
            AuditLog.resource_id == str(version.id),
        ).limit(1))
        if registered is None:
            raise ValueError("COMMUNITY_SKILL_LOCAL_REGISTRATION_REQUIRED")
        return validate_community_presentation_manifest(version.manifest_snapshot)

    def resolve_binding(self, extension_point_id: str, *, scope: dict[str, object] | None = None) -> dict[str, object]:
        self.ensure_builtin_skills()
        contract = self.extension_point_contracts.require_bindable(extension_point_id)
        scope = scope or {}
        candidates = list(
            self.db.scalars(
                select(CapabilityBinding)
                .where(CapabilityBinding.extension_point_id == extension_point_id)
                .where(CapabilityBinding.status == "active")
                .order_by(CapabilityBinding.priority.desc(), CapabilityBinding.created_at.desc())
            )
        )
        for scope_type in ("environment", "project", "workspace", "stage", "domain", "global"):
            for binding in candidates:
                if self._binding_matches_scope(binding, scope_type, scope):
                    version = self.db.get(SkillVersion, binding.skill_version_id)
                    if version is None or version.governance_status != "active":
                        continue
                    skill = self.db.get(Skill, version.skill_ref_id)
                    if skill is None:
                        continue
                    self._validate_binding_compatibility(extension_point_id, version)
                    if version.compatibility.get("runtimeAdapter") == COMMUNITY_REGRESSION_ADAPTER:
                        profile = self._validate_community_enablement_target(binding, version)
                        evidence = (binding.binding_config or {}).get("communityEnablement") or {}
                        if evidence.get("manifestHash") != version.manifest_hash or evidence.get("policyVersion") != COMMUNITY_ENABLEMENT_POLICY:
                            raise ValueError("COMMUNITY_SKILL_ENABLEMENT_EVIDENCE_REQUIRED")
                        validated_report = SkillActivationValidationReport.model_validate(evidence.get("validationReport"))
                        if (
                            not validated_report.passed
                            or validated_report.evaluatedManifestHash != version.manifest_hash
                            or validated_report.bindingId != binding.id
                            or validated_report.skillVersionId != version.id
                            or validated_report.extensionPointId != binding.extension_point_id
                            or evidence.get("validationReportHash") != validated_report.reportHash
                            or evidence.get("conformanceHash") != canonical_content_hash(presentation_conformance(profile))
                            or evidence.get("presentationOnly") is not True
                        ):
                            raise ValueError("COMMUNITY_SKILL_ENABLEMENT_EVIDENCE_INVALID")
                    return self._resolution_payload(
                        extension_point_id,
                        skill=skill,
                        version=version,
                        binding=binding,
                        source="binding",
                        fallback_reason=None,
                        scope=scope,
                    )

        default_skill_id = contract.default_skill_id
        if not contract.allow_fallback or default_skill_id is None:
            raise ValueError(f"extension point fallback is disabled: {extension_point_id}")
        version = self._require_skill_version(default_skill_id, None)
        skill = self._require_skill(default_skill_id)
        self._validate_binding_compatibility(extension_point_id, version)
        return self._resolution_payload(
            extension_point_id,
            skill=skill,
            version=version,
            binding=None,
            source="default",
            fallback_reason="no_active_binding",
            scope=scope,
        )

    def invoke_extension(
        self,
        *,
        extension_point_id: str,
        request: Mapping[str, object],
        context: ServiceContext,
        scope: dict[str, object] | None = None,
        source_workflow: str | None = None,
        execution_id: UUID | None = None,
        agent_run_id: UUID | None = None,
        policy_snapshot: dict[str, object] | None = None,
        connector_binding_snapshot: dict[str, object] | None = None,
        approval_refs: list[dict[str, object]] | None = None,
        idempotency_key: str | None = None,
        capabilities: Mapping[str, object] | None = None,
        execution_mode: str = "synchronous",
        deadline_at: datetime | None = None,
        timeout_seconds: float | None = None,
        cancellation_probe: CancellationProbe | None = None,
        resolution_metadata: dict[str, object] | None = None,
        context_sources: Mapping[str, object] | None = None,
        result_validator: Callable[[object, SkillInvocation], None] | None = None,
        result_transformer: Callable[[object], dict[str, object]] | None = None,
        result_acceptor: Callable[
            [object, SkillInvocation],
            ExtensionInvocationCompletion | dict[str, object],
        ]
        | None = None,
        governance_skill_version_id: UUID | None = None,
        governance_binding_id: UUID | None = None,
        governance_mode: str | None = None,
    ) -> ExtensionInvocationResult:
        """Run one governed extension point through its complete managed lifecycle.

        Domain Services supply a structured request and narrowly scoped in-memory
        capabilities. They do not choose the Skill or runtime adapter and do not
        assemble the Invocation state machine. Integration Skills with no
        extension points intentionally continue to use the direct internal
        compatibility path.
        """
        request_snapshot = dict(request)
        contract = self.extension_point_contracts.validate_request(
            extension_point_id,
            request_snapshot,
            execution_mode=execution_mode,
        )
        if result_acceptor is not None and result_transformer is not None:
            raise ValueError("invoke_extension accepts either result_acceptor or result_transformer, not both")

        candidate_invocation_id = uuid4()
        invocation: SkillInvocation | None = None
        try:
            invocation = self.start_managed_invocation(
                skill_id=None,
                extension_point_id=extension_point_id,
                source_workflow=source_workflow,
                context=context,
                request=request_snapshot,
                scope=scope or {},
                execution_id=execution_id,
                agent_run_id=agent_run_id,
                policy_snapshot={
                    **dict(policy_snapshot or {}),
                    "extensionPointContract": {
                        "extensionPointId": extension_point_id,
                        "inputSchemaRef": contract.input_schema_ref,
                        "outputSchemaRef": contract.output_schema_ref,
                        "executionMode": execution_mode,
                    },
                },
                connector_binding_snapshot=connector_binding_snapshot,
                approval_refs=approval_refs,
                idempotency_key=idempotency_key,
                invocation_id=candidate_invocation_id,
                resolution_metadata=resolution_metadata,
                context_sources=context_sources,
                deadline_at=deadline_at,
                timeout_seconds=timeout_seconds,
                governance_skill_version_id=governance_skill_version_id,
                governance_binding_id=governance_binding_id,
                governance_mode=governance_mode,
            )
            if invocation.id != candidate_invocation_id:
                projection = self.serialize_invocation(invocation, include_snapshots=True)
                return ExtensionInvocationResult(
                    runtime_result=dict(invocation.output_snapshot or {}),
                    invocation_id=invocation.id,
                    status=str(projection["status"]),
                    invocation_projection=projection,
                    deduplicated=True,
                )

            context_envelope = dict(
                (invocation.input_snapshot or {}).get("authorizedContextEnvelope") or {}
            )
            if context_envelope and not bool(context_envelope.get("requiredAvailable", False)):
                raise SkillContextUnavailableError("SKILL_CONTEXT_REQUIRED_UNAVAILABLE")

            execution_policy = self._active_execution_policies.get(invocation.id)
            if execution_policy is None:
                raise ValueError("managed Skill Invocation execution policy is unavailable")
            effective_cancellation_probe = self._cancellation_probe(
                invocation,
                cancellation_probe,
            )
            input_byte_size = int(
                (invocation.policy_snapshot or {})
                .get("skillInvocationExecutionPolicy", {})
                .get("inputByteSize", 0)
            )
            self.reliability_runtime.preflight(
                execution_policy,
                cancellation_probe=effective_cancellation_probe,
                input_size=input_byte_size,
            )

            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution_id,
                root_span_name="skill.invoke",
                span_name=f"skill.extension.{extension_point_id}",
                service_name="orchestrator-service",
                attributes={
                    "skillInvocationId": str(invocation.id),
                    "extensionPointId": extension_point_id,
                    "resolvedSkillId": invocation.resolution_snapshot.get("skillId"),
                    "runtimeAdapter": invocation.resolution_snapshot.get("runtimeAdapter"),
                    "runtimeResultKind": invocation.resolution_snapshot.get("runtimeResultKind"),
                },
            ):
                with self.reliability_runtime.lease(execution_policy):
                    runtime_result = self._execute_extension_with_policy(
                        invocation,
                        execution_policy,
                        dict(invocation.input_snapshot or {}),
                        capabilities=dict(capabilities or {}),
                        cancellation_probe=effective_cancellation_probe,
                        context=context,
                    )
                self.extension_point_contracts.validate_runtime_result(
                    extension_point_id,
                    runtime_result_kind=str(
                        invocation.resolution_snapshot.get("runtimeResultKind") or ""
                    )
                    or None,
                    runtime_result=runtime_result,
                )
                if result_validator is not None:
                    result_validator(runtime_result, invocation)
                if result_acceptor is not None:
                    accepted = result_acceptor(runtime_result, invocation)
                    completion = (
                        accepted
                        if isinstance(accepted, ExtensionInvocationCompletion)
                        else ExtensionInvocationCompletion(output_snapshot=accepted)
                    )
                else:
                    output_snapshot = (
                        result_transformer(runtime_result)
                        if result_transformer is not None
                        else runtime_result
                    )
                    if not isinstance(output_snapshot, dict):
                        raise ValueError(
                            "managed Skill runtime result requires a Skill Result transformer"
                        )
                    completion = ExtensionInvocationCompletion(
                        output_snapshot=output_snapshot
                    )
                completion = replace(
                    completion,
                    output_snapshot=self._with_execution_outcome_metadata(
                        invocation,
                        completion.output_snapshot,
                    ),
                )
                if (
                    self._execution_outcomes.get(invocation.id, {}).get("fallbackUsed")
                    and completion.status == "completed"
                ):
                    completion = replace(completion, status="degraded")
                self._ensure_output_within_policy(
                    invocation,
                    execution_policy,
                    completion.output_snapshot,
                )
                self.reliability_runtime.checkpoint(
                    execution_policy,
                    cancellation_probe=effective_cancellation_probe,
                    phase="result_acceptance",
                )
                projection = self.complete_managed_invocation(
                    invocation,
                    completion.output_snapshot,
                    artifact_refs=completion.artifact_refs,
                    tool_call_refs=completion.tool_call_refs,
                    connector_call_refs=completion.connector_call_refs,
                    status=completion.status,
                    error_message=completion.error_message,
                )
                write_audit_log(
                    self.db,
                    str(context.user.id),
                    "skill.invoke_extension",
                    "skill_invocation",
                    str(invocation.id),
                    context.request_id,
                    context.trace_id,
                    details={
                        "extensionPointId": extension_point_id,
                        "resolvedSkillId": invocation.resolution_snapshot.get("skillId"),
                        "skillVersionId": str(invocation.skill_version_id),
                        "manifestHash": invocation.resolution_snapshot.get("manifestHash"),
                        "runtimeAdapter": invocation.resolution_snapshot.get("runtimeAdapter"),
                        "runtimeResultKind": invocation.resolution_snapshot.get("runtimeResultKind"),
                        "contextEnvelopeHash": context_envelope.get("envelopeHash"),
                        "status": projection["status"],
                        "reasonCode": self._invocation_reason_code(invocation),
                        "attemptCount": self._execution_outcomes.get(invocation.id, {}).get(
                            "attemptCount"
                        ),
                    },
                    execution_id=execution_id,
                )
            return ExtensionInvocationResult(
                runtime_result=runtime_result,
                invocation_id=invocation.id,
                status=str(projection["status"]),
                invocation_projection=projection,
            )
        except Exception as exc:
            classification = self.reliability_runtime.classifier.classify(exc)
            if invocation is not None and invocation.status not in STABLE_INVOCATION_STATUSES:
                self.fail_managed_invocation(
                    invocation,
                    str(exc),
                    status=classification.status,
                    reason_code=classification.reason_code,
                )
            elif invocation is not None and invocation.status in {"running", "created", "queued"}:
                self.fail_managed_invocation(
                    invocation,
                    str(exc),
                    status=classification.status,
                    reason_code=classification.reason_code,
                )
            if invocation is not None:
                write_audit_log(
                    self.db,
                    str(context.user.id),
                    "skill.invoke_extension.failed",
                    "skill_invocation",
                    str(invocation.id),
                    context.request_id,
                    context.trace_id,
                    details={
                        "extensionPointId": extension_point_id,
                        "resolvedSkillId": invocation.resolution_snapshot.get("skillId"),
                        "skillVersionId": str(invocation.skill_version_id),
                        "runtimeAdapter": invocation.resolution_snapshot.get("runtimeAdapter"),
                        "contextEnvelopeHash": (
                            (invocation.resolution_snapshot or {}).get("authorizedContext") or {}
                        ).get("envelopeHash"),
                        "status": self._effective_invocation_status(invocation),
                        "reasonCode": self._invocation_reason_code(invocation),
                        "attemptCount": self._execution_outcomes.get(invocation.id, {}).get(
                            "attemptCount"
                        ),
                        "error": redact_sensitive_text(str(exc)),
                    },
                    execution_id=execution_id,
                )
            if invocation is not None:
                self._extension_failures_pending_reconciliation[invocation.id] = (
                    str(exc),
                    classification.status,
                    classification.reason_code,
                )
            raise
        finally:
            if invocation is not None and invocation.id == candidate_invocation_id:
                self._active_execution_policies.pop(invocation.id, None)
                self._execution_outcomes.pop(invocation.id, None)

    def reconcile_extension_failures_after_rollback(self) -> None:
        """Restore unified-entry failure facts after an owning Service rollback.

        Some Guardrail/Audit boundaries intentionally persist observation facts
        before the Domain Service rolls back its business transaction. If that
        leaves an Invocation at its previously committed running state, this
        method reapplies the failure recorded by invoke_extension without
        exposing lifecycle composition to the Domain Service.
        """
        pending = dict(self._extension_failures_pending_reconciliation)
        self._extension_failures_pending_reconciliation.clear()
        for invocation_id, failure in pending.items():
            error, status, reason_code = failure
            invocation = self.db.get(SkillInvocation, invocation_id)
            if invocation is not None and invocation.status in {"created", "queued", "running"}:
                self.fail_managed_invocation(
                    invocation,
                    error,
                    status=status,
                    reason_code=reason_code,
                )

    def start_managed_invocation(
        self,
        *,
        skill_id: str | None,
        context: ServiceContext,
        request: dict[str, object],
        extension_point_id: str | None = None,
        source_workflow: str | None = None,
        scope: dict[str, object] | None = None,
        execution_id: UUID | None = None,
        agent_run_id: UUID | None = None,
        policy_snapshot: dict[str, object] | None = None,
        connector_binding_snapshot: dict[str, object] | None = None,
        approval_refs: list[dict[str, object]] | None = None,
        idempotency_key: str | None = None,
        invocation_id: UUID | None = None,
        resolution_metadata: dict[str, object] | None = None,
        context_sources: Mapping[str, object] | None = None,
        deadline_at: datetime | None = None,
        timeout_seconds: float | None = None,
        governance_skill_version_id: UUID | None = None,
        governance_binding_id: UUID | None = None,
        governance_mode: str | None = None,
    ) -> SkillInvocation:
        self.ensure_builtin_skills()
        if governance_skill_version_id is not None:
            if extension_point_id is None:
                raise ValueError("governance Skill execution requires extensionPointId")
            if governance_mode not in {
                "evaluation_baseline",
                "evaluation_candidate",
                "shadow_candidate",
            }:
                raise ValueError("invalid internal Skill governance execution mode")
            version = self.db.get(SkillVersion, governance_skill_version_id)
            if version is None or version.governance_status not in {"draft", "active"}:
                raise ValueError("governance Skill version is unavailable")
            skill = self.db.get(Skill, version.skill_ref_id)
            if skill is None:
                raise ValueError("governance Skill is unavailable")
            binding = (
                self.db.get(CapabilityBinding, governance_binding_id)
                if governance_binding_id is not None
                else None
            )
            if binding is not None and (
                binding.extension_point_id != extension_point_id
                or binding.skill_version_id != version.id
            ):
                raise ValueError("governance Skill Binding target changed")
            self._validate_binding_compatibility(extension_point_id, version)
            resolved_skill_id = skill.skill_id
            resolution = self._resolution_payload(
                extension_point_id,
                skill=skill,
                version=version,
                binding=binding,
                source=governance_mode,
                fallback_reason=None,
                scope=scope or {},
            )
            resolution = {
                **resolution,
                "nonAuthoritative": True,
                "governanceMode": governance_mode,
                "canonicalWritesAllowed": False,
                "externalWritesAllowed": False,
            }
        elif extension_point_id:
            resolution = self.resolve_binding(extension_point_id, scope=scope or {})
            resolved_skill_id = str(resolution["skillId"])
            version = self.db.get(SkillVersion, UUID(str(resolution["skillVersionId"])))
            if version is None:
                raise ValueError("resolved skill version not found")
        else:
            if skill_id is None:
                raise ValueError("skillId is required when extensionPointId is absent")
            version = self._require_skill_version(skill_id, None)
            resolved_skill_id = skill_id
            resolution = self._resolution_payload(
                None,
                skill=self._require_skill(resolved_skill_id),
                version=version,
                binding=None,
                source="direct_internal",
                fallback_reason=None,
                scope=scope or {},
            )
        self._validate_runtime_version(version, extension_point_id)
        if resolution_metadata:
            reserved_resolution_fields = {
                "requestedExtensionPointId",
                "resolvedSkillId",
                "skillId",
                "skillVersionId",
                "version",
                "manifestHash",
                "runtimeAdapter",
                "runtimeResultKind",
                "bindingId",
                "scope",
                "source",
                "fallbackReason",
            }
            authority_conflicts = reserved_resolution_fields.intersection(resolution_metadata)
            if authority_conflicts:
                raise ValueError(
                    "resolution metadata cannot override authority fields: "
                    + ",".join(sorted(authority_conflicts))
                )
            resolution = {
                **resolution,
                **redact_sensitive_data(resolution_metadata),
            }
        resolution = self._enrich_resolution_decisions(
            resolution,
            context=context,
            approval_refs=approval_refs or [],
        )
        context_envelope = self.authorized_context_builder.build(
            version=version,
            extension_point_id=extension_point_id or "direct_internal",
            context=context,
            scope=scope or {},
            execution_id=execution_id,
            connector_binding_snapshot=connector_binding_snapshot,
            provided_contexts=context_sources,
        )
        context_summary = context_envelope.summary()
        resolution = {**resolution, "authorizedContext": context_summary}
        binding_config: dict[str, object] = {}
        if resolution.get("bindingId"):
            binding = self.db.get(CapabilityBinding, UUID(str(resolution["bindingId"])))
            if binding is None:
                raise ValueError("resolved capability binding is unavailable")
            binding_config = dict(binding.binding_config or {})
        configured_fallback = binding_config.get("executionPolicy")
        configured_fallback = (
            configured_fallback if isinstance(configured_fallback, dict) else {}
        )
        configured_fallback = configured_fallback.get("fallback")
        configured_fallback = (
            configured_fallback if isinstance(configured_fallback, dict) else {}
        )
        fallback_target = (
            self._governed_fallback_target(
                extension_point_id,
                resolution,
                scope or {},
            )
            if bool(configured_fallback.get("allowed", False))
            else None
        )
        contract = (
            self.extension_point_contracts.require_bindable(extension_point_id)
            if extension_point_id
            else None
        )
        execution_policy = self.reliability_runtime.build_policy(
            extension_point_id=extension_point_id or "direct_internal",
            execution_constraints=(contract.execution_constraints if contract else {}),
            risk_profile=dict(version.risk_profile or {}),
            approval_policy=dict(version.approval_policy or {}),
            binding_config=binding_config,
            resolution=resolution,
            scope=scope or {},
            idempotency_key=idempotency_key,
            caller_policy_snapshot=policy_snapshot or {},
            approval_refs=approval_refs or [],
            deadline_at=deadline_at,
            timeout_seconds=timeout_seconds,
            fallback_target=fallback_target,
        )
        safe_input_snapshot = {
            **redact_sensitive_data(request),
            "authorizedContextEnvelope": context_envelope.model_dump(mode="json"),
        }
        input_byte_size = self.reliability_runtime.json_size(safe_input_snapshot)
        if input_byte_size > execution_policy.max_input_bytes:
            safe_input_snapshot = {
                "rejectedInput": {
                    "contentHash": self._content_hash(safe_input_snapshot),
                    "byteSize": input_byte_size,
                    "reasonCode": SkillInvocationReasonCode.INPUT_TOO_LARGE.value,
                },
                "authorizedContextSummary": context_summary,
            }
        safe_policy_snapshot = {
            **redact_sensitive_data(policy_snapshot or {}),
            "authorizedContext": context_summary,
            "skillInvocationExecutionPolicy": {
                **execution_policy.snapshot(),
                "inputByteSize": input_byte_size,
                "idempotencyKeyPresent": bool(idempotency_key),
            },
        }
        safe_connector_snapshot = self.connector_snapshot_builder.build(connector_binding_snapshot)
        if idempotency_key:
            acquire_transaction_advisory_lock(self.db, "skill-invocation", idempotency_key)
            existing = self._invocation_by_idempotency_key(idempotency_key)
            if existing is not None:
                input_conflict_keys = sorted(
                    key
                    for key in set(existing.input_snapshot) | set(safe_input_snapshot)
                    if existing.input_snapshot.get(key) != safe_input_snapshot.get(key)
                )
                if "payload" in input_conflict_keys:
                    existing_payload = existing.input_snapshot.get("payload")
                    incoming_payload = safe_input_snapshot.get("payload")
                    if isinstance(existing_payload, dict) and isinstance(incoming_payload, dict):
                        payload_keys = sorted(
                            key
                            for key in set(existing_payload) | set(incoming_payload)
                            if existing_payload.get(key) != incoming_payload.get(key)
                        )
                        input_conflict_keys = [
                            *(key for key in input_conflict_keys if key != "payload"),
                            *(f"payload.{key}" for key in payload_keys),
                        ]
                invocation_conflicts = [
                    name
                    for name, mismatch in (
                        ("skillVersionId", existing.skill_version_id != version.id),
                        (
                            "inputSnapshot[" + ",".join(input_conflict_keys) + "]",
                            bool(input_conflict_keys),
                        ),
                        ("executionId", existing.execution_id != execution_id),
                        ("agentRunId", existing.agent_run_id != agent_run_id),
                        (
                            "connectorBindingSnapshot",
                            existing.connector_binding_snapshot != safe_connector_snapshot,
                        ),
                    )
                    if mismatch
                ]
                if invocation_conflicts:
                    raise IdempotencyConflictError(
                        "idempotency conflict for skill invocation "
                        f"'{idempotency_key}' ({','.join(invocation_conflicts)})"
                    )
                return existing
        ensure_trace(
            self.db,
            execution_id=execution_id,
            root_span_name="skill.invoke",
            trace_id=context.trace_id,
        )
        invocation = SkillInvocation(
            id=invocation_id or uuid4(),
            trace_id=UUID(str(context.trace_id)),
            execution_id=execution_id,
            agent_run_id=agent_run_id,
            skill_version_id=version.id,
            binding_id=UUID(str(resolution["bindingId"])) if resolution.get("bindingId") else None,
            extension_point_id=extension_point_id,
            source_workflow=source_workflow,
            status="running",
            idempotency_key=idempotency_key,
            input_snapshot=safe_input_snapshot,
            policy_snapshot={
                **safe_policy_snapshot,
                "resolution": resolution,
            },
            resolution_snapshot=resolution,
            connector_binding_snapshot=safe_connector_snapshot,
            approval_refs=redact_sensitive_data(approval_refs or []),
        )
        self.db.add(invocation)
        self.db.flush()
        self._active_execution_policies[invocation.id] = execution_policy
        self._record_invocation_event(invocation, "resolution", resolution)
        self._record_invocation_event(
            invocation,
            "execution_policy_frozen",
            {
                "policy": execution_policy.snapshot(),
                "inputByteSize": input_byte_size,
            },
        )
        self._record_invocation_event(
            invocation,
            "authorized_context",
            {
                "contextEnvelopeHash": context_envelope.envelopeHash,
                "requiredAvailable": context_envelope.requiredAvailable,
                "contextRefs": context_summary["contextRefs"],
            },
        )
        self._record_skill_guardrail_preflight(invocation, self._guardrail_input_for_invocation(invocation, resolved_skill_id, request), context)
        return invocation

    def execute_managed_runtime(
        self,
        invocation: SkillInvocation,
        request: dict[str, object],
        *,
        capabilities: dict[str, object] | None = None,
        cancellation_probe: CancellationProbe | None = None,
    ) -> object:
        """Dispatch the implementation frozen by this invocation's resolution.

        The Domain Service supplies only the in-memory capability needed by the
        selected adapter. Binding resolution and runtime dispatch therefore
        cannot drift into two different Skill implementations.
        """
        runtime_context = SkillRuntimeContext.from_invocation(
            invocation,
            cancellation_probe=cancellation_probe,
            clock=self.reliability_runtime.clock,
        )
        runtime_request = dict(request)
        runtime_request.pop("authorizedContextEnvelope", None)
        result = self.runtime_registry.dispatch(
            runtime_context,
            runtime_request,
            capabilities=capabilities or {},
        )
        self._record_invocation_event(
            invocation,
            "runtime_dispatch",
            {
                "skillId": runtime_context.skill_id,
                "skillVersionId": str(runtime_context.skill_version_id) if runtime_context.skill_version_id else None,
                "version": runtime_context.version,
                "manifestHash": runtime_context.manifest_hash,
                "runtimeAdapter": runtime_context.runtime_adapter,
                "runtimeResultKind": runtime_context.runtime_result_kind,
                "extensionPointId": runtime_context.extension_point_id,
                "contextEnvelopeHash": (
                    runtime_context.authorized_context or {}
                ).get("envelopeHash"),
            },
        )
        return result

    def _execute_extension_with_policy(
        self,
        invocation: SkillInvocation,
        policy: SkillInvocationExecutionPolicy,
        request: dict[str, object],
        *,
        capabilities: dict[str, object],
        cancellation_probe: CancellationProbe,
        context: ServiceContext,
    ) -> object:
        adapter_id = policy.adapter_id
        attempt = 0
        while attempt < policy.max_attempts:
            attempt += 1
            started_at = self.reliability_runtime.clock()
            self._record_invocation_event(
                invocation,
                "attempt_started",
                {
                    "attemptNumber": attempt,
                    "reasonCode": None,
                    "startedAt": started_at.isoformat(),
                    "finishedAt": None,
                    "retry": False,
                    "backoffDecision": {"applied": False, "seconds": 0.0},
                    "adapterId": adapter_id,
                    "invocationId": str(invocation.id),
                },
            )
            try:
                self.reliability_runtime.checkpoint(
                    policy,
                    cancellation_probe=cancellation_probe,
                    phase="adapter_dispatch",
                )
                circuit_state = self.reliability_runtime.before_adapter(
                    adapter_id,
                    policy,
                )
                with traced_operation(
                    self.db,
                    trace_id=context.trace_id,
                    execution_id=invocation.execution_id,
                    root_span_name="skill.invoke",
                    span_name=f"skill.attempt.{attempt}",
                    service_name="orchestrator-service",
                    attributes={
                        "skillInvocationId": str(invocation.id),
                        "attemptNumber": attempt,
                        "adapterId": adapter_id,
                        "circuitState": circuit_state,
                    },
                ):
                    runtime_result = self.execute_managed_runtime(
                        invocation,
                        request,
                        capabilities=capabilities,
                        cancellation_probe=cancellation_probe,
                    )
                self.reliability_runtime.checkpoint(
                    policy,
                    cancellation_probe=cancellation_probe,
                    phase="result_acceptance",
                )
                result_classification = (
                    self.reliability_runtime.classifier.classify_result(runtime_result)
                )
                should_retry_result = bool(
                    result_classification
                    and self.reliability_runtime.retry_allowed(
                        policy,
                        result_classification,
                        attempt=attempt,
                    )
                )
                if should_retry_result and result_classification is not None:
                    raise SkillInvocationExecutionError(
                        result_classification.reason_code,
                        status=result_classification.status,
                        message="managed Skill runtime returned a retryable terminal result",
                        retryable=True,
                    )
                if result_classification is None:
                    self.reliability_runtime.adapter_succeeded(adapter_id)
                else:
                    self.reliability_runtime.adapter_failed(
                        adapter_id,
                        policy,
                        counts_toward_circuit=result_classification.counts_toward_circuit,
                    )
                finished_at = self.reliability_runtime.clock()
                self._record_invocation_event(
                    invocation,
                    "attempt_finished",
                    {
                        "attemptNumber": attempt,
                        "reasonCode": (
                            result_classification.reason_code
                            if result_classification is not None
                            else None
                        ),
                        "startedAt": started_at.isoformat(),
                        "finishedAt": finished_at.isoformat(),
                        "retry": False,
                        "backoffDecision": {"applied": False, "seconds": 0.0},
                        "adapterId": adapter_id,
                        "invocationId": str(invocation.id),
                        "circuit": self.reliability_runtime.circuit_snapshot(adapter_id),
                    },
                )
                runtime_metadata = (
                    runtime_result.metadata
                    if isinstance(runtime_result, AgentResult)
                    and isinstance(runtime_result.metadata, dict)
                    else {}
                )
                runtime_limitations = (
                    runtime_result.limitations
                    if isinstance(runtime_result, AgentResult)
                    else []
                )
                self._execution_outcomes[invocation.id] = {
                    "attemptCount": attempt,
                    "reasonCode": (
                        None
                        if result_classification is None
                        else SkillInvocationReasonCode.EXTERNAL_WRITE_OUTCOME_UNKNOWN.value
                        if result_classification.retryable and policy.external_write
                        else SkillInvocationReasonCode.NON_IDEMPOTENT_RETRY_FORBIDDEN.value
                        if result_classification.retryable
                        and (policy.mutation or not policy.idempotent)
                        else result_classification.reason_code
                    ),
                    "fallbackUsed": bool(runtime_metadata.get("fallbackUsed", False)),
                    "fallbackReason": runtime_metadata.get("fallbackReason"),
                    "originalAdapter": adapter_id,
                    "originalVersion": policy.adapter_version,
                    "actualAdapter": adapter_id,
                    "actualVersion": policy.adapter_version,
                    "limitations": [
                        *[str(item) for item in runtime_limitations],
                        "Synchronous Adapter cancellation is cooperative; a late result is rejected but physical termination is not guaranteed.",
                    ],
                }
                return runtime_result
            except Exception as exc:
                classification = self.reliability_runtime.classifier.classify(exc)
                self._execution_outcomes[invocation.id] = {
                    "attemptCount": attempt,
                    "fallbackUsed": False,
                    "fallbackReason": None,
                    "originalAdapter": adapter_id,
                    "originalVersion": policy.adapter_version,
                    "actualAdapter": adapter_id,
                    "actualVersion": policy.adapter_version,
                    "limitations": [
                        "The managed Skill result was not accepted; synchronous Adapter termination is cooperative."
                    ],
                }
                circuit_state = self.reliability_runtime.adapter_failed(
                    adapter_id,
                    policy,
                    counts_toward_circuit=classification.counts_toward_circuit,
                )
                retry = self.reliability_runtime.retry_allowed(
                    policy,
                    classification,
                    attempt=attempt,
                )
                delay_seconds = (
                    self.reliability_runtime.backoff_seconds(
                        attempt,
                        classification.reason_code,
                    )
                    if retry
                    else 0.0
                )
                finished_at = self.reliability_runtime.clock()
                self._record_invocation_event(
                    invocation,
                    "attempt_finished",
                    {
                        "attemptNumber": attempt,
                        "reasonCode": classification.reason_code,
                        "startedAt": started_at.isoformat(),
                        "finishedAt": finished_at.isoformat(),
                        "retry": retry,
                        "backoffDecision": {
                            "applied": retry,
                            "seconds": delay_seconds,
                            "strategy": "bounded_exponential",
                        },
                        "adapterId": adapter_id,
                        "invocationId": str(invocation.id),
                        "circuit": {
                            **self.reliability_runtime.circuit_snapshot(adapter_id),
                            "state": circuit_state,
                        },
                    },
                )
                if retry:
                    self.reliability_runtime.wait_for_retry(
                        policy,
                        delay_seconds=delay_seconds,
                        cancellation_probe=cancellation_probe,
                    )
                    continue
                if (
                    policy.fallback_allowed
                    and classification.reason_code in policy.fallback_reason_codes
                    and policy.fallback_target is not None
                ):
                    return self._execute_governed_fallback(
                        invocation,
                        policy,
                        request,
                        capabilities=capabilities,
                        cancellation_probe=cancellation_probe,
                        context=context,
                        original_attempts=attempt,
                        fallback_reason=classification.reason_code,
                    )
                if classification.retryable and attempt >= policy.max_attempts:
                    if policy.external_write:
                        raise SkillInvocationExecutionError(
                            SkillInvocationReasonCode.EXTERNAL_WRITE_OUTCOME_UNKNOWN,
                            status="unavailable",
                        ) from exc
                    if policy.mutation or not policy.idempotent:
                        raise SkillInvocationExecutionError(
                            SkillInvocationReasonCode.NON_IDEMPOTENT_RETRY_FORBIDDEN,
                            status="failed",
                        ) from exc
                    raise SkillInvocationExecutionError(
                        SkillInvocationReasonCode.RETRY_EXHAUSTED,
                        status="unavailable",
                        message=(
                            f"{SkillInvocationReasonCode.RETRY_EXHAUSTED.value}: "
                            f"lastReason={classification.reason_code}"
                        ),
                    ) from exc
                if isinstance(exc, SkillInvocationExecutionError):
                    raise
                raise
        raise SkillInvocationExecutionError(
            SkillInvocationReasonCode.RETRY_EXHAUSTED,
            status="unavailable",
        )

    def _execute_governed_fallback(
        self,
        invocation: SkillInvocation,
        policy: SkillInvocationExecutionPolicy,
        request: dict[str, object],
        *,
        capabilities: dict[str, object],
        cancellation_probe: CancellationProbe,
        context: ServiceContext,
        original_attempts: int,
        fallback_reason: str,
    ) -> object:
        target = dict(policy.fallback_target or {})
        adapter_id = str(target.get("runtimeAdapter") or "")
        if not adapter_id:
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.FALLBACK_NOT_ALLOWED,
                status="unavailable",
            )
        attempt = original_attempts + 1
        started_at = self.reliability_runtime.clock()
        self._record_invocation_event(
            invocation,
            "fallback_started",
            {
                "attemptNumber": attempt,
                "reasonCode": fallback_reason,
                "startedAt": started_at.isoformat(),
                "finishedAt": None,
                "retry": False,
                "backoffDecision": {"applied": False, "seconds": 0.0},
                "adapterId": adapter_id,
                "invocationId": str(invocation.id),
                "fallbackTarget": target,
            },
        )
        try:
            self.reliability_runtime.checkpoint(
                policy,
                cancellation_probe=cancellation_probe,
                phase="fallback_dispatch",
            )
            circuit_state = self.reliability_runtime.before_adapter(adapter_id, policy)
            runtime_context = SkillRuntimeContext.from_invocation(
                invocation,
                cancellation_probe=cancellation_probe,
                clock=self.reliability_runtime.clock,
            )
            runtime_context = replace(
                runtime_context,
                skill_id=str(target.get("skillId") or "") or None,
                skill_version_id=UUID(str(target["skillVersionId"])),
                version=str(target.get("version") or "") or None,
                manifest_hash=str(target.get("manifestHash") or "") or None,
                runtime_adapter=adapter_id,
                runtime_result_kind=str(target.get("runtimeResultKind") or "") or None,
                resolution_snapshot=target,
            )
            runtime_request = dict(request)
            runtime_request.pop("authorizedContextEnvelope", None)
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=invocation.execution_id,
                root_span_name="skill.invoke",
                span_name="skill.fallback",
                service_name="orchestrator-service",
                attributes={
                    "skillInvocationId": str(invocation.id),
                    "attemptNumber": attempt,
                    "adapterId": adapter_id,
                    "fallbackReason": fallback_reason,
                    "circuitState": circuit_state,
                },
            ):
                runtime_result = self.runtime_registry.dispatch(
                    runtime_context,
                    runtime_request,
                    capabilities=capabilities,
                )
            self.reliability_runtime.checkpoint(
                policy,
                cancellation_probe=cancellation_probe,
                phase="result_acceptance",
            )
            self.reliability_runtime.adapter_succeeded(adapter_id)
        except Exception as exc:
            classification = self.reliability_runtime.classifier.classify(exc)
            self.reliability_runtime.adapter_failed(
                adapter_id,
                policy,
                counts_toward_circuit=classification.counts_toward_circuit,
            )
            self._record_invocation_event(
                invocation,
                "fallback_failed",
                {
                    "attemptNumber": attempt,
                    "reasonCode": classification.reason_code,
                    "startedAt": started_at.isoformat(),
                    "finishedAt": self.reliability_runtime.clock().isoformat(),
                    "retry": False,
                    "backoffDecision": {"applied": False, "seconds": 0.0},
                    "adapterId": adapter_id,
                    "invocationId": str(invocation.id),
                },
            )
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.FALLBACK_FAILED,
                status="unavailable",
                message=(
                    f"{SkillInvocationReasonCode.FALLBACK_FAILED.value}: "
                    f"reason={classification.reason_code}"
                ),
            ) from exc
        self._record_invocation_event(
            invocation,
            "fallback_completed",
            {
                "attemptNumber": attempt,
                "reasonCode": fallback_reason,
                "startedAt": started_at.isoformat(),
                "finishedAt": self.reliability_runtime.clock().isoformat(),
                "retry": False,
                "backoffDecision": {"applied": False, "seconds": 0.0},
                "adapterId": adapter_id,
                "invocationId": str(invocation.id),
            },
        )
        self._execution_outcomes[invocation.id] = {
            "attemptCount": attempt,
            "reasonCode": SkillInvocationReasonCode.FALLBACK_USED.value,
            "fallbackUsed": True,
            "fallbackReason": fallback_reason,
            "originalAdapter": policy.adapter_id,
            "originalVersion": policy.adapter_version,
            "actualAdapter": adapter_id,
            "actualVersion": target.get("version"),
            "limitations": [
                "The governed fallback result is degraded and does not prove the original Adapter recovered.",
                "Synchronous Adapter cancellation is cooperative; physical termination is not guaranteed.",
            ],
        }
        return runtime_result

    def complete_managed_invocation(
        self,
        invocation: SkillInvocation,
        output_snapshot: dict[str, object],
        *,
        artifact_refs: list[dict[str, object]] | None = None,
        tool_call_refs: list[dict[str, object]] | None = None,
        connector_call_refs: list[dict[str, object]] | None = None,
        status: str = "completed",
        error_message: str | None = None,
    ) -> dict[str, object]:
        if status not in STABLE_INVOCATION_STATUSES:
            raise ValueError(f"unsupported managed Skill Invocation status: {status}")
        prepared_output = redact_sensitive_data(
            self._with_runtime_metadata(invocation, output_snapshot)
        )
        prepared_metadata = dict(prepared_output.get("metadata") or {})
        prepared_metadata["status"] = status
        if status == "degraded" and not prepared_metadata.get("reasonCode"):
            prepared_metadata["reasonCode"] = (
                SkillInvocationReasonCode.FALLBACK_USED.value
            )
        prepared_output["metadata"] = prepared_metadata
        try:
            validated = self._validate_skill_result(prepared_output)
        except Exception as exc:
            invocation.status = "invalid_output"
            invocation.error_message = redact_sensitive_text(str(exc))
            invocation.output_snapshot = self._terminal_skill_result(
                invocation,
                status="invalid_output",
                reason_code=SkillInvocationReasonCode.OUTPUT_SCHEMA_INVALID.value,
                error=invocation.error_message,
            )
            self._record_invocation_event(
                invocation,
                "invalid_output",
                {
                    "status": "invalid_output",
                    "reasonCode": SkillInvocationReasonCode.OUTPUT_SCHEMA_INVALID.value,
                    "error": invocation.error_message,
                },
            )
            self.db.flush()
            raise
        invocation.output_snapshot = validated
        validated_artifact_refs = validated.get("artifactRefs")
        validated_artifact_refs = (
            validated_artifact_refs if isinstance(validated_artifact_refs, list) else []
        )
        invocation.artifact_refs = artifact_refs or list(validated_artifact_refs)
        invocation.tool_call_refs = tool_call_refs or []
        invocation.connector_call_refs = connector_call_refs or []
        invocation.status = INVOCATION_STORAGE_STATUS.get(status, status)
        invocation.error_message = redact_sensitive_text(error_message) if error_message else None
        self._record_invocation_event(
            invocation,
            "completed" if status == "completed" else status,
            {
                "status": status,
                "reasonCode": self._invocation_reason_code(invocation),
                "artifactCount": len(invocation.artifact_refs),
                "fallbackUsed": bool(
                    self._execution_outcomes.get(invocation.id, {}).get("fallbackUsed")
                ),
            },
        )
        self.db.flush()
        return self.serialize_invocation(invocation, include_snapshots=True)

    def fail_managed_invocation(
        self,
        invocation: SkillInvocation,
        error: str,
        *,
        status: str = "failed",
        reason_code: str = SkillInvocationReasonCode.ADAPTER_FAILED.value,
    ) -> dict[str, object]:
        if status not in STABLE_INVOCATION_STATUSES:
            status = "failed"
        error = redact_sensitive_text(error)
        invocation.status = INVOCATION_STORAGE_STATUS.get(status, status)
        invocation.error_message = error
        invocation.output_snapshot = self._terminal_skill_result(
            invocation,
            status=status,
            reason_code=reason_code,
            error=error,
        )
        self._record_invocation_event(
            invocation,
            status,
            {
                "status": status,
                "reasonCode": reason_code,
                "error": error,
                "attemptCount": self._execution_outcomes.get(invocation.id, {}).get(
                    "attemptCount"
                ),
            },
        )
        self.db.flush()
        return self.serialize_invocation(invocation, include_snapshots=True)

    def create_invocation(
        self,
        payload: SkillInvocationRequest,
        context: ServiceContext,
        *,
        commit: bool = True,
    ) -> dict[str, object]:
        self.ensure_builtin_skills()
        version = self._require_skill_version(payload.skillId, payload.version)
        ensure_trace(
            self.db,
            execution_id=payload.executionId,
            root_span_name="skill.invoke",
            trace_id=context.trace_id,
        )
        manifest = dict(version.manifest_snapshot)
        self._ensure_skill_allowed_for_user(manifest, payload, context)
        request = IntegrationSkillInput(
            skill=payload.skillId,
            operation=str(payload.request.get("operation") or ""),
            provider=payload.request.get("connector"),
            payload=dict(payload.request.get("payload") or {}),
            metadata={
                **dict(payload.request.get("metadata") or {}),
                "requestId": context.request_id,
                "traceId": context.trace_id,
                "contextRefs": payload.contextRefs,
            },
        )
        safe_connector_snapshot = self.connector_snapshot_builder.build(
            payload.connectorBindingSnapshot
        )
        if payload.idempotencyKey:
            acquire_transaction_advisory_lock(
                self.db,
                "skill-invocation",
                payload.idempotencyKey,
            )
            existing = self._invocation_by_idempotency_key(payload.idempotencyKey)
            if existing is not None:
                if (
                    existing.skill_version_id != version.id
                    or existing.input_snapshot
                    != redact_sensitive_data(request.model_dump(mode="json"))
                    or existing.execution_id != payload.executionId
                    or existing.agent_run_id != payload.agentRunId
                    or existing.connector_binding_snapshot != safe_connector_snapshot
                ):
                    raise IdempotencyConflictError(
                        f"idempotency conflict for skill invocation '{payload.idempotencyKey}'"
                    )
                return {
                    **self.serialize_invocation(existing, include_snapshots=True),
                    "idempotentReplay": True,
                }
        if self._requires_approval(manifest, payload, context):
            approval = ApprovalService(self.db).request_skill_invocation(
                skill_id=payload.skillId,
                version=version.version,
                manifest_hash=version.manifest_hash,
                request_payload=payload.request,
                context_refs=payload.contextRefs,
                risk_profile=payload.riskProfile,
                policy_snapshot=payload.policySnapshot,
                connector_binding_snapshot=safe_connector_snapshot,
                idempotency_key=payload.idempotencyKey,
                context=context,
                commit=commit,
            )
            envelope = {
                "resourceType": "skill_invocation",
                "approvalId": approval["approvalId"],
                "skillId": payload.skillId,
                "version": version.version,
                "reason": "approval required by skill approvalPolicy/riskProfile",
            }
            return {
                "approvalRequired": True,
                "approvalEnvelope": envelope,
                "skillId": payload.skillId,
                "version": version.version,
                "manifestHash": version.manifest_hash,
            }

        return self.invoke_integration_skill(
            request,
            context,
            execution_id=payload.executionId,
            agent_run_id=payload.agentRunId,
            policy_snapshot=payload.policySnapshot,
            connector_binding_snapshot=payload.connectorBindingSnapshot,
            idempotency_key=payload.idempotencyKey,
            commit=commit,
        )

    def invoke_integration_skill(
        self,
        request: IntegrationSkillInput,
        context: ServiceContext,
        *,
        execution_id: UUID | None = None,
        agent_run_id: UUID | None = None,
        policy_snapshot: dict[str, object] | None = None,
        connector_binding_snapshot: dict[str, object] | None = None,
        idempotency_key: str | None = None,
        commit: bool = False,
    ) -> dict[str, object]:
        self.ensure_builtin_skills()
        version = self._require_skill_version(request.skill, None)
        self._validate_runtime_version(version, None)
        input_snapshot = redact_sensitive_data(request.model_dump(mode="json"))
        safe_policy_snapshot = redact_sensitive_data(policy_snapshot or {})
        safe_connector_snapshot = self.connector_snapshot_builder.build(connector_binding_snapshot)
        if idempotency_key:
            acquire_transaction_advisory_lock(
                self.db,
                "skill-invocation",
                idempotency_key,
            )
            existing = self._invocation_by_idempotency_key(idempotency_key)
            if existing is not None:
                if (
                    existing.skill_version_id != version.id
                    or existing.input_snapshot != input_snapshot
                    or existing.execution_id != execution_id
                    or existing.agent_run_id != agent_run_id
                    or existing.connector_binding_snapshot != safe_connector_snapshot
                ):
                    raise IdempotencyConflictError(
                        f"idempotency conflict for skill invocation '{idempotency_key}'"
                    )
                return {**self.serialize_invocation(existing, include_snapshots=True), "idempotentReplay": True}
        ensure_trace(
            self.db,
            execution_id=execution_id,
            root_span_name="skill.invoke",
            trace_id=context.trace_id,
        )
        self.db.flush()
        skill = self.db.get(Skill, version.skill_ref_id)
        resolution = self._resolution_payload(
            None,
            skill=skill,
            version=version,
            binding=None,
            source="direct_internal",
            fallback_reason=None,
            scope={},
        ) if skill is not None else {}
        invocation = SkillInvocation(
            id=uuid4(),
            trace_id=UUID(str(context.trace_id)),
            execution_id=execution_id,
            agent_run_id=agent_run_id,
            skill_version_id=version.id,
            status="running",
            idempotency_key=idempotency_key,
            input_snapshot=input_snapshot,
            policy_snapshot={**safe_policy_snapshot, "resolution": resolution},
            resolution_snapshot=resolution,
            connector_binding_snapshot=safe_connector_snapshot,
        )
        self.db.add(invocation)
        self.db.flush()
        self._record_invocation_event(invocation, "resolution", resolution)
        self._record_skill_guardrail_preflight(invocation, request, context)

        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=execution_id,
                root_span_name="skill.invoke",
                span_name=f"skill.{request.skill}",
                service_name="agent-service",
                attributes={
                    "skillInvocationId": str(invocation.id),
                    "skillId": request.skill,
                    "skillVersionId": str(version.id),
                    "manifestHash": version.manifest_hash,
                    "operation": request.operation,
                },
            ):
                result = self._dispatch_integration_runtime(invocation, request)
        except Exception as exc:
            invocation.status = "failed"
            invocation.error_message = redact_sensitive_text(str(exc))
            invocation.output_snapshot = self._failed_skill_result(request, invocation.error_message)
            if commit:
                self.db.commit()
            raise

        output_snapshot = self._validate_skill_result(
            redact_sensitive_data(self._to_skill_result(result))
        )
        invocation.output_snapshot = output_snapshot
        invocation.artifact_refs = output_snapshot["artifactRefs"]
        invocation.status = "completed" if result.succeeded else "failed"
        if result.errors:
            invocation.error_message = redact_sensitive_text("; ".join(result.errors))
        write_audit_log(
            self.db,
            str(context.user.id),
            "skill.invoke",
            "skill",
            request.skill,
            context.request_id,
            context.trace_id,
            details={
                "skillInvocationId": str(invocation.id),
                "skillVersionId": str(version.id),
                "manifestHash": version.manifest_hash,
                "status": invocation.status,
            },
        )
        if commit:
            self.db.commit()
            self.db.refresh(invocation)
        return self.serialize_invocation(invocation, include_snapshots=True)

    def run_integration_skill_for_invocation(
        self,
        invocation: SkillInvocation,
        request: IntegrationSkillInput,
        context: ServiceContext,
        *,
        artifact_refs: list[dict[str, object]] | None = None,
        tool_call_refs: list[dict[str, object]] | None = None,
        connector_call_refs: list[dict[str, object]] | None = None,
        commit: bool = False,
    ) -> dict[str, object]:
        version = self.db.get(SkillVersion, invocation.skill_version_id)
        if version is None:
            raise ValueError("skill version not found")
        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=invocation.execution_id,
                root_span_name="skill.invoke",
                span_name=f"skill.{request.skill}",
                service_name="agent-service",
                attributes={
                    "skillInvocationId": str(invocation.id),
                    "skillId": request.skill,
                    "skillVersionId": str(version.id),
                    "manifestHash": version.manifest_hash,
                    "operation": request.operation,
                },
            ):
                result = self._dispatch_integration_runtime(invocation, request)
        except Exception as exc:
            serialized = self.fail_managed_invocation(invocation, str(exc))
            if commit:
                self.db.commit()
            raise

        serialized = self.complete_managed_invocation(
            invocation,
            self._to_skill_result(result),
            artifact_refs=artifact_refs,
            tool_call_refs=tool_call_refs,
            connector_call_refs=connector_call_refs,
            status="completed" if result.succeeded else "failed",
            error_message="; ".join(result.errors) if result.errors else None,
        )
        write_audit_log(
            self.db,
            str(context.user.id),
            "skill.invoke",
            "skill",
            request.skill,
            context.request_id,
            context.trace_id,
            details={
                "skillInvocationId": str(invocation.id),
                "skillVersionId": str(version.id),
                "manifestHash": version.manifest_hash,
                "status": invocation.status,
            },
        )
        if commit:
            self.db.commit()
            self.db.refresh(invocation)
            serialized = self.serialize_invocation(invocation, include_snapshots=True)
        return serialized

    def _dispatch_integration_runtime(
        self,
        invocation: SkillInvocation,
        request: IntegrationSkillInput,
    ) -> IntegrationSkillResult:
        result = self.execute_managed_runtime(
            invocation,
            request.model_dump(mode="json"),
            capabilities={
                "execute": lambda _runtime_context, _runtime_request: self.skill_registry.run(request),
            },
        )
        if not isinstance(result, IntegrationSkillResult):
            raise ValueError("managed integration Skill runtime returned an incompatible result")
        return result

    def list_invocations(
        self,
        page: int,
        page_size: int,
        *,
        skill_id: str | None = None,
        execution_id: str | None = None,
        include_snapshots: bool = False,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        statement = select(SkillInvocation).join(SkillVersion).join(Skill).order_by(SkillInvocation.created_at.desc())
        if context is not None and self._invocation_scope_required(context):
            project_ids = ScopeAuthorizationService(self.db).authorized_project_ids(context)
            execution_ids = select(Execution.id).join(TestPlan, Execution.plan_id == TestPlan.id).where(
                TestPlan.project_id.in_(project_ids),
            )
            binding_ids = select(CapabilityBinding.id).where(
                CapabilityBinding.project_id.in_({str(item) for item in project_ids}),
            )
            # Filter before counting/pagination; snapshots are not scope authority.
            statement = statement.where(or_(
                SkillInvocation.execution_id.in_(execution_ids),
                and_(SkillInvocation.execution_id.is_(None), SkillInvocation.binding_id.in_(binding_ids)),
            ))
        if skill_id:
            statement = statement.where(Skill.skill_id == skill_id)
        if execution_id:
            statement = statement.where(SkillInvocation.execution_id == UUID(str(execution_id)))
        rows, total = paginate_query(self.db, statement, page, page_size)
        return paginate_result([self.serialize_invocation(row, include_snapshots=include_snapshots) for row in rows], total, page, page_size)

    def get_invocation(
        self, invocation_id: UUID, *, include_snapshots: bool = False,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        invocation = self.db.get(SkillInvocation, invocation_id)
        if invocation is None:
            raise ValueError("skill invocation not found")
        if context is not None and self._invocation_scope_required(context):
            project_id = environment_id = None
            if invocation.execution_id is not None:
                execution = self.db.get(Execution, invocation.execution_id)
                plan = self.db.get(TestPlan, execution.plan_id) if execution else None
                if plan is not None:
                    project_id, environment_id = plan.project_id, plan.environment_id
            elif invocation.binding_id is not None:
                binding = self.db.get(CapabilityBinding, invocation.binding_id)
                if binding is not None and binding.project_id:
                    project_id = UUID(binding.project_id)
                    environment_id = UUID(binding.environment) if binding.scope_type == "environment" and binding.environment else None
            if project_id is None:
                raise ValueError("skill invocation not found")
            ScopeAuthorizationService(self.db).resolve_project(project_id, context, environment_id=environment_id)
        return self.serialize_invocation(invocation, include_snapshots=include_snapshots)

    @staticmethod
    def _invocation_scope_required(context: ServiceContext) -> bool:
        # Existing full-profile platform audit access may include historical
        # unscoped invocations; Community always requires persisted scope.
        return context.user.edition == "community" or not {"admin", "system"}.intersection(context.user.roles)

    def create_connector_binding(
        self,
        payload: ConnectorBindingRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._authorize_community_connector_scope(
            connector_name=payload.connectorName,
            scope=payload.scope,
            context=context,
        )
        self._validate_connector_binding_status(payload.status)
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="connector.binding",
            trace_id=context.trace_id,
        )
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="connector.binding",
            span_name="connector_binding.create",
            service_name="orchestrator-service",
            attributes={"connectorName": payload.connectorName},
            parent_span_id=context.parent_span_id,
        ):
            binding = SkillConnectorBinding(
                id=uuid4(),
                connector_name=payload.connectorName,
                secret_ref=payload.secretRef.strip(),
                credential_ref=payload.credentialRef.strip() if payload.credentialRef else None,
                scope=payload.scope,
                status=payload.status,
            )
            binding_snapshot = self.credential_resolver.validate_binding(
                connector_name=payload.connectorName,
                secret_ref=binding.secret_ref,
                credential_ref=binding.credential_ref,
                scope=binding.scope,
            )
            self.db.add(binding)
            self.db.flush()
            self._record_connector_binding_guardrail(binding, binding_snapshot, context)
            safe_binding = self.serialize_connector_binding(binding)
            write_audit_log(
                self.db,
                str(context.user.id),
                "connector_binding.create",
                "connector_binding",
                str(binding.id),
                context.request_id,
                context.trace_id,
                details={
                    "connectorName": payload.connectorName,
                    "projectId": safe_binding["projectId"],
                    "environmentId": safe_binding["environmentId"],
                    "configurationHash": safe_binding["configurationHash"],
                    "redactionPolicyVersion": safe_binding["redactionPolicyVersion"],
                    "secretConfigured": safe_binding["secretConfigured"],
                    "credentialConfigured": safe_binding["credentialConfigured"],
                    "status": binding.status,
                },
            )
        self.db.commit()
        self.db.refresh(binding)
        return self.serialize_connector_binding(binding)

    def list_connector_bindings(
        self,
        page: int,
        page_size: int,
        connector_name: str | None = None,
        *,
        project_id: str | None = None,
        environment_id: str | None = None,
        status: str | None = None,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        statement = select(SkillConnectorBinding).order_by(SkillConnectorBinding.created_at.desc())
        if connector_name:
            statement = statement.where(SkillConnectorBinding.connector_name == connector_name)
        if status:
            self._validate_connector_binding_status(status)
            statement = statement.where(SkillConnectorBinding.status == status)
        if context is not None and context.user.edition == "community":
            authorized = {
                str(item) for item in ScopeAuthorizationService(self.db).authorized_project_ids(context)
            }
            scoped_rows = [
                row for row in self.db.scalars(statement)
                if self._connector_scope_value(row.scope, "projectId", "project_id") in authorized
            ]
            if project_id:
                scoped_rows = [
                    row for row in scoped_rows
                    if self._connector_scope_value(row.scope, "projectId", "project_id") == project_id
                ]
            if environment_id:
                scoped_rows = [
                    row for row in scoped_rows
                    if self._connector_scope_value(row.scope, "environmentId", "environment_id") == environment_id
                ]
            total = len(scoped_rows)
            rows = scoped_rows[(page - 1) * page_size:page * page_size]
        else:
            rows, total = paginate_query(self.db, statement, page, page_size)
        items = [self.serialize_connector_binding(row) for row in rows]
        if project_id and not (context is not None and context.user.edition == "community"):
            items = [item for item in items if item.get("projectId") == project_id]
        if environment_id and not (context is not None and context.user.edition == "community"):
            items = [item for item in items if item.get("environmentId") == environment_id]
        return paginate_result(items, len(items) if project_id or environment_id else total, page, page_size)

    def get_connector_binding(
        self,
        binding_id: UUID,
        context: ServiceContext | None = None,
    ) -> dict[str, object]:
        binding = self.db.get(SkillConnectorBinding, binding_id)
        if binding is None:
            raise ValueError("connector binding not found")
        if context is not None:
            self._authorize_community_connector_scope(
                connector_name=binding.connector_name,
                scope=binding.scope,
                context=context,
            )
        return self.serialize_connector_binding(binding)

    def update_connector_binding(
        self,
        binding_id: UUID,
        payload: ConnectorBindingUpdateRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        binding = self._require_connector_binding(binding_id)
        self._authorize_community_connector_scope(
            connector_name=binding.connector_name,
            scope=binding.scope,
            context=context,
        )
        updates = payload.model_dump(exclude_unset=True)
        if "secretRef" in updates and updates["secretRef"] is not None:
            binding.secret_ref = str(updates["secretRef"]).strip()
        if "credentialRef" in updates:
            binding.credential_ref = str(updates["credentialRef"]).strip() if updates["credentialRef"] else None
        if "scope" in updates and updates["scope"] is not None:
            self._authorize_community_connector_scope(
                connector_name=binding.connector_name,
                scope=dict(updates["scope"]),
                context=context,
            )
            binding.scope = dict(updates["scope"])
        if "status" in updates and updates["status"] is not None:
            self._validate_connector_binding_status(str(updates["status"]))
            binding.status = str(updates["status"])

        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="connector.binding",
            trace_id=context.trace_id,
        )
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="connector.binding",
            span_name="connector_binding.update",
            service_name="orchestrator-service",
            attributes={"connectorBindingId": str(binding.id), "connectorName": binding.connector_name},
            parent_span_id=context.parent_span_id,
        ):
            binding_snapshot = self.credential_resolver.validate_binding(
                connector_name=binding.connector_name,
                secret_ref=binding.secret_ref,
                credential_ref=binding.credential_ref,
                scope=binding.scope,
            )
            self.db.flush()
            self._record_connector_binding_guardrail(binding, binding_snapshot, context)
            safe_binding = self.serialize_connector_binding(binding)
            write_audit_log(
                self.db,
                str(context.user.id),
                "connector_binding.update",
                "connector_binding",
                str(binding.id),
                context.request_id,
                context.trace_id,
                details={
                    "connectorName": binding.connector_name,
                    "projectId": safe_binding["projectId"],
                    "environmentId": safe_binding["environmentId"],
                    "configurationHash": safe_binding["configurationHash"],
                    "redactionPolicyVersion": safe_binding["redactionPolicyVersion"],
                    "secretConfigured": safe_binding["secretConfigured"],
                    "credentialConfigured": safe_binding["credentialConfigured"],
                    "status": binding.status,
                    "fields": sorted(updates),
                },
            )
        self.db.commit()
        self.db.refresh(binding)
        return self.serialize_connector_binding(binding)

    def archive_connector_binding(self, binding_id: UUID, context: ServiceContext) -> dict[str, object]:
        binding = self._require_connector_binding(binding_id)
        self._authorize_community_connector_scope(
            connector_name=binding.connector_name,
            scope=binding.scope,
            context=context,
        )
        binding.status = "archived"
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="connector.binding",
            trace_id=context.trace_id,
        )
        with traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="connector.binding",
            span_name="connector_binding.archive",
            service_name="orchestrator-service",
            attributes={"connectorBindingId": str(binding.id), "connectorName": binding.connector_name},
            parent_span_id=context.parent_span_id,
        ):
            write_audit_log(
                self.db,
                str(context.user.id),
                "connector_binding.archive",
                "connector_binding",
                str(binding.id),
                context.request_id,
                context.trace_id,
                details={"connectorName": binding.connector_name, "scope": binding.scope},
            )
        self.db.commit()
        self.db.refresh(binding)
        return self.serialize_connector_binding(binding)

    def ensure_builtin_skills(self) -> None:
        for manifest in BUILTIN_SKILL_MANIFESTS.values():
            skill_id = str(manifest["skillId"])
            skill = self.db.scalar(select(Skill).where(Skill.skill_id == skill_id))
            if skill is None:
                skill = Skill(
                    id=uuid4(),
                    skill_id=skill_id,
                    display_name=str(manifest["displayName"]),
                    status="active",
                )
                self.db.add(skill)
                self.db.flush()
            manifest_snapshot = self._manifest_snapshot(manifest)
            manifest_hash = self._manifest_hash(manifest_snapshot)
            version = self.db.scalar(
                select(SkillVersion).where(
                    SkillVersion.skill_ref_id == skill.id,
                    SkillVersion.version == manifest["version"],
                    SkillVersion.manifest_hash == manifest_hash,
                )
            )
            if version is None:
                self.db.add(
                    SkillVersion(
                        id=uuid4(),
                        skill_ref_id=skill.id,
                        version=str(manifest["version"]),
                        manifest_hash=manifest_hash,
                        manifest_snapshot=manifest_snapshot,
                        capabilities=dict(manifest["capabilities"]),
                        input_schema=dict(manifest["inputSchema"]),
                        output_schema=dict(manifest["outputSchema"]),
                        allowed_tools=list(manifest["allowedTools"]),
                        allowed_connectors=list(manifest["allowedConnectors"]),
                        risk_profile=dict(manifest["riskProfile"]),
                        approval_policy=dict(manifest["approvalPolicy"]),
                        data_access_policy=dict(manifest["dataAccessPolicy"]),
                        replay_policy=dict(manifest["replayPolicy"]),
                        extension_points=list(manifest.get("extensionPoints", [])),
                        compatibility=dict(manifest.get("compatibility", {})),
                        governance_status="active",
                    )
                )
            else:
                version.extension_points = list(manifest.get("extensionPoints", []))
                version.compatibility = dict(manifest.get("compatibility", {}))
                version.governance_status = "active"
        self.db.flush()

    def serialize_skill(self, skill: Skill, version: SkillVersion | None) -> dict[str, object]:
        if version is None:
            return {
                "id": str(skill.id),
                "skillId": skill.skill_id,
                "displayName": skill.display_name,
                "status": skill.status,
            }
        return {
            "id": str(skill.id),
            "skillId": skill.skill_id,
            "displayName": skill.display_name,
            "status": skill.status,
            "version": version.version,
            "manifestHash": version.manifest_hash,
            "capabilities": version.capabilities,
            "inputSchema": version.input_schema,
            "outputSchema": version.output_schema,
            "allowedTools": version.allowed_tools,
            "allowedConnectors": version.allowed_connectors,
            "riskProfile": version.risk_profile,
            "approvalPolicy": version.approval_policy,
            "dataAccessPolicy": version.data_access_policy,
            "replayPolicy": version.replay_policy,
            "extensionPoints": version.extension_points,
            "compatibility": version.compatibility,
            "runtime": self._runtime_projection(version),
            "governanceStatus": version.governance_status,
        }

    def serialize_invocation(self, invocation: SkillInvocation, *, include_snapshots: bool = False) -> dict[str, object]:
        version = self.db.get(SkillVersion, invocation.skill_version_id)
        skill = self.db.get(Skill, version.skill_ref_id) if version else None
        safe_connector_snapshot = self.connector_snapshot_builder.build(
            invocation.connector_binding_snapshot
        )
        payload: dict[str, object] = {
            "id": str(invocation.id),
            "skillId": skill.skill_id if skill else None,
            "version": version.version if version else None,
            "manifestHash": version.manifest_hash if version else None,
            "status": self._effective_invocation_status(invocation),
            "storageStatus": invocation.status,
            "idempotencyKey": invocation.idempotency_key,
            "traceId": str(invocation.trace_id) if invocation.trace_id else None,
            "executionId": str(invocation.execution_id) if invocation.execution_id else None,
            "agentRunId": str(invocation.agent_run_id) if invocation.agent_run_id else None,
            "extensionPointId": invocation.extension_point_id,
            "bindingId": str(invocation.binding_id) if invocation.binding_id else None,
            "sourceWorkflow": invocation.source_workflow,
            "resolutionSnapshot": redact_sensitive_data(invocation.resolution_snapshot),
            "connectorBindingSnapshot": safe_connector_snapshot,
            "approvalRefs": redact_sensitive_data(invocation.approval_refs),
            "artifactRefs": redact_sensitive_data(invocation.artifact_refs),
            "toolCallRefs": redact_sensitive_data(invocation.tool_call_refs),
            "connectorCallRefs": redact_sensitive_data(invocation.connector_call_refs),
            "approvalRequired": False,
            "approvalEnvelope": None,
            "createdAt": invocation.created_at.isoformat(),
            "updatedAt": invocation.updated_at.isoformat(),
        }
        if include_snapshots:
            payload.update(
                {
                    "inputSnapshot": redact_sensitive_data(invocation.input_snapshot),
                    "outputSnapshot": redact_sensitive_data(invocation.output_snapshot),
                    "policySnapshot": redact_sensitive_data(invocation.policy_snapshot),
                }
            )
        return payload

    def serialize_connector_binding(self, binding: SkillConnectorBinding) -> dict[str, object]:
        project_id = self._connector_scope_value(binding.scope, "projectId", "project_id")
        environment_id = self._connector_scope_value(binding.scope, "environmentId", "environment_id")
        safe_projection = self.connector_snapshot_builder.build(
            {
                "connectorBindingId": str(binding.id),
                "connectorType": binding.connector_name,
                "scope": binding.scope,
                "bindingRevision": 1,
                "createdAt": binding.created_at,
            }
        )
        return {
            "id": str(binding.id),
            "connectorName": binding.connector_name,
            "secretConfigured": bool(binding.secret_ref),
            "credentialConfigured": bool(binding.credential_ref),
            "scope": {
                key: value
                for key, value in safe_projection.items()
                if key in {"tenantId", "workspaceId", "projectId", "environmentId", "scopeType"}
            },
            "projectId": project_id,
            "environmentId": environment_id,
            "configurationHash": safe_projection["configurationHash"],
            "redactionPolicyVersion": safe_projection["redactionPolicyVersion"],
            "status": binding.status,
            "createdAt": binding.created_at.isoformat(),
            "updatedAt": binding.updated_at.isoformat(),
        }

    def _authorize_community_connector_scope(
        self,
        *,
        connector_name: str,
        scope: dict[str, object],
        context: ServiceContext,
    ) -> None:
        if context.user.edition != "community":
            return
        if connector_name not in {"github", "gitlab", "mock-scm"}:
            raise ValueError("COMMUNITY_CONNECTOR_NOT_ALLOWED")
        project_value = self._connector_scope_value(scope, "projectId", "project_id")
        environment_value = self._connector_scope_value(scope, "environmentId", "environment_id")
        if not project_value:
            raise ValueError("COMMUNITY_CONNECTOR_PROJECT_SCOPE_REQUIRED")
        try:
            project_id = UUID(project_value)
            environment_id = UUID(environment_value) if environment_value else None
        except ValueError as exc:
            raise ValueError("COMMUNITY_CONNECTOR_SCOPE_INVALID") from exc
        ScopeAuthorizationService(self.db).resolve_project(
            project_id,
            context,
            environment_id=environment_id,
            write=True,
        )

    def _require_capability_binding(self, binding_id: UUID) -> CapabilityBinding:
        binding = self.db.get(CapabilityBinding, binding_id)
        if binding is None:
            raise ValueError("capability binding not found")
        return binding

    def _require_bound_skill_version(self, binding: CapabilityBinding) -> SkillVersion:
        version = self.db.get(SkillVersion, binding.skill_version_id)
        if version is None:
            raise ValueError("capability binding skill version not found")
        return version

    @staticmethod
    def _require_governance_capability(
        context: ServiceContext,
        capability: str,
    ) -> None:
        if capability not in set(context.user.capabilities):
            raise PermissionError(f"{capability} capability required")

    def _authorize_binding_scope(
        self,
        binding: CapabilityBinding,
        context: ServiceContext,
        requested_scope: dict[str, object],
    ) -> dict[str, object]:
        """Derive project authority where possible; never trust tenant/workspace input."""

        project_value = binding.project_id or (
            binding.scope_id if binding.scope_type == "project" else None
        )
        if project_value:
            try:
                project_id = UUID(str(project_value))
            except ValueError as exc:
                raise ScopeAuthorizationError(
                    "SCOPE_PROJECT_NOT_FOUND"
                ) from exc
            environment_id: UUID | None = None
            raw_environment = requested_scope.get("environmentId")
            if raw_environment is None and binding.scope_type == "environment":
                raw_environment = binding.environment or binding.scope_id
            if raw_environment:
                try:
                    environment_id = UUID(str(raw_environment))
                except ValueError as exc:
                    raise ScopeAuthorizationError(
                        "SCOPE_ENVIRONMENT_NOT_FOUND"
                    ) from exc
            authority = ScopeAuthorizationService(self.db).resolve_project(
                project_id,
                context,
                environment_id=environment_id,
                write=True,
            )
            projection = authority.projection()
            for key in ("tenantId", "workspaceId", "projectId", "environmentId"):
                requested = requested_scope.get(key)
                authoritative = projection.get(key)
                if requested is not None and str(requested) != str(authoritative):
                    raise ScopeAuthorizationError("SKILL_ACTIVATION_CROSS_SCOPE_DENIED")
            return {
                **projection,
                "environment": binding.environment,
                "stage": binding.stage,
                "domain": binding.domain,
            }

        if not {"admin", "system"}.intersection(context.user.roles):
            raise ScopeAuthorizationError(
                "SKILL_ACTIVATION_PLATFORM_SCOPE_FORBIDDEN",
                status_code=403,
            )
        if requested_scope.get("projectId"):
            raise ScopeAuthorizationError("SKILL_ACTIVATION_CROSS_SCOPE_DENIED")
        return {
            "tenantId": str(requested_scope.get("tenantId") or "local-tenant"),
            "workspaceId": str(
                requested_scope.get("workspaceId") or "platform-workspace"
            ),
            "projectId": None,
            "environmentId": None,
            "environment": binding.environment,
            "stage": binding.stage,
            "domain": binding.domain,
            "scopeType": binding.scope_type,
            "scopeId": binding.scope_id,
            "serverDerived": binding.scope_type == "global",
            "accessSource": "platform_admin",
        }

    def _build_activation_validation_report(
        self,
        *,
        binding: CapabilityBinding,
        version: SkillVersion,
        context: ServiceContext,
        scope: dict[str, object],
        context_sources: Mapping[str, object] | None = None,
    ) -> SkillActivationValidationReport:
        try:
            effective_scope = self._authorize_binding_scope(binding, context, scope)
            scope_authorized = True
        except ScopeAuthorizationError:
            effective_scope = redact_sensitive_data(scope)
            scope_authorized = False
        context_available = False
        if scope_authorized:
            try:
                context_envelope = self.authorized_context_builder.build(
                    version=version,
                    extension_point_id=binding.extension_point_id,
                    context=context,
                    scope=effective_scope,
                    execution_id=None,
                    connector_binding_snapshot=None,
                    provided_contexts=context_sources,
                )
            except (ValueError, SkillContextUnavailableError):
                context_available = False
            else:
                context_available = bool(context_envelope.requiredAvailable)
        contract = self.extension_point_contracts.get(binding.extension_point_id)
        capability_satisfied = bool(
            contract
            and contract.required_capability in set(context.user.capabilities)
            and (
                version.governance_status != "draft"
                or "custom_skills.manage" in set(context.user.capabilities)
            )
        )
        return self.activation_validator.validate(
            skill=self.db.get(Skill, version.skill_ref_id)
            or (_ for _ in ()).throw(ValueError("skill not found")),
            version=version,
            extension_point_id=binding.extension_point_id,
            scope=effective_scope,
            binding_id=binding.id,
            required_capability_satisfied=capability_satisfied,
            scope_authorized=scope_authorized,
            authorized_context_available=context_available,
            runtime_contract=self._runtime_contract(version),
        )

    def _persist_binding_governance_report(
        self,
        *,
        binding: CapabilityBinding,
        version: SkillVersion,
        report_kind: str,
        report: dict[str, object],
        context: ServiceContext,
        status: str,
    ) -> dict[str, object]:
        run_id = f"skill-governance-{report_kind}-{binding.id}-{uuid4()}"
        recorder = TrajectoryRecorder(run_id)
        budget = BudgetSnapshot(
            maxTurns=2,
            maxModelCalls=0,
            maxSkillInvocations=0,
            maxToolCalls=0,
        )
        occurred_at = datetime.now(timezone.utc)
        recorder.emit(
            turn=0,
            state=HarnessRunState.RESOLVE_INTENT,
            occurred_at=occurred_at,
            budget_snapshot=budget,
            metadata={
                "reportKind": report_kind,
                "bindingId": str(binding.id),
                "skillVersionId": str(version.id),
                "nonAuthoritative": report_kind in {
                    "datasetEvaluation",
                    "shadowComparison",
                    "rollbackSuggestion",
                },
            },
        )
        terminal_state = (
            HarnessRunState.COMPLETE
            if status in {"passed", "completed", "suggested"}
            else HarnessRunState.FAILED
        )
        recorder.emit(
            turn=1,
            state=terminal_state,
            occurred_at=occurred_at,
            budget_snapshot=budget,
            metadata={"status": status, "reportKind": report_kind},
        )
        trajectory_refs = list(recorder.refs)
        report_payload = dict(report)
        if report_kind == "contractValidation":
            evidence_refs = list(report_payload.get("evidenceRefs") or [])
            evidence_refs.extend(
                {"type": "harness_trajectory", "ref": ref}
                for ref in trajectory_refs
            )
            report_payload["evidenceRefs"] = evidence_refs
            report_payload.pop("reportHash", None)
            report_payload["reportHash"] = canonical_content_hash(report_payload)
            report_payload = SkillActivationValidationReport.model_validate(
                report_payload
            ).model_dump(mode="json")
        safe_envelope = project_safe_context_content(
            {
                "schemaVersion": "phase8.skill-governance-artifact.v1",
                "reportKind": report_kind,
                "report": report_payload,
                "trajectoryRefs": trajectory_refs,
                "bindingId": str(binding.id),
                "skillVersionId": str(version.id),
                "manifestHash": version.manifest_hash,
            }
        ).content
        encoded = json.dumps(
            safe_envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            storage = self.artifact_storage.write_artifact(
                namespace="skill-governance",
                artifact_id=str(binding.id),
                filename=f"{report_kind}.json",
                payload=encoded,
            )
        except Exception as exc:
            return {
                **report_payload,
                "persistence": {
                    "status": "partial",
                    "reasonCode": "SKILL_GOVERNANCE_EVIDENCE_PERSISTENCE_UNAVAILABLE",
                    "limitations": [redact_sensitive_text(str(exc))],
                },
            }
        report_hash = str(
            report_payload.get("reportHash")
            or report_payload.get("resultHash")
            or canonical_content_hash(report_payload)
        )
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            f"skill_governance.{report_kind}",
            "capability_binding",
            str(binding.id),
            context.request_id,
            context.trace_id,
            details={
                "bindingId": str(binding.id),
                "skillVersionId": str(version.id),
                "manifestHash": version.manifest_hash,
                "reportKind": report_kind,
                "reportHash": report_hash,
                "status": status,
                "storageContentHash": storage["contentHash"],
                "trajectoryRefs": trajectory_refs,
            },
        )
        entry = {
            "schemaVersion": "phase8.skill-governance-evidence-ref.v1",
            "status": status,
            "skillVersionId": str(version.id),
            "manifestHash": version.manifest_hash,
            "reportHash": report_hash,
            "storageRef": storage["storageRef"],
            "storageContentHash": storage["contentHash"],
            "byteSize": storage["byteSize"],
            "auditRef": f"audit-log://{audit.id}",
            "trajectoryRefs": trajectory_refs,
            "recordedAt": datetime.now(timezone.utc).isoformat(),
        }
        config = dict(binding.binding_config or {})
        governance = config.get("activationGovernance")
        governance = dict(governance) if isinstance(governance, dict) else {}
        governance[report_kind] = entry
        config["activationGovernance"] = governance
        binding.binding_config = config
        binding.updated_by = context.user.id
        binding.audit_refs = self._append_ref(
            binding.audit_refs,
            {"type": "audit_log", "id": str(audit.id), "action": audit.action},
        )
        self.db.flush()
        return {**report_payload, "persistence": entry}

    @staticmethod
    def _evaluation_target_reference(
        version: SkillVersion,
        scope_hash: str,
    ) -> EvaluationTargetReference:
        return EvaluationTargetReference(
            kind="skill",
            ref=f"skill-version://{version.id}",
            version=version.version,
            contentHash=version.manifest_hash,
            scopeHash=scope_hash,
        )

    @staticmethod
    def _evaluation_dataset_reference(
        case: dict[str, object],
        scope_hash: str,
    ) -> EvaluationFrozenReference:
        raw_ref = case.get("frozenInputRef")
        if isinstance(raw_ref, dict):
            payload = {
                **raw_ref,
                "scopeHash": scope_hash,
            }
            return EvaluationFrozenReference.model_validate(payload)
        case_id = str(case.get("caseId") or "").strip()
        request = case.get("request")
        if not case_id or not isinstance(request, dict):
            raise ValueError("SKILL_EVALUATION_CASE_INPUT_REF_INVALID")
        replay_ref = case.get("replayRef")
        return EvaluationFrozenReference(
            ref=str(replay_ref or f"evaluation-case://{case_id}"),
            refType="replay_case" if replay_ref else "dataset_case",
            contentHash=canonical_content_hash(request),
            scopeHash=scope_hash,
            trustBoundary="frozen_untrusted",
            redactionStatus="redacted",
        )

    def _invoke_skill_evaluation_case(
        self,
        *,
        evaluation_id: UUID,
        case_id: str,
        request: dict[str, object],
        version: SkillVersion,
        binding_id: UUID | None,
        mode: str,
        extension_point_id: str,
        context: ServiceContext,
        scope: dict[str, object],
        capabilities: dict[str, object],
        context_sources: dict[str, object],
        approval_refs: list[dict[str, object]],
        frozen_input_ref: EvaluationFrozenReference,
    ) -> SkillEvaluationObservation:
        idempotency_key = (
            f"skill-evaluation:{evaluation_id}:{mode}:{case_id}:{version.id}"
        )
        try:
            result = self.invoke_extension(
                extension_point_id=extension_point_id,
                request=request,
                context=context,
                scope=scope,
                source_workflow="skill-version-evaluation",
                approval_refs=approval_refs,
                idempotency_key=idempotency_key,
                capabilities=capabilities,
                context_sources=context_sources,
                result_transformer=self._governance_output_snapshot,
                governance_skill_version_id=version.id,
                governance_binding_id=binding_id,
                governance_mode=mode,
                resolution_metadata={
                    "evaluationId": str(evaluation_id),
                    "evaluationCaseId": case_id,
                    "nonAuthoritative": True,
                },
            )
        except Exception as exc:
            invocation = self._invocation_by_idempotency_key(idempotency_key)
            unavailable_invocation_ref = (
                f"skill-invocation://{invocation.id}"
                if invocation is not None
                else f"skill-invocation-unavailable://{evaluation_id}/{mode}/{case_id}"
            )
            return SkillEvaluationObservation(
                caseId=case_id,
                metrics={},
                outputContractValid=False,
                invocationRef=unavailable_invocation_ref,
                evidenceRefs=[frozen_input_ref],
                limitations=[redact_sensitive_text(str(exc))],
            )
        invocation_projection = result.invocation_projection
        invocation_evidence_ref = EvaluationFrozenReference(
            ref=f"skill-invocation://{result.invocation_id}",
            refType="skill_invocation",
            contentHash=canonical_content_hash(invocation_projection),
            scopeHash=frozen_input_ref.scopeHash,
            trustBoundary="service_authorized",
            redactionStatus="redacted",
        )
        return SkillEvaluationObservation(
            caseId=case_id,
            metrics=self._evaluation_metrics_from_runtime_result(result.runtime_result),
            outputContractValid=True,
            invocationRef=invocation_evidence_ref.ref,
            evidenceRefs=[frozen_input_ref, invocation_evidence_ref],
            artifactRefs=self._evaluation_artifact_refs(
                invocation_projection,
                frozen_input_ref.scopeHash,
            ),
        )

    @staticmethod
    def _evaluation_metrics_from_runtime_result(
        result: object,
    ) -> dict[str, float]:
        metadata: object
        if isinstance(result, AgentResult):
            metadata = result.metadata
        elif isinstance(result, RunnerExecutionResult):
            metadata = result.metadata
        elif isinstance(result, dict):
            metadata = result.get("metadata")
        else:
            metadata = None
        metadata = metadata if isinstance(metadata, dict) else {}
        raw_metrics = metadata.get("evaluationMetrics")
        raw_metrics = raw_metrics if isinstance(raw_metrics, dict) else {}
        metrics: dict[str, float] = {}
        for name, value in raw_metrics.items():
            if isinstance(name, str) and isinstance(value, (int, float)):
                metrics[name] = float(value)
        return metrics

    @staticmethod
    def _evaluation_artifact_refs(
        invocation_projection: dict[str, object],
        scope_hash: str,
    ) -> list[EvaluationFrozenReference]:
        refs: list[EvaluationFrozenReference] = []
        raw_artifact_refs = invocation_projection.get("artifactRefs")
        if not isinstance(raw_artifact_refs, list):
            return refs
        for index, item in enumerate(raw_artifact_refs):
            if not isinstance(item, dict):
                continue
            value = item.get("ref") or item.get("uri") or item.get("storageRef")
            if not value:
                continue
            refs.append(
                EvaluationFrozenReference(
                    ref=str(value),
                    refType=str(item.get("type") or "artifact"),
                    contentHash=(
                        str(item["contentHash"])
                        if str(item.get("contentHash") or "").startswith("sha256:")
                        else canonical_content_hash(
                            {"index": index, "ref": str(value)}
                        )
                    ),
                    scopeHash=scope_hash,
                    trustBoundary="service_authorized",
                    redactionStatus="redacted",
                )
            )
        return refs

    @staticmethod
    def _governance_output_snapshot(result: object) -> dict[str, object]:
        if isinstance(result, AgentResult):
            return {
                "result": result.result,
                "confidence": result.confidence,
                "evidence": [
                    item
                    if isinstance(item, dict)
                    else {"type": "runtime_evidence", "ref": str(item)}
                    for item in result.evidence
                ],
                "artifactRefs": [],
                "rawFindingRefs": [],
                "findingCandidates": [],
                "metadata": {
                    **result.metadata,
                    "limitations": list(result.limitations),
                    "nonAuthoritative": True,
                },
            }
        if isinstance(result, RunnerExecutionResult):
            return {
                "result": {
                    "status": result.status,
                    "toolStatus": result.tool_status,
                    "timedOut": result.timed_out,
                    "durationMs": result.duration_ms,
                },
                "confidence": 1.0 if result.status == "completed" else 0.0,
                "evidence": [],
                "artifactRefs": [
                    {
                        "type": item.artifact_type.value,
                        "ref": item.uri,
                        "summary": item.summary,
                    }
                    for item in result.artifact_refs
                ],
                "rawFindingRefs": [
                    {"type": "raw_finding", "ref": item.raw_ref}
                    for item in result.raw_findings
                ],
                "findingCandidates": [],
                "metadata": {
                    **result.metadata,
                    "nonAuthoritative": True,
                    "canonicalFindingWrite": False,
                },
            }
        if isinstance(result, dict):
            payload = dict(result)
            if {
                "result",
                "confidence",
                "evidence",
                "artifactRefs",
                "rawFindingRefs",
                "findingCandidates",
                "metadata",
            }.issubset(payload):
                metadata = dict(payload.get("metadata") or {})
                return {**payload, "metadata": {**metadata, "nonAuthoritative": True}}
            return {
                "result": payload,
                "confidence": 1.0,
                "evidence": [],
                "artifactRefs": [],
                "rawFindingRefs": [],
                "findingCandidates": [],
                "metadata": {"nonAuthoritative": True},
            }
        raise ValueError("SKILL_GOVERNANCE_RUNTIME_RESULT_UNSUPPORTED")

    @staticmethod
    def _validate_shadow_runtime_result(
        result: object,
        _invocation: SkillInvocation,
    ) -> None:
        payload = SkillService._governance_output_snapshot(result)
        forbidden_keys = {
            "findingRefs",
            "gateDecision",
            "gateDecisionId",
            "memoryWrite",
            "memoryEntry",
            "canonicalFinding",
            "externalWrite",
            "ciWrite",
        }

        def contains_forbidden(value: object) -> bool:
            if isinstance(value, dict):
                if forbidden_keys.intersection(value):
                    return True
                return any(contains_forbidden(item) for item in value.values())
            if isinstance(value, list):
                return any(contains_forbidden(item) for item in value)
            return False

        if contains_forbidden(payload):
            raise ValueError("SKILL_SHADOW_CANONICAL_OR_EXTERNAL_WRITE_FORBIDDEN")
        if contains_unsafe_snapshot_material(payload):
            raise ValueError("SKILL_SHADOW_SECRET_SCAN_BLOCKED")

    def serialize_capability_binding(self, binding: CapabilityBinding) -> dict[str, object]:
        version = self.db.get(SkillVersion, binding.skill_version_id)
        skill = self.db.get(Skill, version.skill_ref_id) if version else None
        return {
            "schemaVersion": "phase8.capability-binding.v1",
            "stateHash": self._binding_state_hash(binding),
            "communityLifecycle": self._community_lifecycle_projection(binding, version),
            "id": str(binding.id),
            "extensionPointId": binding.extension_point_id,
            "skillId": skill.skill_id if skill else None,
            "skillVersionId": str(binding.skill_version_id),
            "version": version.version if version else None,
            "manifestHash": version.manifest_hash if version else None,
            "scopeType": binding.scope_type,
            "scopeId": binding.scope_id,
            "projectId": binding.project_id,
            "environment": binding.environment,
            "stage": binding.stage,
            "domain": binding.domain,
            "status": binding.status,
            "priority": binding.priority,
            "bindingConfig": binding.binding_config,
            "pendingChange": binding.pending_change,
            "approvalRefs": binding.approval_refs,
            "guardrailEventRefs": binding.guardrail_event_refs,
            "auditRefs": binding.audit_refs,
            "approvalRequired": bool(
                isinstance(binding.pending_change, dict)
                and binding.pending_change.get("approvalState") == "pending"
            ),
            "approvalEnvelope": self._pending_binding_approval_envelope(binding),
            "createdAt": binding.created_at.isoformat(),
            "updatedAt": binding.updated_at.isoformat(),
        }

    def _community_lifecycle_projection(self, binding: CapabilityBinding, version: SkillVersion | None) -> dict[str, object]:
        reason = None
        try:
            if version is None:
                raise ValueError("COMMUNITY_SKILL_VERSION_NOT_FOUND")
            self._validate_community_enablement_target(binding, version)
            self._ensure_skill_governance_kill_switch_clear(binding, automatic=False)
        except ValueError as exc:
            reason = str(exc)
        return {
            "policyVersion": COMMUNITY_ENABLEMENT_POLICY,
            "canEnable": reason is None and binding.status in {"draft", "disabled"},
            "canDisable": binding.status in {"draft", "active"},
            "unavailableReason": reason,
        }

    def execute_approved_capability_binding_lifecycle(
        self,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        binding = self.db.get(CapabilityBinding, UUID(str(approval_payload["bindingId"])))
        if binding is None:
            raise ValueError("capability binding not found")
        pending_change = (
            dict(binding.pending_change)
            if isinstance(binding.pending_change, dict)
            else {}
        )
        expected_state_hash = str(
            approval_payload.get("expectedBindingStateHash")
            or pending_change.get("expectedBindingStateHash")
            or ""
        )
        if not expected_state_hash or expected_state_hash != self._binding_state_hash(
            binding
        ):
            raise ValueError("SKILL_BINDING_CONCURRENT_MODIFICATION")
        proposed = dict(approval_payload.get("proposed") or {})
        target_version = self.db.get(SkillVersion, UUID(str(proposed["skillVersionId"])))
        if target_version is None:
            raise ValueError("approved skill version not found")
        self._validate_binding_status(str(proposed["status"]))
        self._validate_scope_type(str(proposed["scopeType"]))
        self._validate_binding_compatibility(str(proposed["extensionPointId"]), target_version)
        current = self._binding_snapshot(binding)
        risk = self._binding_change_risk(current, proposed, target_version=target_version)
        operation = str(approval_payload.get("operation") or "update")
        if operation == "rollback":
            return self._apply_binding_rollback(
                binding=binding,
                proposed=proposed,
                context=context,
                approval_id=approval_id,
                reason_code=str(
                    approval_payload.get("reasonCode")
                    or pending_change.get("reasonCode")
                    or "SKILL_BINDING_ROLLBACK_REQUESTED"
                ),
                automatic=False,
            )
        if str(proposed.get("status")) == "active":
            activation_scope = pending_change.get("scope")
            activation_scope = (
                dict(activation_scope) if isinstance(activation_scope, dict) else {}
            )
            self._ensure_binding_activation_eligible(
                binding=binding,
                target_version=target_version,
                context=context,
                scope=activation_scope,
                approval_id=approval_id,
            )
            if target_version.governance_status == "draft":
                target_version.governance_status = "active"
            self._disable_conflicting_active_bindings(binding)
        self._apply_capability_binding_snapshot(binding, proposed, context)
        self._record_capability_binding_lifecycle_refs(
            binding=binding,
            operation=operation,
            proposed=proposed,
            current=current,
            risk=risk,
            decision=GuardrailDecisionType.ALLOW,
            context=context,
            audit_action="capability_binding.lifecycle_applied",
            approval_id=approval_id,
        )
        binding.pending_change = {}
        binding.approval_refs = self._append_ref(
            binding.approval_refs,
            {"type": "approval", "id": str(approval_id), "decision": "approved"},
        )
        self.db.flush()
        return self.serialize_capability_binding(binding)

    def record_capability_binding_lifecycle_decision(
        self,
        approval_payload: dict[str, object],
        approval_id: UUID,
        decision: str,
        context: ServiceContext,
    ) -> dict[str, object] | None:
        binding_id = approval_payload.get("bindingId")
        if binding_id is None:
            return None
        binding = self.db.get(CapabilityBinding, UUID(str(binding_id)))
        if binding is None:
            return None
        pending_change = dict(binding.pending_change or {})
        if pending_change.get("approvalId") == str(approval_id):
            binding.pending_change = {
                **pending_change,
                "approvalState": decision,
                "decisionBy": str(context.user.id),
            }
        binding.approval_refs = self._append_ref(
            binding.approval_refs,
            {"type": "approval", "id": str(approval_id), "decision": decision},
        )
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            f"capability_binding.lifecycle_{decision}",
            "capability_binding",
            str(binding.id),
            context.request_id,
            context.trace_id,
            details={
                "bindingId": str(binding.id),
                "approvalId": str(approval_id),
                "operation": approval_payload.get("operation"),
                "riskReasons": list(approval_payload.get("riskReasons") or []),
            },
        )
        self.db.flush()
        binding.audit_refs = self._append_ref(
            binding.audit_refs,
            {"type": "audit_log", "id": str(audit.id), "action": audit.action},
        )
        self.db.flush()
        return self.serialize_capability_binding(binding)

    def _request_capability_binding_lifecycle_approval(
        self,
        *,
        binding: CapabilityBinding,
        operation: str,
        proposed: dict[str, object],
        current: dict[str, object] | None,
        risk: dict[str, object],
        context: ServiceContext,
    ) -> dict[str, object]:
        expected_state_hash = self._binding_state_hash(binding)
        refs = self._record_capability_binding_lifecycle_refs(
            binding=binding,
            operation=operation,
            proposed=proposed,
            current=current,
            risk=risk,
            decision=GuardrailDecisionType.WARN,
            context=context,
            audit_action="capability_binding.lifecycle_requested",
        )
        approval = ApprovalService(self.db).request_capability_binding_lifecycle(
            binding_id=binding.id,
            operation=operation,
            current=current,
            proposed=proposed,
            risk_reasons=list(risk.get("reasons") or []),
            guardrail_event_refs=[refs["guardrailEventRef"]],
            audit_refs=[refs["auditRef"]],
            context=context,
            commit=False,
        )
        approval_row = self.db.get(Approval, UUID(str(approval["approvalId"])))
        if approval_row is None:
            raise ValueError("capability binding lifecycle approval was not persisted")
        approval_row.payload = {
            **dict(approval_row.payload or {}),
            "expectedBindingStateHash": expected_state_hash,
        }
        approval_ref = {
            "type": "approval",
            "id": approval["approvalId"],
            "decision": "pending",
            "resourceType": approval["resourceType"],
        }
        binding.approval_refs = self._append_ref(binding.approval_refs, approval_ref)
        binding.pending_change = {
            "schemaVersion": "phase8.capability-binding.lifecycle-change.v1",
            "operation": operation,
            "approvalState": "pending",
            "approvalId": approval["approvalId"],
            "riskLevel": risk["riskLevel"],
            "riskReasons": list(risk.get("reasons") or []),
            "requestedBy": str(context.user.id),
            "current": current,
            "proposed": proposed,
            "guardrailEventRefs": [refs["guardrailEventRef"]],
            "auditRefs": [refs["auditRef"]],
            "expectedBindingStateHash": expected_state_hash,
        }
        self.db.flush()
        return {
            "approvalRequired": True,
            "approvalEnvelope": {
                "resourceType": "capability_binding",
                "approvalId": approval["approvalId"],
                "bindingId": str(binding.id),
                "operation": operation,
                "reason": "high-risk capability binding lifecycle change requires approval",
                "riskReasons": list(risk.get("reasons") or []),
            },
        }

    def _record_capability_binding_lifecycle_refs(
        self,
        *,
        binding: CapabilityBinding,
        operation: str,
        proposed: dict[str, object],
        current: dict[str, object] | None,
        risk: dict[str, object],
        decision: GuardrailDecisionType,
        context: ServiceContext,
        audit_action: str,
        approval_id: UUID | None = None,
    ) -> dict[str, dict[str, object]]:
        event = self._record_capability_binding_guardrail(
            binding=binding,
            operation=operation,
            proposed=proposed,
            current=current,
            risk=risk,
            decision=decision,
            context=context,
            approval_id=approval_id,
        )
        audit = write_audit_log(
            self.db,
            str(context.user.id),
            audit_action,
            "capability_binding",
            str(binding.id),
            context.request_id,
            context.trace_id,
            details={
                "bindingId": str(binding.id),
                "operation": operation,
                "decision": decision.value,
                "riskLevel": risk.get("riskLevel"),
                "riskReasons": list(risk.get("reasons") or []),
                "approvalId": str(approval_id) if approval_id else None,
                "current": current,
                "proposed": proposed,
            },
        )
        self.db.flush()
        guardrail_ref = {
            "type": "guardrail_event",
            "id": str(event.id),
            "ruleId": event.rule_id,
            "decision": event.decision.value,
        }
        audit_ref = {"type": "audit_log", "id": str(audit.id), "action": audit.action}
        binding.guardrail_event_refs = self._append_ref(binding.guardrail_event_refs, guardrail_ref)
        binding.audit_refs = self._append_ref(binding.audit_refs, audit_ref)
        self.db.flush()
        return {"guardrailEventRef": guardrail_ref, "auditRef": audit_ref}

    def _record_capability_binding_guardrail(
        self,
        *,
        binding: CapabilityBinding,
        operation: str,
        proposed: dict[str, object],
        current: dict[str, object] | None,
        risk: dict[str, object],
        decision: GuardrailDecisionType,
        context: ServiceContext,
        approval_id: UUID | None = None,
    ) -> GuardrailEvent:
        ensure_trace(
            self.db,
            execution_id=None,
            root_span_name="capability_binding.lifecycle",
            trace_id=context.trace_id,
        )
        event = GuardrailEvent(
            id=uuid4(),
            policy_id=self._policy_id_for_rule("capability_binding.lifecycle_preflight"),
            rule_id="capability_binding.lifecycle_preflight",
            decision=decision,
            trace_id=UUID(str(context.trace_id)),
            request_id=context.request_id,
            severity="warn" if decision == GuardrailDecisionType.WARN else "info",
            message=(
                "capability binding lifecycle change requires approval"
                if decision == GuardrailDecisionType.WARN
                else "capability binding lifecycle change allowed"
            ),
            evidence=[
                {"type": "capability_binding", "ref": str(binding.id)},
                {"type": "risk", "ref": str(risk.get("riskLevel"))},
            ],
            payload={
                "resourceType": "capability_binding",
                "resourceId": str(binding.id),
                "bindingId": str(binding.id),
                "operation": operation,
                "approvalId": str(approval_id) if approval_id else None,
                "riskLevel": risk.get("riskLevel"),
                "riskReasons": list(risk.get("reasons") or []),
                "current": current,
                "proposed": proposed,
            },
            metadata_json={"extensionPointId": proposed.get("extensionPointId")},
        )
        self.db.add(event)
        self.db.flush()
        return event

    @staticmethod
    def _validate_user_binding_config(binding_config: dict[str, object]) -> None:
        if "activationGovernance" in binding_config or "communityEnablement" in binding_config:
            raise ValueError("activationGovernance is Service-owned")

    def _authorize_community_binding_payload(
        self,
        payload: CapabilityBindingRequest,
        context: ServiceContext,
    ) -> None:
        if context.user.edition != "community":
            return
        if payload.scopeType not in {"project", "environment"} or not payload.projectId:
            raise ValueError("COMMUNITY_SKILL_PROJECT_SCOPE_REQUIRED")
        try:
            project_id = UUID(payload.projectId)
            environment_id = UUID(payload.environment) if payload.scopeType == "environment" and payload.environment else None
        except ValueError as exc:
            raise ValueError("COMMUNITY_SKILL_SCOPE_ID_INVALID") from exc
        if payload.scopeType == "environment" and environment_id is None:
            raise ValueError("COMMUNITY_SKILL_ENVIRONMENT_SCOPE_REQUIRED")
        ScopeAuthorizationService(self.db).resolve_project(
            project_id,
            context,
            environment_id=environment_id,
            write=True,
        )

    def _authorize_community_existing_binding(
        self,
        binding: CapabilityBinding,
        context: ServiceContext,
    ) -> None:
        if context.user.edition != "community":
            return
        if not binding.project_id:
            raise ValueError("capability binding not found")
        try:
            project_id = UUID(binding.project_id)
            environment_id = UUID(binding.environment) if binding.scope_type == "environment" and binding.environment else None
        except ValueError as exc:
            raise ValueError("capability binding not found") from exc
        ScopeAuthorizationService(self.db).resolve_project(
            project_id,
            context,
            environment_id=environment_id,
            write=True,
        )

    def _binding_state_hash(self, binding: CapabilityBinding) -> str:
        """Optimistic token over resolution authority, excluding observation refs."""

        return canonical_content_hash(
            {
                "bindingId": str(binding.id),
                "extensionPointId": binding.extension_point_id,
                "skillVersionId": str(binding.skill_version_id),
                "scopeType": binding.scope_type,
                "scopeId": binding.scope_id,
                "projectId": binding.project_id,
                "environment": binding.environment,
                "stage": binding.stage,
                "domain": binding.domain,
                "status": binding.status,
                "priority": binding.priority,
                "bindingConfig": binding.binding_config,
            }
        )

    def _ensure_skill_governance_kill_switch_clear(
        self,
        binding: CapabilityBinding,
        *,
        automatic: bool,
    ) -> None:
        settings = self.reliability_runtime.settings
        if settings.skill_invocation_global_kill_switch:
            raise ValueError("SKILL_GLOBAL_KILL_SWITCH_ACTIVE")
        if automatic and settings.controlled_autonomy_global_kill_switch:
            raise ValueError("CONTROLLED_AUTONOMY_GLOBAL_KILL_SWITCH_ACTIVE")
        kill_switch = binding.binding_config.get("killSwitch")
        kill_switch = kill_switch if isinstance(kill_switch, dict) else {}
        if bool(kill_switch.get("active")):
            raise ValueError("SKILL_BINDING_KILL_SWITCH_ACTIVE")

    def _ensure_binding_activation_eligible(
        self,
        *,
        binding: CapabilityBinding,
        target_version: SkillVersion,
        context: ServiceContext,
        scope: dict[str, object],
        approval_id: UUID,
    ) -> None:
        self._require_governance_capability(context, "capability_bindings.write")
        self._ensure_skill_governance_kill_switch_clear(binding, automatic=False)
        if target_version.id != binding.skill_version_id:
            raise ValueError("SKILL_ACTIVATION_TARGET_VERSION_CHANGED")
        if manifest_snapshot_hash(target_version.manifest_snapshot) != target_version.manifest_hash:
            raise ValueError("SKILL_ACTIVATION_MANIFEST_HASH_CONFLICT")
        fresh_report = self._build_activation_validation_report(
            binding=binding,
            version=target_version,
            context=context,
            scope=scope,
        )
        if not fresh_report.passed:
            raise ValueError(
                "SKILL_ACTIVATION_VALIDATION_FAILED:"
                + ",".join(fresh_report.failures)
            )
        approval = self.db.get(Approval, approval_id)
        if approval is None or approval.status != ApprovalStatus.APPROVED:
            raise ValueError("SKILL_ACTIVATION_APPROVAL_REQUIRED")
        risk_level = str(target_version.risk_profile.get("level") or "high").lower()
        if risk_level in {"medium", "high"} and approval.status != ApprovalStatus.APPROVED:
            raise ValueError("SKILL_ACTIVATION_APPROVAL_REQUIRED")

        baseline_resolution = self.resolve_binding(
            binding.extension_point_id,
            scope=self._authorize_binding_scope(binding, context, scope),
        )
        baseline_version_id = UUID(str(baseline_resolution["skillVersionId"]))
        candidate_changes_runtime = baseline_version_id != target_version.id
        if not candidate_changes_runtime:
            return
        validation_entry = self._verified_binding_governance_entry(
            binding,
            target_version,
            "contractValidation",
        )
        evaluation_entry = self._verified_binding_governance_entry(
            binding,
            target_version,
            "datasetEvaluation",
        )
        shadow_entry = self._verified_binding_governance_entry(
            binding,
            target_version,
            "shadowComparison",
        )
        if validation_entry.get("status") != "passed":
            raise ValueError("SKILL_ACTIVATION_VALIDATION_EVIDENCE_REQUIRED")
        if evaluation_entry.get("status") != "completed":
            raise ValueError("SKILL_ACTIVATION_EVALUATION_REQUIRED")
        if shadow_entry.get("status") != "completed":
            raise ValueError("SKILL_ACTIVATION_SHADOW_REQUIRED")

    def _verified_binding_governance_entry(
        self,
        binding: CapabilityBinding,
        version: SkillVersion,
        report_kind: str,
    ) -> dict[str, object]:
        config = binding.binding_config if isinstance(binding.binding_config, dict) else {}
        governance = config.get("activationGovernance")
        governance = governance if isinstance(governance, dict) else {}
        entry = governance.get(report_kind)
        if not isinstance(entry, dict):
            raise ValueError(f"SKILL_ACTIVATION_{report_kind.upper()}_EVIDENCE_REQUIRED")
        if (
            entry.get("skillVersionId") != str(version.id)
            or entry.get("manifestHash") != version.manifest_hash
        ):
            raise ValueError("SKILL_ACTIVATION_GOVERNANCE_EVIDENCE_STALE")
        storage_ref = entry.get("storageRef")
        if not isinstance(storage_ref, str):
            raise ValueError("SKILL_ACTIVATION_GOVERNANCE_EVIDENCE_UNAVAILABLE")
        try:
            payload = self.artifact_storage.read_artifact(storage_ref)
        except Exception as exc:
            raise ValueError(
                "SKILL_ACTIVATION_GOVERNANCE_EVIDENCE_UNAVAILABLE"
            ) from exc
        content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
        if content_hash != entry.get("storageContentHash"):
            raise ValueError("SKILL_ACTIVATION_GOVERNANCE_EVIDENCE_HASH_MISMATCH")
        try:
            envelope = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("SKILL_ACTIVATION_GOVERNANCE_EVIDENCE_INVALID") from exc
        if contains_unsafe_snapshot_material(envelope):
            raise ValueError("SKILL_ACTIVATION_GOVERNANCE_EVIDENCE_SECRET_SCAN_BLOCKED")
        report = envelope.get("report") if isinstance(envelope, dict) else None
        if not isinstance(report, dict):
            raise ValueError("SKILL_ACTIVATION_GOVERNANCE_EVIDENCE_INVALID")
        report_hash = str(
            report.get("reportHash")
            or report.get("resultHash")
            or canonical_content_hash(report)
        )
        if report_hash != entry.get("reportHash"):
            raise ValueError("SKILL_ACTIVATION_GOVERNANCE_REPORT_HASH_MISMATCH")
        if report.get("activationEligible") is False and report_kind != "contractValidation":
            raise ValueError("SKILL_ACTIVATION_GOVERNANCE_THRESHOLD_FAILED")
        return dict(entry)

    def _disable_conflicting_active_bindings(
        self,
        target: CapabilityBinding,
    ) -> None:
        candidates = self.db.scalars(
            select(CapabilityBinding).where(
                CapabilityBinding.extension_point_id == target.extension_point_id,
                CapabilityBinding.status == "active",
                CapabilityBinding.id != target.id,
            )
        )
        for binding in candidates:
            if (
                binding.scope_type == target.scope_type
                and binding.scope_id == target.scope_id
                and binding.project_id == target.project_id
                and binding.environment == target.environment
                and binding.stage == target.stage
                and binding.domain == target.domain
            ):
                binding.status = "disabled"

    def _apply_binding_rollback(
        self,
        *,
        binding: CapabilityBinding,
        proposed: dict[str, object],
        context: ServiceContext,
        approval_id: UUID | None,
        reason_code: str,
        automatic: bool,
    ) -> dict[str, object]:
        stable = self.db.get(SkillVersion, UUID(str(proposed["skillVersionId"])))
        if stable is None or stable.governance_status != "active":
            raise ValueError("SKILL_ROLLBACK_STABLE_VERSION_UNAVAILABLE")
        if proposed.get("manifestHash") != stable.manifest_hash:
            raise ValueError("SKILL_ROLLBACK_MANIFEST_HASH_CONFLICT")
        if manifest_snapshot_hash(stable.manifest_snapshot) != stable.manifest_hash:
            raise ValueError("SKILL_ROLLBACK_MANIFEST_HASH_CONFLICT")
        self._validate_binding_compatibility(binding.extension_point_id, stable)
        self._ensure_skill_governance_kill_switch_clear(binding, automatic=automatic)
        risk_level = str(stable.risk_profile.get("level") or "high").lower()
        if risk_level in {"medium", "high"} and approval_id is None:
            raise ValueError("SKILL_ROLLBACK_APPROVAL_REQUIRED")
        replacement = CapabilityBinding(
            id=uuid4(),
            extension_point_id=binding.extension_point_id,
            skill_version_id=stable.id,
            scope_type=binding.scope_type,
            scope_id=binding.scope_id,
            project_id=binding.project_id,
            environment=binding.environment,
            stage=binding.stage,
            domain=binding.domain,
            status="active",
            priority=binding.priority,
            binding_config={
                **dict(proposed.get("bindingConfig") or {}),
                "rollbackSourceBindingId": str(binding.id),
                "rollbackReasonCode": reason_code,
            },
            created_by=context.user.id,
            updated_by=context.user.id,
            approval_refs=(
                [
                    {
                        "type": "approval",
                        "id": str(approval_id),
                        "decision": "approved",
                    }
                ]
                if approval_id
                else []
            ),
        )
        binding.status = "disabled"
        binding.pending_change = {}
        binding.updated_by = context.user.id
        self.db.add(replacement)
        self.db.flush()
        current = self._binding_snapshot(binding)
        replacement_snapshot = self._binding_snapshot(replacement)
        risk = {
            "highRisk": risk_level in {"medium", "high"},
            "requiresApproval": risk_level in {"medium", "high"},
            "riskLevel": risk_level,
            "reasons": ["binding_rollback", reason_code],
        }
        refs = self._record_capability_binding_lifecycle_refs(
            binding=replacement,
            operation="rollback",
            proposed=replacement_snapshot,
            current=current,
            risk=risk,
            decision=GuardrailDecisionType.ALLOW,
            context=context,
            audit_action="capability_binding.rollback_applied",
            approval_id=approval_id,
        )
        rollback_evidence = {
            "schemaVersion": "phase8.skill-binding-rollback-result.v1",
            "reasonCode": reason_code,
            "sourceBindingId": str(binding.id),
            "replacementBindingId": str(replacement.id),
            "previousSkillVersionId": str(binding.skill_version_id),
            "stableSkillVersionId": str(stable.id),
            "manifestHash": stable.manifest_hash,
            "approvalRefs": list(replacement.approval_refs or []),
            "auditRefs": [refs["auditRef"]],
            "traceId": context.trace_id,
            "automatic": automatic,
            "historicalInvocationsModified": False,
            "historicalReplayModified": False,
        }
        persisted = self._persist_binding_governance_report(
            binding=replacement,
            version=stable,
            report_kind="bindingRollback",
            report=rollback_evidence,
            context=context,
            status="completed",
        )
        return {
            **self.serialize_capability_binding(replacement),
            "rollback": persisted,
        }

    def _binding_snapshot(self, binding: CapabilityBinding) -> dict[str, object]:
        version = self.db.get(SkillVersion, binding.skill_version_id)
        skill = self.db.get(Skill, version.skill_ref_id) if version else None
        if version is None or skill is None:
            raise ValueError("capability binding skill version not found")
        return self._binding_snapshot_from_fields(
            extension_point_id=binding.extension_point_id,
            skill_version_id=version.id,
            scope_type=binding.scope_type,
            scope_id=binding.scope_id,
            project_id=binding.project_id,
            environment=binding.environment,
            stage=binding.stage,
            domain=binding.domain,
            status=binding.status,
            priority=binding.priority,
            binding_config=binding.binding_config,
        )

    def _binding_snapshot_from_fields(
        self,
        *,
        extension_point_id: str,
        skill_version_id: UUID,
        scope_type: str,
        scope_id: str | None,
        project_id: str | None,
        environment: str | None,
        stage: str | None,
        domain: str | None,
        status: str,
        priority: int,
        binding_config: dict[str, object],
    ) -> dict[str, object]:
        version = self.db.get(SkillVersion, skill_version_id)
        skill = self.db.get(Skill, version.skill_ref_id) if version else None
        if version is None or skill is None:
            raise ValueError("capability binding skill version not found")
        return {
            "extensionPointId": extension_point_id,
            "skillId": skill.skill_id,
            "skillVersionId": str(skill_version_id),
            "version": version.version,
            "manifestHash": version.manifest_hash,
            "scopeType": scope_type,
            "scopeId": scope_id,
            "projectId": project_id,
            "environment": environment,
            "stage": stage,
            "domain": domain,
            "status": status,
            "priority": int(priority),
            "bindingConfig": dict(binding_config or {}),
        }

    def _target_binding_version(
        self,
        binding: CapabilityBinding,
        payload: CapabilityBindingUpdateRequest,
    ) -> SkillVersion:
        current_version = self.db.get(SkillVersion, binding.skill_version_id)
        if current_version is None:
            raise ValueError("capability binding skill version not found")
        current_skill = self.db.get(Skill, current_version.skill_ref_id)
        if current_skill is None:
            raise ValueError("capability binding skill not found")
        if payload.skillId is None and payload.version is None and payload.manifestHash is None:
            return current_version
        return self._require_skill_version(
            payload.skillId or current_skill.skill_id,
            payload.version if payload.version is not None else current_version.version,
            payload.manifestHash,
        )

    def _proposed_binding_snapshot(
        self,
        binding: CapabilityBinding,
        payload: CapabilityBindingUpdateRequest,
        target_version: SkillVersion,
    ) -> dict[str, object]:
        updates = payload.model_dump(exclude_unset=True)
        binding_config = (
            dict(updates["bindingConfig"])
            if "bindingConfig" in updates and updates["bindingConfig"] is not None
            else dict(binding.binding_config or {})
        )
        return self._binding_snapshot_from_fields(
            extension_point_id=str(updates.get("extensionPointId") or binding.extension_point_id),
            skill_version_id=target_version.id,
            scope_type=str(updates.get("scopeType") or binding.scope_type),
            scope_id=updates["scopeId"] if "scopeId" in updates else binding.scope_id,
            project_id=updates["projectId"] if "projectId" in updates else binding.project_id,
            environment=updates["environment"] if "environment" in updates else binding.environment,
            stage=updates["stage"] if "stage" in updates else binding.stage,
            domain=updates["domain"] if "domain" in updates else binding.domain,
            status=str(updates.get("status") or binding.status),
            priority=int(updates.get("priority") if updates.get("priority") is not None else binding.priority),
            binding_config=binding_config,
        )

    def _apply_capability_binding_snapshot(
        self,
        binding: CapabilityBinding,
        proposed: dict[str, object],
        context: ServiceContext,
    ) -> None:
        binding.extension_point_id = str(proposed["extensionPointId"])
        binding.skill_version_id = UUID(str(proposed["skillVersionId"]))
        binding.scope_type = str(proposed["scopeType"])
        binding.scope_id = proposed.get("scopeId") if proposed.get("scopeId") is None else str(proposed.get("scopeId"))
        binding.project_id = proposed.get("projectId") if proposed.get("projectId") is None else str(proposed.get("projectId"))
        binding.environment = proposed.get("environment") if proposed.get("environment") is None else str(proposed.get("environment"))
        binding.stage = proposed.get("stage") if proposed.get("stage") is None else str(proposed.get("stage"))
        binding.domain = proposed.get("domain") if proposed.get("domain") is None else str(proposed.get("domain"))
        binding.status = str(proposed["status"])
        binding.priority = int(proposed["priority"])
        binding.binding_config = dict(proposed.get("bindingConfig") or {})
        binding.updated_by = context.user.id

    def _binding_change_risk(
        self,
        current: dict[str, object] | None,
        proposed: dict[str, object],
        *,
        target_version: SkillVersion,
    ) -> dict[str, object]:
        reasons: list[str] = []
        if proposed.get("status") == "active" and (current is None or current.get("status") != "active"):
            reasons.append("activate_binding")
        if current is not None and current.get("skillVersionId") != proposed.get("skillVersionId"):
            reasons.append("skill_version_change")
        if current is not None and current.get("manifestHash") != target_version.manifest_hash:
            reasons.append("manifest_hash_change")
        if current is not None and current.get("extensionPointId") != proposed.get("extensionPointId"):
            reasons.append("extension_point_change")
        if current is not None and self._binding_scope_expanded(current, proposed):
            reasons.append("scope_expansion")
        high_risk = bool(reasons)
        return {
            "highRisk": high_risk,
            "requiresApproval": high_risk,
            "riskLevel": "high" if high_risk else "low",
            "reasons": sorted(set(reasons)),
        }

    def _binding_scope_expanded(self, current: dict[str, object], proposed: dict[str, object]) -> bool:
        current_type = str(current.get("scopeType") or "global")
        proposed_type = str(proposed.get("scopeType") or "global")
        if current_type != proposed_type:
            return BINDING_SCOPE_SPECIFICITY.get(proposed_type, 0) < BINDING_SCOPE_SPECIFICITY.get(current_type, 0)
        current_identifier = self._binding_scope_identifier(current)
        proposed_identifier = self._binding_scope_identifier(proposed)
        return bool(current_identifier) and not bool(proposed_identifier)

    def _binding_scope_identifier(self, snapshot: dict[str, object]) -> object:
        scope_type = str(snapshot.get("scopeType") or "global")
        if scope_type == "global":
            return None
        if scope_type == "workspace":
            return snapshot.get("scopeId")
        if scope_type == "project":
            return snapshot.get("projectId") or snapshot.get("scopeId")
        if scope_type == "environment":
            return snapshot.get("environment") or snapshot.get("scopeId")
        if scope_type == "stage":
            return snapshot.get("stage") or snapshot.get("scopeId")
        if scope_type == "domain":
            return snapshot.get("domain") or snapshot.get("scopeId")
        return snapshot.get("scopeId")

    def _ensure_no_pending_capability_binding_change(self, binding: CapabilityBinding) -> None:
        pending_change = binding.pending_change if isinstance(binding.pending_change, dict) else {}
        approval_id = pending_change.get("approvalId")
        if not approval_id or pending_change.get("approvalState") != "pending":
            return
        approval = self.db.get(Approval, UUID(str(approval_id)))
        if approval is not None and approval.status == ApprovalStatus.PENDING:
            raise ValueError("capability binding has a pending lifecycle approval")

    def _pending_binding_approval_envelope(self, binding: CapabilityBinding) -> dict[str, object] | None:
        pending_change = binding.pending_change if isinstance(binding.pending_change, dict) else {}
        if pending_change.get("approvalState") != "pending" or not pending_change.get("approvalId"):
            return None
        return {
            "resourceType": "capability_binding",
            "approvalId": str(pending_change["approvalId"]),
            "bindingId": str(binding.id),
            "operation": pending_change.get("operation"),
            "reason": "high-risk capability binding lifecycle change requires approval",
            "riskReasons": list(pending_change.get("riskReasons") or []),
        }

    def _append_ref(self, refs: list[dict[str, object]] | None, ref: dict[str, object]) -> list[dict[str, object]]:
        existing = list(refs or [])
        ref_key = (ref.get("type"), ref.get("id"), ref.get("action"), ref.get("decision"))
        if any((item.get("type"), item.get("id"), item.get("action"), item.get("decision")) == ref_key for item in existing):
            return existing
        return [*existing, ref]

    def _record_skill_guardrail_preflight(
        self,
        invocation: SkillInvocation,
        request: IntegrationSkillInput,
        context: ServiceContext,
    ) -> None:
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                policy_id=self._policy_id_for_rule("skill.invocation_preflight"),
                rule_id="skill.invocation_preflight",
                decision=GuardrailDecisionType.ALLOW,
                execution_id=invocation.execution_id,
                trace_id=invocation.trace_id,
                agent_run_id=invocation.agent_run_id,
                skill_invocation_id=invocation.id,
                request_id=context.request_id,
                severity="info",
                message="skill invocation preflight allowed",
                evidence=[{"type": "skill_request", "ref": request.skill}],
                payload={
                    "resourceType": "skill",
                    "resourceId": request.skill,
                    "operation": request.operation,
                    "skillInvocationId": str(invocation.id),
                },
                metadata_json={},
            )
        )

    def _record_connector_binding_guardrail(
        self,
        binding: SkillConnectorBinding,
        binding_snapshot: dict[str, object],
        context: ServiceContext,
    ) -> None:
        safe_projection = self.connector_snapshot_builder.build(
            {
                "connectorBindingId": str(binding.id),
                "connectorType": binding.connector_name,
                "scope": binding.scope,
                "bindingRevision": 1,
            }
        )
        self.db.add(
            GuardrailEvent(
                id=uuid4(),
                policy_id=self._policy_id_for_rule("connector.binding_ref_only"),
                rule_id="connector.binding_ref_only",
                decision=GuardrailDecisionType.ALLOW,
                connector_binding_id=binding.id,
                trace_id=UUID(str(context.trace_id)),
                request_id=context.request_id,
                severity="info",
                message="connector binding stores credential references only",
                evidence=[{"type": "connector_binding", "ref": str(binding.id)}],
                payload={
                    "resourceType": "connector",
                    "resourceId": binding.connector_name,
                    "connectorBindingId": str(binding.id),
                    "secretScheme": binding_snapshot.get("secretScheme"),
                    "credentialScheme": binding_snapshot.get("credentialScheme"),
                },
                metadata_json={"connectorBindingSnapshot": safe_projection},
            )
        )

    def _record_invocation_event(self, invocation: SkillInvocation, event_type: str, payload: dict[str, object]) -> None:
        self.db.add(
            SkillInvocationEvent(
                id=uuid4(),
                skill_invocation_id=invocation.id,
                event_type=event_type,
                payload=redact_sensitive_data(payload),
                trace_id=invocation.trace_id,
            )
        )

    def _guardrail_input_for_invocation(
        self,
        invocation: SkillInvocation,
        skill_id: str,
        request: dict[str, object],
    ) -> IntegrationSkillInput:
        return IntegrationSkillInput(
            skill=skill_id,
            operation=str(request.get("operation") or invocation.extension_point_id or "invoke"),
            provider=None,
            payload=dict(request.get("payload") or request),
            metadata={
                "sourceWorkflow": invocation.source_workflow,
                "extensionPointId": invocation.extension_point_id,
                "bindingId": str(invocation.binding_id) if invocation.binding_id else None,
            },
        )

    def _validate_binding_status(self, status_value: str) -> None:
        if status_value not in BINDING_STATUSES:
            raise ValueError("invalid capability binding status")

    def _validate_connector_binding_status(self, status_value: str) -> None:
        if status_value not in {"active", "disabled", "archived"}:
            raise ValueError("invalid connector binding status")

    def _require_connector_binding(self, binding_id: UUID) -> SkillConnectorBinding:
        binding = self.db.get(SkillConnectorBinding, binding_id)
        if binding is None:
            raise ValueError("connector binding not found")
        return binding

    def _connector_scope_value(self, scope: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = scope.get(key)
            if value is not None and str(value).strip():
                return str(value)
        return None

    def _validate_scope_type(self, scope_type: str) -> None:
        if scope_type not in BINDING_SCOPE_TYPES:
            raise ValueError("invalid capability binding scopeType")

    def _validate_binding_compatibility(self, extension_point_id: str, version: SkillVersion) -> None:
        self.extension_point_contracts.require_bindable(extension_point_id)
        extension_points = set(version.extension_points or [])
        if not extension_points:
            raise ValueError("skill version is not bindable to extension points")
        if extension_point_id not in extension_points:
            raise ValueError("skill version is not compatible with extension point")
        compatibility = version.compatibility if isinstance(version.compatibility, dict) else {}
        self.extension_point_contracts.validate_version_contract(
            extension_point_id,
            input_schema=version.input_schema,
            output_schema=version.output_schema,
            compatibility=compatibility,
        )
        if version.manifest_hash and not version.manifest_hash.startswith("sha256:"):
            raise ValueError("skill manifest hash is invalid")
        self.authorized_context_builder.validate_policy(version)
        self._validate_runtime_version(version, extension_point_id)

    def _validate_runtime_version(self, version: SkillVersion, extension_point_id: str | None) -> None:
        runtime_contract = self._runtime_contract(version)
        if extension_point_id is not None:
            contract = self.extension_point_contracts.require_bindable(extension_point_id)
            if runtime_contract.get("runtimeResultKind") not in contract.allowed_runtime_result_kinds:
                raise ValueError(
                    "managed Skill runtime result kind is incompatible with extension point: "
                    f"{extension_point_id} does not allow {runtime_contract.get('runtimeResultKind') or 'missing'}"
                )
        self.runtime_registry.validate(
            adapter_id=runtime_contract.get("runtimeAdapter"),
            result_kind=runtime_contract.get("runtimeResultKind"),
            extension_point_id=extension_point_id,
        )

    def _runtime_contract(self, version: SkillVersion) -> dict[str, str | None]:
        compatibility = version.compatibility if isinstance(version.compatibility, dict) else {}
        adapter_id = str(compatibility.get("runtimeAdapter") or "") or None
        result_kind = str(compatibility.get("runtimeResultKind") or "") or None
        if adapter_id or result_kind:
            return {"runtimeAdapter": adapter_id, "runtimeResultKind": result_kind}
        skill = self.db.get(Skill, version.skill_ref_id)
        builtin = BUILTIN_SKILL_RUNTIME_CONTRACTS.get(skill.skill_id if skill else "", {})
        return {
            "runtimeAdapter": builtin.get("runtimeAdapter"),
            "runtimeResultKind": builtin.get("runtimeResultKind"),
        }

    def _runtime_projection(self, version: SkillVersion) -> dict[str, object]:
        contract = self._runtime_contract(version)
        extension_points = list(version.extension_points or [])
        validation_extension_points: list[str | None] = list(extension_points)
        if not validation_extension_points:
            validation_extension_points.append(None)
        try:
            for extension_point_id in validation_extension_points:
                self.runtime_registry.validate(
                    adapter_id=contract.get("runtimeAdapter"),
                    result_kind=contract.get("runtimeResultKind"),
                    extension_point_id=str(extension_point_id) if extension_point_id else None,
                )
        except ValueError as exc:
            return {**contract, "registered": False, "unavailableReason": str(exc)}
        return {**contract, "registered": True, "unavailableReason": None}

    def _binding_matches_scope(self, binding: CapabilityBinding, scope_type: str, scope: dict[str, object]) -> bool:
        if binding.scope_type != scope_type:
            return False
        if scope_type == "global":
            return True
        if scope_type == "workspace":
            return self._matches_optional(binding.scope_id, scope.get("workspaceId"))
        if scope_type == "project":
            return self._matches_optional(binding.project_id or binding.scope_id, scope.get("projectId"))
        if scope_type == "environment":
            if binding.project_id and not self._matches_optional(binding.project_id, scope.get("projectId")):
                return False
            discriminator = binding.environment or binding.scope_id
            try:
                UUID(str(discriminator))
            except ValueError:
                return self._matches_optional(discriminator, scope.get("environment"))
            return self._matches_optional(discriminator, scope.get("environmentId") or scope.get("environment"))
        if scope_type == "stage":
            return self._matches_optional(binding.stage or binding.scope_id, scope.get("stage"))
        if scope_type == "domain":
            return self._matches_optional(binding.domain or binding.scope_id, scope.get("domain"))
        return False

    def _matches_optional(self, left: str | None, right: object) -> bool:
        return bool(left) and str(left) == str(right)

    def _resolution_payload(
        self,
        extension_point_id: str | None,
        *,
        skill: Skill,
        version: SkillVersion,
        binding: CapabilityBinding | None,
        source: str,
        fallback_reason: str | None,
        scope: dict[str, object],
    ) -> dict[str, object]:
        runtime_contract = self._runtime_contract(version)
        return {
            "requestedExtensionPointId": extension_point_id,
            **({"communityProfile": validate_community_presentation_manifest(version.manifest_snapshot)}
               if runtime_contract.get("runtimeAdapter") == COMMUNITY_REGRESSION_ADAPTER else {}),
            "resolvedSkillId": skill.skill_id,
            "skillId": skill.skill_id,
            "skillVersionId": str(version.id),
            "version": version.version,
            "manifestHash": version.manifest_hash,
            "runtimeAdapter": runtime_contract.get("runtimeAdapter"),
            "runtimeResultKind": runtime_contract.get("runtimeResultKind"),
            "bindingId": str(binding.id) if binding else None,
            "scope": scope,
            "bindingScopeType": binding.scope_type if binding else None,
            "source": source,
            "fallbackReason": fallback_reason,
            "capabilityDecisionRefs": [
                {
                    "type": "binding_resolution",
                    "decision": "allow",
                    "ref": f"{source}:{extension_point_id or skill.skill_id}:{version.id}",
                }
            ],
            "licenseDecisionRefs": [
                {
                    "type": "edition",
                    "decision": "not_required",
                    "ref": "resolver:not_required",
                }
            ],
            "approvalDecisionRefs": [
                {
                    "type": "approval",
                    "decision": "not_required",
                    "ref": "approval:not_required",
                }
            ],
        }

    def _enrich_resolution_decisions(
        self,
        resolution: dict[str, object],
        *,
        context: ServiceContext,
        approval_refs: list[dict[str, object]],
    ) -> dict[str, object]:
        enriched = dict(resolution)
        enriched["capabilityDecisionRefs"] = [
            *list(enriched.get("capabilityDecisionRefs") or []),
            {
                "type": "capability",
                "decision": "allow",
                "ref": f"user:{context.user.id}:skill.invoke",
                "capabilities": sorted(set(context.user.capabilities)),
            },
        ]
        enriched["licenseDecisionRefs"] = [
            *list(enriched.get("licenseDecisionRefs") or []),
            {
                "type": "edition",
                "decision": "allow",
                "ref": f"edition:{context.user.edition}",
            },
        ]
        enriched["approvalDecisionRefs"] = (
            list(approval_refs)
            if approval_refs
            else [
                *list(enriched.get("approvalDecisionRefs") or []),
                {
                    "type": "approval",
                    "decision": "not_required",
                    "ref": "approval:not_required",
                },
            ]
        )
        return enriched

    def _with_runtime_metadata(self, invocation: SkillInvocation, payload: dict[str, object]) -> dict[str, object]:
        metadata = dict(payload.get("metadata") or {})
        resolution = dict(invocation.resolution_snapshot or {})
        metadata.setdefault("runtime", "capability-gateway")
        metadata.setdefault("skillInvocationId", str(invocation.id))
        metadata.setdefault("resolvedSkillId", resolution.get("skillId") or resolution.get("resolvedSkillId"))
        metadata.setdefault("extensionPointId", invocation.extension_point_id)
        return {**payload, "metadata": metadata}

    def _with_execution_outcome_metadata(
        self,
        invocation: SkillInvocation,
        payload: dict[str, object],
    ) -> dict[str, object]:
        outcome = dict(self._execution_outcomes.get(invocation.id) or {})
        metadata = dict(payload.get("metadata") or {})
        raw_attempt_count = outcome.get("attemptCount")
        attempt_count = (
            int(raw_attempt_count)
            if isinstance(raw_attempt_count, (int, float, str))
            else 1
        )
        fallback_used = bool(
            outcome.get("fallbackUsed", False) or metadata.get("fallbackUsed", False)
        )
        fallback_reason = outcome.get("fallbackReason") or metadata.get(
            "fallbackReason"
        )
        metadata_limitations = metadata.get("limitations")
        outcome_limitations = outcome.get("limitations")
        limitations = list(
            dict.fromkeys(
                [
                    *(
                        [str(item) for item in metadata_limitations]
                        if isinstance(metadata_limitations, list)
                        else []
                    ),
                    *(
                        [str(item) for item in outcome_limitations]
                        if isinstance(outcome_limitations, list)
                        else []
                    ),
                ]
            )
        )
        metadata.update(
            {
                "fallbackUsed": fallback_used,
                "fallbackReason": fallback_reason,
                "originalAdapter": outcome.get("originalAdapter"),
                "originalVersion": outcome.get("originalVersion"),
                "actualAdapter": outcome.get("actualAdapter"),
                "actualVersion": outcome.get("actualVersion"),
                "limitations": limitations,
                "attemptCount": attempt_count,
                "executionPolicyRef": (
                    f"skill-invocation://{invocation.id}/policy-snapshot"
                ),
            }
        )
        if outcome.get("reasonCode"):
            metadata["reasonCode"] = outcome["reasonCode"]
        return {**payload, "metadata": metadata}

    def _ensure_output_within_policy(
        self,
        invocation: SkillInvocation,
        policy: SkillInvocationExecutionPolicy,
        payload: dict[str, object],
    ) -> None:
        output_size = self.reliability_runtime.json_size(payload)
        self._record_invocation_event(
            invocation,
            "output_size_checked",
            {
                "outputByteSize": output_size,
                "maxOutputBytes": policy.max_output_bytes,
                "accepted": output_size <= policy.max_output_bytes,
                "reasonCode": (
                    None
                    if output_size <= policy.max_output_bytes
                    else SkillInvocationReasonCode.OUTPUT_TOO_LARGE.value
                ),
            },
        )
        if output_size > policy.max_output_bytes:
            raise SkillInvocationExecutionError(
                SkillInvocationReasonCode.OUTPUT_TOO_LARGE,
                status="invalid_output",
            )

    def _terminal_skill_result(
        self,
        invocation: SkillInvocation,
        *,
        status: str,
        reason_code: str,
        error: str,
    ) -> dict[str, object]:
        outcome = dict(self._execution_outcomes.get(invocation.id) or {})
        raw_attempt_count = outcome.get("attemptCount")
        attempt_count = (
            int(raw_attempt_count)
            if isinstance(raw_attempt_count, (int, float, str))
            else 0
        )
        raw_limitations = outcome.get("limitations")
        limitations = list(raw_limitations) if isinstance(raw_limitations, list) else []
        return self._validate_skill_result(
            {
                "result": {},
                "confidence": 0.0,
                "evidence": [],
                "artifactRefs": [],
                "rawFindingRefs": [],
                "findingCandidates": [],
                "metadata": {
                    "status": status,
                    "reasonCode": reason_code,
                    "errors": [redact_sensitive_text(error)],
                    "fallbackUsed": bool(outcome.get("fallbackUsed", False)),
                    "fallbackReason": outcome.get("fallbackReason"),
                    "originalAdapter": outcome.get("originalAdapter"),
                    "originalVersion": outcome.get("originalVersion"),
                    "actualAdapter": outcome.get("actualAdapter"),
                    "actualVersion": outcome.get("actualVersion"),
                    "attemptCount": attempt_count,
                    "limitations": limitations
                    or [
                        "The managed Skill result was not accepted; synchronous Adapter termination is cooperative."
                    ],
                },
            }
        )

    @staticmethod
    def _effective_invocation_status(invocation: SkillInvocation) -> str:
        output = (
            invocation.output_snapshot
            if isinstance(invocation.output_snapshot, dict)
            else {}
        )
        metadata = output.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        status = str(metadata.get("status") or "")
        if status in STABLE_INVOCATION_STATUSES:
            return status
        return invocation.status

    @staticmethod
    def _invocation_reason_code(invocation: SkillInvocation) -> str | None:
        output = invocation.output_snapshot if isinstance(invocation.output_snapshot, dict) else {}
        metadata = output.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        value = metadata.get("reasonCode")
        return str(value) if value else None

    def _cancellation_probe(
        self,
        invocation: SkillInvocation,
        external_probe: CancellationProbe | None,
    ) -> CancellationProbe:
        def probe() -> bool:
            if external_probe is not None and external_probe():
                return True
            if invocation.status == "cancelled":
                return True
            if invocation.execution_id is not None:
                execution = self.db.get(Execution, invocation.execution_id)
                execution_status = getattr(execution, "status", None)
                if getattr(execution_status, "value", execution_status) == "cancelled":
                    return True
            return False

        return probe

    def _governed_fallback_target(
        self,
        extension_point_id: str | None,
        resolution: Mapping[str, object],
        scope: dict[str, object],
    ) -> dict[str, object] | None:
        if extension_point_id is None or not resolution.get("bindingId"):
            return None
        contract = self.extension_point_contracts.require_bindable(extension_point_id)
        if not contract.allow_fallback or not contract.default_skill_id:
            return None
        version = self._require_skill_version(contract.default_skill_id, None)
        skill = self._require_skill(contract.default_skill_id)
        self._validate_binding_compatibility(extension_point_id, version)
        target = self._resolution_payload(
            extension_point_id,
            skill=skill,
            version=version,
            binding=None,
            source="governed_fallback",
            fallback_reason="runtime_adapter_unavailable",
            scope=scope,
        )
        if (
            target.get("skillVersionId") == resolution.get("skillVersionId")
            and target.get("runtimeAdapter") == resolution.get("runtimeAdapter")
        ):
            return None
        return target

    @staticmethod
    def _content_hash(value: object) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def _policy_id_for_rule(self, rule_id: str) -> UUID | None:
        policy = self.db.scalar(select(GuardrailPolicy).where(GuardrailPolicy.rule_id == rule_id))
        return policy.id if policy else None

    def _to_skill_result(self, result: IntegrationSkillResult) -> dict[str, object]:
        return {
            "result": result.data,
            "confidence": 1.0 if result.succeeded else 0.0,
            "evidence": [self._serialize_evidence_ref(item) for item in result.evidence],
            "artifactRefs": [],
            "rawFindingRefs": [],
            "findingCandidates": [],
            "metadata": {
                **result.metadata,
                "skill": result.skill,
                "operation": result.operation,
                "status": result.status.value,
                "errors": result.errors,
            },
        }

    def _failed_skill_result(self, request: IntegrationSkillInput, error: str) -> dict[str, object]:
        return self._validate_skill_result({
            "result": {},
            "confidence": 0.0,
            "evidence": [],
            "artifactRefs": [],
            "rawFindingRefs": [],
            "findingCandidates": [],
            "metadata": {
                "skill": request.skill,
                "operation": request.operation,
                "status": "failed",
                "errors": [error],
            },
        })

    def _validate_skill_result(self, payload: dict[str, object]) -> dict[str, object]:
        return validate_contract("skill-result", payload)  # type: ignore[arg-type]

    def _serialize_evidence_ref(self, evidence_ref: IntegrationEvidenceRef) -> dict[str, object]:
        return {
            "type": evidence_ref.type,
            "ref": evidence_ref.ref,
            "metadata": evidence_ref.metadata,
        }

    def _requires_approval(
        self,
        manifest: dict[str, object],
        payload: SkillInvocationRequest,
        context: ServiceContext,
    ) -> bool:
        if "admin" in context.user.roles or "system" in context.user.roles:
            return False
        approval_policy = manifest.get("approvalPolicy") if isinstance(manifest.get("approvalPolicy"), dict) else {}
        manifest_risk_profile = manifest.get("riskProfile") if isinstance(manifest.get("riskProfile"), dict) else {}
        risk_profile = payload.riskProfile or manifest_risk_profile
        risk_level = str(risk_profile.get("level") or "").lower()
        return bool(approval_policy.get("required") or risk_profile.get("requiresApproval") or risk_level == "high")

    def _ensure_skill_allowed_for_user(
        self,
        manifest: dict[str, object],
        payload: SkillInvocationRequest,
        context: ServiceContext,
    ) -> None:
        if "admin" in context.user.roles or "system" in context.user.roles:
            return
        approval_policy = manifest.get("approvalPolicy") if isinstance(manifest.get("approvalPolicy"), dict) else {}
        manifest_risk_profile = manifest.get("riskProfile") if isinstance(manifest.get("riskProfile"), dict) else {}
        risk_profile = payload.riskProfile or manifest_risk_profile
        if approval_policy.get("privileged") or risk_profile.get("privileged"):
            raise ValueError("privileged skills require system/admin role")

    def _invocation_by_idempotency_key(self, idempotency_key: str) -> SkillInvocation | None:
        return self.db.scalar(select(SkillInvocation).where(SkillInvocation.idempotency_key == idempotency_key))

    def _require_skill(self, skill_id: str) -> Skill:
        skill = self.db.scalar(select(Skill).where(Skill.skill_id == skill_id))
        if skill is None:
            raise ValueError("skill not found")
        return skill

    def _require_skill_version(self, skill_id: str, version: str | None, manifest_hash: str | None = None) -> SkillVersion:
        skill = self._require_skill(skill_id)
        statement = select(SkillVersion).where(SkillVersion.skill_ref_id == skill.id)
        statement = statement.where(SkillVersion.governance_status == "active")
        if version:
            statement = statement.where(SkillVersion.version == version)
        if manifest_hash:
            statement = statement.where(SkillVersion.manifest_hash == manifest_hash)
        statement = statement.order_by(SkillVersion.created_at.desc())
        skill_version = self.db.scalar(statement)
        if skill_version is None:
            raise ValueError("skill version not found")
        return skill_version

    def _latest_version(self, skill_ref_id: UUID) -> SkillVersion | None:
        return self.db.scalar(
            select(SkillVersion)
            .where(
                SkillVersion.skill_ref_id == skill_ref_id,
                SkillVersion.governance_status == "active",
            )
            .order_by(SkillVersion.created_at.desc())
        )

    def _manifest_snapshot(self, manifest: dict[str, object]) -> dict[str, object]:
        return {
            "skillId": manifest["skillId"],
            "version": manifest["version"],
            "capabilities": manifest["capabilities"],
            "inputSchema": manifest["inputSchema"],
            "outputSchema": manifest["outputSchema"],
            "allowedTools": manifest["allowedTools"],
            "allowedConnectors": manifest["allowedConnectors"],
            "riskProfile": manifest["riskProfile"],
            "approvalPolicy": manifest["approvalPolicy"],
            "dataAccessPolicy": manifest["dataAccessPolicy"],
            "replayPolicy": manifest["replayPolicy"],
            "extensionPoints": manifest.get("extensionPoints", []),
            "compatibility": manifest.get("compatibility", {}),
        }

    def _manifest_hash(self, manifest_snapshot: dict[str, object]) -> str:
        encoded = json.dumps(manifest_snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

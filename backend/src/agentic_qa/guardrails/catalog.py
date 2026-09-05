# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class GuardrailPolicyDefinition:
    """Static metadata and defaults for one runtime guardrail rule."""

    rule_id: str
    name: str
    description: str
    owner: str
    default_enabled: bool = True
    default_decision_overrides: dict[str, str] = field(default_factory=dict)


GUARDRAIL_POLICY_CATALOG: dict[str, GuardrailPolicyDefinition] = {
    "agent_output.structured_result_required": GuardrailPolicyDefinition(
        rule_id="agent_output.structured_result_required",
        name="Structured Agent Output",
        description="Block agent responses that are not structured, evidence-backed, and confidence-scored.",
        owner="agent-service",
    ),
    "action.high_risk_operations_controlled": GuardrailPolicyDefinition(
        rule_id="action.high_risk_operations_controlled",
        name="High-Risk Action Control",
        description="Protect high-risk healing and patch generation actions with role and approval checks.",
        owner="execution-service",
    ),
    "action.visual_grounding_controlled": GuardrailPolicyDefinition(
        rule_id="action.visual_grounding_controlled",
        name="Visual Grounding Action Control",
        description="Route low-confidence, coordinate, production, and high-risk visual actions through approval-backed review.",
        owner="execution-service",
    ),
    "data.visual_artifact_redaction": GuardrailPolicyDefinition(
        rule_id="data.visual_artifact_redaction",
        name="Visual Artifact Redaction",
        description="Require visual screenshots, DOM snapshots, accessibility trees, OCR, and annotations to be redacted before persistence.",
        owner="execution-service",
    ),
    "memory_write.confirmed_fact_only": GuardrailPolicyDefinition(
        rule_id="memory_write.confirmed_fact_only",
        name="Confirmed Memory Writes",
        description="Prevent unverified or speculative information from entering long-term memory.",
        owner="memory-service",
    ),
    "model_routing.required_roles_resolved": GuardrailPolicyDefinition(
        rule_id="model_routing.required_roles_resolved",
        name="Required Model Roles Resolved",
        description="Ensure routing previews satisfy required primary, challenger, and local model expectations.",
        owner="model-gateway",
    ),
    "model_governance.mutation_preflight": GuardrailPolicyDefinition(
        rule_id="model_governance.mutation_preflight",
        name="Model Governance Mutation Preflight",
        description="Require backend-controlled preflight before model configuration, health, or capability governance operations continue.",
        owner="model-gateway",
    ),
    "routing_policy.mutation_preflight": GuardrailPolicyDefinition(
        rule_id="routing_policy.mutation_preflight",
        name="Routing Policy Mutation Preflight",
        description="Require approval-backed backend preflight before routing policy configuration changes can take effect.",
        owner="model-gateway",
    ),
    "gate_policy.mutation_preflight": GuardrailPolicyDefinition(
        rule_id="gate_policy.mutation_preflight",
        name="Gate Policy Mutation Preflight",
        description="Require project-scoped backend preflight and approval-backed review for Gate Policy governance mutations.",
        owner="orchestrator-service",
    ),
    "graph.staleness.assessment.v1": GuardrailPolicyDefinition(
        rule_id="graph.staleness.assessment.v1",
        name="Canonical Graph Staleness Assessment",
        description="Require structured evidence and fail-closed applicability status before freshness is persisted.",
        owner="orchestrator-service",
    ),
    "graph.staleness.review.v1": GuardrailPolicyDefinition(
        rule_id="graph.staleness.review.v1",
        name="Canonical Graph Staleness Review",
        description="Require approval-backed review with reason, evidence, and bounded expiry for freshness overrides.",
        owner="orchestrator-service",
    ),
    "graph.staleness.review.apply.v1": GuardrailPolicyDefinition(
        rule_id="graph.staleness.review.apply.v1",
        name="Canonical Graph Staleness Review Apply",
        description="Recheck Approval and immutable assessment context before applying review or lifecycle state.",
        owner="orchestrator-service",
    ),
    "prompt_safety.redact_sensitive_material": GuardrailPolicyDefinition(
        rule_id="prompt_safety.redact_sensitive_material",
        name="Sensitive Prompt Redaction",
        description="Redact obvious secrets before prompt or memory payloads are persisted or sent downstream.",
        owner="guardrails",
    ),
    "requirement_intake.external_link_preflight": GuardrailPolicyDefinition(
        rule_id="requirement_intake.external_link_preflight",
        name="Requirement Intake External Link Preflight",
        description="Validate external requirement document URL, host, size, timeout, text type, and redaction state before persistence.",
        owner="orchestrator-service",
    ),
    "requirement_intake.ocr_preflight": GuardrailPolicyDefinition(
        rule_id="requirement_intake.ocr_preflight",
        name="Requirement Intake OCR Preflight",
        description="Validate OCR source type, size, confidence, risk, redaction state, and ref-only evidence before confirmation.",
        owner="orchestrator-service",
    ),
    "requirement_intake.paste_preflight": GuardrailPolicyDefinition(
        rule_id="requirement_intake.paste_preflight",
        name="Requirement Intake Paste Preflight",
        description="Normalize and redact pasted requirement content and metadata before Draft persistence.",
        owner="orchestrator-service",
    ),
    "requirement_intake.upload_preflight": GuardrailPolicyDefinition(
        rule_id="requirement_intake.upload_preflight",
        name="Requirement Intake Upload Preflight",
        description="Validate uploaded requirement document type, size, parser result, redaction state, and ref-only storage boundary.",
        owner="orchestrator-service",
    ),
    "skill.invocation_preflight": GuardrailPolicyDefinition(
        rule_id="skill.invocation_preflight",
        name="Skill Invocation Preflight",
        description="Require Service-managed Skill Invocation preflight before any Skill can request Tool or Connector capabilities.",
        owner="agent-service",
    ),
    "capability_binding.lifecycle_preflight": GuardrailPolicyDefinition(
        rule_id="capability_binding.lifecycle_preflight",
        name="Capability Binding Lifecycle Preflight",
        description="Require approval-backed review before high-risk binding activation, scope expansion, or Skill version changes can take effect.",
        owner="orchestrator-service",
    ),
    "connector.binding_ref_only": GuardrailPolicyDefinition(
        rule_id="connector.binding_ref_only",
        name="Connector Binding Reference Only",
        description="Ensure connector bindings store secretRef or credentialRef references, never plaintext credentials.",
        owner="agent-service",
    ),
    "connector.requirement_document_fetch_preflight": GuardrailPolicyDefinition(
        rule_id="connector.requirement_document_fetch_preflight",
        name="Requirement Document Connector Preflight",
        description="Allow only read-only requirement document connector fetches through Service-managed Skill Invocation.",
        owner="orchestrator-service",
    ),
    "change.ingest_preflight.v1": GuardrailPolicyDefinition(
        rule_id="change.ingest_preflight.v1",
        name="Change Set Ingestion Preflight",
        description="Enforce project/repository scope, redaction, stable revision, and Service-owned normalization before Change Set persistence.",
        owner="orchestrator-service",
    ),
}


def get_guardrail_definition(rule_id: str) -> GuardrailPolicyDefinition | None:
    """Return the catalog definition for one rule when it exists."""

    return GUARDRAIL_POLICY_CATALOG.get(rule_id)


def list_guardrail_definitions() -> list[GuardrailPolicyDefinition]:
    """Return all catalog definitions in a deterministic order."""

    return [GUARDRAIL_POLICY_CATALOG[rule_id] for rule_id in sorted(GUARDRAIL_POLICY_CATALOG)]

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import CapabilityRegistry, EditionCapability, RbacRoleCapability, User, UserEntitlement


EDITION_BASIC = "basic"
EDITION_COMMUNITY = "community"
EDITION_PRO = "pro"
EDITION_ENTERPRISE = "enterprise"
VALID_EDITIONS = (EDITION_BASIC, EDITION_COMMUNITY, EDITION_PRO, EDITION_ENTERPRISE)


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    key: str
    category: str
    description: str
    risk_level: str = "low"


CAPABILITY_DEFINITIONS: tuple[CapabilityDefinition, ...] = (
    CapabilityDefinition("coverage.read", "coverage", "Read Coverage Matrix results."),
    CapabilityDefinition("coverage.proof.read", "coverage", "Read Coverage Proof Bundle results."),
    CapabilityDefinition("change.read", "change", "Read normalized Requirement and Code Change Sets."),
    CapabilityDefinition("change.create", "change", "Ingest governed sources into normalized Change Sets.", "medium"),
    CapabilityDefinition("impact.read", "impact", "Read backend-computed Capability Mapping and Impact Result projections."),
    CapabilityDefinition("impact.analyze", "impact", "Run bounded evidence-backed impact analysis from frozen inputs.", "high"),
    CapabilityDefinition("impact.manage_mapping", "impact", "Manage versioned canonical Capability Mappings.", "high"),
    CapabilityDefinition("replay.plan.read", "replay", "Read backend-computed Selective Replay plans."),
    CapabilityDefinition("replay.plan.create", "replay", "Create an immutable Selective Replay plan without executing it."),
    CapabilityDefinition("replay.read", "replay", "Read replay views."),
    CapabilityDefinition("replay.export.read", "replay", "Read replay export packages."),
    CapabilityDefinition("replay.repository.read", "replay", "Read persistent replay repository entries."),
    CapabilityDefinition("replay.repository.manage", "replay", "Manage persistent replay repository entries.", "high"),
    CapabilityDefinition("replay.compare", "replay", "Compare replay packages.", "medium"),
    CapabilityDefinition("audit.logs.read", "audit", "Read audit and structured logs."),
    CapabilityDefinition("audit.retention.manage", "audit", "Manage audit retention policy.", "high"),
    CapabilityDefinition("evidence.read", "evidence", "Read redacted Evidence Index entries and status."),
    CapabilityDefinition("evidence.query", "evidence", "Run controlled read-only Evidence queries."),
    CapabilityDefinition("evidence.raw.read", "evidence", "Read backend-redacted raw evidence projections.", "medium"),
    CapabilityDefinition("graph.read", "graph", "Reserved read access for Canonical Execution Graph data."),
    CapabilityDefinition("graph.manage", "graph", "Reserved managed write access for draft/candidate CEG topology.", "high"),
    CapabilityDefinition("graph.candidate.read", "graph", "Read Trace-derived Candidate Path observations."),
    CapabilityDefinition("graph.candidate.create", "graph", "Run the internal Trace-to-Candidate transformation.", "high"),
    CapabilityDefinition("graph.correction.read", "graph", "Read Graph Correction and controlled Promotion projections."),
    CapabilityDefinition("graph.correction.propose", "graph", "Create or edit structured Graph Correction proposals.", "high"),
    CapabilityDefinition("graph.correction.validate", "graph", "Validate structured Graph Correction proposals.", "high"),
    CapabilityDefinition("graph.promotion.assess", "graph", "Evaluate Graph Promotion eligibility from persisted evidence.", "high"),
    CapabilityDefinition("graph.promotion.promote", "graph", "Promote a validated Graph candidate through controlled governance.", "high"),
    CapabilityDefinition("graph.learning_policy.manage", "graph", "Manage versioned Graph Learning Policy and Binding.", "high"),
    CapabilityDefinition("graph.autonomy.pause", "graph", "Pause or resume controlled Graph autonomy.", "high"),
    CapabilityDefinition("graph.autonomy.configure", "graph", "Request approval-backed controlled Graph autonomy configuration for a project or environment.", "high"),
    CapabilityDefinition("graph.promotion.rollback", "graph", "Rollback to an immutable Canonical Graph version.", "high"),
    CapabilityDefinition("graph.staleness.read", "graph", "Read Canonical Graph applicability, staleness, and selection projections."),
    CapabilityDefinition("graph.staleness.assess", "graph", "Assess Canonical Graph applicability and staleness from persisted signals.", "high"),
    CapabilityDefinition("graph.staleness.review", "graph", "Request and apply human Graph staleness confirmation or bounded override.", "high"),
    CapabilityDefinition("graph.staleness.deprecate", "graph", "Request and apply approval-backed Canonical Graph deprecation.", "high"),
    CapabilityDefinition("gate_policy.read", "gate_policy", "Read project-scoped Gate Policy governance projections."),
    CapabilityDefinition("gate_policy.draft.write", "gate_policy", "Create, update, and validate Gate Policy drafts.", "high"),
    CapabilityDefinition("gate_policy.submit", "gate_policy", "Submit validated Gate Policy drafts for review.", "high"),
    CapabilityDefinition("gate_policy.review", "gate_policy", "Approve or reject Gate Policy governance reviews.", "high"),
    CapabilityDefinition("gate_policy.lifecycle.manage", "gate_policy", "Request disable, deprecate, or archive transitions.", "high"),
    CapabilityDefinition("gate_policy.simulate", "gate_policy", "Run non-authoritative Gate Policy simulation against frozen historical inputs.", "high"),
    CapabilityDefinition("gate_policy.mode.manage", "gate_policy", "Manage Observe and Shadow Gate Policy modes.", "high"),
    CapabilityDefinition("gate_policy.activate", "gate_policy", "Request approval-backed Enforce activation.", "high"),
    CapabilityDefinition("gate_policy.rollback", "gate_policy", "Request approval-backed rollback to an immutable Gate Policy version.", "high"),
    CapabilityDefinition("model.governance.manage", "model", "Manage model governance changes through approval-backed workflow.", "high"),
    CapabilityDefinition("correction.read", "correction", "Read governed correction records."),
    CapabilityDefinition("correction.apply", "correction", "Apply approved governed corrections.", "high"),
    CapabilityDefinition("correction.validate", "correction", "Validate governed corrections.", "high"),
    CapabilityDefinition("correction.rollback", "correction", "Rollback governed corrections.", "high"),
    CapabilityDefinition("correction.promote", "correction", "Promote validated corrections into CCG knowledge governance.", "high"),
    CapabilityDefinition("knowledge.read", "knowledge", "Read governed knowledge records."),
    CapabilityDefinition("knowledge.promote", "knowledge", "Reserved independent knowledge promotion capability.", "high"),
    CapabilityDefinition("knowledge.supersede", "knowledge", "Supersede governed knowledge records.", "high"),
    CapabilityDefinition("lesson.read", "knowledge", "Read project-scoped Lesson Candidate and governed promotion projections."),
    CapabilityDefinition("lesson.feedback", "knowledge", "Submit project-scoped structured feedback with evidence.", "high"),
    CapabilityDefinition("lesson.review", "knowledge", "Review evidence-backed Lesson Candidates.", "high"),
    CapabilityDefinition("lesson.promote", "knowledge", "Promote an accepted confirmed Lesson through controlled Knowledge governance.", "high"),
    CapabilityDefinition("improvement.read", "knowledge", "Read project-scoped typed Improvement Proposal projections."),
    CapabilityDefinition("improvement.create", "knowledge", "Create, edit, and validate evidence-backed Improvement Proposals.", "high"),
    CapabilityDefinition("improvement.review", "knowledge", "Submit and assess Improvement Proposals and effectiveness evidence.", "high"),
    CapabilityDefinition("improvement.route", "knowledge", "Route an approved Improvement Proposal into its target authority workflow.", "high"),
    CapabilityDefinition("governance.read", "governance", "Read project-scoped Edition, Capability, Scope, and governance readiness projections."),
    CapabilityDefinition("governance.aggregate.read", "governance", "Read minimum-visibility cross-project governance trends within an authorized workspace.", "medium"),
    CapabilityDefinition("access_control.manage", "access_control", "Manage access control settings.", "high"),
    CapabilityDefinition("project.settings.manage", "settings", "Manage project settings.", "high"),
    CapabilityDefinition("environment.settings.manage", "settings", "Manage environment settings.", "high"),
    CapabilityDefinition("project.members.manage", "settings", "Manage fixed Community project memberships.", "medium"),
    CapabilityDefinition("model.config.manage", "model", "Manage project-scoped Community model configuration and role bindings.", "medium"),
    CapabilityDefinition("connector_bindings.manage", "integrations", "Manage Community connector bindings within an authorized project.", "medium"),
    CapabilityDefinition("community_skills.manage", "skills", "Register and bind trusted low-risk local Community Skills.", "medium"),
    CapabilityDefinition("issue_tracker.sync", "integrations", "Create, update, and status-sync external issue tracker defects.", "high"),
    CapabilityDefinition("webhook.service", "integrations", "Authenticate and admit verified SCM Webhook deliveries.", "high"),
    CapabilityDefinition("pr.read", "integrations", "Read provider-neutral PR Context and Requirement Match projections."),
    CapabilityDefinition("match.review", "integrations", "Review Requirement Match candidates through a governed follow-up workflow.", "high"),
    CapabilityDefinition("admission.read", "integrations", "Read PR Admission Observe, Shadow, and Enforce runs, timelines, evidence, reviews, and CI projections."),
    CapabilityDefinition("admission.execute", "integrations", "Start the fixed service-managed PR Admission workflow.", "high"),
    CapabilityDefinition("admission.review", "integrations", "Request and decide governed human review of a non-authoritative Admission result.", "high"),
    CapabilityDefinition("admission.retry", "integrations", "Retry Admission execution through the existing approval-backed retry workflow.", "high"),
    CapabilityDefinition("admission.mode.manage", "integrations", "Select an approved Admission mode for a new run.", "high"),
    CapabilityDefinition("ci.write", "integrations", "Write a Service-owned Admission CI conclusion through a scoped SCM Connector binding.", "high"),
    CapabilityDefinition("enforce.manage", "integrations", "Request and approve governed PR Admission Enforce policy changes.", "high"),
    CapabilityDefinition("ci.retry", "integrations", "Request an approval-backed retry of a failed or unknown CI writeback attempt.", "high"),
    CapabilityDefinition("exploratory_sessions.read", "exploratory", "Read exploratory testing sessions, candidates, reports, and refs."),
    CapabilityDefinition("exploratory_sessions.manage", "exploratory", "Create and update exploratory testing sessions, notes, evidence refs, and bug candidates.", "high"),
    CapabilityDefinition("work_items.read", "workflow", "Read human WorkItem collaboration tasks."),
    CapabilityDefinition("work_items.manage", "workflow", "Create, assign, claim, and transition human WorkItems.", "high"),
    CapabilityDefinition("requirements.read", "workflow", "Read Requirement Library projections."),
    CapabilityDefinition("requirements.manage", "workflow", "Create requirement pipelines and answer clarifications.", "high"),
    CapabilityDefinition("test_plans.manage", "workflow", "Create, update, delete, and generate test plans.", "high"),
    CapabilityDefinition("executions.manage", "workflow", "Start, cancel, retry, heal, and gate executions.", "high"),
    CapabilityDefinition("skills.catalog.read", "skills", "Read Skill catalog projections."),
    CapabilityDefinition("skill_invocations.read", "skills", "Read Skill Invocation observation records."),
    CapabilityDefinition("capability_bindings.read", "skills", "Read workflow capability bindings and graph projections."),
    CapabilityDefinition("capability_bindings.write", "skills", "Create or update capability bindings.", "high"),
    CapabilityDefinition("capability_bindings.admin", "skills", "Administer capability binding lifecycle.", "high"),
    CapabilityDefinition("custom_skills.manage", "skills", "Manage custom Skill manifest lifecycle.", "high"),
)

CAPABILITY_KEYS = tuple(definition.key for definition in CAPABILITY_DEFINITIONS)

BASIC_CAPABILITIES = frozenset(
    {
        "coverage.read",
        "coverage.proof.read",
        "change.read",
        "impact.read",
        "replay.plan.read",
        "replay.read",
        "replay.export.read",
        "audit.logs.read",
        "evidence.read",
        "evidence.query",
        "graph.candidate.read",
        "graph.correction.read",
        "graph.staleness.read",
        "gate_policy.read",
        "correction.read",
        "knowledge.read",
        "lesson.read",
        "improvement.read",
        "governance.read",
        "skills.catalog.read",
        "skill_invocations.read",
        "capability_bindings.read",
        "exploratory_sessions.read",
        "work_items.read",
        "requirements.read",
        "pr.read",
        "admission.read",
    }
)

PRO_CAPABILITIES = frozenset(BASIC_CAPABILITIES | {"replay.repository.read"})

# Community is the Apache-2.0 self-hosted product edition. It is intentionally
# independent from the commercial Basic tier: Community grants only routes in
# the physically isolated OSS composition plus its bounded local mutations.
COMMUNITY_CAPABILITIES = frozenset(
    {
        "audit.logs.read",
        "capability_bindings.read",
        "capability_bindings.write",
        "change.read",
        "community_skills.manage",
        "connector_bindings.manage",
        "coverage.read",
        "environment.settings.manage",
        "executions.manage",
        "exploratory_sessions.read",
        "graph.candidate.read",
        "impact.read",
        "model.config.manage",
        "project.members.manage",
        "project.settings.manage",
        "replay.plan.read",
        "skill_invocations.read",
        "skills.catalog.read",
        "test_plans.manage",
        "work_items.read",
        "work_items.manage",
    }
)

RESERVED_CAPABILITIES = frozenset(
    {
        # Reserved for a future independent knowledge management entry.
        "knowledge.promote",
        # P10 reserves names only. Product grants and governance are follow-up work.
        "graph.read",
        "graph.manage",
        # Webhook admission is authenticated by a connector binding secret and
        # belongs only to the Service actor, never to ordinary user sessions.
        "webhook.service",
    }
)

ENTERPRISE_CAPABILITIES = frozenset(set(CAPABILITY_KEYS) - RESERVED_CAPABILITIES)

EDITION_CAPABILITIES: dict[str, frozenset[str]] = {
    EDITION_BASIC: BASIC_CAPABILITIES,
    EDITION_COMMUNITY: COMMUNITY_CAPABILITIES,
    EDITION_PRO: PRO_CAPABILITIES,
    EDITION_ENTERPRISE: ENTERPRISE_CAPABILITIES,
}

ROLE_CAPABILITY_GRANTS: dict[str, frozenset[str]] = {
    "admin": ENTERPRISE_CAPABILITIES,
    "system": frozenset(ENTERPRISE_CAPABILITIES | {"webhook.service"}),
    "user": BASIC_CAPABILITIES,
    "agent": frozenset(
        {
            "skills.catalog.read",
            "skill_invocations.read",
            "evidence.read",
            "evidence.query",
        }
    ),
}


def normalize_edition(value: str | None) -> str:
    edition = (value or EDITION_BASIC).strip().lower()
    if edition not in VALID_EDITIONS:
        return EDITION_BASIC
    return edition


def capabilities_for_edition(edition: str) -> list[str]:
    return sorted(EDITION_CAPABILITIES[normalize_edition(edition)])


class CapabilityService:
    """Service-owned capability registry and authorization checks."""

    def __init__(self, db: Session | None = None) -> None:
        self.db = db

    def ensure_seed_data(self) -> None:
        if self.db is None:
            return
        for definition in CAPABILITY_DEFINITIONS:
            existing = self.db.get(CapabilityRegistry, definition.key)
            if existing is None:
                self.db.add(
                    CapabilityRegistry(
                        capability_key=definition.key,
                        category=definition.category,
                        description=definition.description,
                        risk_level=definition.risk_level,
                    )
                )
                continue
            existing.category = definition.category
            existing.description = definition.description
            existing.risk_level = definition.risk_level
            existing.is_active = True

        for edition, capability_keys in EDITION_CAPABILITIES.items():
            for capability_key in capability_keys:
                mapping = self.db.get(EditionCapability, {"edition": edition, "capability_key": capability_key})
                if mapping is None:
                    self.db.add(EditionCapability(edition=edition, capability_key=capability_key, enabled=True))
                else:
                    mapping.enabled = True

        for role_name, capability_keys in ROLE_CAPABILITY_GRANTS.items():
            for capability_key in capability_keys:
                grant = self.db.get(RbacRoleCapability, {"role_name": role_name, "capability_key": capability_key})
                if grant is None:
                    self.db.add(RbacRoleCapability(role_name=role_name, capability_key=capability_key, effect="allow"))
                else:
                    grant.effect = "allow"

    def effective_capabilities_for_user(self, user_id: UUID, fallback_edition: str = EDITION_BASIC) -> tuple[str, list[str]]:
        edition = normalize_edition(fallback_edition)
        if self.db is None:
            return edition, capabilities_for_edition(edition)

        user = self.db.get(User, user_id)
        user_roles: list[str] = []
        if user is not None:
            edition = normalize_edition(user.edition)
            user_roles = [str(role) for role in (user.roles or [])]

        capability_keys = set(self._edition_capabilities(edition))
        role_capabilities = self._role_capabilities(user_roles)
        role_allowed = {
            item.capability_key
            for item in role_capabilities
            if item.effect == "allow" and self._capability_is_active(item.capability_key)
        }
        role_denied = {item.capability_key for item in role_capabilities if item.effect == "deny"}
        capability_keys.update(role_allowed)
        capability_keys.difference_update(role_denied)
        now = datetime.now(timezone.utc)
        entitlements = self.db.scalars(select(UserEntitlement).where(UserEntitlement.user_id == user_id)).all()
        for entitlement in entitlements:
            expires_at = entitlement.expires_at
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at is not None and expires_at <= now:
                continue
            if entitlement.effect == "deny":
                capability_keys.discard(entitlement.capability_key)
            elif entitlement.effect == "allow" and self._capability_is_active(entitlement.capability_key):
                capability_keys.add(entitlement.capability_key)
        capability_keys.discard("knowledge.promote")
        return edition, sorted(capability_keys)

    def effective_access_projection_for_user(
        self,
        user_id: UUID,
        fallback_edition: str = EDITION_BASIC,
        *,
        edition_override: str | None = None,
        capability_ceiling: Collection[str] | None = None,
    ) -> tuple[str, list[str], dict[str, object]]:
        edition, effective = self.effective_capabilities_for_user(user_id, fallback_edition)
        if edition_override is not None:
            edition = normalize_edition(edition_override)
        effective_set = set(effective)
        if capability_ceiling is not None:
            effective_set.intersection_update(capability_ceiling)
        edition_set = set(self._edition_capabilities(edition))
        role_allows: set[str] = set()
        role_denies: set[str] = set()
        entitlement_allows: set[str] = set()
        entitlement_denies: set[str] = set()
        inactive: set[str] = set()
        token_version = 0

        if self.db is not None:
            user = self.db.get(User, user_id)
            token_version = int(user.token_version) if user is not None else 0
            roles = [str(value) for value in (user.roles or [])] if user is not None else []
            for grant in self._role_capabilities(roles):
                (role_allows if grant.effect == "allow" else role_denies).add(grant.capability_key)
            now = datetime.now(timezone.utc)
            for entitlement in self.db.scalars(
                select(UserEntitlement).where(UserEntitlement.user_id == user_id)
            ):
                expires_at = entitlement.expires_at
                if expires_at is not None and expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if expires_at is not None and expires_at <= now:
                    continue
                target = entitlement_allows if entitlement.effect == "allow" else entitlement_denies
                target.add(entitlement.capability_key)
            inactive = {
                definition.key
                for definition in CAPABILITY_DEFINITIONS
                if not self._capability_is_active(definition.key)
            }

        revision_payload = {
            "userId": str(user_id),
            "tokenVersion": token_version,
            "edition": edition,
            "effective": sorted(effective_set),
            "editionCapabilities": sorted(edition_set),
            "roleAllows": sorted(role_allows),
            "roleDenies": sorted(role_denies),
            "entitlementAllows": sorted(entitlement_allows),
            "entitlementDenies": sorted(entitlement_denies),
            "inactive": sorted(inactive),
        }
        authorization_revision = "sha256:" + hashlib.sha256(
            json.dumps(revision_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        decisions: list[dict[str, object]] = []
        for definition in CAPABILITY_DEFINITIONS:
            capability = definition.key
            if capability in inactive:
                source = "inactive"
            elif capability in RESERVED_CAPABILITIES:
                source = "reserved"
            elif capability in entitlement_allows or capability in entitlement_denies:
                source = "entitlement"
            elif capability in role_allows or capability in role_denies:
                source = "role"
            elif capability in edition_set:
                source = "edition"
            else:
                source = "not_granted"
            decision_digest = hashlib.sha256(
                f"{authorization_revision}:{capability}:{capability in effective_set}:{source}".encode("utf-8")
            ).hexdigest()
            decisions.append(
                {
                    "capability": capability,
                    "granted": capability in effective_set,
                    "source": source,
                    "riskLevel": definition.risk_level,
                    "decisionRef": f"capability-decision://{decision_digest}",
                }
            )
        projection = {
            "schemaVersion": "phase8.edition-projection.v1",
            "edition": edition,
            "authorizationRevision": authorization_revision,
            "effectiveCapabilities": decisions,
            "backendAuthoritative": True,
            "editionStringAuthorizes": False,
        }
        return edition, sorted(effective_set), projection

    def _role_capabilities(self, roles: list[str]) -> list[RbacRoleCapability]:
        if self.db is None or not roles:
            return []
        return list(self.db.scalars(select(RbacRoleCapability).where(RbacRoleCapability.role_name.in_(roles))))

    def _edition_capabilities(self, edition: str) -> set[str]:
        if self.db is None:
            return set(capabilities_for_edition(edition))
        rows = self.db.scalars(
            select(EditionCapability).where(
                EditionCapability.edition == normalize_edition(edition),
                EditionCapability.enabled.is_(True),
            )
        ).all()
        if not rows:
            return set(capabilities_for_edition(edition))
        return {row.capability_key for row in rows if self._capability_is_active(row.capability_key)}

    def _capability_is_active(self, capability_key: str) -> bool:
        if self.db is None:
            return capability_key in CAPABILITY_KEYS
        row = self.db.get(CapabilityRegistry, capability_key)
        return bool(row and row.is_active)


def require_capability(user_capabilities: list[str], capability: str) -> None:
    if capability not in set(user_capabilities):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "errorCode": "CAPABILITY_REQUIRED",
                "capability": capability,
                "message": "current user edition does not grant this capability",
            },
        )

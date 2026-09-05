# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, Enum as SAEnum, ForeignKey, ForeignKeyConstraint, Index, Integer, Numeric, String, Text, UniqueConstraint, Uuid, event, func, inspect as sa_inspect, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Mapped, mapped_column

from agentic_qa.db.base import Base
from agentic_qa.domain.enums import (
    AgentRunStatus,
    ApprovalStatus,
    ApprovalType,
    ArtifactType,
    CoverageStatus,
    ExecutionStage,
    FindingCategory,
    FindingSource,
    FindingSeverity,
    FindingStatus,
    GateResult,
    GatePolicyScopeType,
    GatePolicyMode,
    GatePolicyStatus,
    GraphScope,
    GraphSource,
    GraphStatus,
    GuardrailDecisionType,
    GuardrailPolicyStatus,
    GuardrailScope,
    HealthStatus,
    IntegrationEventStatus,
    JobStatus,
    MemoryScope,
    MemoryType,
    ModelRole,
    PlanStatus,
    ProofStatus,
    ProviderType,
    RiskLevel,
    SourceType,
    TaskStatus,
    TestDomain,
    TraceabilityRelationSource,
    TraceabilityRelationStatus,
    TriageCategory,
    UserStatus,
)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


_ENUM_TYPE_NAMES = {
    GuardrailDecisionType: "guardrail_decision",
}


def _enum_type_name(enum_cls: type) -> str:
    if enum_cls in _ENUM_TYPE_NAMES:
        return _ENUM_TYPE_NAMES[enum_cls]
    name = enum_cls.__name__
    chars: list[str] = []
    for index, char in enumerate(name):
        if char.isupper() and index > 0:
            chars.append("_")
        chars.append(char.lower())
    return "".join(chars)


def db_enum(enum_cls: type) -> SAEnum:
    return SAEnum(
        enum_cls,
        values_callable=lambda values: [item.value for item in values],
        name=_enum_type_name(enum_cls),
    )


class TraceabilityRelationMixin:
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    relation_type: Mapped[str] = mapped_column(String(80), default="covers", nullable=False)
    scope_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[TraceabilityRelationStatus] = mapped_column(
        db_enum(TraceabilityRelationStatus),
        default=TraceabilityRelationStatus.CANDIDATE,
        nullable=False,
    )
    source: Mapped[TraceabilityRelationSource] = mapped_column(db_enum(TraceabilityRelationSource), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), default=Decimal("1.0"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    validated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    invalidated_reason: Mapped[str | None] = mapped_column(Text)
    trace_id: Mapped[UUID | None] = mapped_column(Uuid)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    username: Mapped[str | None] = mapped_column(String(100), unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(512))
    roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    edition: Mapped[str] = mapped_column(String(32), default="basic", nullable=False)
    status: Mapped[UserStatus] = mapped_column(db_enum(UserStatus), default=UserStatus.ACTIVE, nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("edition IN ('basic', 'community', 'pro', 'enterprise')", name="chk_users_edition"),
    )


class AuthToken(Base):
    __tablename__ = "auth_tokens"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    token_name: Mapped[str | None] = mapped_column(String(100))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'archived')", name="chk_projects_status"),
        Index("idx_projects_status", "status"),
        Index("idx_projects_created_by", "created_by"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ProjectEnvironment(Base, TimestampMixin):
    __tablename__ = "project_environments"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'disabled', 'archived')", name="chk_project_environments_status"),
        UniqueConstraint("project_id", "key", name="uq_project_environments_project_key"),
        UniqueConstraint("id", "project_id", name="uq_project_environments_id_project"),
        Index("idx_project_environments_project", "project_id"),
        Index("idx_project_environments_status", "status"),
        Index("idx_project_environments_created_by", "created_by"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    base_url: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    variables: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ProjectMember(Base, TimestampMixin):
    __tablename__ = "project_members"
    __table_args__ = (
        CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name="chk_project_members_role"),
        CheckConstraint("status IN ('active', 'inactive')", name="chk_project_members_status"),
        UniqueConstraint("project_id", "user_id", name="uq_project_members_project_user"),
        Index("idx_project_members_project", "project_id"),
        Index("idx_project_members_user", "user_id"),
        Index("idx_project_members_role", "role"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    role: Mapped[str] = mapped_column(String(32), default="viewer", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ExploratorySession(Base, TimestampMixin):
    __tablename__ = "exploratory_sessions"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'completed', 'cancelled')", name="chk_exploratory_sessions_status"),
        CheckConstraint("timebox_minutes > 0", name="chk_exploratory_sessions_timebox"),
        Index("idx_exploratory_sessions_project", "project_id"),
        Index("idx_exploratory_sessions_environment", "environment_id"),
        Index("idx_exploratory_sessions_execution", "backing_execution_id"),
        Index("idx_exploratory_sessions_status", "status"),
        Index("idx_exploratory_sessions_created_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    environment_id: Mapped[UUID] = mapped_column(ForeignKey("project_environments.id", ondelete="RESTRICT"), nullable=False)
    backing_plan_id: Mapped[UUID] = mapped_column(ForeignKey("test_plans.id", ondelete="RESTRICT"), nullable=False)
    backing_execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="RESTRICT"), nullable=False)
    charter: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    timebox_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    tester_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    tester_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    debrief: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    report_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ExploratorySessionNote(Base):
    __tablename__ = "exploratory_session_notes"
    __table_args__ = (
        CheckConstraint("note_type IN ('note', 'observation', 'risk', 'question')", name="chk_exploratory_session_notes_type"),
        Index("idx_exploratory_session_notes_session", "session_id"),
        Index("idx_exploratory_session_notes_type", "note_type"),
        Index("idx_exploratory_session_notes_created_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("exploratory_sessions.id", ondelete="CASCADE"), nullable=False)
    note_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ExploratoryBugCandidate(Base, TimestampMixin):
    __tablename__ = "exploratory_bug_candidates"
    __table_args__ = (
        CheckConstraint("status IN ('candidate', 'normalized', 'rejected')", name="chk_exploratory_bug_candidates_status"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_exploratory_bug_candidates_confidence"),
        Index("idx_exploratory_bug_candidates_session", "session_id"),
        Index("idx_exploratory_bug_candidates_raw", "raw_finding_id"),
        Index("idx_exploratory_bug_candidates_normalized", "normalized_finding_id"),
        Index("idx_exploratory_bug_candidates_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("exploratory_sessions.id", ondelete="CASCADE"), nullable=False)
    raw_finding_id: Mapped[UUID | None] = mapped_column(ForeignKey("raw_findings.id", ondelete="SET NULL"))
    normalized_finding_id: Mapped[UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    location: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="candidate", nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ExploratoryEvidenceRef(Base):
    __tablename__ = "exploratory_evidence_refs"
    __table_args__ = (
        CheckConstraint("redaction_status IN ('not_required', 'redacted', 'pending')", name="chk_exploratory_evidence_refs_redaction"),
        Index("idx_exploratory_evidence_refs_session", "session_id"),
        Index("idx_exploratory_evidence_refs_note", "note_id"),
        Index("idx_exploratory_evidence_refs_candidate", "candidate_id"),
        Index("idx_exploratory_evidence_refs_artifact", "artifact_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("exploratory_sessions.id", ondelete="CASCADE"), nullable=False)
    note_id: Mapped[UUID | None] = mapped_column(ForeignKey("exploratory_session_notes.id", ondelete="SET NULL"))
    candidate_id: Mapped[UUID | None] = mapped_column(ForeignKey("exploratory_bug_candidates.id", ondelete="SET NULL"))
    artifact_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_artifacts.id", ondelete="SET NULL"))
    evidence_type: Mapped[str] = mapped_column(String(80), nullable=False)
    ref: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    redaction_status: Mapped[str] = mapped_column(String(50), default="redacted", nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CapabilityRegistry(Base, TimestampMixin):
    __tablename__ = "capability_registry"

    capability_key: Mapped[str] = mapped_column(String(120), primary_key=True)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="chk_capability_registry_risk_level"),
    )


class EditionCapability(Base):
    __tablename__ = "edition_capabilities"

    edition: Mapped[str] = mapped_column(String(32), primary_key=True)
    capability_key: Mapped[str] = mapped_column(ForeignKey("capability_registry.capability_key", ondelete="CASCADE"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint("edition IN ('basic', 'community', 'pro', 'enterprise')", name="chk_edition_capabilities_edition"),
    )


class UserEntitlement(Base):
    __tablename__ = "user_entitlements"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    capability_key: Mapped[str] = mapped_column(ForeignKey("capability_registry.capability_key", ondelete="CASCADE"), nullable=False)
    effect: Mapped[str] = mapped_column(String(16), default="allow", nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint("effect IN ('allow', 'deny')", name="chk_user_entitlements_effect"),
        UniqueConstraint("user_id", "capability_key", name="uq_user_entitlements_user_capability"),
        Index("idx_user_entitlements_user_id", "user_id"),
        Index("idx_user_entitlements_capability_key", "capability_key"),
    )


class RbacRoleCapability(Base):
    __tablename__ = "rbac_role_capabilities"

    role_name: Mapped[str] = mapped_column(String(80), primary_key=True)
    capability_key: Mapped[str] = mapped_column(ForeignKey("capability_registry.capability_key", ondelete="CASCADE"), primary_key=True)
    effect: Mapped[str] = mapped_column(String(16), default="allow", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint("effect IN ('allow', 'deny')", name="chk_rbac_role_capabilities_effect"),
        Index("idx_rbac_role_capabilities_capability", "capability_key"),
        Index("idx_rbac_role_capabilities_effect", "effect"),
    )


class Model(Base, TimestampMixin):
    __tablename__ = "models"
    __table_args__ = (
        ForeignKeyConstraint(
            ["environment_id", "project_id"],
            ["project_environments.id", "project_environments.project_id"],
            name="fk_models_environment_project",
            ondelete="CASCADE",
        ),
        Index("idx_models_project_id", "project_id"),
        Index("idx_models_environment_id", "environment_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    project_id: Mapped[UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    environment_id: Mapped[UUID | None] = mapped_column(ForeignKey("project_environments.id", ondelete="CASCADE"))
    provider: Mapped[ProviderType] = mapped_column(db_enum(ProviderType), nullable=False)
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text)
    api_key_ref: Mapped[str | None] = mapped_column(String(255))
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    health_status: Mapped[HealthStatus] = mapped_column(db_enum(HealthStatus), default=HealthStatus.UNKNOWN, nullable=False)
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ModelRoleBinding(Base):
    __tablename__ = "model_roles"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    model_id: Mapped[UUID] = mapped_column(ForeignKey("models.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[ModelRole] = mapped_column(db_enum(ModelRole), nullable=False)
    weight: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ModelHealthCheck(Base):
    __tablename__ = "model_health_checks"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    model_id: Mapped[UUID] = mapped_column(ForeignKey("models.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[HealthStatus] = mapped_column(db_enum(HealthStatus), nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ModelCapabilityScan(Base):
    __tablename__ = "model_capability_scans"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    model_id: Mapped[UUID] = mapped_column(ForeignKey("models.id", ondelete="CASCADE"), nullable=False)
    scanner: Mapped[str] = mapped_column(String(120), default="model-gateway-config", nullable=False)
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_model_capability_scans_model_id", "model_id"),
        Index("idx_model_capability_scans_scanned_at", "scanned_at"),
    )


class RoutingPolicy(Base, TimestampMixin):
    __tablename__ = "routing_policies"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    task_type: Mapped[str] = mapped_column(String(100), nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(db_enum(RiskLevel), nullable=False)
    requires_tools: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requires_vision: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requires_json: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    data_sensitivity: Mapped[str] = mapped_column(String(50), default="internal", nullable=False)
    prefer_local: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    challenger_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    fallback_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    human_approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class GuardrailPolicy(Base, TimestampMixin):
    __tablename__ = "guardrail_policies"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[GuardrailScope] = mapped_column(db_enum(GuardrailScope), nullable=False)
    status: Mapped[GuardrailPolicyStatus] = mapped_column(
        db_enum(GuardrailPolicyStatus),
        default=GuardrailPolicyStatus.ACTIVE,
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    decision_override: Mapped[GuardrailDecisionType | None] = mapped_column(db_enum(GuardrailDecisionType))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class GuardrailPolicyVersion(Base):
    __tablename__ = "guardrail_policy_versions"
    __table_args__ = (
        UniqueConstraint("policy_id", "version_no", name="uq_guardrail_policy_versions_policy_version"),
        Index("idx_guardrail_policy_versions_rule", "rule_id"),
        Index("idx_guardrail_policy_versions_policy", "policy_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(ForeignKey("guardrail_policies.id", ondelete="CASCADE"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    version_no: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[GuardrailPolicyStatus] = mapped_column(db_enum(GuardrailPolicyStatus), nullable=False)
    decision_override: Mapped[GuardrailDecisionType | None] = mapped_column(db_enum(GuardrailDecisionType))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    change_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RequirementVersion(Base, TimestampMixin):
    __tablename__ = "requirement_versions"
    __table_args__ = (
        UniqueConstraint("source_ref", "version_no", name="uq_requirement_version_number"),
        UniqueConstraint("source_ref", "content_hash", name="uq_requirement_version_content"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    source_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    version_no: Mapped[int] = mapped_column(Integer, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    document: Mapped[str] = mapped_column(Text, nullable=False)
    requirements: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    acceptance_criteria: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ChangeSourceSnapshot(Base):
    __tablename__ = "change_source_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "project_id",
            "source_type",
            "source_id",
            "revision",
            "content_hash",
            name="uq_change_source_snapshots_identity",
        ),
        Index(
            "idx_change_source_snapshots_scope",
            "tenant_id",
            "workspace_id",
            "project_id",
            "acquired_at",
        ),
        Index("idx_change_source_snapshots_source", "source_type", "source_id", "revision"),
        CheckConstraint("length(content_hash) = 71", name="chk_change_source_snapshots_content_hash"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    environment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("project_environments.id", ondelete="SET NULL")
    )
    source_type: Mapped[str] = mapped_column(String(80), nullable=False)
    source_id: Mapped[str] = mapped_column(String(500), nullable=False)
    revision: Mapped[str] = mapped_column(String(255), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    snapshot_ref: Mapped[str] = mapped_column(String(1000), unique=True, nullable=False)
    source_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    snapshot_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ChangeSetRecord(Base):
    __tablename__ = "change_sets"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "fingerprint", name="uq_change_sets_fingerprint"
        ),
        CheckConstraint("change_set_type IN ('requirement', 'code')", name="chk_change_sets_type"),
        CheckConstraint("status IN ('completed', 'partial', 'unknown')", name="chk_change_sets_status"),
        CheckConstraint("item_count >= 0 AND issue_count >= 0", name="chk_change_sets_counts"),
        CheckConstraint("length(fingerprint) = 71", name="chk_change_sets_fingerprint"),
        Index("idx_change_sets_scope", "tenant_id", "workspace_id", "project_id", "created_at"),
        Index("idx_change_sets_source_snapshot", "source_snapshot_id"),
        Index("idx_change_sets_type_status", "change_set_type", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    environment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("project_environments.id", ondelete="SET NULL")
    )
    source_snapshot_id: Mapped[UUID] = mapped_column(
        ForeignKey("change_source_snapshots.id", ondelete="RESTRICT"), nullable=False
    )
    change_set_type: Mapped[str] = mapped_column(String(32), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    normalizer_version: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    issue_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RequirementChangeSetRecord(Base):
    __tablename__ = "requirement_change_sets"
    __table_args__ = (
        Index("idx_requirement_change_sets_head", "head_requirement_version_id"),
        Index("idx_requirement_change_sets_base", "base_requirement_version_id"),
    )

    change_set_id: Mapped[UUID] = mapped_column(
        ForeignKey("change_sets.id", ondelete="CASCADE"), primary_key=True
    )
    base_requirement_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("requirement_versions.id", ondelete="RESTRICT")
    )
    head_requirement_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("requirement_versions.id", ondelete="RESTRICT"), nullable=False
    )


class RequirementChangeItemRecord(Base):
    __tablename__ = "requirement_change_items"
    __table_args__ = (
        CheckConstraint(
            "change_type IN ('add', 'update', 'remove', 'rename', 'split', 'merge', 'unknown')",
            name="chk_requirement_change_items_type",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_requirement_change_items_confidence"),
        UniqueConstraint("change_set_id", "ordinal", name="uq_requirement_change_items_ordinal"),
        Index("idx_requirement_change_items_requirement", "requirement_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    change_set_id: Mapped[UUID] = mapped_column(
        ForeignKey("requirement_change_sets.change_set_id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(255), nullable=False)
    before_requirement_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("requirement_versions.id", ondelete="RESTRICT")
    )
    after_requirement_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("requirement_versions.id", ondelete="RESTRICT")
    )
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    before_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    after_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    changed_fields: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    explicit_capability_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    related_requirement_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


class CodeChangeSetRecord(Base):
    __tablename__ = "code_change_sets"
    __table_args__ = (
        CheckConstraint("base_sha <> head_sha OR empty_diff = TRUE", name="chk_code_change_sets_revision"),
        Index("idx_code_change_sets_repository", "repository_ref", "head_sha"),
    )

    change_set_id: Mapped[UUID] = mapped_column(
        ForeignKey("change_sets.id", ondelete="CASCADE"), primary_key=True
    )
    repository_ref: Mapped[str] = mapped_column(String(1000), nullable=False)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    empty_diff: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    force_push: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    base_reachable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class CodeChangeFileRecord(Base):
    __tablename__ = "code_change_files"
    __table_args__ = (
        CheckConstraint(
            "change_type IN ('add', 'update', 'remove', 'rename', 'copy', 'unknown')",
            name="chk_code_change_files_type",
        ),
        UniqueConstraint("change_set_id", "ordinal", name="uq_code_change_files_ordinal"),
        UniqueConstraint("change_set_id", "path", name="uq_code_change_files_path"),
        Index("idx_code_change_files_path", "path"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    change_set_id: Mapped[UUID] = mapped_column(
        ForeignKey("code_change_sets.change_set_id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    path: Mapped[str] = mapped_column(String(2000), nullable=False)
    old_path: Mapped[str | None] = mapped_column(String(2000))
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    language: Mapped[str | None] = mapped_column(String(80))
    binary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    generated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    vendor: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    submodule: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_hints: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    diff_artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


class CodeChangeHunkRecord(Base):
    __tablename__ = "code_change_hunks"
    __table_args__ = (
        UniqueConstraint("file_id", "ordinal", name="uq_code_change_hunks_ordinal"),
        CheckConstraint("redaction_count >= 0", name="chk_code_change_hunks_redaction_count"),
        CheckConstraint("length(content_hash) = 71", name="chk_code_change_hunks_content_hash"),
        Index("idx_code_change_hunks_file", "file_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    file_id: Mapped[UUID] = mapped_column(
        ForeignKey("code_change_files.id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    header: Mapped[str] = mapped_column(String(500), nullable=False)
    old_line_start: Mapped[int | None] = mapped_column(Integer)
    old_line_count: Mapped[int | None] = mapped_column(Integer)
    new_line_start: Mapped[int | None] = mapped_column(Integer)
    new_line_count: Mapped[int | None] = mapped_column(Integer)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    diff_artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    redaction_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class CodeChangeSymbolRecord(Base):
    __tablename__ = "code_change_symbols"
    __table_args__ = (
        CheckConstraint(
            "change_type IN ('add', 'update', 'remove', 'unknown')",
            name="chk_code_change_symbols_type",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_code_change_symbols_confidence"),
        UniqueConstraint("hunk_id", "ordinal", name="uq_code_change_symbols_ordinal"),
        Index("idx_code_change_symbols_name", "name"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    hunk_id: Mapped[UUID] = mapped_column(
        ForeignKey("code_change_hunks.id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    kind: Mapped[str] = mapped_column(String(80), nullable=False)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    old_line_start: Mapped[int | None] = mapped_column(Integer)
    old_line_end: Mapped[int | None] = mapped_column(Integer)
    new_line_start: Mapped[int | None] = mapped_column(Integer)
    new_line_end: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


class ChangeNormalizationIssueRecord(Base):
    __tablename__ = "change_normalization_issues"
    __table_args__ = (
        CheckConstraint(
            "category IN ('incomplete', 'ambiguous', 'unsupported', 'sensitive')",
            name="chk_change_normalization_issues_category",
        ),
        UniqueConstraint("change_set_id", "ordinal", name="uq_change_normalization_issues_ordinal"),
        Index("idx_change_normalization_issues_category", "category"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    change_set_id: Mapped[UUID] = mapped_column(
        ForeignKey("change_sets.id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    code: Mapped[str] = mapped_column(String(120), nullable=False)
    message: Mapped[str] = mapped_column(String(1000), nullable=False)
    field: Mapped[str | None] = mapped_column(String(255))
    recoverable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


def _protect_append_only_change_set_record(*_: Any, **__: Any) -> None:
    raise ValueError("Requirement and Code Change Set records are immutable")


for _change_set_fact in (
    ChangeSourceSnapshot,
    ChangeSetRecord,
    RequirementChangeSetRecord,
    RequirementChangeItemRecord,
    CodeChangeSetRecord,
    CodeChangeFileRecord,
    CodeChangeHunkRecord,
    CodeChangeSymbolRecord,
    ChangeNormalizationIssueRecord,
):
    event.listen(_change_set_fact, "before_update", _protect_append_only_change_set_record)
    event.listen(_change_set_fact, "before_delete", _protect_append_only_change_set_record)


class CapabilityMappingRecord(Base):
    """Versioned, evidence-backed canonical mapping owned by the P18 Service boundary."""

    __tablename__ = "capability_mappings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "mapping_key", "version",
            name="uq_capability_mappings_version",
        ),
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "idempotency_key",
            name="uq_capability_mappings_idempotency",
        ),
        CheckConstraint(
            "source_entity_type IN ('requirement', 'code_path', 'code_symbol', 'test')",
            name="chk_capability_mappings_entity_type",
        ),
        CheckConstraint(
            "mapping_source IN ('manual', 'explicit_configuration', 'verified_traceability', "
            "'static_symbol_coverage', 'historical_evidence')",
            name="chk_capability_mappings_source",
        ),
        CheckConstraint(
            "status IN ('active', 'superseded', 'disabled')",
            name="chk_capability_mappings_status",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_capability_mappings_confidence"),
        CheckConstraint("source_priority >= 0", name="chk_capability_mappings_priority"),
        CheckConstraint("version > 0", name="chk_capability_mappings_version"),
        CheckConstraint(
            "length(content_hash) = 71 AND content_hash LIKE 'sha256:%'",
            name="chk_capability_mappings_content_hash",
        ),
        Index(
            "idx_capability_mappings_scope_source",
            "tenant_id", "workspace_id", "project_id", "source_entity_type", "source_entity_ref",
        ),
        Index("idx_capability_mappings_capability", "project_id", "capability_ref", "status"),
        Index("idx_capability_mappings_repository", "project_id", "repository_ref", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    mapping_key: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source_entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_entity_ref: Mapped[str] = mapped_column(String(1000), nullable=False)
    capability_ref: Mapped[str] = mapped_column(String(1000), nullable=False)
    mapping_source: Mapped[str] = mapped_column(String(40), nullable=False)
    source_priority: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="active", nullable=False)
    repository_ref: Mapped[str | None] = mapped_column(String(1000))
    graph_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT")
    )
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ImpactResultRecord(Base):
    """Immutable evaluation snapshot; never a Gate, Memory, Replay selection, or test execution fact."""

    __tablename__ = "impact_results"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "input_fingerprint",
            name="uq_impact_results_fingerprint",
        ),
        CheckConstraint("status IN ('complete', 'partial', 'unknown')", name="chk_impact_results_status"),
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="chk_impact_results_risk"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_impact_results_confidence"),
        CheckConstraint("visited_node_count >= 0", name="chk_impact_results_visited"),
        CheckConstraint(
            "length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'",
            name="chk_impact_results_fingerprint",
        ),
        CheckConstraint(
            "length(mapping_snapshot_hash) = 71 AND mapping_snapshot_hash LIKE 'sha256:%'",
            name="chk_impact_results_mapping_hash",
        ),
        Index("idx_impact_results_scope", "tenant_id", "workspace_id", "project_id", "created_at"),
        Index("idx_impact_results_change_sets", "project_id"),
        Index("idx_impact_results_graph_version", "graph_version_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    change_set_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    graph_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graphs.id", ondelete="RESTRICT"), nullable=False)
    graph_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False
    )
    graph_assessment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("canonical_graph_staleness_assessments.id", ondelete="SET NULL")
    )
    graph_staleness: Mapped[str] = mapped_column(String(24), nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    mapping_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    mapping_version_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    algorithm_version: Mapped[str] = mapped_column(String(80), nullable=False)
    model_invocation_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    review_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approval_id: Mapped[UUID | None] = mapped_column(ForeignKey("approvals.id", ondelete="SET NULL"))
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    visited_node_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    replay_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SelectiveReplayPlanRecord(Base):
    """Immutable P19 plan snapshot; it is never an execution or retry fact."""

    __tablename__ = "selective_replay_plans"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "input_fingerprint",
            name="uq_selective_replay_plans_fingerprint",
        ),
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "idempotency_key",
            name="uq_selective_replay_plans_idempotency",
        ),
        UniqueConstraint("plan_hash", name="uq_selective_replay_plans_hash"),
        CheckConstraint("status IN ('ready', 'fallback')", name="chk_selective_replay_plans_status"),
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="chk_selective_replay_plans_risk"),
        CheckConstraint("selected_test_count > 0", name="chk_selective_replay_plans_nonempty"),
        CheckConstraint("estimated_seconds > 0", name="chk_selective_replay_plans_cost"),
        CheckConstraint(
            "length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'",
            name="chk_selective_replay_plans_fingerprint",
        ),
        CheckConstraint(
            "length(plan_hash) = 71 AND plan_hash LIKE 'sha256:%'",
            name="chk_selective_replay_plans_plan_hash",
        ),
        Index(
            "idx_selective_replay_plans_scope",
            "tenant_id", "workspace_id", "project_id", "created_at",
        ),
        Index("idx_selective_replay_plans_impact", "impact_result_id", "created_at"),
        Index("idx_selective_replay_plans_execution", "base_execution_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    impact_result_id: Mapped[UUID] = mapped_column(
        ForeignKey("impact_results.id", ondelete="RESTRICT"), nullable=False
    )
    base_execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("executions.id", ondelete="RESTRICT"), nullable=False
    )
    coverage_snapshot_id: Mapped[UUID] = mapped_column(
        ForeignKey("graph_coverage_snapshots.id", ondelete="RESTRICT"), nullable=False
    )
    environment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("project_environments.id", ondelete="RESTRICT")
    )
    graph_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False
    )
    graph_assessment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("canonical_graph_staleness_assessments.id", ondelete="RESTRICT")
    )
    algorithm_version: Mapped[str] = mapped_column(String(80), nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    fallback_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    selected_test_count: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    plan_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    replay_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


def _protect_append_only_impact_record(*_: Any, **__: Any) -> None:
    raise ValueError("Impact and Selective Replay plan snapshots are immutable")


for _impact_fact in (CapabilityMappingRecord, ImpactResultRecord, SelectiveReplayPlanRecord):
    event.listen(_impact_fact, "before_update", _protect_append_only_impact_record)
    event.listen(_impact_fact, "before_delete", _protect_append_only_impact_record)


class ScmWebhookReceipt(Base, TimestampMixin):
    """Service-owned verified SCM delivery receipt and retry state."""

    __tablename__ = "scm_webhook_receipts"
    __table_args__ = (
        UniqueConstraint(
            "connector_binding_id", "provider", "delivery_id",
            name="uq_scm_webhook_receipts_delivery",
        ),
        UniqueConstraint("idempotency_key", name="uq_scm_webhook_receipts_idempotency"),
        CheckConstraint(
            "provider IN ('github', 'gitlab', 'mock-scm')",
            name="chk_scm_webhook_receipts_provider",
        ),
        CheckConstraint(
            "status IN ('queued', 'processing', 'processed', 'ignored_out_of_order', 'failed')",
            name="chk_scm_webhook_receipts_status",
        ),
        CheckConstraint("attempt_count >= 0", name="chk_scm_webhook_receipts_attempt_count"),
        CheckConstraint(
            "length(payload_hash) = 71 AND payload_hash LIKE 'sha256:%'",
            name="chk_scm_webhook_receipts_payload_hash",
        ),
        Index("idx_scm_webhook_receipts_scope", "tenant_id", "workspace_id", "project_id", "received_at"),
        Index("idx_scm_webhook_receipts_status", "status", "created_at"),
        Index("idx_scm_webhook_receipts_pr", "project_id", "repository_ref", "pull_request_number"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    connector_binding_id: Mapped[UUID] = mapped_column(
        ForeignKey("skill_connector_bindings.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    delivery_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    installation_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    repository_ref: Mapped[str] = mapped_column(String(1000), nullable=False)
    repository_native_id: Mapped[str] = mapped_column(String(255), nullable=False)
    pull_request_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str | None] = mapped_column(String(64))
    provider_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    envelope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    binding_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="queued", nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(160))
    pr_context_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("scm_pr_context_versions.id", ondelete="SET NULL")
    )
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


class ScmPrContextRecord(Base, TimestampMixin):
    """Provider-neutral PR identity; immutable facts live in version records."""

    __tablename__ = "scm_pr_contexts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "provider", "repository_ref", "pull_request_number",
            name="uq_scm_pr_contexts_identity",
        ),
        CheckConstraint("state IN ('open', 'closed', 'merged', 'unknown')", name="chk_scm_pr_contexts_state"),
        CheckConstraint("latest_version > 0", name="chk_scm_pr_contexts_version"),
        Index("idx_scm_pr_contexts_scope", "tenant_id", "workspace_id", "project_id", "updated_at"),
        Index("idx_scm_pr_contexts_repository", "project_id", "repository_ref", "pull_request_number"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    connector_binding_id: Mapped[UUID] = mapped_column(
        ForeignKey("skill_connector_bindings.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    repository_ref: Mapped[str] = mapped_column(String(1000), nullable=False)
    repository_native_id: Mapped[str] = mapped_column(String(255), nullable=False)
    pull_request_number: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    latest_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    latest_head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    latest_provider_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScmPrContextVersionRecord(Base):
    """Immutable P20 PR Context version snapshot."""

    __tablename__ = "scm_pr_context_versions"
    __table_args__ = (
        UniqueConstraint("context_id", "version", name="uq_scm_pr_context_versions_number"),
        UniqueConstraint("webhook_receipt_id", name="uq_scm_pr_context_versions_receipt"),
        UniqueConstraint("context_hash", name="uq_scm_pr_context_versions_hash"),
        CheckConstraint("version > 0", name="chk_scm_pr_context_versions_version"),
        CheckConstraint(
            "length(context_hash) = 71 AND context_hash LIKE 'sha256:%'",
            name="chk_scm_pr_context_versions_hash",
        ),
        Index("idx_scm_pr_context_versions_context", "context_id", "version"),
        Index("idx_scm_pr_context_versions_head", "context_id", "head_sha"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    context_id: Mapped[UUID] = mapped_column(ForeignKey("scm_pr_contexts.id", ondelete="RESTRICT"), nullable=False)
    webhook_receipt_id: Mapped[UUID] = mapped_column(
        ForeignKey("scm_webhook_receipts.id", ondelete="RESTRICT"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    base_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    head_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    change_set_id: Mapped[UUID | None] = mapped_column(ForeignKey("change_sets.id", ondelete="RESTRICT"))
    skill_invocation_id: Mapped[UUID | None] = mapped_column(ForeignKey("skill_invocations.id", ondelete="SET NULL"))
    context_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    context_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    replay_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RequirementMatchSnapshotRecord(Base):
    """Immutable result of the ordered P20 matching algorithm."""

    __tablename__ = "requirement_match_snapshots"
    __table_args__ = (
        UniqueConstraint("pr_context_version_id", name="uq_requirement_match_snapshots_context_version"),
        UniqueConstraint("snapshot_hash", name="uq_requirement_match_snapshots_hash"),
        CheckConstraint("status IN ('confirmed', 'candidate', 'conflict', 'unknown')", name="chk_requirement_match_snapshots_status"),
        CheckConstraint(
            "length(snapshot_hash) = 71 AND snapshot_hash LIKE 'sha256:%'",
            name="chk_requirement_match_snapshots_hash",
        ),
        Index("idx_requirement_match_snapshots_context", "pr_context_version_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    pr_context_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("scm_pr_context_versions.id", ondelete="RESTRICT"), nullable=False
    )
    algorithm_version: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    review_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    explicit_unknown_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    model_invocation_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    replay_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RequirementMatchRecord(Base):
    __tablename__ = "requirement_matches"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "ordinal", name="uq_requirement_matches_ordinal"),
        UniqueConstraint("match_hash", name="uq_requirement_matches_hash"),
        CheckConstraint(
            "source IN ('explicit_reference', 'manual_mapping', 'verified_traceability', 'rule', 'history', 'ai_suggestion')",
            name="chk_requirement_matches_source",
        ),
        CheckConstraint(
            "status IN ('confirmed', 'candidate', 'rejected', 'unknown')",
            name="chk_requirement_matches_status",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_requirement_matches_confidence"),
        CheckConstraint(
            "status <> 'confirmed' OR confidence >= 0.8",
            name="chk_requirement_matches_confirmed_confidence",
        ),
        CheckConstraint(
            "NOT (source IN ('rule', 'history', 'ai_suggestion') AND status = 'confirmed')",
            name="chk_requirement_matches_no_implicit_confirmation",
        ),
        CheckConstraint(
            "length(match_hash) = 71 AND match_hash LIKE 'sha256:%'",
            name="chk_requirement_matches_hash",
        ),
        Index("idx_requirement_matches_snapshot", "snapshot_id", "ordinal"),
        Index("idx_requirement_matches_requirement", "requirement_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    snapshot_id: Mapped[UUID] = mapped_column(
        ForeignKey("requirement_match_snapshots.id", ondelete="RESTRICT"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(255), nullable=False)
    requirement_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("requirement_versions.id", ondelete="RESTRICT")
    )
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    review_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    model_invocation_ref: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    match_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AdmissionRunRecord(Base, TimestampMixin):
    """P21-P23 PR Admission orchestration snapshot in the existing lifecycle."""

    __tablename__ = "admission_runs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "input_fingerprint",
            name="uq_admission_runs_fingerprint",
        ),
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "idempotency_key",
            name="uq_admission_runs_idempotency",
        ),
        UniqueConstraint("execution_id", name="uq_admission_runs_execution"),
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "repository_ref",
            "pull_request_number", "source_head_sha", "admission_mode", "workflow_version",
            name="uq_admission_runs_orchestration",
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'partial', 'unavailable', 'cancelled', 'stale')",
            name="chk_admission_runs_status",
        ),
        CheckConstraint(
            "length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'",
            name="chk_admission_runs_fingerprint",
        ),
        CheckConstraint(
            "admission_mode IN ('observe', 'shadow', 'enforce')",
            name="chk_admission_runs_mode",
        ),
        CheckConstraint(
            "(admission_mode = 'enforce' AND non_authoritative = FALSE) OR "
            "(admission_mode <> 'enforce' AND non_authoritative = TRUE)",
            name="chk_admission_runs_non_authoritative",
        ),
        Index(
            "idx_admission_runs_scope",
            "tenant_id", "workspace_id", "project_id", "created_at",
        ),
        Index("idx_admission_runs_pr_context", "pr_context_version_id", "created_at"),
        Index("idx_admission_runs_status", "status", "updated_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    pr_context_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("scm_pr_context_versions.id", ondelete="RESTRICT"), nullable=False
    )
    requirement_match_snapshot_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("requirement_match_snapshots.id", ondelete="RESTRICT")
    )
    selective_replay_plan_id: Mapped[UUID] = mapped_column(
        ForeignKey("selective_replay_plans.id", ondelete="RESTRICT"), nullable=False
    )
    environment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("project_environments.id", ondelete="RESTRICT")
    )
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("executions.id", ondelete="RESTRICT"), nullable=False
    )
    repository_ref: Mapped[str] = mapped_column(String(1000), nullable=False)
    pull_request_number: Mapped[int] = mapped_column(Integer, nullable=False)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    source_head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    admission_mode: Mapped[str] = mapped_column(String(16), default="observe", nullable=False)
    workflow_version: Mapped[str] = mapped_column(String(120), nullable=False)
    non_authoritative: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    sandbox_profile: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    plan_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    stage_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    result_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_snapshot_hash: Mapped[str | None] = mapped_column(String(80))
    shadow_gate_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    retry_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    replay_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class CIEnforcementPolicyRecord(Base, TimestampMixin):
    """Service-owned approval-backed CI writeback and Enforce policy."""

    __tablename__ = "ci_enforcement_policies"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "project_id", "repository_ref", "check_name",
            name="uq_ci_enforcement_policy_scope",
        ),
        CheckConstraint("mode IN ('observe', 'shadow', 'enforce')", name="chk_ci_enforcement_policy_mode"),
        CheckConstraint(
            "status IN ('active', 'approval_pending', 'disabled')",
            name="chk_ci_enforcement_policy_status",
        ),
        CheckConstraint(
            "length(policy_hash) = 71 AND policy_hash LIKE 'sha256:%'",
            name="chk_ci_enforcement_policy_hash",
        ),
        CheckConstraint("lock_version > 0", name="chk_ci_enforcement_policy_lock"),
        Index(
            "idx_ci_enforcement_policy_scope",
            "tenant_id", "workspace_id", "project_id", "repository_ref",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    repository_ref: Mapped[str] = mapped_column(String(1000), nullable=False)
    check_name: Mapped[str] = mapped_column(String(120), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    branch_protection_configured: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    activation_approval_id: Mapped[UUID | None] = mapped_column(ForeignKey("approvals.id", ondelete="RESTRICT"))
    pending_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class CIWritebackAttemptRecord(Base, TimestampMixin):
    """Auditable, idempotent Connector write attempt for one frozen Admission head."""

    __tablename__ = "ci_writeback_attempts"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_ci_writeback_attempt_idempotency"),
        CheckConstraint(
            "status IN ('pending', 'in_progress', 'success', 'failure', 'neutral', "
            "'cancelled', 'stale', 'write_failed', 'unknown')",
            name="chk_ci_writeback_attempt_status",
        ),
        CheckConstraint(
            "provider IN ('github', 'gitlab', 'mock-scm')",
            name="chk_ci_writeback_attempt_provider",
        ),
        CheckConstraint(
            "admission_mode IN ('observe', 'shadow', 'enforce')",
            name="chk_ci_writeback_attempt_mode",
        ),
        CheckConstraint("attempt_count > 0", name="chk_ci_writeback_attempt_count"),
        CheckConstraint(
            "length(request_hash) = 71 AND request_hash LIKE 'sha256:%'",
            name="chk_ci_writeback_attempt_request_hash",
        ),
        Index(
            "idx_ci_writeback_attempt_scope",
            "tenant_id", "workspace_id", "project_id", "created_at",
        ),
        Index(
            "idx_ci_writeback_attempt_pr_head",
            "project_id", "repository_ref", "pull_request_number", "head_sha", "check_name",
        ),
        Index("idx_ci_writeback_attempt_admission", "admission_run_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    admission_run_id: Mapped[UUID] = mapped_column(ForeignKey("admission_runs.id", ondelete="RESTRICT"), nullable=False)
    connector_binding_id: Mapped[UUID] = mapped_column(
        ForeignKey("skill_connector_bindings.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    repository_ref: Mapped[str] = mapped_column(String(1000), nullable=False)
    pull_request_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    check_name: Mapped[str] = mapped_column(String(120), nullable=False)
    admission_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="pending", nullable=False)
    conclusion_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    enforcement_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    stale_revision_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    response_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    external_action_ref: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    legacy_field_notice: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    connector_call_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(160))
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)


def _protect_append_only_scm_context(*_: Any, **__: Any) -> None:
    raise ValueError("PR Context versions and Requirement Match snapshots are immutable")


for _scm_fact in (ScmPrContextVersionRecord, RequirementMatchSnapshotRecord, RequirementMatchRecord):
    event.listen(_scm_fact, "before_update", _protect_append_only_scm_context)
    event.listen(_scm_fact, "before_delete", _protect_append_only_scm_context)


class RequirementScopeRecord(Base):
    __tablename__ = "requirement_scopes"
    __table_args__ = (
        Index("idx_requirement_scopes_primary_version", "primary_requirement_version_id"),
        Index("idx_requirement_scopes_schema_version", "schema_version"),
    )

    scope_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    primary_requirement_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("requirement_versions.id", ondelete="RESTRICT"), nullable=False
    )
    scope_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RequirementScopeVersionRef(Base):
    __tablename__ = "requirement_scope_versions"
    __table_args__ = (
        UniqueConstraint("scope_id", "requirement_version_id", name="uq_requirement_scope_version"),
        Index("idx_requirement_scope_versions_version", "requirement_version_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scope_id: Mapped[str] = mapped_column(
        ForeignKey("requirement_scopes.scope_id", ondelete="CASCADE"), nullable=False
    )
    requirement_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("requirement_versions.id", ondelete="RESTRICT"), nullable=False
    )
    requirement_item_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)


class RequirementIntakeDraft(Base, TimestampMixin):
    __tablename__ = "requirement_intake_drafts"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('paste', 'upload', 'ocr_upload', 'external_link', 'connector')",
            name="chk_requirement_intake_drafts_source_type",
        ),
        CheckConstraint(
            "status IN ('draft', 'previewed', 'review_required', 'blocked', 'confirmed', 'discarded')",
            name="chk_requirement_intake_drafts_status",
        ),
        CheckConstraint(
            "redaction_status IN ('not_required', 'redacted', 'pending')",
            name="chk_requirement_intake_drafts_redaction_status",
        ),
        Index("idx_requirement_intake_drafts_source_ref", "source_ref"),
        Index("idx_requirement_intake_drafts_source_type", "source_type"),
        Index("idx_requirement_intake_drafts_content_hash", "content_hash"),
        Index("idx_requirement_intake_drafts_project", "project_id"),
        Index("idx_requirement_intake_drafts_environment", "environment_id"),
        Index("idx_requirement_intake_drafts_status", "status"),
        Index("idx_requirement_intake_drafts_created_by", "created_by"),
        Index("idx_requirement_intake_drafts_created_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    source_type: Mapped[str] = mapped_column(String(32), default="paste", nullable=False)
    source_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    source_uri: Mapped[str | None] = mapped_column(String(2048))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_document: Mapped[str] = mapped_column(Text, nullable=False)
    storage_ref: Mapped[str | None] = mapped_column(String(500))
    content_hash: Mapped[str | None] = mapped_column(String(80))
    mime_type: Mapped[str | None] = mapped_column(String(120))
    byte_size: Mapped[int | None] = mapped_column(Integer)
    artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    redaction_status: Mapped[str] = mapped_column(String(32), default="not_required", nullable=False)
    project_id: Mapped[UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="SET NULL"))
    environment_id: Mapped[UUID | None] = mapped_column(ForeignKey("project_environments.id", ondelete="SET NULL"))
    environment: Mapped[str] = mapped_column(String(100), default="local", nullable=False)
    domains: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(db_enum(RiskLevel), default=RiskLevel.MEDIUM, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="draft", nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    skill_invocation_id: Mapped[UUID | None] = mapped_column(ForeignKey("skill_invocations.id", ondelete="SET NULL"))
    connector_binding_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    connector_call_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class RequirementIntakePreview(Base, TimestampMixin):
    __tablename__ = "requirement_intake_previews"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('paste', 'upload', 'ocr_upload', 'external_link', 'connector')",
            name="chk_requirement_intake_previews_source_type",
        ),
        CheckConstraint(
            "status IN ('generated', 'review_required', 'blocked', 'confirmed', 'superseded')",
            name="chk_requirement_intake_previews_status",
        ),
        CheckConstraint(
            "redaction_status IN ('not_required', 'redacted', 'pending')",
            name="chk_requirement_intake_previews_redaction_status",
        ),
        Index("idx_requirement_intake_previews_draft", "draft_id"),
        Index("idx_requirement_intake_previews_source_type", "source_type"),
        Index("idx_requirement_intake_previews_content_hash", "content_hash"),
        Index("idx_requirement_intake_previews_pipeline", "linked_pipeline_id"),
        Index("idx_requirement_intake_previews_requirement", "linked_requirement_version_id"),
        Index("idx_requirement_intake_previews_status", "status"),
        Index("idx_requirement_intake_previews_created_by", "created_by"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    draft_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_intake_drafts.id", ondelete="CASCADE"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), default="paste", nullable=False)
    source_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    source_uri: Mapped[str | None] = mapped_column(String(2048))
    document: Mapped[str] = mapped_column(Text, nullable=False)
    storage_ref: Mapped[str | None] = mapped_column(String(500))
    content_hash: Mapped[str | None] = mapped_column(String(80))
    mime_type: Mapped[str | None] = mapped_column(String(120))
    byte_size: Mapped[int | None] = mapped_column(Integer)
    artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    redaction_status: Mapped[str] = mapped_column(String(32), default="not_required", nullable=False)
    requirements: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    acceptance_criteria: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    pipeline_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="generated", nullable=False)
    linked_requirement_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_versions.id", ondelete="SET NULL"))
    linked_pipeline_id: Mapped[UUID | None] = mapped_column(ForeignKey("orchestration_runs.id", ondelete="SET NULL"))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    skill_invocation_id: Mapped[UUID | None] = mapped_column(ForeignKey("skill_invocations.id", ondelete="SET NULL"))
    connector_binding_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    connector_call_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class RequirementIntakeBatch(Base, TimestampMixin):
    __tablename__ = "requirement_intake_batches"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'ready', 'partially_failed', 'failed', 'partially_confirmed', 'confirmed')",
            name="chk_requirement_intake_batches_status",
        ),
        UniqueConstraint("created_by", "idempotency_key", name="uq_requirement_intake_batches_created_by_idempotency"),
        Index("idx_requirement_intake_batches_status", "status"),
        Index("idx_requirement_intake_batches_project", "project_id"),
        Index("idx_requirement_intake_batches_environment", "environment_id"),
        Index("idx_requirement_intake_batches_created_by", "created_by"),
        Index("idx_requirement_intake_batches_created_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    environment: Mapped[str] = mapped_column(String(100), default="local", nullable=False)
    project_id: Mapped[UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="SET NULL"))
    environment_id: Mapped[UUID | None] = mapped_column(ForeignKey("project_environments.id", ondelete="SET NULL"))
    domains: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(db_enum(RiskLevel), default=RiskLevel.MEDIUM, nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class RequirementIntakeBatchSource(Base, TimestampMixin):
    __tablename__ = "requirement_intake_batch_sources"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('paste', 'upload', 'external_link', 'connector')",
            name="chk_requirement_intake_batch_sources_source_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'pending_confirm', 'failed', 'confirmed')",
            name="chk_requirement_intake_batch_sources_status",
        ),
        UniqueConstraint("batch_id", "source_key", name="uq_requirement_intake_batch_sources_key"),
        Index("idx_requirement_intake_batch_sources_batch", "batch_id"),
        Index("idx_requirement_intake_batch_sources_status", "status"),
        Index("idx_requirement_intake_batch_sources_source_type", "source_type"),
        Index("idx_requirement_intake_batch_sources_draft", "draft_id"),
        Index("idx_requirement_intake_batch_sources_preview", "preview_id"),
        Index("idx_requirement_intake_batch_sources_pipeline", "linked_pipeline_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    batch_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_intake_batches.id", ondelete="CASCADE"), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_key: Mapped[str] = mapped_column(String(180), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    draft_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_intake_drafts.id", ondelete="SET NULL"))
    preview_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_intake_previews.id", ondelete="SET NULL"))
    linked_requirement_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_versions.id", ondelete="SET NULL"))
    linked_pipeline_id: Mapped[UUID | None] = mapped_column(ForeignKey("orchestration_runs.id", ondelete="SET NULL"))
    error_message: Mapped[str | None] = mapped_column(Text)
    artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ClarificationItem(Base, TimestampMixin):
    __tablename__ = "clarification_items"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    requirement_version_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_versions.id", ondelete="CASCADE"), nullable=False)
    question_key: Mapped[str] = mapped_column(String(100), nullable=False)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    answer: Mapped[str | None] = mapped_column(Text)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    answered_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class TestAsset(Base, TimestampMixin):
    __tablename__ = "test_assets"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    requirement_version_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_versions.id", ondelete="CASCADE"), nullable=False)
    test_plan_id: Mapped[UUID | None] = mapped_column(ForeignKey("test_plans.id", ondelete="SET NULL"))
    asset_type: Mapped[str] = mapped_column(String(30), nullable=False)
    domain: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    requirement_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="draft", nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class TestAssetReview(Base, TimestampMixin):
    __tablename__ = "test_asset_reviews"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    requirement_version_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_versions.id", ondelete="CASCADE"), nullable=False)
    test_plan_id: Mapped[UUID] = mapped_column(ForeignKey("test_plans.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    issues: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    coverage_map: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class ExecutionPlan(Base, TimestampMixin):
    __tablename__ = "execution_plans"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    requirement_version_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_versions.id", ondelete="CASCADE"), nullable=False)
    test_plan_id: Mapped[UUID] = mapped_column(ForeignKey("test_plans.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(db_enum(RiskLevel), nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tasks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    asset_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    retry_strategy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    requirement_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    requirement_scope_id: Mapped[str | None] = mapped_column(
        ForeignKey("requirement_scopes.scope_id", ondelete="SET NULL")
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class CorrectionRecord(Base, TimestampMixin):
    __tablename__ = "correction_records"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    requirement_version_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_versions.id", ondelete="CASCADE"), nullable=False)
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    before_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    after_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    actor_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    affected_asset_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class CorrectionProposal(Base, TimestampMixin):
    __tablename__ = "correction_proposals"
    __table_args__ = (
        CheckConstraint(
            "status IN ('draft', 'pending_approval', 'approved', 'rejected', 'cancelled', 'expired')",
            name="chk_correction_proposals_status",
        ),
        Index("idx_correction_proposals_requirement", "requirement_version_id"),
        Index("idx_correction_proposals_execution", "execution_id"),
        Index("idx_correction_proposals_status", "status"),
        Index("idx_correction_proposals_type", "proposal_type"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    proposal_type: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="draft", nullable=False)
    proposed_change: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    requirement_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_versions.id", ondelete="SET NULL"))
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    finding_id: Mapped[UUID | None] = mapped_column(Uuid)
    attribution_id: Mapped[str | None] = mapped_column(String(255))
    risk_level: Mapped[RiskLevel] = mapped_column(db_enum(RiskLevel), nullable=False)
    requester_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    requested_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    promotion_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contract_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(255))
    idempotency_key: Mapped[str | None] = mapped_column(String(255), unique=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class CorrectionApplication(Base, TimestampMixin):
    __tablename__ = "correction_applications"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'applying', 'applied', 'failed_to_apply')",
            name="chk_correction_applications_status",
        ),
        UniqueConstraint("correction_proposal_id", "idempotency_key", name="uq_correction_applications_proposal_idempotency"),
        Index("idx_correction_applications_proposal", "correction_proposal_id"),
        Index("idx_correction_applications_status", "status"),
        Index("idx_correction_applications_request", "request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    correction_proposal_id: Mapped[UUID] = mapped_column(ForeignKey("correction_proposals.id", ondelete="CASCADE"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="pending", nullable=False)
    applied_change_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    side_effect_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    contract_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    applied_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class CorrectionValidation(Base, TimestampMixin):
    __tablename__ = "correction_validations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'validated', 'validation_failed', 'cancelled', 'error')",
            name="chk_correction_validations_status",
        ),
        UniqueConstraint("correction_application_id", "idempotency_key", name="uq_correction_validations_application_idempotency"),
        Index("idx_correction_validations_proposal", "correction_proposal_id"),
        Index("idx_correction_validations_application", "correction_application_id"),
        Index("idx_correction_validations_status", "status"),
        Index("idx_correction_validations_request", "request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    correction_proposal_id: Mapped[UUID] = mapped_column(ForeignKey("correction_proposals.id", ondelete="CASCADE"), nullable=False)
    correction_application_id: Mapped[UUID] = mapped_column(ForeignKey("correction_applications.id", ondelete="CASCADE"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="pending", nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    trace_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    contract_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class RollbackRecord(Base, TimestampMixin):
    __tablename__ = "rollback_records"
    __table_args__ = (
        CheckConstraint(
            "status IN ('rollback_not_required', 'rolling_back', 'rolled_back', 'rollback_failed')",
            name="chk_rollback_records_status",
        ),
        UniqueConstraint("correction_proposal_id", "idempotency_key", name="uq_rollback_records_proposal_idempotency"),
        Index("idx_rollback_records_proposal", "correction_proposal_id"),
        Index("idx_rollback_records_application", "correction_application_id"),
        Index("idx_rollback_records_validation", "correction_validation_id"),
        Index("idx_rollback_records_status", "status"),
        Index("idx_rollback_records_request", "request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    correction_proposal_id: Mapped[UUID] = mapped_column(ForeignKey("correction_proposals.id", ondelete="CASCADE"), nullable=False)
    correction_application_id: Mapped[UUID | None] = mapped_column(ForeignKey("correction_applications.id", ondelete="SET NULL"))
    correction_validation_id: Mapped[UUID | None] = mapped_column(ForeignKey("correction_validations.id", ondelete="SET NULL"))
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    rollback_reason: Mapped[str] = mapped_column(Text, nullable=False)
    rollback_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    contract_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class KnowledgePromotionRecord(Base, TimestampMixin):
    __tablename__ = "knowledge_promotion_records"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'promoted', 'rejected', 'rolled_back', 'superseded')",
            name="chk_knowledge_promotion_records_status",
        ),
        CheckConstraint(
            "approval_state IN ('satisfied', 'not_required')",
            name="chk_knowledge_promotion_records_approval_state",
        ),
        CheckConstraint(
            "projection_state IN ('skipped', 'projected', 'projection_failed', 'retry')",
            name="chk_knowledge_promotion_records_projection_state",
        ),
        UniqueConstraint("source_correction_id", "idempotency_key", name="uq_knowledge_promotion_records_proposal_idempotency"),
        Index("idx_knowledge_promotion_records_source", "source_correction_id"),
        Index("idx_knowledge_promotion_records_validation", "correction_validation_id"),
        Index("idx_knowledge_promotion_records_coverage_proof", "coverage_proof_bundle_id"),
        Index("idx_knowledge_promotion_records_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    source_correction_id: Mapped[UUID] = mapped_column(ForeignKey("correction_proposals.id", ondelete="CASCADE"), nullable=False)
    correction_validation_id: Mapped[UUID] = mapped_column(ForeignKey("correction_validations.id", ondelete="RESTRICT"), nullable=False)
    replay_validation_id: Mapped[str | None] = mapped_column(String(255))
    replay_validation_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    coverage_proof_bundle_id: Mapped[UUID] = mapped_column(ForeignKey("coverage_proof_bundles.id", ondelete="RESTRICT"), nullable=False)
    coverage_proof_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    knowledge_entry_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    approval_state: Mapped[str] = mapped_column(String(40), nullable=False)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    rollback_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    supersede_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    projection_state: Mapped[str] = mapped_column(String(40), default="skipped", nullable=False)
    projection_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="pending", nullable=False)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    promoted_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    contract_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(255))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class DomainEventRecord(Base):
    __tablename__ = "domain_events"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    event_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(50), nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    correlation_refs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_ref: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    source_ref: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class LessonCandidateRecord(Base, TimestampMixin):
    __tablename__ = "lesson_candidates"
    __table_args__ = (
        CheckConstraint(
            "lesson_type IN ('false_positive', 'false_negative', 'repeated_failure', "
            "'flaky', 'environment_issue', 'test_issue', 'human_override', "
            "'graph_correction', 'gate_disagreement', 'admission_outcome', "
            "'auto_promotion_conflict', 'auto_promotion_rollback', "
            "'promotion_policy_too_strict', 'promotion_policy_too_loose')",
            name="chk_lesson_candidates_type",
        ),
        CheckConstraint(
            "source_event_type IN ('finding', 'admission_run', 'gate_decision', "
            "'graph_correction', 'graph_promotion', 'domain_event')",
            name="chk_lesson_candidates_source_type",
        ),
        CheckConstraint(
            "scope_type IN ('project', 'environment', 'repository')",
            name="chk_lesson_candidates_scope_type",
        ),
        CheckConstraint(
            "status IN ('candidate', 'under_review', 'accepted', 'rejected', "
            "'promoted', 'expired')",
            name="chk_lesson_candidates_status",
        ),
        CheckConstraint(
            "impact IN ('low', 'medium', 'high', 'critical')",
            name="chk_lesson_candidates_impact",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_lesson_candidates_confidence"),
        CheckConstraint("frequency > 0", name="chk_lesson_candidates_frequency"),
        CheckConstraint("lock_version > 0", name="chk_lesson_candidates_lock"),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "project_id",
            "source_event_type",
            "source_event_id",
            "lesson_type",
            "scope_type",
            "scope_id",
            "dedupe_key",
            name="uq_lesson_candidate_source_taxonomy_scope_dedupe",
        ),
        Index(
            "idx_lesson_candidates_scope_status",
            "tenant_id",
            "workspace_id",
            "project_id",
            "status",
            "updated_at",
        ),
        Index("idx_lesson_candidates_cluster", "tenant_id", "workspace_id", "project_id", "cluster_key"),
        Index("idx_lesson_candidates_expiry", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    lesson_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_version: Mapped[str | None] = mapped_column(String(255))
    source_event_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(1000), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    observations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    raw_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    frequency: Mapped[int] = mapped_column(Integer, nullable=False)
    impact: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="candidate", nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)
    cluster_key: Mapped[str] = mapped_column(String(80), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class LessonEvidenceRecord(Base):
    __tablename__ = "lesson_evidence"
    __table_args__ = (
        CheckConstraint(
            "retention_state IN ('active', 'missing', 'purged', 'expired')",
            name="chk_lesson_evidence_retention",
        ),
        CheckConstraint(
            "classification IN ('public', 'internal', 'confidential', 'restricted')",
            name="chk_lesson_evidence_classification",
        ),
        CheckConstraint(
            "redaction_status IN ('not_required', 'redacted', 'unavailable')",
            name="chk_lesson_evidence_redaction",
        ),
        UniqueConstraint("candidate_id", "content_hash", name="uq_lesson_evidence_candidate_hash"),
        Index("idx_lesson_evidence_candidate", "candidate_id", "captured_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    candidate_id: Mapped[UUID] = mapped_column(ForeignKey("lesson_candidates.id", ondelete="CASCADE"), nullable=False)
    evidence_ref: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    raw_ref: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    retention_state: Mapped[str] = mapped_column(String(24), default="active", nullable=False)
    classification: Mapped[str] = mapped_column(String(24), default="internal", nullable=False)
    redaction_status: Mapped[str] = mapped_column(String(24), default="not_required", nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class LessonFeedbackRecord(Base):
    __tablename__ = "lesson_feedback"
    __table_args__ = (
        CheckConstraint(
            "feedback_type IN ('confirm', 'refute', 'supplement', 'uncertain')",
            name="chk_lesson_feedback_type",
        ),
        UniqueConstraint("candidate_id", "created_by", "idempotency_key", name="uq_lesson_feedback_actor_idempotency"),
        Index("idx_lesson_feedback_candidate", "candidate_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    candidate_id: Mapped[UUID] = mapped_column(ForeignKey("lesson_candidates.id", ondelete="CASCADE"), nullable=False)
    feedback_type: Mapped[str] = mapped_column(String(24), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    observations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class LessonReviewRecord(Base):
    __tablename__ = "lesson_reviews"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('accepted', 'rejected', 'needs_evidence')",
            name="chk_lesson_reviews_decision",
        ),
        CheckConstraint(
            "(decision = 'accepted' AND confirmed_fact = TRUE) OR "
            "(decision <> 'accepted' AND confirmed_fact = FALSE)",
            name="chk_lesson_reviews_confirmed_fact",
        ),
        UniqueConstraint("candidate_id", "idempotency_key", name="uq_lesson_reviews_candidate_idempotency"),
        Index("idx_lesson_reviews_candidate", "candidate_id", "reviewed_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    candidate_id: Mapped[UUID] = mapped_column(ForeignKey("lesson_candidates.id", ondelete="CASCADE"), nullable=False)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    confirmed_fact: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    candidate_lock_version: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    reviewed_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class LessonPromotionResultRecord(Base):
    __tablename__ = "lesson_promotion_results"
    __table_args__ = (
        CheckConstraint(
            "status IN ('approval_pending', 'promoted', 'rejected', 'failed', 'partial')",
            name="chk_lesson_promotion_results_status",
        ),
        CheckConstraint(
            "memory_type IN ('episodic', 'semantic', 'procedural')",
            name="chk_lesson_promotion_results_memory_type",
        ),
        CheckConstraint(
            "approval_state IN ('pending', 'satisfied', 'not_required', 'rejected')",
            name="chk_lesson_promotion_results_approval",
        ),
        CheckConstraint(
            "projection_state IN ('skipped', 'projected', 'projection_failed')",
            name="chk_lesson_promotion_results_projection",
        ),
        UniqueConstraint("candidate_id", "idempotency_key", name="uq_lesson_promotion_candidate_idempotency"),
        Index("idx_lesson_promotion_candidate", "candidate_id", "created_at"),
        Index("idx_lesson_promotion_status", "status", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    candidate_id: Mapped[UUID] = mapped_column(ForeignKey("lesson_candidates.id", ondelete="RESTRICT"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    memory_type: Mapped[str] = mapped_column(String(24), nullable=False)
    memory_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    approval_state: Mapped[str] = mapped_column(String(24), nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    raw_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    projection_state: Mapped[str] = mapped_column(String(32), default="skipped", nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(160))
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class ImprovementProposalRecord(Base, TimestampMixin):
    __tablename__ = "improvement_proposals"
    __table_args__ = (
        CheckConstraint(
            "target_type IN ('skill', 'gate_policy', 'graph', 'graph_learning_policy', "
            "'test_case', 'test_step', 'tool_config', 'connector_config')",
            name="chk_improvement_proposals_target_type",
        ),
        CheckConstraint(
            "status IN ('draft', 'validation_failed', 'validated', 'review_pending', "
            "'review_approved', 'review_rejected', 'routed', 'effectiveness_pending', "
            "'effective', 'ineffective', 'inconclusive', 'rollback_pending', "
            "'rollback_routed', 'partial', 'failed', 'archived')",
            name="chk_improvement_proposals_status",
        ),
        CheckConstraint(
            "requested_risk IN ('low', 'medium', 'high', 'critical') AND "
            "evaluated_risk IN ('low', 'medium', 'high', 'critical')",
            name="chk_improvement_proposals_risk",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="chk_improvement_proposals_confidence",
        ),
        CheckConstraint("lock_version > 0", name="chk_improvement_proposals_lock"),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "project_id",
            "idempotency_key",
            name="uq_improvement_proposal_idempotency",
        ),
        Index(
            "idx_improvement_proposals_scope_status",
            "tenant_id",
            "workspace_id",
            "project_id",
            "status",
            "updated_at",
        ),
        Index(
            "idx_improvement_proposals_target",
            "tenant_id",
            "workspace_id",
            "project_id",
            "target_type",
            "target_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    source_lesson_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    source_lessons_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    target_type: Mapped[str] = mapped_column(String(48), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    target_key: Mapped[str] = mapped_column(String(255), nullable=False)
    target_base_version: Mapped[str] = mapped_column(String(255), nullable=False)
    target_base_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    target_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    structured_change: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    change_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    requested_risk: Mapped[str] = mapped_column(String(16), nullable=False)
    evaluated_risk: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    validation_plan: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    validation_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="draft", nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    route_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    effectiveness_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    rollback_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    effectiveness_window: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(
        ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False
    )
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class ImprovementProposalVersionRecord(Base):
    __tablename__ = "improvement_proposal_versions"
    __table_args__ = (
        UniqueConstraint("proposal_id", "version_number", name="uq_improvement_proposal_version"),
        UniqueConstraint("proposal_id", "content_hash", name="uq_improvement_proposal_version_hash"),
        Index("idx_improvement_proposal_versions_proposal", "proposal_id", "version_number"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    proposal_id: Mapped[UUID] = mapped_column(
        ForeignKey("improvement_proposals.id", ondelete="CASCADE"), nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    source_lesson_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    target_base_version: Mapped[str] = mapped_column(String(255), nullable=False)
    target_base_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(
        ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False
    )
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ImprovementValidationResultRecord(Base):
    __tablename__ = "improvement_validation_results"
    __table_args__ = (
        CheckConstraint(
            "status IN ('passed', 'failed', 'insufficient', 'unavailable')",
            name="chk_improvement_validation_status",
        ),
        UniqueConstraint(
            "proposal_id", "idempotency_key", name="uq_improvement_validation_idempotency"
        ),
        Index("idx_improvement_validation_proposal", "proposal_id", "validated_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    proposal_id: Mapped[UUID] = mapped_column(
        ForeignKey("improvement_proposals.id", ondelete="CASCADE"), nullable=False
    )
    proposal_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    historical_simulation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    counterexample_regression: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    validator_version: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(
        ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False
    )
    validated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    validated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ImprovementEffectivenessResultRecord(Base):
    __tablename__ = "improvement_effectiveness_results"
    __table_args__ = (
        CheckConstraint(
            "status IN ('effective', 'ineffective', 'inconclusive')",
            name="chk_improvement_effectiveness_status",
        ),
        UniqueConstraint(
            "proposal_id", "idempotency_key", name="uq_improvement_effectiveness_idempotency"
        ),
        Index("idx_improvement_effectiveness_proposal", "proposal_id", "measured_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    proposal_id: Mapped[UUID] = mapped_column(
        ForeignKey("improvement_proposals.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    target_outcome_ref: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    before_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    after_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    deltas: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False)
    rollback_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(
        ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False
    )
    measured_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    measured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class EvidenceIndexEntry(Base):
    __tablename__ = "evidence_index_entries"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "project_id",
            "source_type",
            "source_id",
            "source_version",
            "content_hash",
            "redaction_version",
            name="uq_evidence_index_source_version_hash",
        ),
        CheckConstraint(
            "source_type IN ('execution', 'finding', 'gate', 'policy', 'trace', 'replay', 'graph', 'artifact')",
            name="chk_evidence_index_source_type",
        ),
        CheckConstraint(
            "classification IN ('public', 'internal', 'confidential', 'restricted')",
            name="chk_evidence_index_classification",
        ),
        CheckConstraint(
            "retention_state IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')",
            name="chk_evidence_index_retention_state",
        ),
        Index(
            "idx_evidence_index_scope",
            "tenant_id",
            "workspace_id",
            "project_id",
            "stale",
        ),
        Index("idx_evidence_index_source", "source_type", "source_id"),
        Index("idx_evidence_index_classification", "classification"),
        Index("idx_evidence_index_indexed_at", "indexed_at"),
        Index("idx_evidence_index_retention", "retention_state"),
    )

    entry_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_version: Mapped[str] = mapped_column(String(255), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    search_text: Mapped[str] = mapped_column(Text, nullable=False)
    facets: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    classification: Mapped[str] = mapped_column(String(40), nullable=False)
    redaction_version: Mapped[str] = mapped_column(String(80), nullable=False)
    indexed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stale: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    retention_state: Mapped[str] = mapped_column(
        String(40), default="active", nullable=False
    )
    unavailable_reason_code: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )


class EvidenceIndexJob(Base):
    __tablename__ = "evidence_index_jobs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "project_id",
            "idempotency_key",
            name="uq_evidence_index_jobs_scope_idempotency",
        ),
        CheckConstraint(
            "job_type IN ('incremental', 'rebuild', 'redaction_reindex')",
            name="chk_evidence_index_jobs_type",
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="chk_evidence_index_jobs_status",
        ),
        Index("idx_evidence_index_jobs_scope", "tenant_id", "workspace_id", "project_id"),
        Index("idx_evidence_index_jobs_status", "status", "created_at"),
    )

    job_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    job_type: Mapped[str] = mapped_column(String(40), default="incremental", nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="queued", nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    source_types: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    scanned_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    upserted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unchanged_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stale_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    redaction_version: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(120))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class CanonicalExecutionGraph(Base, TimestampMixin):
    """Stable CEG identity owned by the existing orchestrator Service boundary."""

    __tablename__ = "canonical_execution_graphs"
    __table_args__ = (
        ForeignKeyConstraint(
            ("environment_id", "project_id"),
            ("project_environments.id", "project_environments.project_id"),
            name="fk_ceg_graphs_environment_project",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "project_id",
            "scope_type",
            "scope_id",
            "graph_key",
            name="uq_ceg_graphs_scope_key",
        ),
        UniqueConstraint(
            "id",
            "tenant_id",
            "workspace_id",
            "project_id",
            "scope_type",
            "scope_id",
            name="uq_ceg_graphs_scoped_identity",
        ),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "idempotency_key",
            name="uq_ceg_graphs_idempotency",
        ),
        CheckConstraint("length(trim(tenant_id)) > 0", name="chk_ceg_graphs_tenant_not_blank"),
        CheckConstraint("length(trim(workspace_id)) > 0", name="chk_ceg_graphs_workspace_not_blank"),
        CheckConstraint(
            "(scope_type = 'project' AND environment_id IS NULL AND scope_id = project_id) OR "
            "(scope_type = 'environment' AND environment_id IS NOT NULL AND scope_id = environment_id)",
            name="chk_ceg_graphs_scope_identity",
        ),
        CheckConstraint("length(request_hash) = 71", name="chk_ceg_graphs_request_hash_length"),
        CheckConstraint("substr(request_hash, 1, 7) = 'sha256:'", name="chk_ceg_graphs_request_hash_prefix"),
        CheckConstraint("lock_version > 0", name="chk_ceg_graphs_lock_version"),
        CheckConstraint(
            "retention_status IN ('active', 'archived', 'purge_eligible', 'legal_hold')",
            name="chk_ceg_graphs_retention_status",
        ),
        Index("idx_ceg_graphs_scope", "tenant_id", "workspace_id", "project_id", "scope_type", "scope_id"),
        Index("idx_ceg_graphs_environment", "environment_id"),
        Index("idx_ceg_graphs_status", "status"),
        Index("idx_ceg_graphs_retention", "retention_status", "retention_until"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    environment_id: Mapped[UUID | None] = mapped_column(Uuid)
    scope_type: Mapped[GraphScope] = mapped_column(db_enum(GraphScope), nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    graph_key: Mapped[str] = mapped_column(String(128), nullable=False)
    graph_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[GraphStatus] = mapped_column(
        db_enum(GraphStatus), default=GraphStatus.DRAFT, nullable=False
    )
    retention_policy: Mapped[str] = mapped_column(String(80), default="default", nullable=False)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retention_status: Mapped[str] = mapped_column(String(40), default="active", nullable=False)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)

    __mapper_args__ = {"version_id_col": lock_version}


class CanonicalExecutionGraphVersion(Base, TimestampMixin):
    """Versioned CEG metadata and immutable canonical topology owner."""

    __tablename__ = "canonical_execution_graph_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ("graph_id", "tenant_id", "workspace_id", "project_id", "scope_type", "scope_id"),
            (
                "canonical_execution_graphs.id",
                "canonical_execution_graphs.tenant_id",
                "canonical_execution_graphs.workspace_id",
                "canonical_execution_graphs.project_id",
                "canonical_execution_graphs.scope_type",
                "canonical_execution_graphs.scope_id",
            ),
            name="fk_ceg_versions_graph_scope",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("environment_id", "project_id"),
            ("project_environments.id", "project_environments.project_id"),
            name="fk_ceg_versions_environment_project",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("parent_version_id", "graph_id", "tenant_id", "workspace_id", "project_id", "scope_id"),
            (
                "canonical_execution_graph_versions.id",
                "canonical_execution_graph_versions.graph_id",
                "canonical_execution_graph_versions.tenant_id",
                "canonical_execution_graph_versions.workspace_id",
                "canonical_execution_graph_versions.project_id",
                "canonical_execution_graph_versions.scope_id",
            ),
            name="fk_ceg_versions_parent_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("graph_id", "version_number", name="uq_ceg_versions_graph_version"),
        UniqueConstraint("graph_id", "content_hash", name="uq_ceg_versions_graph_hash"),
        UniqueConstraint(
            "id",
            "graph_id",
            "tenant_id",
            "workspace_id",
            "project_id",
            "scope_id",
            name="uq_ceg_versions_parent_identity",
        ),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "idempotency_key",
            name="uq_ceg_versions_idempotency",
        ),
        CheckConstraint("version_number > 0", name="chk_ceg_versions_number"),
        CheckConstraint("parent_version_id IS NULL OR parent_version_id <> id", name="chk_ceg_versions_parent_not_self"),
        CheckConstraint(
            "(scope_type = 'project' AND environment_id IS NULL AND scope_id = project_id) OR "
            "(scope_type = 'environment' AND environment_id IS NOT NULL AND scope_id = environment_id)",
            name="chk_ceg_versions_scope_identity",
        ),
        CheckConstraint("length(content_hash) = 71", name="chk_ceg_versions_content_hash_length"),
        CheckConstraint("substr(content_hash, 1, 7) = 'sha256:'", name="chk_ceg_versions_content_hash_prefix"),
        CheckConstraint("length(request_hash) = 71", name="chk_ceg_versions_request_hash_length"),
        CheckConstraint("substr(request_hash, 1, 7) = 'sha256:'", name="chk_ceg_versions_request_hash_prefix"),
        CheckConstraint("lock_version > 0", name="chk_ceg_versions_lock_version"),
        CheckConstraint(
            "retention_status IN ('active', 'archived', 'purge_eligible', 'legal_hold')",
            name="chk_ceg_versions_retention_status",
        ),
        CheckConstraint(
            "(is_frozen = false AND frozen_at IS NULL AND frozen_by IS NULL) OR "
            "(is_frozen = true AND frozen_at IS NOT NULL)",
            name="chk_ceg_versions_frozen_metadata",
        ),
        CheckConstraint(
            "source <> 'canonical' OR "
            "(is_frozen = true AND status IN ('active', 'superseded', 'deprecated', 'archived'))",
            name="chk_ceg_versions_canonical_frozen",
        ),
        CheckConstraint(
            "status <> 'active' OR (source = 'canonical' AND is_frozen = true)",
            name="chk_ceg_versions_active_canonical",
        ),
        Index("idx_ceg_versions_graph", "graph_id", "version_number"),
        Index("idx_ceg_versions_scope", "tenant_id", "workspace_id", "project_id", "scope_id"),
        Index("idx_ceg_versions_parent", "parent_version_id"),
        Index("idx_ceg_versions_status_source", "status", "source"),
        Index("idx_ceg_versions_hash", "content_hash"),
        Index("idx_ceg_versions_retention", "retention_status", "retention_until"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    graph_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[UUID | None] = mapped_column(Uuid)
    scope_type: Mapped[GraphScope] = mapped_column(db_enum(GraphScope), nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    version_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    parent_version_id: Mapped[UUID | None] = mapped_column(Uuid)
    status: Mapped[GraphStatus] = mapped_column(
        db_enum(GraphStatus), default=GraphStatus.DRAFT, nullable=False
    )
    source: Mapped[GraphSource] = mapped_column(db_enum(GraphSource), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(80), default="ceg.v1", nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    source_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    applicability: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_frozen: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    frozen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    frozen_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    retention_policy: Mapped[str] = mapped_column(String(80), default="default", nullable=False)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retention_status: Mapped[str] = mapped_column(String(40), default="active", nullable=False)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)

    __mapper_args__ = {"version_id_col": lock_version}


class CanonicalExecutionGraphNode(Base, TimestampMixin):
    """Structured semantic node owned by one scoped CEG version."""

    __tablename__ = "canonical_execution_graph_nodes"
    __table_args__ = (
        ForeignKeyConstraint(
            ("version_id", "graph_id", "tenant_id", "workspace_id", "project_id", "scope_id"),
            (
                "canonical_execution_graph_versions.id",
                "canonical_execution_graph_versions.graph_id",
                "canonical_execution_graph_versions.tenant_id",
                "canonical_execution_graph_versions.workspace_id",
                "canonical_execution_graph_versions.project_id",
                "canonical_execution_graph_versions.scope_id",
            ),
            name="fk_ceg_nodes_version_scope",
            ondelete="CASCADE",
        ),
        UniqueConstraint("id", "version_id", name="uq_ceg_nodes_version_identity"),
        UniqueConstraint("version_id", "client_key", name="uq_ceg_nodes_client_key"),
        UniqueConstraint("version_id", "semantic_key", name="uq_ceg_nodes_semantic_key"),
        CheckConstraint(
            "node_type IN ('requirement', 'capability', 'page', 'component', 'element', "
            "'action', 'assertion', 'data', 'api', 'code', 'test', 'evidence')",
            name="chk_ceg_nodes_type",
        ),
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="chk_ceg_nodes_risk"),
        CheckConstraint(
            "source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')",
            name="chk_ceg_nodes_source",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_ceg_nodes_confidence"),
        CheckConstraint("lock_version > 0", name="chk_ceg_nodes_lock_version"),
        CheckConstraint(
            "length(request_hash) = 71 AND request_hash LIKE 'sha256:%'",
            name="chk_ceg_nodes_request_hash",
        ),
        Index("idx_ceg_nodes_version_type", "version_id", "node_type"),
        Index("idx_ceg_nodes_scope", "tenant_id", "workspace_id", "project_id", "scope_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    node_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    graph_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    client_key: Mapped[str] = mapped_column(String(128), nullable=False)
    semantic_key: Mapped[str] = mapped_column(String(256), nullable=False)
    node_type: Mapped[str] = mapped_column(String(40), nullable=False)
    display_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    attributes_json: Mapped[dict[str, Any]] = mapped_column("attributes", JSON, default=dict, nullable=False)
    external_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), default="low", nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class CanonicalExecutionGraphEdge(Base, TimestampMixin):
    """Controlled typed relation between two nodes in the same CEG version."""

    __tablename__ = "canonical_execution_graph_edges"
    __table_args__ = (
        ForeignKeyConstraint(
            ("version_id", "graph_id", "tenant_id", "workspace_id", "project_id", "scope_id"),
            (
                "canonical_execution_graph_versions.id",
                "canonical_execution_graph_versions.graph_id",
                "canonical_execution_graph_versions.tenant_id",
                "canonical_execution_graph_versions.workspace_id",
                "canonical_execution_graph_versions.project_id",
                "canonical_execution_graph_versions.scope_id",
            ),
            name="fk_ceg_edges_version_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ("source_node_id", "version_id"),
            ("canonical_execution_graph_nodes.id", "canonical_execution_graph_nodes.version_id"),
            name="fk_ceg_edges_source_version",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("target_node_id", "version_id"),
            ("canonical_execution_graph_nodes.id", "canonical_execution_graph_nodes.version_id"),
            name="fk_ceg_edges_target_version",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("id", "version_id", name="uq_ceg_edges_version_identity"),
        UniqueConstraint("version_id", "client_key", name="uq_ceg_edges_client_key"),
        UniqueConstraint("version_id", "semantic_hash", name="uq_ceg_edges_semantic_hash"),
        CheckConstraint(
            "edge_type IN ('contains', 'precedes', 'transitions_to', 'depends_on', 'implements', "
            "'verifies', 'produces', 'evidenced_by', 'changes', 'affects')",
            name="chk_ceg_edges_type",
        ),
        CheckConstraint("source_node_id <> target_node_id", name="chk_ceg_edges_not_self"),
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="chk_ceg_edges_risk"),
        CheckConstraint(
            "review_status IN ('not_required', 'pending_review', 'approved', 'rejected')",
            name="chk_ceg_edges_review_status",
        ),
        CheckConstraint(
            "source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')",
            name="chk_ceg_edges_source",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_ceg_edges_confidence"),
        CheckConstraint("lock_version > 0", name="chk_ceg_edges_lock_version"),
        CheckConstraint(
            "length(semantic_hash) = 71 AND semantic_hash LIKE 'sha256:%'",
            name="chk_ceg_edges_semantic_hash",
        ),
        CheckConstraint(
            "length(request_hash) = 71 AND request_hash LIKE 'sha256:%'",
            name="chk_ceg_edges_request_hash",
        ),
        Index("idx_ceg_edges_version_type", "version_id", "edge_type"),
        Index("idx_ceg_edges_source", "version_id", "source_node_id"),
        Index("idx_ceg_edges_target", "version_id", "target_node_id"),
        Index("idx_ceg_edges_scope", "tenant_id", "workspace_id", "project_id", "scope_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    edge_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    graph_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    client_key: Mapped[str] = mapped_column(String(128), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_node_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    target_node_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    condition_json: Mapped[dict[str, Any] | None] = mapped_column("condition", JSON)
    risk_level: Mapped[str] = mapped_column(String(20), default="low", nullable=False)
    review_status: Mapped[str] = mapped_column(String(40), default="not_required", nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    semantic_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class CanonicalExecutionGraphPath(Base, TimestampMixin):
    """Named canonical-path candidate with structured boundaries and conditions."""

    __tablename__ = "canonical_execution_graph_paths"
    __table_args__ = (
        ForeignKeyConstraint(
            ("version_id", "graph_id", "tenant_id", "workspace_id", "project_id", "scope_id"),
            (
                "canonical_execution_graph_versions.id",
                "canonical_execution_graph_versions.graph_id",
                "canonical_execution_graph_versions.tenant_id",
                "canonical_execution_graph_versions.workspace_id",
                "canonical_execution_graph_versions.project_id",
                "canonical_execution_graph_versions.scope_id",
            ),
            name="fk_ceg_paths_version_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ("entry_node_id", "version_id"),
            ("canonical_execution_graph_nodes.id", "canonical_execution_graph_nodes.version_id"),
            name="fk_ceg_paths_entry_version",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("exit_node_id", "version_id"),
            ("canonical_execution_graph_nodes.id", "canonical_execution_graph_nodes.version_id"),
            name="fk_ceg_paths_exit_version",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("id", "version_id", name="uq_ceg_paths_version_identity"),
        UniqueConstraint("version_id", "client_key", name="uq_ceg_paths_client_key"),
        UniqueConstraint("version_id", "path_key", name="uq_ceg_paths_path_key"),
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="chk_ceg_paths_risk"),
        CheckConstraint(
            "source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')",
            name="chk_ceg_paths_source",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="chk_ceg_paths_confidence"),
        CheckConstraint("lock_version > 0", name="chk_ceg_paths_lock_version"),
        CheckConstraint(
            "length(request_hash) = 71 AND request_hash LIKE 'sha256:%'",
            name="chk_ceg_paths_request_hash",
        ),
        Index("idx_ceg_paths_version", "version_id", "path_key"),
        Index("idx_ceg_paths_entry", "version_id", "entry_node_id"),
        Index("idx_ceg_paths_exit", "version_id", "exit_node_id"),
        Index("idx_ceg_paths_scope", "tenant_id", "workspace_id", "project_id", "scope_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    path_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    graph_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    client_key: Mapped[str] = mapped_column(String(128), nullable=False)
    path_key: Mapped[str] = mapped_column(String(256), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    entry_node_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    exit_node_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    preconditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    postconditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), default="low", nullable=False)
    applicability: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class CanonicalExecutionGraphPathStep(Base, TimestampMixin):
    """Ordered node traversal joined to a Canonical Path and version."""

    __tablename__ = "canonical_execution_graph_path_steps"
    __table_args__ = (
        ForeignKeyConstraint(
            ("version_id", "graph_id", "tenant_id", "workspace_id", "project_id", "scope_id"),
            (
                "canonical_execution_graph_versions.id",
                "canonical_execution_graph_versions.graph_id",
                "canonical_execution_graph_versions.tenant_id",
                "canonical_execution_graph_versions.workspace_id",
                "canonical_execution_graph_versions.project_id",
                "canonical_execution_graph_versions.scope_id",
            ),
            name="fk_ceg_steps_version_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ("path_id", "version_id"),
            ("canonical_execution_graph_paths.id", "canonical_execution_graph_paths.version_id"),
            name="fk_ceg_steps_path_version",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ("node_id", "version_id"),
            ("canonical_execution_graph_nodes.id", "canonical_execution_graph_nodes.version_id"),
            name="fk_ceg_steps_node_version",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("via_edge_id", "version_id"),
            ("canonical_execution_graph_edges.id", "canonical_execution_graph_edges.version_id"),
            name="fk_ceg_steps_edge_version",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("path_id", "step_order", name="uq_ceg_steps_path_order"),
        UniqueConstraint("path_id", "client_key", name="uq_ceg_steps_client_key"),
        CheckConstraint("step_order > 0", name="chk_ceg_steps_order"),
        CheckConstraint("lock_version > 0", name="chk_ceg_steps_lock_version"),
        Index("idx_ceg_steps_version", "version_id", "path_id"),
        Index("idx_ceg_steps_node", "version_id", "node_id"),
        Index("idx_ceg_steps_edge", "version_id", "via_edge_id"),
        Index("idx_ceg_steps_scope", "tenant_id", "workspace_id", "project_id", "scope_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    step_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    path_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    graph_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    client_key: Mapped[str] = mapped_column(String(128), nullable=False)
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    node_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    via_edge_id: Mapped[UUID | None] = mapped_column(Uuid)
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class CandidateGraphBuildRun(Base, TimestampMixin):
    """Service-owned, idempotent Observed Trace to Candidate build record."""

    __tablename__ = "candidate_graph_build_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            (
                "candidate_version_id",
                "graph_id",
                "tenant_id",
                "workspace_id",
                "project_id",
                "scope_id",
            ),
            (
                "canonical_execution_graph_versions.id",
                "canonical_execution_graph_versions.graph_id",
                "canonical_execution_graph_versions.tenant_id",
                "canonical_execution_graph_versions.workspace_id",
                "canonical_execution_graph_versions.project_id",
                "canonical_execution_graph_versions.scope_id",
            ),
            name="fk_candidate_builds_version_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("build_ref", name="uq_candidate_builds_ref"),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "graph_id",
            "execution_id",
            "transformer_version",
            "config_hash",
            name="uq_candidate_builds_idempotency",
        ),
        CheckConstraint(
            "status IN ('running', 'completed', 'failed')",
            name="chk_candidate_builds_status",
        ),
        CheckConstraint(
            "outcome IN ('success', 'failure', 'partial', 'unknown')",
            name="chk_candidate_builds_outcome",
        ),
        CheckConstraint(
            "length(config_hash) = 71 AND config_hash LIKE 'sha256:%'",
            name="chk_candidate_builds_config_hash",
        ),
        CheckConstraint(
            "length(request_hash) = 71 AND request_hash LIKE 'sha256:%'",
            name="chk_candidate_builds_request_hash",
        ),
        CheckConstraint(
            "length(source_identity_hash) = 71 AND source_identity_hash LIKE 'sha256:%'",
            name="chk_candidate_builds_source_identity_hash",
        ),
        CheckConstraint(
            "length(semantic_path_hash) = 71 AND semantic_path_hash LIKE 'sha256:%'",
            name="chk_candidate_builds_semantic_path_hash",
        ),
        CheckConstraint(
            "source_revision_hash IS NULL OR (length(source_revision_hash) = 71 AND source_revision_hash LIKE 'sha256:%')",
            name="chk_candidate_builds_revision_hash",
        ),
        CheckConstraint("action_count > 0", name="chk_candidate_builds_action_count"),
        CheckConstraint(
            "verified_action_count >= 0 AND verified_action_count <= action_count",
            name="chk_candidate_builds_verified_count",
        ),
        CheckConstraint(
            "retry_count >= 0 AND coordinate_click_count >= 0",
            name="chk_candidate_builds_counts",
        ),
        CheckConstraint(
            "canonical = false AND active = false AND promotion_performed = false",
            name="chk_candidate_builds_never_canonical",
        ),
        Index(
            "idx_candidate_builds_scope",
            "tenant_id",
            "workspace_id",
            "project_id",
            "graph_id",
        ),
        Index("idx_candidate_builds_execution", "execution_id"),
        Index(
            "idx_candidate_builds_semantic_path",
            "graph_id",
            "semantic_path_hash",
            "created_at",
        ),
        Index("idx_candidate_builds_version", "candidate_version_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    build_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    graph_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    candidate_version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("executions.id", ondelete="RESTRICT"), nullable=False
    )
    source_identity_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    semantic_path_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    transformer_version: Mapped[str] = mapped_column(String(80), nullable=False)
    config_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="running", nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    source_revision_hash: Mapped[str | None] = mapped_column(String(80))
    source_environment: Mapped[str] = mapped_column(String(100), nullable=False)
    source_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    action_count: Mapped[int] = mapped_column(Integer, nullable=False)
    verified_action_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    coordinate_click_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fallback_types: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    observed_trace_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    ambiguities: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    model_suggestion: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    model_invocation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("model_invocations.id", ondelete="SET NULL")
    )
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(
        ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False
    )
    canonical: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    promotion_performed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(120))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


@event.listens_for(CandidateGraphBuildRun, "before_update")
def _protect_candidate_build_identity(
    _mapper: object,
    _connection: object,
    target: CandidateGraphBuildRun,
) -> None:
    state = cast(Any, sa_inspect(target))
    immutable_fields = (
        "id",
        "build_ref",
        "tenant_id",
        "workspace_id",
        "project_id",
        "graph_id",
        "scope_id",
        "candidate_version_id",
        "execution_id",
        "source_identity_hash",
        "semantic_path_hash",
        "transformer_version",
        "config_hash",
        "request_hash",
        "status",
        "outcome",
        "source_revision_hash",
        "source_environment",
        "source_observed_at",
        "action_count",
        "verified_action_count",
        "retry_count",
        "coordinate_click_count",
        "fallback_types",
        "observed_trace_snapshot",
        "ambiguities",
        "model_suggestion",
        "model_invocation_id",
        "guardrail_event_refs",
        "trace_id",
        "canonical",
        "active",
        "promotion_performed",
    )
    if any(state.attrs[field_name].history.has_changes() for field_name in immutable_fields):
        raise ValueError("Candidate build facts and source identity are immutable")


@event.listens_for(CandidateGraphBuildRun, "before_delete")
def _protect_candidate_build_delete(
    _mapper: object,
    _connection: object,
    _target: CandidateGraphBuildRun,
) -> None:
    raise ValueError("Candidate build provenance cannot be deleted")


class CandidateGraphSourceMapping(Base):
    """Per-build provenance sidecar for every Candidate node, edge, path, and step."""

    __tablename__ = "candidate_graph_source_mappings"
    __table_args__ = (
        ForeignKeyConstraint(
            (
                "candidate_version_id",
                "graph_id",
                "tenant_id",
                "workspace_id",
                "project_id",
                "scope_id",
            ),
            (
                "canonical_execution_graph_versions.id",
                "canonical_execution_graph_versions.graph_id",
                "canonical_execution_graph_versions.tenant_id",
                "canonical_execution_graph_versions.workspace_id",
                "canonical_execution_graph_versions.project_id",
                "canonical_execution_graph_versions.scope_id",
            ),
            name="fk_candidate_mappings_version_scope",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "build_id",
            "entity_type",
            "entity_id",
            name="uq_candidate_mappings_build_entity",
        ),
        CheckConstraint(
            "entity_type IN ('node', 'edge', 'path', 'path_step')",
            name="chk_candidate_mappings_entity_type",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="chk_candidate_mappings_confidence",
        ),
        Index("idx_candidate_mappings_build", "build_id", "entity_type"),
        Index(
            "idx_candidate_mappings_version_entity",
            "candidate_version_id",
            "entity_type",
            "entity_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    build_id: Mapped[UUID] = mapped_column(
        ForeignKey("candidate_graph_build_runs.id", ondelete="CASCADE"), nullable=False
    )
    candidate_version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    graph_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    entity_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    source_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    observation_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    transformer_version: Mapped[str] = mapped_column(String(80), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    ambiguities: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


def _protect_candidate_source_mapping_mutation(
    _mapper: object,
    _connection: object,
    _target: CandidateGraphSourceMapping,
) -> None:
    raise ValueError("Candidate source mappings are append-only")


event.listen(CandidateGraphSourceMapping, "before_update", _protect_candidate_source_mapping_mutation)
event.listen(CandidateGraphSourceMapping, "before_delete", _protect_candidate_source_mapping_mutation)


class GraphCorrectionProposalRecord(Base, TimestampMixin):
    """P13 graph-specific sidecar extending the existing CCG proposal authority."""

    __tablename__ = "graph_correction_proposals"
    __table_args__ = (
        UniqueConstraint("correction_proposal_id", name="uq_graph_corrections_ccg_proposal"),
        UniqueConstraint(
            "tenant_id", "workspace_id", "idempotency_key",
            name="uq_graph_corrections_idempotency",
        ),
        CheckConstraint(
            "status IN ('draft', 'validated', 'invalid', 'pending_review', 'promoted', 'rejected')",
            name="chk_graph_corrections_status",
        ),
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="chk_graph_corrections_risk"),
        CheckConstraint("lock_version > 0", name="chk_graph_corrections_lock_version"),
        Index("idx_graph_corrections_graph", "graph_id", "created_at"),
        Index("idx_graph_corrections_candidate", "candidate_version_id"),
        Index("idx_graph_corrections_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    correction_proposal_id: Mapped[UUID] = mapped_column(
        ForeignKey("correction_proposals.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    environment_id: Mapped[UUID | None] = mapped_column(ForeignKey("project_environments.id", ondelete="RESTRICT"))
    graph_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graphs.id", ondelete="RESTRICT"), nullable=False)
    base_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    base_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    base_version_lock_version: Mapped[int] = mapped_column(Integer, nullable=False)
    candidate_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    candidate_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    candidate_build_id: Mapped[UUID] = mapped_column(ForeignKey("candidate_graph_build_runs.id", ondelete="RESTRICT"), nullable=False)
    structured_patch: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    patch_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    rationale_code: Mapped[str] = mapped_column(String(120), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="draft", nullable=False)
    validation_report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    validation_hash: Mapped[str | None] = mapped_column(String(80))
    validator_version: Mapped[str | None] = mapped_column(String(80))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    policy_decision_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    rollback_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    latest_assessment_id: Mapped[UUID | None] = mapped_column(Uuid)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class GraphLearningPolicy(Base, TimestampMixin):
    __tablename__ = "graph_learning_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "project_id", "policy_key", name="uq_graph_learning_policy_key"),
        CheckConstraint("status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')", name="chk_graph_learning_policy_status"),
        CheckConstraint("lock_version > 0", name="chk_graph_learning_policy_lock"),
        Index("idx_graph_learning_policy_scope", "tenant_id", "workspace_id", "project_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    policy_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="draft", nullable=False)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class GraphLearningPolicyVersion(Base, TimestampMixin):
    __tablename__ = "graph_learning_policy_versions"
    __table_args__ = (
        UniqueConstraint("policy_id", "version_number", name="uq_graph_learning_policy_version"),
        UniqueConstraint("policy_id", "content_hash", name="uq_graph_learning_policy_hash"),
        UniqueConstraint("tenant_id", "workspace_id", "idempotency_key", name="uq_graph_learning_policy_version_idempotency"),
        CheckConstraint("status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')", name="chk_graph_learning_policy_version_status"),
        CheckConstraint("version_number > 0 AND lock_version > 0", name="chk_graph_learning_policy_version_numbers"),
        Index("idx_graph_learning_policy_version_scope", "tenant_id", "workspace_id", "project_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(ForeignKey("graph_learning_policies.id", ondelete="RESTRICT"), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class GraphLearningPolicyBinding(Base, TimestampMixin):
    __tablename__ = "graph_learning_policy_bindings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "project_id", "scope_type", "scope_id", name="uq_graph_learning_binding_scope"),
        UniqueConstraint("tenant_id", "workspace_id", "idempotency_key", name="uq_graph_learning_binding_idempotency"),
        CheckConstraint("scope_type IN ('project', 'environment')", name="chk_graph_learning_binding_scope"),
        CheckConstraint("learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')", name="chk_graph_learning_binding_mode"),
        CheckConstraint("status IN ('active', 'disabled', 'deprecated', 'archived')", name="chk_graph_learning_binding_status"),
        CheckConstraint("lock_version > 0", name="chk_graph_learning_binding_lock"),
        Index("idx_graph_learning_binding_resolve", "tenant_id", "workspace_id", "project_id", "environment_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    environment_id: Mapped[UUID | None] = mapped_column(ForeignKey("project_environments.id", ondelete="CASCADE"))
    scope_type: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    policy_version_id: Mapped[UUID] = mapped_column(ForeignKey("graph_learning_policy_versions.id", ondelete="RESTRICT"), nullable=False)
    policy_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    learning_mode: Mapped[str] = mapped_column(String(40), default="human_supervised", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    autonomy_paused: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    pause_reason_code: Mapped[str | None] = mapped_column(String(120))
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class GraphPromotionEligibilityAssessment(Base):
    __tablename__ = "graph_promotion_eligibility_assessments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "proposal_id", "idempotency_key", name="uq_graph_promotion_assessment_idempotency"),
        CheckConstraint("learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')", name="chk_graph_promotion_assessment_mode"),
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="chk_graph_promotion_assessment_risk"),
        Index("idx_graph_promotion_assessment_proposal", "proposal_id", "evaluated_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    proposal_id: Mapped[UUID] = mapped_column(ForeignKey("graph_correction_proposals.id", ondelete="CASCADE"), nullable=False)
    graph_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graphs.id", ondelete="RESTRICT"), nullable=False)
    candidate_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    base_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    learning_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    eligible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    automatic_promotion_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    human_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    checks_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    policy_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("graph_learning_policy_versions.id", ondelete="RESTRICT"))
    policy_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    binding_id: Mapped[UUID | None] = mapped_column(ForeignKey("graph_learning_policy_bindings.id", ondelete="RESTRICT"))
    eligibility_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    policy_decision_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evaluated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class CanonicalGraphPromotionRecord(Base):
    __tablename__ = "canonical_graph_promotion_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "idempotency_key", name="uq_canonical_graph_promotion_idempotency"),
        UniqueConstraint("target_version_id", name="uq_canonical_graph_promotion_target"),
        CheckConstraint(
            "promotion_type IN ('human_approved_promotion', 'policy_approved_auto_promotion', 'human_approved_rollback')",
            name="chk_canonical_graph_promotion_type",
        ),
        CheckConstraint("actor_type IN ('human', 'system')", name="chk_canonical_graph_promotion_actor"),
        CheckConstraint(
            "(actor_type = 'system' AND actor_ref = 'system://controlled-graph-promotion') OR "
            "(actor_type = 'human' AND actor_ref LIKE 'user://users/%')",
            name="chk_canonical_graph_promotion_actor_ref",
        ),
        CheckConstraint(
            "(promotion_type = 'policy_approved_auto_promotion' AND human_approval = false) OR "
            "(promotion_type <> 'policy_approved_auto_promotion' AND human_approval = true)",
            name="chk_canonical_graph_promotion_approval_truth",
        ),
        CheckConstraint("status IN ('promoted', 'rolled_back')", name="chk_canonical_graph_promotion_status"),
        Index("idx_canonical_graph_promotion_graph", "graph_id", "promoted_at"),
        Index("idx_canonical_graph_promotion_proposal", "proposal_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    graph_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graphs.id", ondelete="RESTRICT"), nullable=False)
    proposal_id: Mapped[UUID] = mapped_column(ForeignKey("graph_correction_proposals.id", ondelete="RESTRICT"), nullable=False)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("graph_promotion_eligibility_assessments.id", ondelete="RESTRICT"), nullable=False)
    before_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    before_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    candidate_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    target_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    target_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    promotion_type: Mapped[str] = mapped_column(String(48), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    human_approval: Mapped[bool] = mapped_column(Boolean, nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    policy_decision_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    eligibility_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    policy_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("graph_learning_policy_versions.id", ondelete="RESTRICT"))
    policy_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    shadow_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    rollback_target_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"))
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    promoted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    promoted_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


def _protect_append_only_graph_promotion_record(
    _mapper: object, _connection: object, _target: object
) -> None:
    raise ValueError("Graph Promotion assessments and records are immutable")


for _graph_promotion_fact in (
    GraphPromotionEligibilityAssessment,
    CanonicalGraphPromotionRecord,
):
    event.listen(_graph_promotion_fact, "before_update", _protect_append_only_graph_promotion_record)
    event.listen(_graph_promotion_fact, "before_delete", _protect_append_only_graph_promotion_record)


class CanonicalGraphStalenessAssessment(Base):
    """Immutable P14 applicability and freshness decision for one exact Graph version."""

    __tablename__ = "canonical_graph_staleness_assessments"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "graph_version_id", "source_fingerprint",
            name="uq_ceg_staleness_source_fingerprint",
        ),
        UniqueConstraint(
            "tenant_id", "workspace_id", "graph_version_id", "idempotency_key",
            name="uq_ceg_staleness_idempotency",
        ),
        CheckConstraint(
            "status IN ('fresh', 'suspect', 'stale', 'invalid', 'unknown')",
            name="chk_ceg_staleness_status",
        ),
        CheckConstraint(
            "length(source_fingerprint) = 71 AND source_fingerprint LIKE 'sha256:%'",
            name="chk_ceg_staleness_source_fingerprint",
        ),
        CheckConstraint(
            "length(assessment_hash) = 71 AND assessment_hash LIKE 'sha256:%'",
            name="chk_ceg_staleness_assessment_hash",
        ),
        Index(
            "idx_ceg_staleness_current",
            "tenant_id", "workspace_id", "project_id", "graph_version_id", "assessed_at",
        ),
        Index("idx_ceg_staleness_status", "status", "assessed_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    graph_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graphs.id", ondelete="RESTRICT"), nullable=False)
    graph_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    applicability_range: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    signals_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(80), nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    impact_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    automatic_promotion_eligible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    assessment_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assessed_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CanonicalGraphStalenessReview(Base, TimestampMixin):
    """Approval-backed P14 human confirmation, bounded override, or deprecation request."""

    __tablename__ = "canonical_graph_staleness_reviews"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workspace_id", "graph_version_id", "idempotency_key",
            name="uq_ceg_staleness_review_idempotency",
        ),
        CheckConstraint(
            "action IN ('confirm', 'override', 'deprecate')",
            name="chk_ceg_staleness_review_action",
        ),
        CheckConstraint(
            "status IN ('pending', 'applied', 'rejected', 'expired')",
            name="chk_ceg_staleness_review_status",
        ),
        CheckConstraint(
            "requested_status IS NULL OR requested_status IN ('fresh', 'suspect', 'stale', 'invalid', 'unknown')",
            name="chk_ceg_staleness_review_requested_status",
        ),
        CheckConstraint(
            "(action = 'override' AND requested_status IS NOT NULL AND expires_at IS NOT NULL) "
            "OR (action <> 'override' AND requested_status IS NULL)",
            name="chk_ceg_staleness_review_override_expiry",
        ),
        CheckConstraint("lock_version > 0", name="chk_ceg_staleness_review_lock"),
        Index("idx_ceg_staleness_review_version", "graph_version_id", "created_at"),
        Index("idx_ceg_staleness_review_status", "status", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    graph_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graphs.id", ondelete="RESTRICT"), nullable=False)
    graph_version_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("canonical_graph_staleness_assessments.id", ondelete="RESTRICT"), nullable=False)
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    requested_status: Mapped[str | None] = mapped_column(String(24))
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="pending", nullable=False)
    approval_id: Mapped[UUID] = mapped_column(ForeignKey("approvals.id", ondelete="RESTRICT"), nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="RESTRICT"), nullable=False)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    requested_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


for _graph_staleness_fact in (CanonicalGraphStalenessAssessment,):
    event.listen(_graph_staleness_fact, "before_update", _protect_append_only_graph_promotion_record)
    event.listen(_graph_staleness_fact, "before_delete", _protect_append_only_graph_promotion_record)


@event.listens_for(GraphLearningPolicyVersion, "before_update")
def _protect_published_graph_learning_policy(
    _mapper: object, _connection: object, target: GraphLearningPolicyVersion
) -> None:
    state: Any = cast(Any, sa_inspect(target))
    original_status = (
        state.attrs.status.history.deleted[0]
        if state.attrs.status.history.deleted
        else target.status
    )
    if original_status != "draft" and any(
        state.attrs[name].history.has_changes()
        for name in ("policy_id", "version_number", "policy_document", "content_hash")
    ):
        raise ValueError("published Graph Learning Policy versions are immutable")


_CEG_IDENTITY_FIELDS = (
    "tenant_id",
    "workspace_id",
    "project_id",
    "environment_id",
    "scope_type",
    "scope_id",
    "graph_key",
    "graph_ref",
)
_CEG_VERSION_CONTENT_FIELDS = (
    "graph_id",
    "tenant_id",
    "workspace_id",
    "project_id",
    "environment_id",
    "scope_type",
    "scope_id",
    "version_number",
    "version_ref",
    "parent_version_id",
    "source",
    "schema_version",
    "content_hash",
    "source_refs",
    "applicability",
    "metadata_json",
)
_CEG_MUTABLE_VERSION_STATUSES = {GraphStatus.DRAFT, GraphStatus.CANDIDATE}


@event.listens_for(CanonicalExecutionGraph, "before_update")
def _protect_ceg_identity(_mapper: object, _connection: object, target: CanonicalExecutionGraph) -> None:
    state = sa_inspect(target)
    status_history = state.attrs.status.history
    original_status = status_history.deleted[0] if status_history.deleted else target.status
    if original_status == GraphStatus.ARCHIVED:
        raise ValueError("archived Canonical Execution Graph identities are immutable")
    if any(state.attrs[field_name].history.has_changes() for field_name in _CEG_IDENTITY_FIELDS):
        raise ValueError("Canonical Execution Graph identity and scope are immutable")


@event.listens_for(CanonicalExecutionGraphVersion, "before_update")
def _protect_ceg_version(
    _mapper: object,
    _connection: object,
    target: CanonicalExecutionGraphVersion,
) -> None:
    state = sa_inspect(target)
    status_history = state.attrs.status.history
    frozen_history = state.attrs.is_frozen.history
    original_status = status_history.deleted[0] if status_history.deleted else target.status
    original_frozen = frozen_history.deleted[0] if frozen_history.deleted else target.is_frozen
    content_changed = any(
        state.attrs[field_name].history.has_changes() for field_name in _CEG_VERSION_CONTENT_FIELDS
    )
    if original_status == GraphStatus.ARCHIVED:
        raise ValueError("archived Canonical Execution Graph versions are immutable")
    if (original_frozen or original_status not in _CEG_MUTABLE_VERSION_STATUSES) and content_changed:
        raise ValueError("frozen or published Canonical Execution Graph version content is immutable")
    controlled_promotion_transition = (
        not original_frozen
        and original_status in _CEG_MUTABLE_VERSION_STATUSES
        and target.is_frozen
        and target.status == GraphStatus.ACTIVE
        and target.source == GraphSource.CANONICAL
        and target.metadata_json.get("promotionType")
        in {
            "human_approved_promotion",
            "policy_approved_auto_promotion",
            "human_approved_rollback",
        }
    )
    if (
        target.is_frozen or target.status not in _CEG_MUTABLE_VERSION_STATUSES
    ) and content_changed and not controlled_promotion_transition:
        raise ValueError("freezing or publishing a Canonical Execution Graph version cannot change content")


@event.listens_for(CanonicalExecutionGraphVersion, "before_delete")
def _protect_ceg_version_delete(
    _mapper: object,
    _connection: object,
    target: CanonicalExecutionGraphVersion,
) -> None:
    if target.is_frozen or target.status not in _CEG_MUTABLE_VERSION_STATUSES:
        raise ValueError("frozen or published Canonical Execution Graph versions cannot be deleted")


_CEG_TOPOLOGY_MODELS = (
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
)
_CEG_TOPOLOGY_IMMUTABLE_FIELDS: dict[type, tuple[str, ...]] = {
    CanonicalExecutionGraphNode: (
        "id", "node_ref", "version_id", "graph_id", "tenant_id", "workspace_id",
        "project_id", "scope_id", "client_key",
    ),
    CanonicalExecutionGraphEdge: (
        "id", "edge_ref", "version_id", "graph_id", "tenant_id", "workspace_id",
        "project_id", "scope_id", "client_key",
    ),
    CanonicalExecutionGraphPath: (
        "id", "path_ref", "version_id", "graph_id", "tenant_id", "workspace_id",
        "project_id", "scope_id", "client_key",
    ),
    CanonicalExecutionGraphPathStep: (
        "id", "step_ref", "path_id", "version_id", "graph_id", "tenant_id",
        "workspace_id", "project_id", "scope_id", "client_key",
    ),
}


def _require_ceg_topology_version_mutable(connection: Connection, version_id: UUID) -> None:
    row = connection.execute(
        select(
            CanonicalExecutionGraphVersion.status,
            CanonicalExecutionGraphVersion.is_frozen,
        ).where(CanonicalExecutionGraphVersion.id == version_id)
    ).first()
    if row is None:
        raise ValueError("Canonical Execution Graph topology requires an existing version")
    if row.is_frozen or row.status not in _CEG_MUTABLE_VERSION_STATUSES:
        raise ValueError("canonical or published Canonical Execution Graph topology is immutable")


def _protect_ceg_topology_insert(
    _mapper: object,
    connection: Connection,
    target: CanonicalExecutionGraphNode
    | CanonicalExecutionGraphEdge
    | CanonicalExecutionGraphPath
    | CanonicalExecutionGraphPathStep,
) -> None:
    _require_ceg_topology_version_mutable(connection, target.version_id)


def _protect_ceg_topology_update(
    _mapper: object,
    connection: Connection,
    target: CanonicalExecutionGraphNode
    | CanonicalExecutionGraphEdge
    | CanonicalExecutionGraphPath
    | CanonicalExecutionGraphPathStep,
) -> None:
    _require_ceg_topology_version_mutable(connection, target.version_id)
    state: Any = cast(Any, sa_inspect(target))
    if state is None:
        raise ValueError("Canonical Execution Graph topology state is unavailable")
    if any(
        state.attrs[field_name].history.has_changes()
        for field_name in _CEG_TOPOLOGY_IMMUTABLE_FIELDS[type(target)]
    ):
        raise ValueError("Canonical Execution Graph topology identity and scope are immutable")


def _protect_ceg_topology_delete(
    _mapper: object,
    connection: Connection,
    target: CanonicalExecutionGraphNode
    | CanonicalExecutionGraphEdge
    | CanonicalExecutionGraphPath
    | CanonicalExecutionGraphPathStep,
) -> None:
    _require_ceg_topology_version_mutable(connection, target.version_id)


for _ceg_topology_model in _CEG_TOPOLOGY_MODELS:
    event.listen(_ceg_topology_model, "before_insert", _protect_ceg_topology_insert)
    event.listen(_ceg_topology_model, "before_update", _protect_ceg_topology_update)
    event.listen(_ceg_topology_model, "before_delete", _protect_ceg_topology_delete)


class TestPlan(Base, TimestampMixin):
    __tablename__ = "test_plans"
    __table_args__ = (
        Index("idx_test_plans_project", "project_id"),
        Index("idx_test_plans_environment_ref", "environment_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(db_enum(SourceType), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(255))
    environment: Mapped[str] = mapped_column(String(100), nullable=False)
    project_id: Mapped[UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="SET NULL"))
    environment_id: Mapped[UUID | None] = mapped_column(ForeignKey("project_environments.id", ondelete="SET NULL"))
    risk_level: Mapped[RiskLevel] = mapped_column(db_enum(RiskLevel), default=RiskLevel.MEDIUM, nullable=False)
    status: Mapped[PlanStatus] = mapped_column(db_enum(PlanStatus), default=PlanStatus.DRAFT, nullable=False)
    input_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    generated_plan: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    requirement_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    requirement_scope_id: Mapped[str | None] = mapped_column(
        ForeignKey("requirement_scopes.scope_id", ondelete="SET NULL")
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    requirement_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_versions.id", ondelete="SET NULL"))


class TestPlanDomain(Base):
    __tablename__ = "test_plan_domains"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    plan_id: Mapped[UUID] = mapped_column(ForeignKey("test_plans.id", ondelete="CASCADE"), nullable=False)
    domain: Mapped[TestDomain] = mapped_column(db_enum(TestDomain), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class Execution(Base, TimestampMixin):
    __tablename__ = "executions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    plan_id: Mapped[UUID] = mapped_column(ForeignKey("test_plans.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[TaskStatus] = mapped_column(db_enum(TaskStatus), default=TaskStatus.QUEUED, nullable=False)
    stage: Mapped[ExecutionStage] = mapped_column(db_enum(ExecutionStage), default=ExecutionStage.PREPARE, nullable=False)
    environment: Mapped[str] = mapped_column(String(100), nullable=False)
    triggered_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    trigger_source: Mapped[str] = mapped_column(String(50), default="manual", nullable=False)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_plan_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_plans.id", ondelete="SET NULL"))


class ExecutionTask(Base, TimestampMixin):
    __tablename__ = "execution_tasks"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    parent_task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="SET NULL"))
    domain: Mapped[TestDomain] = mapped_column(db_enum(TestDomain), nullable=False)
    task_type: Mapped[str] = mapped_column(String(150), nullable=False)
    runner: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[TaskStatus] = mapped_column(db_enum(TaskStatus), default=TaskStatus.QUEUED, nullable=False)
    stage: Mapped[ExecutionStage | None] = mapped_column(db_enum(ExecutionStage))
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExecutionMetric(Base):
    __tablename__ = "execution_metrics"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    metric_name: Mapped[str] = mapped_column(String(150), nullable=False)
    metric_value: Mapped[Decimal] = mapped_column(Numeric(20, 6), nullable=False)
    metric_unit: Mapped[str | None] = mapped_column(String(50))
    threshold_value: Mapped[Decimal | None] = mapped_column(Numeric(20, 6))
    baseline_value: Mapped[Decimal | None] = mapped_column(Numeric(20, 6))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ExecutionArtifact(Base):
    __tablename__ = "execution_artifacts"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    artifact_type: Mapped[ArtifactType] = mapped_column(db_enum(ArtifactType), nullable=False)
    uri: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    redaction_status: Mapped[str] = mapped_column(String(50), default="not_required", nullable=False)
    redacted_uri: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ExecutionLog(Base):
    __tablename__ = "execution_logs"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    level: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RawFindingRecord(Base):
    __tablename__ = "raw_findings"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    normalized_finding_id: Mapped[UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="SET NULL"))
    domain: Mapped[TestDomain] = mapped_column(db_enum(TestDomain), nullable=False)
    source: Mapped[FindingSource] = mapped_column(db_enum(FindingSource), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(db_enum(FindingSeverity), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(db_enum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    category: Mapped[FindingCategory] = mapped_column(db_enum(FindingCategory), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_ref: Mapped[UUID | None] = mapped_column(ForeignKey("execution_artifacts.id", ondelete="SET NULL"))
    comment: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)


class WorkItem(Base, TimestampMixin):
    __tablename__ = "work_items"
    __table_args__ = (
        CheckConstraint("status IN ('open', 'assigned', 'in_progress', 'completed', 'cancelled')", name="chk_work_items_status"),
        CheckConstraint("priority IN ('low', 'medium', 'high', 'urgent')", name="chk_work_items_priority"),
        Index("idx_work_items_project", "project_id"),
        Index("idx_work_items_requirement_version", "requirement_version_id"),
        Index("idx_work_items_execution", "execution_id"),
        Index("idx_work_items_finding", "finding_id"),
        Index("idx_work_items_assignee", "assignee_id"),
        Index("idx_work_items_claimed_by", "claimed_by"),
        Index("idx_work_items_status", "status"),
        Index("idx_work_items_created_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    requirement_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_versions.id", ondelete="SET NULL"))
    requirement_item_id: Mapped[str | None] = mapped_column(String(255))
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    finding_id: Mapped[UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    evidence_artifact_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_artifacts.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    priority: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    assignee_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    claimed_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ExternalIssueLink(Base, TimestampMixin):
    __tablename__ = "external_issue_links"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_external_issue_links_idempotency_key"),
        Index("idx_external_issue_links_finding", "finding_id"),
        Index("idx_external_issue_links_execution", "execution_id"),
        Index("idx_external_issue_links_connector", "connector_name"),
        Index("idx_external_issue_links_external_issue", "connector_name", "external_issue_key"),
        Index("idx_external_issue_links_sync_status", "sync_status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    connector_binding_id: Mapped[UUID | None] = mapped_column(ForeignKey("skill_connector_bindings.id", ondelete="SET NULL"))
    connector_name: Mapped[str] = mapped_column(String(128), nullable=False)
    external_issue_id: Mapped[str | None] = mapped_column(String(255))
    external_issue_key: Mapped[str | None] = mapped_column(String(255))
    external_issue_url: Mapped[str | None] = mapped_column(Text)
    external_status: Mapped[str | None] = mapped_column(String(80))
    sync_status: Mapped[str] = mapped_column(String(40), default="pending", nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    connector_call_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    payload_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)


class TriageResult(Base):
    __tablename__ = "triage_results"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    category: Mapped[TriageCategory] = mapped_column(db_enum(TriageCategory), default=TriageCategory.UNKNOWN, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), default=Decimal("0.0"), nullable=False)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    challenged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    final_decision_by: Mapped[str | None] = mapped_column(String(50))
    raw_output: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class HealingSuggestion(Base):
    __tablename__ = "healing_suggestions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    suggestion_type: Mapped[str] = mapped_column(String(100), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    patch: Mapped[str | None] = mapped_column(Text)
    success: Mapped[bool | None] = mapped_column(Boolean)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class GateDecision(Base, TimestampMixin):
    __tablename__ = "gate_results"
    __table_args__ = (
        Index("idx_gate_results_policy_version", "policy_version_id"),
        Index("idx_gate_results_input_fingerprint", "input_fingerprint"),
        Index("idx_gate_results_decision_snapshot_hash", "decision_snapshot_hash"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), unique=True, nullable=False)
    functional: Mapped[GateResult] = mapped_column(db_enum(GateResult), default=GateResult.WARN, nullable=False)
    performance: Mapped[GateResult] = mapped_column(db_enum(GateResult), default=GateResult.WARN, nullable=False)
    security: Mapped[GateResult] = mapped_column(db_enum(GateResult), default=GateResult.WARN, nullable=False)
    overall: Mapped[GateResult] = mapped_column(db_enum(GateResult), default=GateResult.WARN, nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    decided_by: Mapped[str] = mapped_column(String(50), default="system", nullable=False)
    policy_version_id: Mapped[str | None] = mapped_column(String(255))
    policy_version_hash: Mapped[str | None] = mapped_column(String(80))
    policy_binding_ref: Mapped[str | None] = mapped_column(String(500))
    reason_codes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    matched_rules: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    completeness: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 4), default=Decimal("0"), nullable=False)
    input_fingerprint: Mapped[str | None] = mapped_column(String(80))
    decision_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    decision_snapshot_hash: Mapped[str | None] = mapped_column(String(80))
    evaluator_version: Mapped[str] = mapped_column(String(80), default="legacy.gate-evaluator.v1", nullable=False)


class GatePolicy(Base, TimestampMixin):
    __tablename__ = "gate_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "policy_key", name="uq_gate_policies_scope_key"),
        UniqueConstraint("id", "tenant_id", "workspace_id", name="uq_gate_policies_tenant_identity"),
        CheckConstraint("length(trim(tenant_id)) > 0", name="chk_gate_policies_tenant_not_blank"),
        CheckConstraint("length(trim(workspace_id)) > 0", name="chk_gate_policies_workspace_not_blank"),
        CheckConstraint("lock_version > 0", name="chk_gate_policies_lock_version"),
        Index("idx_gate_policies_tenant_workspace", "tenant_id", "workspace_id"),
        Index("idx_gate_policies_project", "project_id"),
        Index("idx_gate_policies_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"))
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_key: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[GatePolicyStatus] = mapped_column(
        db_enum(GatePolicyStatus),
        default=GatePolicyStatus.DRAFT,
        nullable=False,
    )
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class GatePolicyVersion(Base, TimestampMixin):
    __tablename__ = "gate_policy_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ("policy_id", "tenant_id", "workspace_id"),
            ("gate_policies.id", "gate_policies.tenant_id", "gate_policies.workspace_id"),
            name="fk_gate_policy_versions_policy_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("policy_id", "version_number", name="uq_gate_policy_versions_policy_version"),
        UniqueConstraint("policy_id", "content_hash", name="uq_gate_policy_versions_policy_hash"),
        UniqueConstraint(
            "id",
            "policy_id",
            "tenant_id",
            "workspace_id",
            "content_hash",
            name="uq_gate_policy_versions_tenant_identity",
        ),
        CheckConstraint("version_number > 0", name="chk_gate_policy_versions_number"),
        CheckConstraint("length(content_hash) = 71", name="chk_gate_policy_versions_hash_length"),
        CheckConstraint("substr(content_hash, 1, 7) = 'sha256:'", name="chk_gate_policy_versions_hash_prefix"),
        CheckConstraint("lock_version > 0", name="chk_gate_policy_versions_lock_version"),
        CheckConstraint(
            "validation_status IN ('not_validated', 'valid', 'invalid')",
            name="chk_gate_policy_versions_validation_status",
        ),
        CheckConstraint(
            "governance_status IN ("
            "'draft', 'review_pending', 'review_approved', 'review_rejected', "
            "'review_cancelled', 'review_expired', 'transition_pending', "
            "'transition_applied', 'transition_rejected', 'transition_cancelled', 'transition_expired'"
            ")",
            name="chk_gate_policy_versions_governance_status",
        ),
        Index("idx_gate_policy_versions_policy_status", "policy_id", "status"),
        Index("idx_gate_policy_versions_scope", "tenant_id", "workspace_id"),
        Index("idx_gate_policy_versions_hash", "content_hash"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    version_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[GatePolicyStatus] = mapped_column(db_enum(GatePolicyStatus), nullable=False)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    capability_ref: Mapped[str | None] = mapped_column(String(500))
    approval_policy_ref: Mapped[str | None] = mapped_column(String(500))
    validation_status: Mapped[str] = mapped_column(String(32), default="not_validated", nullable=False)
    validation_report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    validated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    governance_status: Mapped[str] = mapped_column(String(40), default="draft", nullable=False)
    current_approval_id: Mapped[UUID | None] = mapped_column(ForeignKey("approvals.id", ondelete="SET NULL"))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class GatePolicyBinding(Base, TimestampMixin):
    __tablename__ = "gate_policy_bindings"
    __table_args__ = (
        ForeignKeyConstraint(
            ("policy_version_id", "policy_id", "tenant_id", "workspace_id", "policy_version_hash"),
            (
                "gate_policy_versions.id",
                "gate_policy_versions.policy_id",
                "gate_policy_versions.tenant_id",
                "gate_policy_versions.workspace_id",
                "gate_policy_versions.content_hash",
            ),
            name="fk_gate_policy_bindings_version_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "idempotency_key",
            name="uq_gate_policy_bindings_idempotency",
        ),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "policy_id",
            "scope_type",
            "scope_key",
            "effective_from",
            name="uq_gate_policy_bindings_effective_scope",
        ),
        CheckConstraint("length(trim(tenant_id)) > 0", name="chk_gate_policy_bindings_tenant_not_blank"),
        CheckConstraint("length(trim(workspace_id)) > 0", name="chk_gate_policy_bindings_workspace_not_blank"),
        CheckConstraint(
            "(scope_type = 'global' AND scope_id IS NULL AND scope_key = 'global') OR "
            "(scope_type <> 'global' AND scope_id IS NOT NULL AND length(trim(scope_id)) > 0 AND scope_key = scope_id)",
            name="chk_gate_policy_bindings_scope_identity",
        ),
        CheckConstraint(
            "scope_type <> 'workspace' OR scope_id = workspace_id",
            name="chk_gate_policy_bindings_workspace_scope",
        ),
        CheckConstraint(
            "effective_until IS NULL OR effective_until > effective_from",
            name="chk_gate_policy_bindings_effective_window",
        ),
        CheckConstraint("length(policy_version_hash) = 71", name="chk_gate_policy_bindings_hash_length"),
        CheckConstraint("substr(policy_version_hash, 1, 7) = 'sha256:'", name="chk_gate_policy_bindings_hash_prefix"),
        CheckConstraint("length(request_hash) = 71", name="chk_gate_policy_bindings_request_hash_length"),
        CheckConstraint("substr(request_hash, 1, 7) = 'sha256:'", name="chk_gate_policy_bindings_request_hash_prefix"),
        CheckConstraint("lock_version > 0", name="chk_gate_policy_bindings_lock_version"),
        CheckConstraint("mode IN ('observe', 'shadow', 'enforce')", name="chk_gate_policy_bindings_mode"),
        Index("idx_gate_policy_bindings_resolution", "tenant_id", "workspace_id", "scope_type", "scope_key", "status"),
        Index(
            "idx_gate_policy_bindings_mode_resolution",
            "tenant_id",
            "workspace_id",
            "scope_type",
            "scope_key",
            "mode",
            "status",
        ),
        Index("idx_gate_policy_bindings_version", "policy_version_id"),
        Index("idx_gate_policy_bindings_effective", "effective_from", "effective_until"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    policy_version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    policy_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    binding_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    scope_type: Mapped[GatePolicyScopeType] = mapped_column(db_enum(GatePolicyScopeType), nullable=False)
    scope_id: Mapped[str | None] = mapped_column(String(255))
    scope_key: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[GatePolicyStatus] = mapped_column(
        db_enum(GatePolicyStatus),
        default=GatePolicyStatus.DRAFT,
        nullable=False,
    )
    mode: Mapped[GatePolicyMode] = mapped_column(
        db_enum(GatePolicyMode),
        default=GatePolicyMode.ENFORCE,
        nullable=False,
    )
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    effective_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    capability_ref: Mapped[str | None] = mapped_column(String(500))
    approval_policy_ref: Mapped[str | None] = mapped_column(String(500))
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __mapper_args__ = {"version_id_col": lock_version}


class GatePolicyGovernanceRequest(Base, TimestampMixin):
    """Durable idempotency journal for Service-owned Gate Policy mutations."""

    __tablename__ = "gate_policy_governance_requests"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "operation",
            "idempotency_key",
            name="uq_gate_policy_governance_request_idempotency",
        ),
        CheckConstraint("length(trim(tenant_id)) > 0", name="chk_gate_policy_governance_tenant_not_blank"),
        CheckConstraint("length(trim(workspace_id)) > 0", name="chk_gate_policy_governance_workspace_not_blank"),
        CheckConstraint("length(request_hash) = 71", name="chk_gate_policy_governance_hash_length"),
        CheckConstraint("substr(request_hash, 1, 7) = 'sha256:'", name="chk_gate_policy_governance_hash_prefix"),
        Index("idx_gate_policy_governance_project", "project_id", "created_at"),
        Index("idx_gate_policy_governance_resource", "resource_type", "resource_id"),
        Index("idx_gate_policy_governance_approval", "approval_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    operation: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    approval_id: Mapped[UUID | None] = mapped_column(ForeignKey("approvals.id", ondelete="SET NULL"))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class GatePolicySimulationRun(Base, TimestampMixin):
    __tablename__ = "gate_policy_simulation_runs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "run_type",
            "idempotency_key",
            name="uq_gate_policy_simulation_run_idempotency",
        ),
        CheckConstraint("run_type IN ('historical', 'shadow')", name="chk_gate_policy_simulation_run_type"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled', 'timed_out')",
            name="chk_gate_policy_simulation_run_status",
        ),
        CheckConstraint("length(dataset_fingerprint) = 71", name="chk_gate_policy_simulation_dataset_hash_length"),
        CheckConstraint("substr(dataset_fingerprint, 1, 7) = 'sha256:'", name="chk_gate_policy_simulation_dataset_hash_prefix"),
        CheckConstraint("length(policy_version_hash) = 71", name="chk_gate_policy_simulation_policy_hash_length"),
        CheckConstraint("substr(policy_version_hash, 1, 7) = 'sha256:'", name="chk_gate_policy_simulation_policy_hash_prefix"),
        CheckConstraint("length(request_hash) = 71", name="chk_gate_policy_simulation_request_hash_length"),
        CheckConstraint("substr(request_hash, 1, 7) = 'sha256:'", name="chk_gate_policy_simulation_request_hash_prefix"),
        CheckConstraint("total_cases >= 0 AND completed_cases >= 0 AND unavailable_cases >= 0 AND failed_cases >= 0", name="chk_gate_policy_simulation_counts"),
        Index("idx_gate_policy_simulation_project", "project_id", "created_at"),
        Index("idx_gate_policy_simulation_version", "policy_version_id", "status"),
        Index("idx_gate_policy_simulation_retention", "retention_until"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    policy_id: Mapped[UUID] = mapped_column(ForeignKey("gate_policies.id", ondelete="RESTRICT"), nullable=False)
    source_policy_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("gate_policy_versions.id", ondelete="SET NULL"))
    policy_version_id: Mapped[UUID] = mapped_column(ForeignKey("gate_policy_versions.id", ondelete="RESTRICT"), nullable=False)
    policy_version_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    evaluator_version: Mapped[str] = mapped_column(String(80), nullable=False)
    run_type: Mapped[str] = mapped_column(String(24), default="historical", nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    dataset_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    case_snapshot_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    total_cases: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completed_cases: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unavailable_cases: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_cases: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(120))
    job_id: Mapped[UUID | None] = mapped_column(ForeignKey("jobs.id", ondelete="SET NULL"))
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class GatePolicySimulationCase(Base):
    __tablename__ = "gate_policy_simulation_cases"
    __table_args__ = (
        UniqueConstraint("simulation_run_id", "case_index", name="uq_gate_policy_simulation_case_index"),
        UniqueConstraint("simulation_run_id", "gate_input_snapshot_ref", name="uq_gate_policy_simulation_case_snapshot"),
        CheckConstraint("status IN ('completed', 'unavailable', 'failed')", name="chk_gate_policy_simulation_case_status"),
        Index("idx_gate_policy_simulation_case_run", "simulation_run_id", "case_index"),
        Index("idx_gate_policy_simulation_case_gate", "gate_decision_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    simulation_run_id: Mapped[UUID] = mapped_column(ForeignKey("gate_policy_simulation_runs.id", ondelete="CASCADE"), nullable=False)
    case_index: Mapped[int] = mapped_column(Integer, nullable=False)
    gate_input_snapshot_id: Mapped[UUID | None] = mapped_column(ForeignKey("gate_input_snapshots.id", ondelete="SET NULL"))
    gate_decision_id: Mapped[UUID | None] = mapped_column(ForeignKey("gate_results.id", ondelete="SET NULL"))
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    gate_input_snapshot_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    gate_input_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    input_fingerprint: Mapped[str | None] = mapped_column(String(80))
    case_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    old_decision: Mapped[str | None] = mapped_column(String(24))
    new_decision: Mapped[str | None] = mapped_column(String(24))
    old_decision_snapshot_hash: Mapped[str | None] = mapped_column(String(80))
    new_decision_snapshot_hash: Mapped[str | None] = mapped_column(String(80))
    reason_diff: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    false_pass_risk: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    new_block: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class GatePolicyBindingHistory(Base, TimestampMixin):
    __tablename__ = "gate_policy_binding_history"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "action",
            "idempotency_key",
            name="uq_gate_policy_binding_history_idempotency",
        ),
        CheckConstraint("action IN ('mode_change', 'activation', 'rollback')", name="chk_gate_policy_binding_history_action"),
        CheckConstraint("mode IN ('observe', 'shadow', 'enforce')", name="chk_gate_policy_binding_history_mode"),
        CheckConstraint("status IN ('applied', 'failed')", name="chk_gate_policy_binding_history_status"),
        Index("idx_gate_policy_binding_history_project", "project_id", "created_at"),
        Index("idx_gate_policy_binding_history_binding", "binding_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    mode: Mapped[GatePolicyMode] = mapped_column(db_enum(GatePolicyMode), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    binding_id: Mapped[UUID] = mapped_column(ForeignKey("gate_policy_bindings.id", ondelete="RESTRICT"), nullable=False)
    previous_binding_id: Mapped[UUID | None] = mapped_column(ForeignKey("gate_policy_bindings.id", ondelete="SET NULL"))
    policy_version_id: Mapped[UUID] = mapped_column(ForeignKey("gate_policy_versions.id", ondelete="RESTRICT"), nullable=False)
    previous_policy_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("gate_policy_versions.id", ondelete="SET NULL"))
    simulation_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("gate_policy_simulation_runs.id", ondelete="SET NULL"))
    approval_id: Mapped[UUID | None] = mapped_column(ForeignKey("approvals.id", ondelete="SET NULL"))
    before_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    after_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


@event.listens_for(GatePolicyBindingHistory, "before_update")
@event.listens_for(GatePolicyBindingHistory, "before_delete")
def _prevent_gate_policy_binding_history_mutation(
    _mapper: object, _connection: object, _target: GatePolicyBindingHistory
) -> None:
    raise ValueError("Gate Policy binding history is append-only")


@event.listens_for(GatePolicyVersion, "before_update")
def _prevent_published_gate_policy_version_update(_mapper: object, _connection: object, target: GatePolicyVersion) -> None:
    state = sa_inspect(target)
    status_history = state.attrs.status.history
    original_status = status_history.deleted[0] if status_history.deleted else target.status
    immutable_fields = (
        "policy_id",
        "tenant_id",
        "workspace_id",
        "version_number",
        "version_ref",
        "schema_version",
        "policy_snapshot",
        "content_hash",
        "capability_ref",
        "approval_policy_ref",
    )
    if original_status != GatePolicyStatus.DRAFT and any(
        state.attrs[field_name].history.has_changes() for field_name in immutable_fields
    ):
        raise ValueError("published Gate Policy versions are immutable")
    if target.status != GatePolicyStatus.DRAFT and any(
        state.attrs[field_name].history.has_changes() for field_name in immutable_fields
    ):
        raise ValueError("publishing a Gate Policy version cannot change its frozen content")


_EFFECTIVE_RELATION_WHERE = text("status IN ('confirmed', 'system_verified')")


class RequirementItemTestPoint(Base, TraceabilityRelationMixin):
    __tablename__ = "requirement_item_test_points"
    __table_args__ = (
        Index(
            "uq_requirement_item_test_points_effective",
            "requirement_item_id",
            "test_point_id",
            "relation_type",
            "scope_id",
            unique=True,
            postgresql_where=_EFFECTIVE_RELATION_WHERE,
            sqlite_where=_EFFECTIVE_RELATION_WHERE,
        ),
        Index("idx_requirement_item_test_points_requirement", "requirement_version_id"),
        Index("idx_requirement_item_test_points_test_point", "test_point_id"),
        Index("idx_requirement_item_test_points_status", "status"),
    )

    requirement_item_id: Mapped[str] = mapped_column(String(255), nullable=False)
    test_point_id: Mapped[UUID] = mapped_column(ForeignKey("test_assets.id", ondelete="CASCADE"), nullable=False)
    requirement_version_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_versions.id", ondelete="CASCADE"), nullable=False)


class TestPointTestCase(Base, TraceabilityRelationMixin):
    __tablename__ = "test_point_test_cases"
    __table_args__ = (
        Index(
            "uq_test_point_test_cases_effective",
            "test_point_id",
            "test_case_id",
            "relation_type",
            "scope_id",
            unique=True,
            postgresql_where=_EFFECTIVE_RELATION_WHERE,
            sqlite_where=_EFFECTIVE_RELATION_WHERE,
        ),
        Index("idx_test_point_test_cases_test_point", "test_point_id"),
        Index("idx_test_point_test_cases_test_case", "test_case_id"),
        Index("idx_test_point_test_cases_status", "status"),
    )

    test_point_id: Mapped[UUID] = mapped_column(ForeignKey("test_assets.id", ondelete="CASCADE"), nullable=False)
    test_case_id: Mapped[UUID] = mapped_column(ForeignKey("test_assets.id", ondelete="CASCADE"), nullable=False)


class TestCaseExecutionTask(Base, TraceabilityRelationMixin):
    __tablename__ = "test_case_execution_tasks"
    __table_args__ = (
        Index(
            "uq_test_case_execution_tasks_effective",
            "test_case_id",
            "execution_task_id",
            "relation_type",
            "scope_id",
            unique=True,
            postgresql_where=_EFFECTIVE_RELATION_WHERE,
            sqlite_where=_EFFECTIVE_RELATION_WHERE,
        ),
        Index("idx_test_case_execution_tasks_test_case", "test_case_id"),
        Index("idx_test_case_execution_tasks_task", "execution_task_id"),
        Index("idx_test_case_execution_tasks_run", "run_id"),
        Index("idx_test_case_execution_tasks_status", "status"),
    )

    test_case_id: Mapped[UUID] = mapped_column(ForeignKey("test_assets.id", ondelete="CASCADE"), nullable=False)
    execution_task_id: Mapped[UUID] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[UUID | None] = mapped_column(Uuid)


class ExecutionTaskEvidenceArtifact(Base, TraceabilityRelationMixin):
    __tablename__ = "execution_task_evidence_artifacts"
    __table_args__ = (
        Index(
            "uq_execution_task_evidence_artifacts_effective",
            "execution_task_id",
            "evidence_artifact_id",
            "relation_type",
            "scope_id",
            unique=True,
            postgresql_where=_EFFECTIVE_RELATION_WHERE,
            sqlite_where=_EFFECTIVE_RELATION_WHERE,
        ),
        Index("idx_execution_task_evidence_artifacts_task", "execution_task_id"),
        Index("idx_execution_task_evidence_artifacts_artifact", "evidence_artifact_id"),
        Index("idx_execution_task_evidence_artifacts_status", "status"),
    )

    execution_task_id: Mapped[UUID] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"), nullable=False)
    evidence_artifact_id: Mapped[UUID] = mapped_column(ForeignKey("execution_artifacts.id", ondelete="CASCADE"), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(80), nullable=False)


class EvidenceRawFinding(Base, TraceabilityRelationMixin):
    __tablename__ = "evidence_raw_findings"
    __table_args__ = (
        Index(
            "uq_evidence_raw_findings_effective",
            "evidence_artifact_id",
            "raw_finding_id",
            "relation_type",
            "scope_id",
            unique=True,
            postgresql_where=_EFFECTIVE_RELATION_WHERE,
            sqlite_where=_EFFECTIVE_RELATION_WHERE,
        ),
        Index("idx_evidence_raw_findings_artifact", "evidence_artifact_id"),
        Index("idx_evidence_raw_findings_raw", "raw_finding_id"),
        Index("idx_evidence_raw_findings_status", "status"),
    )

    evidence_artifact_id: Mapped[UUID] = mapped_column(ForeignKey("execution_artifacts.id", ondelete="CASCADE"), nullable=False)
    raw_finding_id: Mapped[UUID] = mapped_column(ForeignKey("raw_findings.id", ondelete="CASCADE"), nullable=False)


class RawNormalizedFinding(Base, TraceabilityRelationMixin):
    __tablename__ = "raw_normalized_findings"
    __table_args__ = (
        Index(
            "uq_raw_normalized_findings_effective",
            "raw_finding_id",
            "normalized_finding_id",
            "relation_type",
            "scope_id",
            unique=True,
            postgresql_where=_EFFECTIVE_RELATION_WHERE,
            sqlite_where=_EFFECTIVE_RELATION_WHERE,
        ),
        Index("idx_raw_normalized_findings_raw", "raw_finding_id"),
        Index("idx_raw_normalized_findings_normalized", "normalized_finding_id"),
        Index("idx_raw_normalized_findings_status", "status"),
    )

    raw_finding_id: Mapped[UUID] = mapped_column(ForeignKey("raw_findings.id", ondelete="CASCADE"), nullable=False)
    normalized_finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    normalization_method: Mapped[str] = mapped_column(String(100), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)
    merge_group_id: Mapped[str | None] = mapped_column(String(255))


class NormalizedFindingGateDecision(Base, TraceabilityRelationMixin):
    __tablename__ = "normalized_finding_gate_decisions"
    __table_args__ = (
        Index(
            "uq_normalized_finding_gate_decisions_effective",
            "normalized_finding_id",
            "gate_decision_id",
            "relation_type",
            "scope_id",
            unique=True,
            postgresql_where=_EFFECTIVE_RELATION_WHERE,
            sqlite_where=_EFFECTIVE_RELATION_WHERE,
        ),
        Index("idx_normalized_finding_gate_decisions_finding", "normalized_finding_id"),
        Index("idx_normalized_finding_gate_decisions_gate", "gate_decision_id"),
        Index("idx_normalized_finding_gate_decisions_status", "status"),
    )

    normalized_finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    gate_decision_id: Mapped[UUID] = mapped_column(ForeignKey("gate_results.id", ondelete="CASCADE"), nullable=False)
    impact: Mapped[str] = mapped_column(String(80), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)


class GateDecisionReplayExport(Base, TraceabilityRelationMixin):
    __tablename__ = "gate_decision_replay_exports"
    __table_args__ = (
        Index(
            "uq_gate_decision_replay_exports_effective",
            "gate_decision_id",
            "replay_export_id",
            "relation_type",
            "scope_id",
            unique=True,
            postgresql_where=_EFFECTIVE_RELATION_WHERE,
            sqlite_where=_EFFECTIVE_RELATION_WHERE,
        ),
        Index("idx_gate_decision_replay_exports_gate", "gate_decision_id"),
        Index("idx_gate_decision_replay_exports_export", "replay_export_id"),
        Index("idx_gate_decision_replay_exports_status", "status"),
    )

    gate_decision_id: Mapped[UUID] = mapped_column(ForeignKey("gate_results.id", ondelete="CASCADE"), nullable=False)
    replay_export_id: Mapped[str] = mapped_column(String(255), nullable=False)
    export_hash: Mapped[str] = mapped_column(String(80), nullable=False)


class ReplayRepositoryEntry(Base, TimestampMixin):
    __tablename__ = "replay_repository_entries"
    __table_args__ = (
        UniqueConstraint("replay_id", name="uq_replay_repository_entries_replay_id"),
        UniqueConstraint("source_replay_export_hash", name="uq_replay_repository_entries_export_hash"),
        Index("idx_replay_repository_entries_execution", "execution_id"),
        Index("idx_replay_repository_entries_created_at", "created_at"),
        Index("idx_replay_repository_entries_retention", "retention_status"),
        CheckConstraint("approval_mode IN ('always', 'policy_only', 'threshold')", name="chk_replay_repository_entries_approval_mode"),
        CheckConstraint(
            "approval_state IN ('pending', 'approved', 'not_required', 'rejected', 'cancelled')",
            name="chk_replay_repository_entries_approval_state",
        ),
        CheckConstraint(
            "retention_status IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')",
            name="chk_replay_repository_entries_retention_status",
        ),
        CheckConstraint(
            "validity_status IN ('valid', 'invalid', 'unknown')",
            name="chk_replay_repository_entries_validity_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    replay_id: Mapped[str] = mapped_column(String(120), nullable=False)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="RESTRICT"), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(80), default="phase8.replay-repository.v1", nullable=False)
    source_replay_export_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    export_payload_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    summary_projection: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    section_index: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    storage_adapter: Mapped[str] = mapped_column(String(40), default="local", nullable=False)
    redaction_status: Mapped[str] = mapped_column(String(40), default="redacted", nullable=False)
    validity_status: Mapped[str] = mapped_column(String(40), default="valid", nullable=False)
    approval_mode: Mapped[str] = mapped_column(String(40), default="always", nullable=False)
    approval_state: Mapped[str] = mapped_column(String(40), default="approved", nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    retention_policy: Mapped[str] = mapped_column(String(80), default="default", nullable=False)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    purge_eligible_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retention_status: Mapped[str] = mapped_column(String(40), default="active", nullable=False)
    frozen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ReplayRepositorySection(Base):
    __tablename__ = "replay_repository_sections"
    __table_args__ = (
        UniqueConstraint("replay_entry_id", "section_name", name="uq_replay_repository_sections_entry_section"),
        Index("idx_replay_repository_sections_entry", "replay_entry_id"),
        Index("idx_replay_repository_sections_name", "section_name"),
        CheckConstraint("byte_size >= 0", name="chk_replay_repository_sections_byte_size"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    replay_entry_id: Mapped[UUID] = mapped_column(ForeignKey("replay_repository_entries.id", ondelete="CASCADE"), nullable=False)
    section_name: Mapped[str] = mapped_column(String(120), nullable=False)
    storage_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    compression: Mapped[str] = mapped_column(String(40), default="none", nullable=False)
    redaction_status: Mapped[str] = mapped_column(String(40), default="redacted", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ReplayGovernancePolicy(Base, TimestampMixin):
    __tablename__ = "replay_governance_policies"
    __table_args__ = (
        UniqueConstraint("scope_type", "scope_id", name="uq_replay_governance_policies_scope"),
        Index("idx_replay_governance_policies_scope", "scope_type", "scope_id"),
        CheckConstraint("approval_mode IN ('always', 'policy_only', 'threshold')", name="chk_replay_governance_policies_approval_mode"),
        CheckConstraint("threshold_level IN ('low', 'medium', 'high')", name="chk_replay_governance_policies_threshold_level"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scope_type: Mapped[str] = mapped_column(String(40), default="global", nullable=False)
    scope_id: Mapped[str] = mapped_column(String(120), default="global", nullable=False)
    approval_mode: Mapped[str] = mapped_column(String(40), default="always", nullable=False)
    threshold_level: Mapped[str] = mapped_column(String(40), default="high", nullable=False)
    policy_rules: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ReplayExportRecord(Base):
    __tablename__ = "replay_exports"
    __table_args__ = (
        UniqueConstraint("execution_id", "export_payload_hash", name="uq_replay_exports_execution_payload_hash"),
        UniqueConstraint("export_id", name="uq_replay_exports_export_id"),
        UniqueConstraint("export_hash", name="uq_replay_exports_export_hash"),
        Index("idx_replay_exports_execution", "execution_id"),
        Index("idx_replay_exports_created_at", "created_at"),
        CheckConstraint("trace_refs IS NOT NULL", name="chk_replay_exports_trace_refs_not_null"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    export_id: Mapped[str] = mapped_column(String(120), nullable=False)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(80), default="phase8.replay-export.v1", nullable=False)
    export_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    export_payload_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    storage_ref: Mapped[str | None] = mapped_column(String(500))
    export_artifact_ref: Mapped[str | None] = mapped_column(String(500))
    redaction_status: Mapped[str] = mapped_column(String(40), nullable=False)
    trace_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(255))
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TraceabilitySnapshotRecord(Base):
    __tablename__ = "traceability_snapshots"
    __table_args__ = (
        UniqueConstraint("traceability_snapshot_hash", name="uq_traceability_snapshots_hash"),
        Index("idx_traceability_snapshots_requirement", "requirement_version_id"),
        Index("idx_traceability_snapshots_scope", "scope_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    requirement_version_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_versions.id", ondelete="CASCADE"), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(255), nullable=False)
    traceability_snapshot_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    traceability_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    traceability_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    coverage_summary_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    coverage_matrix_snapshot_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    coverage_matrix_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    coverage_matrix_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    relation_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class GateInputSnapshot(Base):
    __tablename__ = "gate_input_snapshots"
    __table_args__ = (
        UniqueConstraint("gate_input_snapshot_hash", name="uq_gate_input_snapshots_hash"),
        Index("idx_gate_input_snapshots_gate", "gate_decision_id"),
        Index("idx_gate_input_snapshots_execution", "execution_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    gate_decision_id: Mapped[UUID] = mapped_column(ForeignKey("gate_results.id", ondelete="CASCADE"), nullable=False)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    gate_input_snapshot_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    gate_input_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    gate_input_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    policy_snapshot_ref: Mapped[str | None] = mapped_column(String(255))
    policy_snapshot_hash: Mapped[str | None] = mapped_column(String(80))
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CoverageProofBundleRecord(Base):
    __tablename__ = "coverage_proof_bundles"
    __table_args__ = (
        Index("idx_coverage_proof_bundles_requirement", "requirement_version_id", "requirement_item_id"),
        Index("idx_coverage_proof_bundles_snapshot", "traceability_snapshot_id"),
        Index("idx_coverage_proof_bundles_status", "coverage_status", "proof_status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    requirement_version_id: Mapped[UUID] = mapped_column(ForeignKey("requirement_versions.id", ondelete="CASCADE"), nullable=False)
    requirement_item_id: Mapped[str] = mapped_column(String(255), nullable=False)
    traceability_snapshot_id: Mapped[UUID] = mapped_column(ForeignKey("traceability_snapshots.id", ondelete="RESTRICT"), nullable=False)
    gate_input_snapshot_id: Mapped[UUID | None] = mapped_column(ForeignKey("gate_input_snapshots.id", ondelete="SET NULL"))
    coverage_status: Mapped[CoverageStatus] = mapped_column(db_enum(CoverageStatus), nullable=False)
    proof_status: Mapped[ProofStatus] = mapped_column(db_enum(ProofStatus), nullable=False)
    proof_bundle: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    proof_chain: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    proof_issues: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    replay_export_ref: Mapped[str | None] = mapped_column(String(255))
    replay_export_hash: Mapped[str | None] = mapped_column(String(80))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CoverageProofReplayRef(Base):
    __tablename__ = "coverage_proof_replay_refs"
    __table_args__ = (
        UniqueConstraint("coverage_proof_bundle_id", "replay_export_hash", name="uq_coverage_proof_replay_refs_bundle_hash"),
        Index("idx_coverage_proof_replay_refs_bundle", "coverage_proof_bundle_id"),
        Index("idx_coverage_proof_replay_refs_export", "replay_export_ref"),
        Index("idx_coverage_proof_replay_refs_hash", "replay_export_hash"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    coverage_proof_bundle_id: Mapped[UUID] = mapped_column(ForeignKey("coverage_proof_bundles.id", ondelete="CASCADE"), nullable=False)
    replay_export_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    replay_export_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    traceability_snapshot_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    traceability_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    coverage_matrix_snapshot_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    coverage_matrix_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class GraphCoverageSnapshot(Base):
    """Immutable P15 sidecar extending the existing Traceability/Coverage authority."""

    __tablename__ = "graph_coverage_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "input_fingerprint",
            name="uq_graph_coverage_snapshots_input",
        ),
        UniqueConstraint("snapshot_hash", name="uq_graph_coverage_snapshots_hash"),
        Index(
            "idx_graph_coverage_snapshots_graph",
            "tenant_id",
            "workspace_id",
            "project_id",
            "graph_version_id",
            "computed_at",
        ),
        Index("idx_graph_coverage_snapshots_execution", "execution_id"),
        Index("idx_graph_coverage_snapshots_requirement", "requirement_version_id"),
        Index("idx_graph_coverage_snapshots_proof", "coverage_proof_bundle_id"),
        CheckConstraint(
            "status IN ('covered', 'partial', 'uncovered', 'not_applicable', 'unknown')",
            name="chk_graph_coverage_snapshots_status",
        ),
        CheckConstraint(
            "length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'",
            name="chk_graph_coverage_snapshots_input_hash",
        ),
        CheckConstraint(
            "length(snapshot_hash) = 71 AND snapshot_hash LIKE 'sha256:%'",
            name="chk_graph_coverage_snapshots_snapshot_hash",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False
    )
    graph_id: Mapped[UUID] = mapped_column(
        ForeignKey("canonical_execution_graphs.id", ondelete="RESTRICT"), nullable=False
    )
    graph_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("canonical_execution_graph_versions.id", ondelete="RESTRICT"), nullable=False
    )
    coverage_proof_bundle_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("coverage_proof_bundles.id", ondelete="SET NULL")
    )
    requirement_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("requirement_versions.id", ondelete="RESTRICT"), nullable=False
    )
    execution_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("executions.id", ondelete="SET NULL")
    )
    staleness_assessment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("canonical_graph_staleness_assessments.id", ondelete="SET NULL")
    )
    algorithm_version: Mapped[str] = mapped_column(String(80), nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    snapshot_ref: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    result_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    coverage_proof_ref: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    traceability_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    metric_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    gap_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    raw_finding_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    normalized_finding_refs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    replay_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("traces.id", ondelete="SET NULL")
    )
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


def _protect_graph_coverage_snapshot_mutation(
    _mapper: object,
    _connection: object,
    _target: GraphCoverageSnapshot,
) -> None:
    raise ValueError("Graph Coverage snapshots are immutable")


event.listen(GraphCoverageSnapshot, "before_update", _protect_graph_coverage_snapshot_mutation)
event.listen(GraphCoverageSnapshot, "before_delete", _protect_graph_coverage_snapshot_mutation)


class Memory(Base, TimestampMixin):
    __tablename__ = "memories"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    type: Mapped[MemoryType] = mapped_column(db_enum(MemoryType), nullable=False)
    scope: Mapped[MemoryScope] = mapped_column(db_enum(MemoryScope), nullable=False)
    namespace: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    embedding: Mapped[list[float] | None] = mapped_column(JSON)
    source_type: Mapped[str | None] = mapped_column(String(100))
    source_ref: Mapped[str | None] = mapped_column(String(255))
    heat_score: Mapped[Decimal] = mapped_column(Numeric(10, 4), default=Decimal("0"), nullable=False)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class MemoryJob(Base, TimestampMixin):
    __tablename__ = "memory_jobs"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scope: Mapped[MemoryScope] = mapped_column(db_enum(MemoryScope), nullable=False)
    namespace: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[JobStatus] = mapped_column(db_enum(JobStatus), default=JobStatus.QUEUED, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"))
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    trace_id: Mapped[UUID | None] = mapped_column(Uuid)
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[AgentRunStatus] = mapped_column(db_enum(AgentRunStatus), default=AgentRunStatus.QUEUED, nullable=False)
    input_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    output_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    model_id: Mapped[UUID | None] = mapped_column(ForeignKey("models.id", ondelete="SET NULL"))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class GuardrailEvent(Base):
    __tablename__ = "guardrail_events"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_id: Mapped[UUID | None] = mapped_column(ForeignKey("guardrail_policies.id", ondelete="SET NULL"))
    policy_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("guardrail_policy_versions.id", ondelete="SET NULL"))
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[GuardrailDecisionType] = mapped_column(db_enum(GuardrailDecisionType), nullable=False)
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    agent_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("agent_runs.id", ondelete="SET NULL"))
    skill_invocation_id: Mapped[UUID | None] = mapped_column(ForeignKey("skill_invocations.id", ondelete="SET NULL"))
    connector_binding_id: Mapped[UUID | None] = mapped_column(ForeignKey("skill_connector_bindings.id", ondelete="SET NULL"))
    tool_call_id: Mapped[UUID | None] = mapped_column(ForeignKey("skill_tool_calls.id", ondelete="SET NULL"))
    request_id: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str | None] = mapped_column(String(50))
    message: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Approval(Base, TimestampMixin):
    __tablename__ = "approvals"
    __table_args__ = (
        Index(
            "uq_approvals_pending_resource",
            "type",
            "resource_type",
            "resource_id",
            unique=True,
            postgresql_where=text("status = 'pending'"),
            sqlite_where=text("status = 'pending'"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    type: Mapped[ApprovalType] = mapped_column(db_enum(ApprovalType), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[ApprovalStatus] = mapped_column(db_enum(ApprovalStatus), default=ApprovalStatus.PENDING, nullable=False)
    requested_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decision_comment: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Job(Base, TimestampMixin):
    __tablename__ = "jobs"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[JobStatus] = mapped_column(db_enum(JobStatus), default=JobStatus.QUEUED, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_ref: Mapped[str | None] = mapped_column(String(255))
    error_message: Mapped[str | None] = mapped_column(Text)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), unique=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Trace(Base):
    __tablename__ = "traces"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"))
    root_span_name: Mapped[str | None] = mapped_column(String(255))
    trace_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TraceSpan(Base):
    __tablename__ = "trace_spans"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    trace_id: Mapped[UUID] = mapped_column(ForeignKey("traces.id", ondelete="CASCADE"), nullable=False)
    parent_span_id: Mapped[UUID | None] = mapped_column(ForeignKey("trace_spans.id", ondelete="CASCADE"))
    span_name: Mapped[str] = mapped_column(String(255), nullable=False)
    span_type: Mapped[str | None] = mapped_column(String(100))
    service_name: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str | None] = mapped_column(String(50))
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class VisualGroundingAttempt(Base):
    __tablename__ = "visual_grounding_attempts"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    trace_span_id: Mapped[UUID | None] = mapped_column(ForeignKey("trace_spans.id", ondelete="SET NULL"))
    action_id: Mapped[str] = mapped_column(String(150), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    semantic_action: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    locator_strategy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    fallback_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    candidate_locators: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    chosen_locator: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    threshold: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    coordinate_click_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(db_enum(RiskLevel), default=RiskLevel.MEDIUM, nullable=False)
    guardrail_decision: Mapped[GuardrailDecisionType | None] = mapped_column(db_enum(GuardrailDecisionType))
    guardrail_event_id: Mapped[UUID | None] = mapped_column(ForeignKey("guardrail_events.id", ondelete="SET NULL"))
    verification_status: Mapped[str | None] = mapped_column(String(50))
    verification_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    redaction_status: Mapped[str] = mapped_column(String(50), default="redacted", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="completed", nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class VerificationResult(Base):
    __tablename__ = "verification_results"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("executions.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(ForeignKey("execution_tasks.id", ondelete="CASCADE"))
    visual_attempt_id: Mapped[UUID | None] = mapped_column(ForeignKey("visual_grounding_attempts.id", ondelete="SET NULL"))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    verification_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    normalized_finding_id: Mapped[UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    __table_args__ = (
        Index("idx_audit_logs_retention_status", "retention_status"),
        CheckConstraint(
            "retention_status IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')",
            name="chk_audit_logs_retention_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    actor_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(255))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    retention_policy: Mapped[str] = mapped_column(String(80), default="default-audit-log-retention", nullable=False)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    purge_eligible_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retention_status: Mapped[str] = mapped_column(String(40), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IntegrationEvent(Base, TimestampMixin):
    __tablename__ = "integration_events"
    __table_args__ = (
        Index(
            "uq_integration_events_source_type_ref",
            "source",
            "event_type",
            "external_ref",
            unique=True,
            postgresql_where=text(
                "external_ref IS NOT NULL AND source LIKE 'issue-tracker:%'"
            ),
            sqlite_where=text(
                "external_ref IS NOT NULL AND source LIKE 'issue-tracker:%'"
            ),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    external_ref: Mapped[str | None] = mapped_column(String(255))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[IntegrationEventStatus] = mapped_column(
        db_enum(IntegrationEventStatus),
        default=IntegrationEventStatus.RECEIVED,
        nullable=False,
    )
    linked_pipeline_id: Mapped[UUID | None] = mapped_column(ForeignKey("orchestration_runs.id", ondelete="SET NULL"))
    linked_plan_id: Mapped[UUID | None] = mapped_column(ForeignKey("test_plans.id", ondelete="SET NULL"))
    linked_execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    linked_requirement_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_versions.id", ondelete="SET NULL"))


class Skill(Base, TimestampMixin):
    __tablename__ = "skills"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    skill_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)


class SkillVersion(Base, TimestampMixin):
    __tablename__ = "skill_versions"
    __table_args__ = (
        UniqueConstraint("skill_ref_id", "version", "manifest_hash", name="uq_skill_manifest"),
        CheckConstraint(
            "governance_status IN ('draft', 'active', 'rejected', 'deprecated', 'archived')",
            name="chk_skill_versions_governance_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    skill_ref_id: Mapped[UUID] = mapped_column(ForeignKey("skills.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    manifest_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    output_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    allowed_tools: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    allowed_connectors: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    risk_profile: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    approval_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    data_access_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    replay_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    extension_points: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    compatibility: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    governance_status: Mapped[str] = mapped_column(String(24), default="active", nullable=False)


class SkillConnectorBinding(Base, TimestampMixin):
    __tablename__ = "skill_connector_bindings"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    connector_name: Mapped[str] = mapped_column(String(128), nullable=False)
    secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    credential_ref: Mapped[str | None] = mapped_column(Text)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)


class CapabilityBinding(Base, TimestampMixin):
    __tablename__ = "capability_bindings"
    __table_args__ = (
        Index("idx_capability_bindings_extension_status", "extension_point_id", "status"),
        Index("idx_capability_bindings_scope", "scope_type", "scope_id"),
        Index("idx_capability_bindings_skill_version", "skill_version_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    extension_point_id: Mapped[str] = mapped_column(String(160), nullable=False)
    skill_version_id: Mapped[UUID] = mapped_column(ForeignKey("skill_versions.id", ondelete="RESTRICT"), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(40), default="global", nullable=False)
    scope_id: Mapped[str | None] = mapped_column(String(255))
    project_id: Mapped[str | None] = mapped_column(String(255))
    environment: Mapped[str | None] = mapped_column(String(120))
    stage: Mapped[str | None] = mapped_column(String(80))
    domain: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(32), default="draft", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    binding_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    pending_change: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    guardrail_event_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    audit_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class SkillInvocation(Base, TimestampMixin):
    __tablename__ = "skill_invocations"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    agent_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("agent_runs.id", ondelete="SET NULL"))
    skill_version_id: Mapped[UUID] = mapped_column(ForeignKey("skill_versions.id", ondelete="RESTRICT"), nullable=False)
    binding_id: Mapped[UUID | None] = mapped_column(ForeignKey("capability_bindings.id", ondelete="SET NULL"))
    extension_point_id: Mapped[str | None] = mapped_column(String(160))
    source_workflow: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), unique=True)
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    output_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    resolution_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    connector_binding_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    approval_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    artifact_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    tool_call_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    connector_call_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)


class SkillInvocationEvent(Base):
    __tablename__ = "skill_invocation_events"
    __table_args__ = (
        Index("idx_skill_invocation_events_invocation", "skill_invocation_id"),
        Index("idx_skill_invocation_events_type", "event_type"),
        Index("idx_skill_invocation_events_trace", "trace_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    skill_invocation_id: Mapped[UUID] = mapped_column(ForeignKey("skill_invocations.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SkillToolCall(Base):
    __tablename__ = "skill_tool_calls"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    skill_invocation_id: Mapped[UUID] = mapped_column(ForeignKey("skill_invocations.id", ondelete="CASCADE"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_call_ref: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SkillConnectorCall(Base):
    __tablename__ = "skill_connector_calls"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    skill_invocation_id: Mapped[UUID] = mapped_column(ForeignKey("skill_invocations.id", ondelete="CASCADE"), nullable=False)
    connector_name: Mapped[str] = mapped_column(String(128), nullable=False)
    connector_call_ref: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class OrchestrationRun(Base, TimestampMixin):
    __tablename__ = "orchestration_runs"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[JobStatus] = mapped_column(db_enum(JobStatus), default=JobStatus.QUEUED, nullable=False)
    current_step: Mapped[str] = mapped_column(String(100), default="PLAN", nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(255))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    linked_plan_id: Mapped[UUID | None] = mapped_column(ForeignKey("test_plans.id", ondelete="SET NULL"))
    linked_execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    linked_requirement_version_id: Mapped[UUID | None] = mapped_column(ForeignKey("requirement_versions.id", ondelete="SET NULL"))
    requirement_scope_id: Mapped[str | None] = mapped_column(
        ForeignKey("requirement_scopes.scope_id", ondelete="SET NULL")
    )
    requirement_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    envelope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OrchestrationCheckpoint(Base):
    __tablename__ = "orchestration_checkpoints"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("orchestration_runs.id", ondelete="CASCADE"), nullable=False)
    sequence_no: Mapped[int] = mapped_column(Integer, nullable=False)
    step_name: Mapped[str] = mapped_column(String(100), nullable=False)
    execution_stage: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[JobStatus] = mapped_column(db_enum(JobStatus), default=JobStatus.QUEUED, nullable=False)
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    envelope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ModelInvocation(Base):
    __tablename__ = "model_invocations"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    model_id: Mapped[UUID | None] = mapped_column(ForeignKey("models.id", ondelete="SET NULL"))
    trace_id: Mapped[UUID | None] = mapped_column(ForeignKey("traces.id", ondelete="SET NULL"))
    execution_id: Mapped[UUID | None] = mapped_column(ForeignKey("executions.id", ondelete="SET NULL"))
    agent_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("agent_runs.id", ondelete="SET NULL"))
    request_summary: Mapped[str | None] = mapped_column(Text)
    request_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    response_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)
    total_tokens: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    cost_amount: Mapped[Decimal | None] = mapped_column(Numeric(18, 6))
    currency: Mapped[str] = mapped_column(String(16), default="USD", nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

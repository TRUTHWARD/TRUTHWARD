# SPDX-License-Identifier: Apache-2.0
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.db.base import Base, register_orm_metadata
from agentic_qa.db.session import engine
from agentic_qa.domain.enums import GuardrailPolicyStatus, GuardrailScope, UserRole, UserStatus
from agentic_qa.domain.models import GuardrailPolicy, User
from agentic_qa.guardrails.catalog import list_guardrail_definitions
from agentic_qa.infra.security import DEMO_ADMIN_ID, DEMO_USER_ID
from agentic_qa.infra.settings import get_settings
from agentic_qa.services.capability_service import CapabilityService, EDITION_BASIC, EDITION_ENTERPRISE
from agentic_qa.services.guardrail_service import GuardrailService
from agentic_qa.services.skill_service import SkillService


def initialize_database() -> None:
    register_orm_metadata()
    settings = get_settings()
    if settings.auto_create_tables:
        Base.metadata.create_all(bind=engine)

    with Session(engine) as db:
        CapabilityService(db).ensure_seed_data()
        if settings.deployment_profile == "full":
            seed_demo_users(db)
        seed_default_guardrail_policies(db)
        SkillService(db).ensure_builtin_skills()
        db.commit()


def seed_demo_users(db: Session) -> None:
    admin = db.scalar(select(User).where(User.id == DEMO_ADMIN_ID))
    if admin is None:
        db.add(
            User(
                id=DEMO_ADMIN_ID,
                name="admin",
                username="admin",
                email="admin@example.com",
                display_name="Platform Admin",
                roles=[UserRole.ADMIN.value],
                edition=EDITION_ENTERPRISE,
                status=UserStatus.ACTIVE,
            )
        )
    else:
        admin.edition = EDITION_ENTERPRISE

    user = db.scalar(select(User).where(User.id == DEMO_USER_ID))
    if user is None:
        db.add(
            User(
                id=DEMO_USER_ID,
                name="user",
                username="user",
                email="user@example.com",
                display_name="Platform User",
                roles=[UserRole.USER.value],
                edition=EDITION_BASIC,
                status=UserStatus.ACTIVE,
            )
        )
    else:
        user.edition = user.edition or EDITION_BASIC


def seed_default_guardrail_policies(db: Session) -> None:
    service = GuardrailService(db)
    # Community has no demo user. System seed data has no human actor; never
    # invent an administrator merely to satisfy the policy foreign keys.
    seed_actor_id = DEMO_ADMIN_ID if get_settings().deployment_profile == "full" else None
    for definition in list_guardrail_definitions():
        policy = db.scalar(select(GuardrailPolicy).where(GuardrailPolicy.rule_id == definition.rule_id))
        if policy is None:
            policy = GuardrailPolicy(
                id=uuid4(),
                rule_id=definition.rule_id,
                name=definition.name,
                scope=_scope_for_rule(definition.rule_id),
                status=GuardrailPolicyStatus.ACTIVE,
                enabled=definition.default_enabled,
                config={"decisionOverrides": dict(definition.default_decision_overrides)},
                metadata_json={"seeded": True},
                created_by=seed_actor_id,
                updated_by=seed_actor_id,
            )
            db.add(policy)
            db.flush()
        service.current_policy_version(policy)


def _scope_for_rule(rule_id: str) -> GuardrailScope:
    prefix = rule_id.split(".", 1)[0]
    mapping = {
        "prompt_safety": GuardrailScope.REQUEST,
        "requirement_intake": GuardrailScope.REQUEST,
        "model_routing": GuardrailScope.ROUTING,
        "agent_output": GuardrailScope.AGENT_OUTPUT,
        "memory_write": GuardrailScope.MEMORY_WRITE,
        "action": GuardrailScope.ACTION,
        "skill": GuardrailScope.SKILL,
        "connector": GuardrailScope.CONNECTOR,
    }
    return mapping.get(prefix, GuardrailScope.SYSTEM)

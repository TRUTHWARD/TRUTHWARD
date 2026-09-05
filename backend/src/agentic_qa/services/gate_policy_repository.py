# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    GatePolicy,
    GatePolicyBinding,
    GatePolicyGovernanceRequest,
    GatePolicyVersion,
)
from agentic_qa.domain.enums import GatePolicyMode


class GatePolicyRepository:
    """Tenant/workspace-scoped persistence for the Gate Policy data foundation."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def find_policy_by_key(
        self,
        tenant_id: str,
        workspace_id: str,
        policy_key: str,
        *,
        for_update: bool = False,
    ) -> GatePolicy | None:
        statement = select(GatePolicy).where(
            GatePolicy.tenant_id == tenant_id,
            GatePolicy.workspace_id == workspace_id,
            GatePolicy.policy_key == policy_key,
        )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def find_policy(
        self,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        *,
        for_update: bool = False,
    ) -> GatePolicy | None:
        statement = select(GatePolicy).where(
            GatePolicy.id == policy_id,
            GatePolicy.tenant_id == tenant_id,
            GatePolicy.workspace_id == workspace_id,
        )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def find_policy_for_project(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        policy_id: UUID,
        *,
        for_update: bool = False,
    ) -> GatePolicy | None:
        statement = select(GatePolicy).where(
            GatePolicy.id == policy_id,
            GatePolicy.project_id == project_id,
            GatePolicy.tenant_id == tenant_id,
            GatePolicy.workspace_id == workspace_id,
        )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def list_policies_for_project(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        *,
        status: str | None = None,
    ) -> list[GatePolicy]:
        statement = select(GatePolicy).where(
            GatePolicy.project_id == project_id,
            GatePolicy.tenant_id == tenant_id,
            GatePolicy.workspace_id == workspace_id,
        )
        if status is not None:
            statement = statement.where(GatePolicy.status == status)
        return list(self.db.scalars(statement.order_by(GatePolicy.created_at.desc(), GatePolicy.id.asc())))

    def find_version_by_number(
        self,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        version_number: int,
        *,
        for_update: bool = False,
    ) -> GatePolicyVersion | None:
        statement = select(GatePolicyVersion).where(
            GatePolicyVersion.tenant_id == tenant_id,
            GatePolicyVersion.workspace_id == workspace_id,
            GatePolicyVersion.policy_id == policy_id,
            GatePolicyVersion.version_number == version_number,
        )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def find_version(
        self,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        *,
        for_update: bool = False,
    ) -> GatePolicyVersion | None:
        statement = select(GatePolicyVersion).where(
            GatePolicyVersion.id == version_id,
            GatePolicyVersion.tenant_id == tenant_id,
            GatePolicyVersion.workspace_id == workspace_id,
        )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def find_version_for_policy(
        self,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        version_id: UUID,
        *,
        for_update: bool = False,
    ) -> GatePolicyVersion | None:
        statement = select(GatePolicyVersion).where(
            GatePolicyVersion.id == version_id,
            GatePolicyVersion.policy_id == policy_id,
            GatePolicyVersion.tenant_id == tenant_id,
            GatePolicyVersion.workspace_id == workspace_id,
        )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def find_version_by_hash(
        self,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        content_hash: str,
    ) -> GatePolicyVersion | None:
        return self.db.scalar(
            select(GatePolicyVersion).where(
                GatePolicyVersion.tenant_id == tenant_id,
                GatePolicyVersion.workspace_id == workspace_id,
                GatePolicyVersion.policy_id == policy_id,
                GatePolicyVersion.content_hash == content_hash,
            )
        )

    def find_binding(
        self,
        tenant_id: str,
        workspace_id: str,
        binding_id: UUID,
        *,
        for_update: bool = False,
    ) -> GatePolicyBinding | None:
        statement = select(GatePolicyBinding).where(
            GatePolicyBinding.id == binding_id,
            GatePolicyBinding.tenant_id == tenant_id,
            GatePolicyBinding.workspace_id == workspace_id,
        )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def find_binding_by_idempotency_key(
        self,
        tenant_id: str,
        workspace_id: str,
        idempotency_key: str,
    ) -> GatePolicyBinding | None:
        return self.db.scalar(
            select(GatePolicyBinding).where(
                GatePolicyBinding.tenant_id == tenant_id,
                GatePolicyBinding.workspace_id == workspace_id,
                GatePolicyBinding.idempotency_key == idempotency_key,
            )
        )

    def find_effective_scope_binding(
        self,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
        scope_type: str,
        scope_key: str,
        effective_from: datetime,
    ) -> GatePolicyBinding | None:
        return self.db.scalar(
            select(GatePolicyBinding).where(
                GatePolicyBinding.tenant_id == tenant_id,
                GatePolicyBinding.workspace_id == workspace_id,
                GatePolicyBinding.policy_id == policy_id,
                GatePolicyBinding.scope_type == scope_type,
                GatePolicyBinding.scope_key == scope_key,
                GatePolicyBinding.effective_from == effective_from,
            )
        )

    def list_versions(
        self,
        tenant_id: str,
        workspace_id: str,
        policy_id: UUID,
    ) -> list[GatePolicyVersion]:
        return list(
            self.db.scalars(
                select(GatePolicyVersion)
                .where(
                    GatePolicyVersion.tenant_id == tenant_id,
                    GatePolicyVersion.workspace_id == workspace_id,
                    GatePolicyVersion.policy_id == policy_id,
                )
                .order_by(GatePolicyVersion.version_number.asc())
            )
        )

    def list_bindings(
        self,
        tenant_id: str,
        workspace_id: str,
    ) -> list[GatePolicyBinding]:
        return list(
            self.db.scalars(
                select(GatePolicyBinding)
                .where(
                    GatePolicyBinding.tenant_id == tenant_id,
                    GatePolicyBinding.workspace_id == workspace_id,
                )
                .order_by(
                    GatePolicyBinding.scope_type.asc(),
                    GatePolicyBinding.scope_key.asc(),
                    GatePolicyBinding.effective_from.asc(),
                    GatePolicyBinding.id.asc(),
                )
            )
        )

    def list_resolution_candidates(
        self,
        tenant_id: str,
        workspace_id: str,
        scope_keys: dict[str, str],
    ) -> list[GatePolicyBinding]:
        """Return only exact-scope candidates inside one ownership boundary.

        Resolution precedence and validity remain Service responsibilities. The
        repository deliberately does not inspect another tenant/workspace and
        does not broaden a missing context identifier into a wildcard query.
        """

        scope_clauses = [
            and_(
                GatePolicyBinding.scope_type == scope_type,
                GatePolicyBinding.scope_key == scope_key,
            )
            for scope_type, scope_key in scope_keys.items()
        ]
        if not scope_clauses:
            return []
        statement = (
            select(GatePolicyBinding)
            .where(
                GatePolicyBinding.tenant_id == tenant_id,
                GatePolicyBinding.workspace_id == workspace_id,
                GatePolicyBinding.mode == GatePolicyMode.ENFORCE,
                or_(*scope_clauses),
            )
            .order_by(
                GatePolicyBinding.scope_type.asc(),
                GatePolicyBinding.scope_key.asc(),
                GatePolicyBinding.effective_from.asc(),
                GatePolicyBinding.id.asc(),
            )
        )
        return list(self.db.scalars(statement))

    def policy_has_versions(self, tenant_id: str, workspace_id: str, policy_id: UUID) -> bool:
        return self.db.scalar(
            select(GatePolicyVersion.id)
            .where(
                GatePolicyVersion.tenant_id == tenant_id,
                GatePolicyVersion.workspace_id == workspace_id,
                GatePolicyVersion.policy_id == policy_id,
            )
            .limit(1)
        ) is not None

    def version_has_bindings(self, tenant_id: str, workspace_id: str, version_id: UUID) -> bool:
        return self.db.scalar(
            select(GatePolicyBinding.id)
            .where(
                GatePolicyBinding.tenant_id == tenant_id,
                GatePolicyBinding.workspace_id == workspace_id,
                GatePolicyBinding.policy_version_id == version_id,
            )
            .limit(1)
        ) is not None

    def find_governance_request(
        self,
        tenant_id: str,
        workspace_id: str,
        operation: str,
        idempotency_key: str,
    ) -> GatePolicyGovernanceRequest | None:
        return self.db.scalar(
            select(GatePolicyGovernanceRequest).where(
                GatePolicyGovernanceRequest.tenant_id == tenant_id,
                GatePolicyGovernanceRequest.workspace_id == workspace_id,
                GatePolicyGovernanceRequest.operation == operation,
                GatePolicyGovernanceRequest.idempotency_key == idempotency_key,
            )
        )

    def add(
        self,
        record: GatePolicy | GatePolicyVersion | GatePolicyBinding | GatePolicyGovernanceRequest,
    ) -> None:
        self.db.add(record)

    def delete(self, record: GatePolicy | GatePolicyVersion | GatePolicyBinding) -> None:
        self.db.delete(record)

    def flush(self) -> None:
        self.db.flush()

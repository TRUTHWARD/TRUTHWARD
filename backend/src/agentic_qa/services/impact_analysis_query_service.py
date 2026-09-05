# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    CapabilityMappingRecord,
    ImpactResultRecord,
    SelectiveReplayPlanRecord,
)
from agentic_qa.schemas.impact_analysis import (
    CapabilityMappingContract,
    ImpactResultContract,
)
from agentic_qa.schemas.selective_replay import SelectiveReplayPlan
from agentic_qa.services.change_set_query_service import (
    ChangeSetError,
    ChangeSetQueryService,
    ChangeSetScope,
)
from agentic_qa.services.common import ServiceContext, paginate_result


class ImpactAnalysisError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


class ImpactAnalysisQueryService:
    """Project-scoped, read-only impact-analysis projection for OSS."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def list_mappings(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        scope = self._scope(project_id, context, "impact.read")
        statement = select(CapabilityMappingRecord).where(
            CapabilityMappingRecord.tenant_id == scope.tenant_id,
            CapabilityMappingRecord.workspace_id == scope.workspace_id,
            CapabilityMappingRecord.project_id == project_id,
        )
        total = int(self.db.scalar(select(func.count()).select_from(statement.subquery())) or 0)
        rows = list(
            self.db.scalars(
                statement.order_by(
                    CapabilityMappingRecord.created_at.desc(),
                    CapabilityMappingRecord.id.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        return {
            "schemaVersion": "phase8.capability-mapping-list.v1",
            **paginate_result(
                [self._mapping_projection(item) for item in rows],
                total,
                page,
                page_size,
            ),
            "sourcePriority": [
                "manual|explicit_configuration",
                "verified_traceability",
                "static_symbol_coverage",
                "historical_evidence",
                "ai_suggestion",
            ],
            "readOnly": "impact.manage_mapping" not in set(context.user.capabilities),
        }

    def list_results(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        change_set_id: UUID | None,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        scope = self._scope(project_id, context, "impact.read")
        rows = list(
            self.db.scalars(
                select(ImpactResultRecord)
                .where(
                    ImpactResultRecord.tenant_id == scope.tenant_id,
                    ImpactResultRecord.workspace_id == scope.workspace_id,
                    ImpactResultRecord.project_id == project_id,
                )
                .order_by(ImpactResultRecord.created_at.desc(), ImpactResultRecord.id.desc())
            )
        )
        if change_set_id is not None:
            rows = [item for item in rows if str(change_set_id) in set(item.change_set_ids)]
        total = len(rows)
        page_rows = rows[(page - 1) * page_size : page * page_size]
        return {
            "schemaVersion": "phase8.impact-result-list.v1",
            **paginate_result(
                [self._result_projection(item, deduplicated=False) for item in page_rows],
                total,
                page,
                page_size,
            ),
            "readOnly": True,
            "backendComputed": True,
        }

    def get_result(
        self,
        project_id: UUID,
        impact_result_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._scope(project_id, context, "impact.read")
        record = self.db.scalar(
            select(ImpactResultRecord).where(
                ImpactResultRecord.id == impact_result_id,
                ImpactResultRecord.tenant_id == scope.tenant_id,
                ImpactResultRecord.workspace_id == scope.workspace_id,
                ImpactResultRecord.project_id == project_id,
            )
        )
        if record is None:
            raise ImpactAnalysisError("IMPACT_RESULT_NOT_FOUND", status_code=404)
        return self._result_projection(record, deduplicated=False)

    def _scope(
        self,
        project_id: UUID,
        context: ServiceContext,
        capability: str,
    ) -> ChangeSetScope:
        try:
            return ChangeSetQueryService(self.db)._require_scope(
                project_id,
                None,
                context,
                capability,
            )
        except ChangeSetError as exc:
            code = (
                "IMPACT_CAPABILITY_REQUIRED"
                if exc.status_code == 403
                else "IMPACT_PROJECT_NOT_FOUND"
            )
            raise ImpactAnalysisError(
                code,
                status_code=exc.status_code,
                field=exc.field,
            ) from exc

    @staticmethod
    def _mapping_projection(record: CapabilityMappingRecord) -> dict[str, Any]:
        return CapabilityMappingContract.model_validate(
            {
                "schemaVersion": "phase8.capability-mapping.v1",
                "mappingId": str(record.id),
                "mappingKey": record.mapping_key,
                "version": record.version,
                "projectId": str(record.project_id),
                "sourceEntityType": record.source_entity_type,
                "sourceEntityRef": record.source_entity_ref,
                "capabilityRef": record.capability_ref,
                "mappingSource": record.mapping_source,
                "sourcePriority": record.source_priority,
                "confidence": float(record.confidence),
                "status": record.status,
                "repositoryRef": record.repository_ref,
                "graphVersionId": (
                    str(record.graph_version_id) if record.graph_version_id else None
                ),
                "evidenceRefs": record.evidence_refs,
                "contentHash": record.content_hash,
                "traceId": str(record.trace_id),
                "createdAt": record.created_at,
                "createdBy": str(record.created_by) if record.created_by else None,
            }
        ).model_dump(mode="json")

    @staticmethod
    def _result_projection(
        record: ImpactResultRecord,
        *,
        deduplicated: bool,
    ) -> dict[str, Any]:
        result = dict(record.result_snapshot)
        result["deduplicated"] = deduplicated
        return ImpactResultContract.model_validate(result).model_dump(mode="json")


class SelectiveReplayQueryService:
    """Project-scoped, read-only selective-replay plan projection for OSS."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def list_selective_replay_plans(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        impact_result_id: UUID | None,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        scope = self._selective_replay_scope(project_id, context, "replay.plan.read")
        statement = select(SelectiveReplayPlanRecord).where(
            SelectiveReplayPlanRecord.tenant_id == scope.tenant_id,
            SelectiveReplayPlanRecord.workspace_id == scope.workspace_id,
            SelectiveReplayPlanRecord.project_id == project_id,
        )
        if impact_result_id is not None:
            statement = statement.where(
                SelectiveReplayPlanRecord.impact_result_id == impact_result_id
            )
        rows = list(
            self.db.scalars(
                statement.order_by(
                    SelectiveReplayPlanRecord.created_at.desc(),
                    SelectiveReplayPlanRecord.id.desc(),
                )
            )
        )
        total = len(rows)
        selected = rows[(page - 1) * page_size : page * page_size]
        return {
            "schemaVersion": "phase8.selective-replay-plan-list.v1",
            **paginate_result(
                [self._selective_replay_projection(row, deduplicated=False) for row in selected],
                total,
                page,
                page_size,
            ),
            "readOnly": True,
            "backendComputed": True,
            "executionCreated": False,
        }

    def get_selective_replay_plan(
        self,
        project_id: UUID,
        plan_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._selective_replay_scope(project_id, context, "replay.plan.read")
        row = self.db.scalar(
            select(SelectiveReplayPlanRecord).where(
                SelectiveReplayPlanRecord.id == plan_id,
                SelectiveReplayPlanRecord.tenant_id == scope.tenant_id,
                SelectiveReplayPlanRecord.workspace_id == scope.workspace_id,
                SelectiveReplayPlanRecord.project_id == project_id,
            )
        )
        if row is None:
            raise ValueError("SELECTIVE_REPLAY_PLAN_NOT_FOUND")
        return self._selective_replay_projection(row, deduplicated=False)

    def selective_replay_confirmation_projection(
        self,
        project_id: UUID,
        plan_id: UUID,
        context: ServiceContext,
        *,
        current_head_revision: str | None = None,
    ) -> dict[str, object]:
        plan = self.get_selective_replay_plan(project_id, plan_id, context)
        expected_head = plan["replaySnapshot"].get("expectedHeadRevision")
        head_changed = bool(
            current_head_revision
            and expected_head
            and current_head_revision != expected_head
        )
        if head_changed:
            plan["validity"] = {
                "state": "stale",
                "reasonCodes": ["SELECTIVE_REPLAY_HEAD_REVISION_CHANGED"],
                "requiresRegeneration": True,
            }
        valid = plan["validity"]["state"] == "active"
        return {
            "schemaVersion": "phase8.selective-replay-confirmation.v1",
            "planId": str(plan_id),
            "planHash": plan["planHash"],
            "validity": plan["validity"],
            "canContinue": valid and "executions.manage" in set(context.user.capabilities),
            "requiredCapability": "executions.manage",
            "nextBoundary": "service-managed-execution-workflow",
            "executionCreated": False,
            "approvalRequiredForExecution": plan["riskSummary"][
                "approvalRequiredForExecution"
            ],
            "approvalRefs": [],
            "readOnly": True,
        }

    def _selective_replay_scope(
        self,
        project_id: UUID,
        context: ServiceContext,
        capability: str,
    ) -> ChangeSetScope:
        try:
            return ChangeSetQueryService(self.db)._require_scope(
                project_id,
                None,
                context,
                capability,
            )
        except ChangeSetError as exc:
            code = (
                "SELECTIVE_REPLAY_CAPABILITY_REQUIRED"
                if exc.status_code == 403
                else "SELECTIVE_REPLAY_PROJECT_NOT_FOUND"
            )
            raise ValueError(code) from exc

    @staticmethod
    def _selective_replay_projection(
        record: SelectiveReplayPlanRecord,
        *,
        deduplicated: bool,
    ) -> dict[str, object]:
        projection = dict(record.plan_snapshot)
        projection["deduplicated"] = deduplicated
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        expired = datetime.now(timezone.utc) >= expires_at
        projection["validity"] = {
            "state": "expired" if expired else "active",
            "reasonCodes": ["SELECTIVE_REPLAY_PLAN_EXPIRED"] if expired else [],
            "requiresRegeneration": expired,
        }
        return SelectiveReplayPlan.model_validate(projection).model_dump(mode="json")


__all__ = [
    "ImpactAnalysisError",
    "ImpactAnalysisQueryService",
    "SelectiveReplayQueryService",
]

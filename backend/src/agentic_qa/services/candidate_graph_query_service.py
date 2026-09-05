# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import GraphSource, GraphStatus
from agentic_qa.domain.models import (
    CandidateGraphBuildRun,
    CandidateGraphSourceMapping,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
    CanonicalExecutionGraphVersion,
)
from agentic_qa.schemas.candidate_graph import CandidateBuildResult
from agentic_qa.services.common import ServiceContext, paginate
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


class CandidateGraphError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


class CandidateGraphQueryService:
    """Project-scoped, read-only candidate-graph projection for OSS."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_build(
        self,
        project_id: UUID,
        build_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.candidate.read")
        scope = self._scope(project_id, context)
        build = self.db.scalar(
            select(CandidateGraphBuildRun).where(
                CandidateGraphBuildRun.id == build_id,
                CandidateGraphBuildRun.tenant_id == scope.tenant_id,
                CandidateGraphBuildRun.workspace_id == scope.workspace_id,
                CandidateGraphBuildRun.project_id == project_id,
            )
        )
        if build is None:
            raise CandidateGraphError("CANDIDATE_BUILD_NOT_FOUND", status_code=404)
        return self._build_projection(build)

    def list_builds(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        graph_id: UUID | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        self._require_capability(context, "graph.candidate.read")
        scope = self._scope(project_id, context)
        statement = select(CandidateGraphBuildRun).where(
            CandidateGraphBuildRun.tenant_id == scope.tenant_id,
            CandidateGraphBuildRun.workspace_id == scope.workspace_id,
            CandidateGraphBuildRun.project_id == project_id,
        )
        if graph_id is not None:
            statement = statement.where(CandidateGraphBuildRun.graph_id == graph_id)
        rows = list(
            self.db.scalars(
                statement.order_by(
                    CandidateGraphBuildRun.created_at.desc(),
                    CandidateGraphBuildRun.id.asc(),
                )
            )
        )
        summaries = [
            {
                "buildId": str(item.id),
                "buildRef": item.build_ref,
                "graphId": str(item.graph_id),
                "executionId": str(item.execution_id),
                "candidateVersionId": str(item.candidate_version_id),
                "status": item.status,
                "outcome": item.outcome,
                "transformerVersion": item.transformer_version,
                "evidenceSummary": item.evidence_summary,
                "ambiguityCount": len(item.ambiguities),
                "modelSuggestionStatus": item.model_suggestion.get("status", "not_requested"),
                "canonical": False,
                "active": False,
                "promotionPerformed": False,
                "readOnly": True,
                "observedAt": item.source_observed_at.isoformat(),
                "createdAt": item.created_at.isoformat(),
            }
            for item in rows
        ]
        return paginate(summaries, page, page_size)

    def _scope(self, project_id: UUID, context: ServiceContext):
        try:
            return ScopeAuthorizationService(self.db).resolve_project(project_id, context)
        except ScopeAuthorizationError as exc:
            code = "CEG_SCOPE_INVALID" if exc.status_code == 409 else "CEG_PROJECT_NOT_FOUND"
            raise CandidateGraphError(
                code,
                status_code=exc.status_code,
                field=exc.field,
            ) from exc

    @staticmethod
    def _require_capability(context: ServiceContext, capability: str) -> None:
        if capability not in set(context.user.capabilities):
            raise CandidateGraphError(
                "CANDIDATE_CAPABILITY_REQUIRED",
                status_code=403,
                field=capability,
            )

    def _topology(
        self,
        version: CanonicalExecutionGraphVersion,
    ) -> tuple[
        list[CanonicalExecutionGraphNode],
        list[CanonicalExecutionGraphEdge],
        CanonicalExecutionGraphPath,
        list[CanonicalExecutionGraphPathStep],
    ]:
        nodes = list(
            self.db.scalars(
                select(CanonicalExecutionGraphNode)
                .where(CanonicalExecutionGraphNode.version_id == version.id)
                .order_by(CanonicalExecutionGraphNode.client_key)
            )
        )
        edges = list(
            self.db.scalars(
                select(CanonicalExecutionGraphEdge)
                .where(CanonicalExecutionGraphEdge.version_id == version.id)
                .order_by(CanonicalExecutionGraphEdge.client_key)
            )
        )
        path = self.db.scalar(
            select(CanonicalExecutionGraphPath)
            .where(CanonicalExecutionGraphPath.version_id == version.id)
            .order_by(CanonicalExecutionGraphPath.client_key)
        )
        if path is None:
            raise CandidateGraphError("CANDIDATE_PATH_NOT_FOUND", status_code=409)
        steps = list(
            self.db.scalars(
                select(CanonicalExecutionGraphPathStep)
                .where(CanonicalExecutionGraphPathStep.path_id == path.id)
                .order_by(CanonicalExecutionGraphPathStep.step_order)
            )
        )
        if not nodes or len(nodes) != len(steps):
            raise CandidateGraphError("CANDIDATE_TOPOLOGY_INVALID", status_code=409)
        return nodes, edges, path, steps

    def _build_projection(self, build: CandidateGraphBuildRun) -> dict[str, Any]:
        version = self.db.get(CanonicalExecutionGraphVersion, build.candidate_version_id)
        if (
            version is None
            or version.status != GraphStatus.CANDIDATE
            or version.source != GraphSource.CANDIDATE
            or version.is_frozen
        ):
            raise CandidateGraphError(
                "CANDIDATE_VERSION_BOUNDARY_VIOLATION",
                status_code=409,
            )
        nodes, edges, path, steps = self._topology(version)
        mappings = list(
            self.db.scalars(
                select(CandidateGraphSourceMapping).where(
                    CandidateGraphSourceMapping.build_id == build.id
                )
            )
        )
        mapping_by_key = {(item.entity_type, item.entity_id): item for item in mappings}
        node_items = []
        for node in nodes:
            mapping = mapping_by_key[("node", node.id)]
            node_items.append(
                {
                    "nodeId": node.id,
                    "nodeRef": node.node_ref,
                    "semanticKey": node.semantic_key,
                    "nodeType": node.node_type,
                    "actionType": mapping.observation_summary.get("actionType")
                    or node.attributes_json.get("actionType")
                    or node.attributes_json.get("assertionType"),
                    "intentKey": mapping.observation_summary.get("intentKey")
                    or node.attributes_json.get("intentKey")
                    or node.semantic_key.rsplit(".", 1)[-1],
                    "provenance": self._provenance(mapping),
                }
            )
        edge_items = []
        for edge in edges:
            mapping = mapping_by_key[("edge", edge.id)]
            edge_items.append(
                {
                    "edgeId": edge.id,
                    "edgeRef": edge.edge_ref,
                    "edgeType": edge.edge_type,
                    "sourceNodeId": edge.source_node_id,
                    "targetNodeId": edge.target_node_id,
                    "reviewStatus": edge.review_status,
                    "provenance": self._provenance(mapping),
                }
            )
        step_items = []
        for step in steps:
            mapping = mapping_by_key[("path_step", step.id)]
            summary = mapping.observation_summary
            step_items.append(
                {
                    "stepId": step.id,
                    "stepRef": step.step_ref,
                    "order": step.step_order,
                    "nodeId": step.node_id,
                    "viaEdgeId": step.via_edge_id,
                    "outcome": summary.get("outcome", "unknown"),
                    "retryCount": summary.get("retryCount", 0),
                    "fallbackTypes": summary.get("fallbackTypes", []),
                    "verificationStatus": summary.get("verificationStatus"),
                    "provenance": self._provenance(mapping),
                }
            )
        path_mapping = mapping_by_key[("path", path.id)]
        projection = {
            "schemaVersion": "phase8.candidate-build-result.v1",
            "buildId": build.id,
            "buildRef": build.build_ref,
            "projectId": build.project_id,
            "graphId": build.graph_id,
            "candidateVersionId": build.candidate_version_id,
            "status": "completed",
            "transformerVersion": build.transformer_version,
            "configHash": build.config_hash,
            "observedTrace": build.observed_trace_snapshot,
            "candidatePath": {
                "pathId": path.id,
                "pathRef": path.path_ref,
                "pathKey": path.path_key,
                "versionId": version.id,
                "status": "candidate",
                "source": "candidate",
                "confidence": float(path.confidence),
                "nodes": node_items,
                "edges": edge_items,
                "steps": step_items,
                "provenance": self._provenance(path_mapping),
                "activeCanonical": False,
                "promotionEligible": False,
            },
            "evidenceSummary": build.evidence_summary,
            "ambiguities": build.ambiguities,
            "modelSuggestion": build.model_suggestion,
            "traceId": build.trace_id,
            "guardrailEventRefs": build.guardrail_event_refs,
            "auditRefs": build.audit_refs,
            "canonical": False,
            "active": False,
            "promotionPerformed": False,
            "writesGate": False,
            "writesMemory": False,
            "executesActions": False,
            "readOnly": True,
        }
        return CandidateBuildResult.model_validate(projection).model_dump(mode="json")

    @staticmethod
    def _provenance(mapping: CandidateGraphSourceMapping) -> dict[str, Any]:
        return {
            "sourceEventRefs": mapping.source_event_refs,
            "evidenceRefs": mapping.evidence_refs,
            "transformerVersion": mapping.transformer_version,
            "confidence": float(mapping.confidence),
            "ambiguities": mapping.ambiguities,
        }


__all__ = ["CandidateGraphError", "CandidateGraphQueryService"]

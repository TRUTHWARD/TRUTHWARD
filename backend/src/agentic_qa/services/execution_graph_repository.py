# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    CanonicalExecutionGraph,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
    CanonicalExecutionGraphVersion,
)


class ExecutionGraphRepository:
    """Strictly scoped persistence adapter for the Service-owned CEG foundation."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def find_graph(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        *,
        for_update: bool = False,
    ) -> CanonicalExecutionGraph | None:
        statement = select(CanonicalExecutionGraph).where(
            CanonicalExecutionGraph.id == graph_id,
            CanonicalExecutionGraph.tenant_id == tenant_id,
            CanonicalExecutionGraph.workspace_id == workspace_id,
            CanonicalExecutionGraph.project_id == project_id,
        )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def find_graph_by_scope_key(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        scope_type: str,
        scope_id: UUID,
        graph_key: str,
    ) -> CanonicalExecutionGraph | None:
        return self.db.scalar(
            select(CanonicalExecutionGraph).where(
                CanonicalExecutionGraph.tenant_id == tenant_id,
                CanonicalExecutionGraph.workspace_id == workspace_id,
                CanonicalExecutionGraph.project_id == project_id,
                CanonicalExecutionGraph.scope_type == scope_type,
                CanonicalExecutionGraph.scope_id == scope_id,
                CanonicalExecutionGraph.graph_key == graph_key,
            )
        )

    def find_graph_by_idempotency_key(
        self,
        tenant_id: str,
        workspace_id: str,
        idempotency_key: str,
    ) -> CanonicalExecutionGraph | None:
        return self.db.scalar(
            select(CanonicalExecutionGraph).where(
                CanonicalExecutionGraph.tenant_id == tenant_id,
                CanonicalExecutionGraph.workspace_id == workspace_id,
                CanonicalExecutionGraph.idempotency_key == idempotency_key,
            )
        )

    def list_graphs(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        *,
        status: str | None = None,
        scope_type: str | None = None,
        scope_id: UUID | None = None,
    ) -> list[CanonicalExecutionGraph]:
        statement = select(CanonicalExecutionGraph).where(
            CanonicalExecutionGraph.tenant_id == tenant_id,
            CanonicalExecutionGraph.workspace_id == workspace_id,
            CanonicalExecutionGraph.project_id == project_id,
        )
        if status is not None:
            statement = statement.where(CanonicalExecutionGraph.status == status)
        if scope_type is not None:
            statement = statement.where(CanonicalExecutionGraph.scope_type == scope_type)
        if scope_id is not None:
            statement = statement.where(CanonicalExecutionGraph.scope_id == scope_id)
        return list(
            self.db.scalars(
                statement.order_by(
                    CanonicalExecutionGraph.created_at.desc(),
                    CanonicalExecutionGraph.id.asc(),
                )
            )
        )

    def find_version(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        *,
        for_update: bool = False,
    ) -> CanonicalExecutionGraphVersion | None:
        statement = select(CanonicalExecutionGraphVersion).where(
                CanonicalExecutionGraphVersion.id == version_id,
                CanonicalExecutionGraphVersion.graph_id == graph_id,
                CanonicalExecutionGraphVersion.tenant_id == tenant_id,
                CanonicalExecutionGraphVersion.workspace_id == workspace_id,
                CanonicalExecutionGraphVersion.project_id == project_id,
            )
        if for_update:
            statement = statement.with_for_update()
        return self.db.scalar(statement)

    def find_version_by_idempotency_key(
        self,
        tenant_id: str,
        workspace_id: str,
        idempotency_key: str,
    ) -> CanonicalExecutionGraphVersion | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphVersion).where(
                CanonicalExecutionGraphVersion.tenant_id == tenant_id,
                CanonicalExecutionGraphVersion.workspace_id == workspace_id,
                CanonicalExecutionGraphVersion.idempotency_key == idempotency_key,
            )
        )

    def find_version_by_hash(
        self,
        tenant_id: str,
        workspace_id: str,
        graph_id: UUID,
        content_hash: str,
    ) -> CanonicalExecutionGraphVersion | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphVersion).where(
                CanonicalExecutionGraphVersion.tenant_id == tenant_id,
                CanonicalExecutionGraphVersion.workspace_id == workspace_id,
                CanonicalExecutionGraphVersion.graph_id == graph_id,
                CanonicalExecutionGraphVersion.content_hash == content_hash,
            )
        )

    def list_versions(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
    ) -> list[CanonicalExecutionGraphVersion]:
        return list(
            self.db.scalars(
                select(CanonicalExecutionGraphVersion)
                .where(
                    CanonicalExecutionGraphVersion.tenant_id == tenant_id,
                    CanonicalExecutionGraphVersion.workspace_id == workspace_id,
                    CanonicalExecutionGraphVersion.project_id == project_id,
                    CanonicalExecutionGraphVersion.graph_id == graph_id,
                )
                .order_by(CanonicalExecutionGraphVersion.version_number.asc())
            )
        )

    def max_version_number(
        self,
        tenant_id: str,
        workspace_id: str,
        graph_id: UUID,
    ) -> int:
        return int(
            self.db.scalar(
                select(func.max(CanonicalExecutionGraphVersion.version_number)).where(
                    CanonicalExecutionGraphVersion.tenant_id == tenant_id,
                    CanonicalExecutionGraphVersion.workspace_id == workspace_id,
                    CanonicalExecutionGraphVersion.graph_id == graph_id,
                )
            )
            or 0
        )

    def list_nodes(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
    ) -> list[CanonicalExecutionGraphNode]:
        return list(
            self.db.scalars(
                select(CanonicalExecutionGraphNode)
                .where(
                    CanonicalExecutionGraphNode.tenant_id == tenant_id,
                    CanonicalExecutionGraphNode.workspace_id == workspace_id,
                    CanonicalExecutionGraphNode.project_id == project_id,
                    CanonicalExecutionGraphNode.graph_id == graph_id,
                    CanonicalExecutionGraphNode.version_id == version_id,
                )
                .order_by(CanonicalExecutionGraphNode.semantic_key.asc(), CanonicalExecutionGraphNode.id.asc())
            )
        )

    def find_node(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        node_id: UUID,
    ) -> CanonicalExecutionGraphNode | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphNode).where(
                CanonicalExecutionGraphNode.id == node_id,
                CanonicalExecutionGraphNode.version_id == version_id,
                CanonicalExecutionGraphNode.graph_id == graph_id,
                CanonicalExecutionGraphNode.tenant_id == tenant_id,
                CanonicalExecutionGraphNode.workspace_id == workspace_id,
                CanonicalExecutionGraphNode.project_id == project_id,
            )
        )

    def find_node_by_client_key(
        self,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        client_key: str,
    ) -> CanonicalExecutionGraphNode | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphNode).where(
                CanonicalExecutionGraphNode.tenant_id == tenant_id,
                CanonicalExecutionGraphNode.workspace_id == workspace_id,
                CanonicalExecutionGraphNode.version_id == version_id,
                CanonicalExecutionGraphNode.client_key == client_key,
            )
        )

    def find_node_by_semantic_key(
        self,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        semantic_key: str,
    ) -> CanonicalExecutionGraphNode | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphNode).where(
                CanonicalExecutionGraphNode.tenant_id == tenant_id,
                CanonicalExecutionGraphNode.workspace_id == workspace_id,
                CanonicalExecutionGraphNode.version_id == version_id,
                CanonicalExecutionGraphNode.semantic_key == semantic_key,
            )
        )

    def list_edges(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
    ) -> list[CanonicalExecutionGraphEdge]:
        return list(
            self.db.scalars(
                select(CanonicalExecutionGraphEdge)
                .where(
                    CanonicalExecutionGraphEdge.tenant_id == tenant_id,
                    CanonicalExecutionGraphEdge.workspace_id == workspace_id,
                    CanonicalExecutionGraphEdge.project_id == project_id,
                    CanonicalExecutionGraphEdge.graph_id == graph_id,
                    CanonicalExecutionGraphEdge.version_id == version_id,
                )
                .order_by(CanonicalExecutionGraphEdge.client_key.asc(), CanonicalExecutionGraphEdge.id.asc())
            )
        )

    def find_edge(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        edge_id: UUID,
    ) -> CanonicalExecutionGraphEdge | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphEdge).where(
                CanonicalExecutionGraphEdge.id == edge_id,
                CanonicalExecutionGraphEdge.version_id == version_id,
                CanonicalExecutionGraphEdge.graph_id == graph_id,
                CanonicalExecutionGraphEdge.tenant_id == tenant_id,
                CanonicalExecutionGraphEdge.workspace_id == workspace_id,
                CanonicalExecutionGraphEdge.project_id == project_id,
            )
        )

    def find_edge_by_client_key(
        self,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        client_key: str,
    ) -> CanonicalExecutionGraphEdge | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphEdge).where(
                CanonicalExecutionGraphEdge.tenant_id == tenant_id,
                CanonicalExecutionGraphEdge.workspace_id == workspace_id,
                CanonicalExecutionGraphEdge.version_id == version_id,
                CanonicalExecutionGraphEdge.client_key == client_key,
            )
        )

    def find_edge_by_semantic_hash(
        self,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        semantic_hash: str,
    ) -> CanonicalExecutionGraphEdge | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphEdge).where(
                CanonicalExecutionGraphEdge.tenant_id == tenant_id,
                CanonicalExecutionGraphEdge.workspace_id == workspace_id,
                CanonicalExecutionGraphEdge.version_id == version_id,
                CanonicalExecutionGraphEdge.semantic_hash == semantic_hash,
            )
        )

    def list_paths(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
    ) -> list[CanonicalExecutionGraphPath]:
        return list(
            self.db.scalars(
                select(CanonicalExecutionGraphPath)
                .where(
                    CanonicalExecutionGraphPath.tenant_id == tenant_id,
                    CanonicalExecutionGraphPath.workspace_id == workspace_id,
                    CanonicalExecutionGraphPath.project_id == project_id,
                    CanonicalExecutionGraphPath.graph_id == graph_id,
                    CanonicalExecutionGraphPath.version_id == version_id,
                )
                .order_by(CanonicalExecutionGraphPath.path_key.asc(), CanonicalExecutionGraphPath.id.asc())
            )
        )

    def find_path(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        path_id: UUID,
    ) -> CanonicalExecutionGraphPath | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphPath).where(
                CanonicalExecutionGraphPath.id == path_id,
                CanonicalExecutionGraphPath.version_id == version_id,
                CanonicalExecutionGraphPath.graph_id == graph_id,
                CanonicalExecutionGraphPath.tenant_id == tenant_id,
                CanonicalExecutionGraphPath.workspace_id == workspace_id,
                CanonicalExecutionGraphPath.project_id == project_id,
            )
        )

    def find_path_by_client_key(
        self,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        client_key: str,
    ) -> CanonicalExecutionGraphPath | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphPath).where(
                CanonicalExecutionGraphPath.tenant_id == tenant_id,
                CanonicalExecutionGraphPath.workspace_id == workspace_id,
                CanonicalExecutionGraphPath.version_id == version_id,
                CanonicalExecutionGraphPath.client_key == client_key,
            )
        )

    def find_path_by_path_key(
        self,
        tenant_id: str,
        workspace_id: str,
        version_id: UUID,
        path_key: str,
    ) -> CanonicalExecutionGraphPath | None:
        return self.db.scalar(
            select(CanonicalExecutionGraphPath).where(
                CanonicalExecutionGraphPath.tenant_id == tenant_id,
                CanonicalExecutionGraphPath.workspace_id == workspace_id,
                CanonicalExecutionGraphPath.version_id == version_id,
                CanonicalExecutionGraphPath.path_key == path_key,
            )
        )

    def list_steps(
        self,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        *,
        path_id: UUID | None = None,
    ) -> list[CanonicalExecutionGraphPathStep]:
        statement = select(CanonicalExecutionGraphPathStep).where(
            CanonicalExecutionGraphPathStep.tenant_id == tenant_id,
            CanonicalExecutionGraphPathStep.workspace_id == workspace_id,
            CanonicalExecutionGraphPathStep.project_id == project_id,
            CanonicalExecutionGraphPathStep.graph_id == graph_id,
            CanonicalExecutionGraphPathStep.version_id == version_id,
        )
        if path_id is not None:
            statement = statement.where(CanonicalExecutionGraphPathStep.path_id == path_id)
        return list(
            self.db.scalars(
                statement.order_by(
                    CanonicalExecutionGraphPathStep.path_id.asc(),
                    CanonicalExecutionGraphPathStep.step_order.asc(),
                )
            )
        )

    def topology_counts(self, version_id: UUID) -> tuple[int, int, int, int]:
        models = (
            CanonicalExecutionGraphNode,
            CanonicalExecutionGraphEdge,
            CanonicalExecutionGraphPath,
            CanonicalExecutionGraphPathStep,
        )
        counts = tuple(
            int(self.db.scalar(select(func.count()).select_from(model).where(model.version_id == version_id)) or 0)
            for model in models
        )
        return counts[0], counts[1], counts[2], counts[3]

    def add(
        self,
        record: CanonicalExecutionGraph
        | CanonicalExecutionGraphVersion
        | CanonicalExecutionGraphNode
        | CanonicalExecutionGraphEdge
        | CanonicalExecutionGraphPath
        | CanonicalExecutionGraphPathStep,
    ) -> None:
        self.db.add(record)

    def delete(self, record: object) -> None:
        self.db.delete(record)

    def flush(self) -> None:
        self.db.flush()

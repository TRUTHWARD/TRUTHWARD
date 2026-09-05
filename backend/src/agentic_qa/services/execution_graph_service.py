# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from agentic_qa.domain.enums import GraphScope, GraphSource, GraphStatus
from agentic_qa.domain.models import (
    CanonicalExecutionGraph,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
    CanonicalExecutionGraphVersion,
    Project,
    ProjectEnvironment,
)
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.execution_graph import (
    CEG_SCHEMA_VERSION,
    CanonicalExecutionGraphContract,
    CreateCanonicalPathRequest,
    CreateGraphEdgeRequest,
    CreateGraphIdentityRequest,
    CreateGraphNodeRequest,
    CreateGraphVersionRequest,
    GraphSourceContract,
    UpdateCanonicalPathRequest,
    UpdateGraphEdgeRequest,
    UpdateGraphNodeRequest,
    ValidateGraphVersionRequest,
    validate_graph_node_attributes,
)
from agentic_qa.services.common import (
    ServiceContext,
    acquire_transaction_advisory_lock,
    canonical_hash,
    paginate,
)
from agentic_qa.services.execution_graph_repository import ExecutionGraphRepository
from agentic_qa.services.execution_graph_hash import (
    build_graph_topology_hash,
    build_graph_topology_material,
    build_graph_version_content_hash,
)
from agentic_qa.services.execution_graph_validator import (
    ExecutionGraphValidator,
    edge_pair_allowed,
    edge_requires_review,
    would_create_forbidden_cycle,
)
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


@dataclass(frozen=True, slots=True)
class ExecutionGraphScope:
    project: Project
    tenant_id: str
    workspace_id: str


class ExecutionGraphError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


class ExecutionGraphService:
    """P10-P11 CEG identity/version and structured topology Service boundary.

    Identity/version creation remains draft-only. P11 manages topology only on
    draft/candidate versions; it never promotes, approves, writes Gate/Memory,
    or executes a Skill, Agent, Tool, Connector, browser, or Visual Grounding.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = ExecutionGraphRepository(db)

    def create_draft_graph(
        self,
        payload: CreateGraphIdentityRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_project_scope(payload.projectId, context)
        environment, scope_type, scope_id = self._resolve_environment_scope(
            scope.project,
            payload.environmentId,
        )
        graph_key = payload.graphKey.strip().lower()
        idempotency_key = self._idempotency_key(payload.idempotencyKey)
        request_material = {
            "projectId": str(scope.project.id),
            "environmentId": str(environment.id) if environment else None,
            "scopeType": scope_type.value,
            "scopeId": str(scope_id),
            "graphKey": graph_key,
            "name": payload.name,
            "description": payload.description,
            "retentionPolicy": payload.retentionPolicy,
            "retentionUntil": payload.retentionUntil,
            "metadata": payload.metadata,
        }
        request_hash = canonical_hash(request_material)
        lock_scope = (
            f"{scope.tenant_id}:{scope.workspace_id}:{scope.project.id}:"
            f"{scope_type.value}:{scope_id}:{graph_key}"
        )
        acquire_transaction_advisory_lock(self.db, "ceg-identity-create", lock_scope)

        retry = self.repository.find_graph_by_idempotency_key(
            scope.tenant_id,
            scope.workspace_id,
            idempotency_key,
        )
        if retry is not None:
            self._require_same_request(retry.request_hash, request_hash)
            return self._identity_projection(retry)

        existing = self.repository.find_graph_by_scope_key(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            scope_type.value,
            scope_id,
            graph_key,
        )
        if existing is not None:
            self._require_same_request(existing.request_hash, request_hash)
            return self._identity_projection(existing)

        graph_id = uuid4()
        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=None,
                root_span_name="ceg.foundation",
                span_name="ceg.identity.create_draft",
                service_name="orchestrator-service",
                attributes={
                    "graphId": str(graph_id),
                    "projectId": str(scope.project.id),
                    "scopeType": scope_type.value,
                    "createsCanonical": False,
                },
                parent_span_id=context.parent_span_id,
            ):
                graph = CanonicalExecutionGraph(
                    id=graph_id,
                    tenant_id=scope.tenant_id,
                    workspace_id=scope.workspace_id,
                    project_id=scope.project.id,
                    environment_id=environment.id if environment else None,
                    scope_type=scope_type,
                    scope_id=scope_id,
                    graph_key=graph_key,
                    graph_ref=f"ceg://graphs/{graph_id}",
                    name=payload.name,
                    description=payload.description,
                    status=GraphStatus.DRAFT,
                    retention_policy=payload.retentionPolicy,
                    retention_until=payload.retentionUntil,
                    retention_status="active",
                    legal_hold=False,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    audit_refs=[],
                    trace_id=UUID(context.trace_id),
                    created_by=context.user.id,
                    updated_by=context.user.id,
                    metadata_json=dict(payload.metadata),
                )
                self.repository.add(graph)
                self.repository.flush()
                audit = write_audit_log(
                    self.db,
                    context.user.id,
                    "ceg.identity.create_draft",
                    "canonical_execution_graph",
                    str(graph.id),
                    context.request_id,
                    context.trace_id,
                    details={
                        "projectId": str(graph.project_id),
                        "environmentId": str(graph.environment_id) if graph.environment_id else None,
                        "scopeType": scope_type.value,
                        "graphKey": graph.graph_key,
                        "status": GraphStatus.DRAFT.value,
                        "createsCanonical": False,
                    },
                )
                self.db.flush()
                graph.audit_refs = [{"type": "audit", "ref": f"audit://records/{audit.id}", "contentHash": None}]
                self.repository.flush()
            self.db.commit()
            self.db.refresh(graph)
            return self._identity_projection(graph)
        except IntegrityError as exc:
            self.db.rollback()
            recovered = self.repository.find_graph_by_idempotency_key(
                scope.tenant_id,
                scope.workspace_id,
                idempotency_key,
            ) or self.repository.find_graph_by_scope_key(
                scope.tenant_id,
                scope.workspace_id,
                scope.project.id,
                scope_type.value,
                scope_id,
                graph_key,
            )
            if recovered is not None and recovered.request_hash == request_hash:
                return self._identity_projection(recovered)
            raise ExecutionGraphError("CEG_IDENTITY_CONFLICT", status_code=409) from exc

    def create_draft_version(
        self,
        project_id: UUID,
        payload: CreateGraphVersionRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_project_scope(project_id, context)
        idempotency_key = self._idempotency_key(payload.idempotencyKey)
        acquire_transaction_advisory_lock(
            self.db,
            "ceg-version-create",
            f"{scope.tenant_id}:{scope.workspace_id}:{payload.graphId}",
        )
        graph = self.repository.find_graph(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            payload.graphId,
            for_update=True,
        )
        if graph is None:
            raise ExecutionGraphError("CEG_GRAPH_NOT_FOUND", status_code=404)
        if graph.status == GraphStatus.ARCHIVED:
            raise ExecutionGraphError("CEG_GRAPH_ARCHIVED", status_code=409)

        normalized_refs = self._normalized_source_refs(payload)
        request_material = {
            "graphId": str(graph.id),
            "parentVersionId": str(payload.parentVersionId) if payload.parentVersionId else None,
            "source": payload.source,
            "sourceRefs": normalized_refs,
            "schemaVersion": payload.schemaVersion,
            "applicability": payload.applicability,
            "retentionPolicy": payload.retentionPolicy,
            "retentionUntil": payload.retentionUntil,
            "metadata": payload.metadata,
        }
        request_hash = canonical_hash(request_material)
        retry = self.repository.find_version_by_idempotency_key(
            scope.tenant_id,
            scope.workspace_id,
            idempotency_key,
        )
        if retry is not None:
            self._require_same_request(retry.request_hash, request_hash)
            return self._version_contract(graph, retry)

        current_version = self.repository.max_version_number(
            scope.tenant_id,
            scope.workspace_id,
            graph.id,
        )
        parent = self._validate_parent(scope, graph, payload.parentVersionId, current_version)
        content_hash = build_graph_version_content_hash(
            graph=graph,
            parent_version_id=parent.id if parent else None,
            source=payload.source,
            source_refs=normalized_refs,
            schema_version=payload.schemaVersion,
            applicability=payload.applicability,
            metadata=payload.metadata,
        )
        duplicate = self.repository.find_version_by_hash(
            scope.tenant_id,
            scope.workspace_id,
            graph.id,
            content_hash,
        )
        if duplicate is not None:
            self._require_same_request(duplicate.request_hash, request_hash)
            return self._version_contract(graph, duplicate)

        version_id = uuid4()
        version_number = current_version + 1
        try:
            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=None,
                root_span_name="ceg.foundation",
                span_name="ceg.version.create_draft",
                service_name="orchestrator-service",
                attributes={
                    "graphId": str(graph.id),
                    "versionId": str(version_id),
                    "version": version_number,
                    "source": payload.source,
                    "createsCanonical": False,
                },
                parent_span_id=context.parent_span_id,
            ):
                version = CanonicalExecutionGraphVersion(
                    id=version_id,
                    graph_id=graph.id,
                    tenant_id=graph.tenant_id,
                    workspace_id=graph.workspace_id,
                    project_id=graph.project_id,
                    environment_id=graph.environment_id,
                    scope_type=graph.scope_type,
                    scope_id=graph.scope_id,
                    version_number=version_number,
                    version_ref=f"ceg-version://versions/{version_id}",
                    parent_version_id=parent.id if parent else None,
                    status=GraphStatus.DRAFT,
                    source=GraphSource(payload.source),
                    schema_version=payload.schemaVersion,
                    content_hash=content_hash,
                    source_refs=normalized_refs,
                    applicability=dict(payload.applicability),
                    is_frozen=False,
                    frozen_at=None,
                    frozen_by=None,
                    retention_policy=payload.retentionPolicy,
                    retention_until=payload.retentionUntil,
                    retention_status="active",
                    legal_hold=False,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    audit_refs=[],
                    trace_id=UUID(context.trace_id),
                    created_by=context.user.id,
                    updated_by=context.user.id,
                    metadata_json=dict(payload.metadata),
                )
                self.repository.add(version)
                self.repository.flush()
                audit = write_audit_log(
                    self.db,
                    context.user.id,
                    "ceg.version.create_draft",
                    "canonical_execution_graph_version",
                    str(version.id),
                    context.request_id,
                    context.trace_id,
                    details={
                        "graphId": str(graph.id),
                        "version": version_number,
                        "parentVersionId": str(parent.id) if parent else None,
                        "source": payload.source,
                        "contentHash": content_hash,
                        "status": GraphStatus.DRAFT.value,
                        "createsCanonical": False,
                    },
                )
                self.db.flush()
                version.audit_refs = [{"type": "audit", "ref": f"audit://records/{audit.id}", "contentHash": None}]
                self.repository.flush()
            self.db.commit()
            self.db.refresh(version)
            return self._version_contract(graph, version)
        except IntegrityError as exc:
            self.db.rollback()
            recovered = self.repository.find_version_by_idempotency_key(
                scope.tenant_id,
                scope.workspace_id,
                idempotency_key,
            ) or self.repository.find_version_by_hash(
                scope.tenant_id,
                scope.workspace_id,
                graph.id,
                content_hash,
            )
            if recovered is not None and recovered.request_hash == request_hash:
                recovered_graph = self.repository.find_graph(
                    scope.tenant_id,
                    scope.workspace_id,
                    scope.project.id,
                    recovered.graph_id,
                )
                if recovered_graph is not None:
                    return self._version_contract(recovered_graph, recovered)
            raise ExecutionGraphError("CEG_VERSION_CONFLICT", status_code=409) from exc

    def create_node(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        payload: CreateGraphNodeRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        request_material = payload.model_dump(mode="json", exclude={"versionLockVersion"})
        request_hash = canonical_hash(request_material)
        retry = self.repository.find_node_by_client_key(
            scope.tenant_id, scope.workspace_id, version.id, payload.clientKey
        )
        if retry is not None:
            self._require_same_request(retry.request_hash, request_hash)
            return self._node_mutation_response(scope, graph, version, retry)
        self._require_mutable_version(version, payload.versionLockVersion)
        semantic_conflict = self.repository.find_node_by_semantic_key(
            scope.tenant_id, scope.workspace_id, version.id, payload.semanticKey
        )
        if semantic_conflict is not None:
            raise ExecutionGraphError(
                "CEG_NODE_SEMANTIC_KEY_CONFLICT", status_code=409, field="semanticKey"
            )
        node_count, _, _, _ = self.repository.topology_counts(version.id)
        if node_count >= 5_000:
            raise ExecutionGraphError("CEG_NODE_LIMIT_EXCEEDED", status_code=422)

        node_id = uuid4()
        try:
            with self._topology_trace(
                context, "ceg.node.create", graph.id, version.id, node_id
            ):
                node = CanonicalExecutionGraphNode(
                    id=node_id,
                    node_ref=f"ceg-node://versions/{version.id}/nodes/{node_id}",
                    version_id=version.id,
                    graph_id=graph.id,
                    tenant_id=graph.tenant_id,
                    workspace_id=graph.workspace_id,
                    project_id=graph.project_id,
                    scope_id=graph.scope_id,
                    client_key=payload.clientKey,
                    semantic_key=payload.semanticKey,
                    node_type=payload.nodeType,
                    display_metadata=payload.display.model_dump(mode="json"),
                    attributes_json=dict(payload.attributes),
                    external_refs=[item.model_dump(mode="json") for item in payload.externalRefs],
                    risk_level=payload.riskLevel,
                    source=payload.source,
                    confidence=Decimal(str(payload.confidence)),
                    request_hash=request_hash,
                    audit_refs=[],
                    trace_id=UUID(context.trace_id),
                    created_by=context.user.id,
                    updated_by=context.user.id,
                )
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.node.create",
                    "canonical_execution_graph_node",
                    node.id,
                    graph,
                    version,
                    {"clientKey": node.client_key, "semanticKey": node.semantic_key, "nodeType": node.node_type},
                )
                node.audit_refs = [audit_ref]
                self.repository.add(node)
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(node)
            self.db.refresh(version)
            return self._node_mutation_response(scope, graph, version, node)
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            recovered = self.repository.find_node_by_client_key(
                scope.tenant_id, scope.workspace_id, version.id, payload.clientKey
            )
            if recovered is not None and recovered.request_hash == request_hash:
                recovered_version = self.repository.find_version(
                    scope.tenant_id,
                    scope.workspace_id,
                    scope.project.id,
                    graph.id,
                    version.id,
                )
                if recovered_version is not None:
                    return self._node_mutation_response(scope, graph, recovered_version, recovered)
            raise ExecutionGraphError("CEG_NODE_CONFLICT", status_code=409) from exc

    def update_node(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        node_id: UUID,
        payload: UpdateGraphNodeRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        self._require_mutable_version(version, payload.versionLockVersion)
        node = self.repository.find_node(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            node_id,
        )
        if node is None:
            raise ExecutionGraphError("CEG_NODE_NOT_FOUND", status_code=404)
        self._require_lock(node.lock_version, payload.lockVersion, "lockVersion")
        next_semantic_key = payload.semanticKey or node.semantic_key
        next_node_type = payload.nodeType or node.node_type
        next_attributes = payload.attributes if payload.attributes is not None else node.attributes_json
        validate_graph_node_attributes(next_node_type, next_attributes)
        semantic_conflict = self.repository.find_node_by_semantic_key(
            scope.tenant_id, scope.workspace_id, version.id, next_semantic_key
        )
        if semantic_conflict is not None and semantic_conflict.id != node.id:
            raise ExecutionGraphError(
                "CEG_NODE_SEMANTIC_KEY_CONFLICT", status_code=409, field="semanticKey"
            )
        changed_fields = sorted(payload.model_fields_set - {"lockVersion", "versionLockVersion"})
        try:
            with self._topology_trace(
                context, "ceg.node.update", graph.id, version.id, node.id
            ):
                if payload.semanticKey is not None:
                    node.semantic_key = payload.semanticKey
                if payload.nodeType is not None:
                    node.node_type = payload.nodeType
                if payload.display is not None:
                    node.display_metadata = payload.display.model_dump(mode="json")
                if payload.attributes is not None:
                    node.attributes_json = dict(payload.attributes)
                if payload.externalRefs is not None:
                    node.external_refs = [
                        item.model_dump(mode="json") for item in payload.externalRefs
                    ]
                if payload.riskLevel is not None:
                    node.risk_level = payload.riskLevel
                if payload.source is not None:
                    node.source = payload.source
                if payload.confidence is not None:
                    node.confidence = Decimal(str(payload.confidence))
                node.updated_by = context.user.id
                node.trace_id = UUID(context.trace_id)
                node.request_hash = canonical_hash(self._node_semantic_payload(node))
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.node.update",
                    "canonical_execution_graph_node",
                    node.id,
                    graph,
                    version,
                    {"changedFields": changed_fields},
                )
                node.audit_refs = [*node.audit_refs, audit_ref][-128:]
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(node)
            self.db.refresh(version)
            return self._node_mutation_response(scope, graph, version, node)
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise ExecutionGraphError("CEG_CONCURRENT_MODIFICATION", status_code=409) from exc

    def delete_node(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        node_id: UUID,
        *,
        lock_version: int,
        version_lock_version: int,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        self._require_mutable_version(version, version_lock_version)
        node = self.repository.find_node(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            node_id,
        )
        if node is None:
            raise ExecutionGraphError("CEG_NODE_NOT_FOUND", status_code=404)
        self._require_lock(node.lock_version, lock_version, "lockVersion")
        edges = self.repository.list_edges(
            scope.tenant_id, scope.workspace_id, scope.project.id, graph.id, version.id
        )
        paths = self.repository.list_paths(
            scope.tenant_id, scope.workspace_id, scope.project.id, graph.id, version.id
        )
        steps = self.repository.list_steps(
            scope.tenant_id, scope.workspace_id, scope.project.id, graph.id, version.id
        )
        if any(
            item.source_node_id == node.id or item.target_node_id == node.id for item in edges
        ) or any(
            item.entry_node_id == node.id or item.exit_node_id == node.id for item in paths
        ) or any(item.node_id == node.id for item in steps):
            raise ExecutionGraphError("CEG_NODE_REFERENCED", status_code=409)
        try:
            with self._topology_trace(
                context, "ceg.node.delete", graph.id, version.id, node.id
            ):
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.node.delete",
                    "canonical_execution_graph_node",
                    node.id,
                    graph,
                    version,
                    {"semanticKey": node.semantic_key, "nodeType": node.node_type},
                )
                self.repository.delete(node)
                self.repository.flush()
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(version)
            return {
                "deleted": True,
                "nodeId": str(node_id),
                "version": self._version_projection_summary(scope, graph, version),
            }
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise ExecutionGraphError("CEG_NODE_REFERENCED", status_code=409) from exc

    def create_edge(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        payload: CreateGraphEdgeRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        request_material = payload.model_dump(mode="json", exclude={"versionLockVersion"})
        request_hash = canonical_hash(request_material)
        retry = self.repository.find_edge_by_client_key(
            scope.tenant_id, scope.workspace_id, version.id, payload.clientKey
        )
        if retry is not None:
            self._require_same_request(retry.request_hash, request_hash)
            return self._edge_mutation_response(scope, graph, version, retry)
        self._require_mutable_version(version, payload.versionLockVersion)
        source_node, target_node = self._require_edge_nodes(
            scope, graph, version, payload.sourceNodeId, payload.targetNodeId
        )
        self._require_edge_relation(payload.edgeType, source_node.node_type, target_node.node_type)
        edges = self.repository.list_edges(
            scope.tenant_id, scope.workspace_id, scope.project.id, graph.id, version.id
        )
        if len(edges) >= 20_000:
            raise ExecutionGraphError("CEG_EDGE_LIMIT_EXCEEDED", status_code=422)
        if would_create_forbidden_cycle(
            edges,
            edge_type=payload.edgeType,
            source_node_id=source_node.id,
            target_node_id=target_node.id,
        ):
            raise ExecutionGraphError("CEG_FORBIDDEN_CYCLE", status_code=422, field="edgeType")
        condition = payload.condition.model_dump(mode="json") if payload.condition else {}
        semantic_hash = self._edge_semantic_hash(
            payload.edgeType, source_node.semantic_key, target_node.semantic_key, condition
        )
        semantic_conflict = self.repository.find_edge_by_semantic_hash(
            scope.tenant_id, scope.workspace_id, version.id, semantic_hash
        )
        if semantic_conflict is not None:
            raise ExecutionGraphError("CEG_EDGE_DUPLICATE", status_code=409)
        edge_id = uuid4()
        try:
            with self._topology_trace(
                context, "ceg.edge.create", graph.id, version.id, edge_id
            ):
                edge = CanonicalExecutionGraphEdge(
                    id=edge_id,
                    edge_ref=f"ceg-edge://versions/{version.id}/edges/{edge_id}",
                    version_id=version.id,
                    graph_id=graph.id,
                    tenant_id=graph.tenant_id,
                    workspace_id=graph.workspace_id,
                    project_id=graph.project_id,
                    scope_id=graph.scope_id,
                    client_key=payload.clientKey,
                    edge_type=payload.edgeType,
                    source_node_id=source_node.id,
                    target_node_id=target_node.id,
                    condition_json=condition,
                    risk_level=payload.riskLevel,
                    review_status=(
                        "pending_review"
                        if edge_requires_review(payload.edgeType, payload.riskLevel)
                        else "not_required"
                    ),
                    source=payload.source,
                    confidence=Decimal(str(payload.confidence)),
                    semantic_hash=semantic_hash,
                    request_hash=request_hash,
                    audit_refs=[],
                    trace_id=UUID(context.trace_id),
                    created_by=context.user.id,
                    updated_by=context.user.id,
                )
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.edge.create",
                    "canonical_execution_graph_edge",
                    edge.id,
                    graph,
                    version,
                    {
                        "clientKey": edge.client_key,
                        "edgeType": edge.edge_type,
                        "sourceNodeId": str(edge.source_node_id),
                        "targetNodeId": str(edge.target_node_id),
                        "reviewStatus": edge.review_status,
                    },
                )
                edge.audit_refs = [audit_ref]
                self.repository.add(edge)
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(edge)
            self.db.refresh(version)
            return self._edge_mutation_response(scope, graph, version, edge)
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise ExecutionGraphError("CEG_EDGE_CONFLICT", status_code=409) from exc

    def update_edge(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        edge_id: UUID,
        payload: UpdateGraphEdgeRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        self._require_mutable_version(version, payload.versionLockVersion)
        edge = self.repository.find_edge(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            edge_id,
        )
        if edge is None:
            raise ExecutionGraphError("CEG_EDGE_NOT_FOUND", status_code=404)
        self._require_lock(edge.lock_version, payload.lockVersion, "lockVersion")
        edge_type = payload.edgeType or edge.edge_type
        source_node_id = payload.sourceNodeId or edge.source_node_id
        target_node_id = payload.targetNodeId or edge.target_node_id
        if source_node_id == target_node_id:
            raise ExecutionGraphError("CEG_EDGE_SELF_LOOP", status_code=422, field="targetNodeId")
        source_node, target_node = self._require_edge_nodes(
            scope, graph, version, source_node_id, target_node_id
        )
        self._require_edge_relation(edge_type, source_node.node_type, target_node.node_type)
        edges = self.repository.list_edges(
            scope.tenant_id, scope.workspace_id, scope.project.id, graph.id, version.id
        )
        if would_create_forbidden_cycle(
            edges,
            edge_type=edge_type,
            source_node_id=source_node.id,
            target_node_id=target_node.id,
            exclude_edge_id=edge.id,
        ):
            raise ExecutionGraphError("CEG_FORBIDDEN_CYCLE", status_code=422, field="edgeType")
        condition = (
            payload.condition.model_dump(mode="json")
            if payload.condition is not None
            else ({} if "condition" in payload.model_fields_set else (edge.condition_json or {}))
        )
        semantic_hash = self._edge_semantic_hash(
            edge_type, source_node.semantic_key, target_node.semantic_key, condition
        )
        semantic_conflict = self.repository.find_edge_by_semantic_hash(
            scope.tenant_id, scope.workspace_id, version.id, semantic_hash
        )
        if semantic_conflict is not None and semantic_conflict.id != edge.id:
            raise ExecutionGraphError("CEG_EDGE_DUPLICATE", status_code=409)
        changed_fields = sorted(payload.model_fields_set - {"lockVersion", "versionLockVersion"})
        try:
            with self._topology_trace(
                context, "ceg.edge.update", graph.id, version.id, edge.id
            ):
                edge.edge_type = edge_type
                edge.source_node_id = source_node.id
                edge.target_node_id = target_node.id
                edge.condition_json = condition
                if payload.riskLevel is not None:
                    edge.risk_level = payload.riskLevel
                if payload.source is not None:
                    edge.source = payload.source
                if payload.confidence is not None:
                    edge.confidence = Decimal(str(payload.confidence))
                edge.review_status = (
                    "pending_review"
                    if edge_requires_review(edge.edge_type, edge.risk_level)
                    else "not_required"
                )
                edge.semantic_hash = semantic_hash
                edge.updated_by = context.user.id
                edge.trace_id = UUID(context.trace_id)
                edge.request_hash = canonical_hash(self._edge_semantic_payload(edge))
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.edge.update",
                    "canonical_execution_graph_edge",
                    edge.id,
                    graph,
                    version,
                    {"changedFields": changed_fields, "reviewStatus": edge.review_status},
                )
                edge.audit_refs = [*edge.audit_refs, audit_ref][-128:]
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(edge)
            self.db.refresh(version)
            return self._edge_mutation_response(scope, graph, version, edge)
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise ExecutionGraphError("CEG_CONCURRENT_MODIFICATION", status_code=409) from exc

    def delete_edge(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        edge_id: UUID,
        *,
        lock_version: int,
        version_lock_version: int,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        self._require_mutable_version(version, version_lock_version)
        edge = self.repository.find_edge(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            edge_id,
        )
        if edge is None:
            raise ExecutionGraphError("CEG_EDGE_NOT_FOUND", status_code=404)
        self._require_lock(edge.lock_version, lock_version, "lockVersion")
        steps = self.repository.list_steps(
            scope.tenant_id, scope.workspace_id, scope.project.id, graph.id, version.id
        )
        if any(item.via_edge_id == edge.id for item in steps):
            raise ExecutionGraphError("CEG_EDGE_REFERENCED_BY_PATH", status_code=409)
        try:
            with self._topology_trace(
                context, "ceg.edge.delete", graph.id, version.id, edge.id
            ):
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.edge.delete",
                    "canonical_execution_graph_edge",
                    edge.id,
                    graph,
                    version,
                    {"edgeType": edge.edge_type, "clientKey": edge.client_key},
                )
                self.repository.delete(edge)
                self.repository.flush()
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(version)
            return {
                "deleted": True,
                "edgeId": str(edge_id),
                "version": self._version_projection_summary(scope, graph, version),
            }
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise ExecutionGraphError("CEG_EDGE_REFERENCED_BY_PATH", status_code=409) from exc

    def create_path(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        payload: CreateCanonicalPathRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        request_material = payload.model_dump(mode="json", exclude={"versionLockVersion"})
        request_hash = canonical_hash(request_material)
        retry = self.repository.find_path_by_client_key(
            scope.tenant_id, scope.workspace_id, version.id, payload.clientKey
        )
        if retry is not None:
            self._require_same_request(retry.request_hash, request_hash)
            return self._path_mutation_response(scope, graph, version, retry)
        self._require_mutable_version(version, payload.versionLockVersion)
        if self.repository.find_path_by_path_key(
            scope.tenant_id, scope.workspace_id, version.id, payload.pathKey
        ) is not None:
            raise ExecutionGraphError("CEG_PATH_KEY_CONFLICT", status_code=409, field="pathKey")
        _, _, path_count, step_count = self.repository.topology_counts(version.id)
        if path_count >= 1_000 or step_count + len(payload.steps) > 20_000:
            raise ExecutionGraphError("CEG_PATH_LIMIT_EXCEEDED", status_code=422)
        self._validate_path_components(
            scope,
            graph,
            version,
            payload.entryNodeId,
            payload.exitNodeId,
            payload.steps,
        )
        path_id = uuid4()
        try:
            with self._topology_trace(
                context, "ceg.path.create", graph.id, version.id, path_id
            ):
                path = CanonicalExecutionGraphPath(
                    id=path_id,
                    path_ref=f"ceg-path://versions/{version.id}/paths/{path_id}",
                    version_id=version.id,
                    graph_id=graph.id,
                    tenant_id=graph.tenant_id,
                    workspace_id=graph.workspace_id,
                    project_id=graph.project_id,
                    scope_id=graph.scope_id,
                    client_key=payload.clientKey,
                    path_key=payload.pathKey,
                    name=payload.name,
                    description=payload.description,
                    entry_node_id=payload.entryNodeId,
                    exit_node_id=payload.exitNodeId,
                    preconditions=[item.model_dump(mode="json") for item in payload.preconditions],
                    postconditions=[item.model_dump(mode="json") for item in payload.postconditions],
                    risk_level=payload.riskLevel,
                    applicability=dict(payload.applicability),
                    evidence_refs=[item.model_dump(mode="json") for item in payload.evidenceRefs],
                    source=payload.source,
                    confidence=Decimal(str(payload.confidence)),
                    request_hash=request_hash,
                    audit_refs=[],
                    trace_id=UUID(context.trace_id),
                    created_by=context.user.id,
                    updated_by=context.user.id,
                )
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.path.create",
                    "canonical_execution_graph_path",
                    path.id,
                    graph,
                    version,
                    {
                        "clientKey": path.client_key,
                        "pathKey": path.path_key,
                        "stepCount": len(payload.steps),
                    },
                )
                path.audit_refs = [audit_ref]
                self.repository.add(path)
                self._add_path_steps(path, version, payload.steps, context, audit_ref)
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(path)
            self.db.refresh(version)
            return self._path_mutation_response(scope, graph, version, path)
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise ExecutionGraphError("CEG_PATH_CONFLICT", status_code=409) from exc

    def update_path(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        path_id: UUID,
        payload: UpdateCanonicalPathRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        self._require_mutable_version(version, payload.versionLockVersion)
        path = self.repository.find_path(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            path_id,
        )
        if path is None:
            raise ExecutionGraphError("CEG_PATH_NOT_FOUND", status_code=404)
        self._require_lock(path.lock_version, payload.lockVersion, "lockVersion")
        next_path_key = payload.pathKey or path.path_key
        path_key_conflict = self.repository.find_path_by_path_key(
            scope.tenant_id, scope.workspace_id, version.id, next_path_key
        )
        if path_key_conflict is not None and path_key_conflict.id != path.id:
            raise ExecutionGraphError("CEG_PATH_KEY_CONFLICT", status_code=409, field="pathKey")
        existing_steps = self.repository.list_steps(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            path_id=path.id,
        )
        next_entry = payload.entryNodeId or path.entry_node_id
        next_exit = payload.exitNodeId or path.exit_node_id
        next_steps = payload.steps if payload.steps is not None else existing_steps
        self._validate_path_components(
            scope, graph, version, next_entry, next_exit, next_steps
        )
        changed_fields = sorted(payload.model_fields_set - {"lockVersion", "versionLockVersion"})
        try:
            with self._topology_trace(
                context, "ceg.path.update", graph.id, version.id, path.id
            ):
                if payload.pathKey is not None:
                    path.path_key = payload.pathKey
                if payload.name is not None:
                    path.name = payload.name
                if "description" in payload.model_fields_set:
                    path.description = payload.description
                path.entry_node_id = next_entry
                path.exit_node_id = next_exit
                if payload.preconditions is not None:
                    path.preconditions = [
                        item.model_dump(mode="json") for item in payload.preconditions
                    ]
                if payload.postconditions is not None:
                    path.postconditions = [
                        item.model_dump(mode="json") for item in payload.postconditions
                    ]
                if payload.riskLevel is not None:
                    path.risk_level = payload.riskLevel
                if payload.applicability is not None:
                    path.applicability = dict(payload.applicability)
                if payload.evidenceRefs is not None:
                    path.evidence_refs = [
                        item.model_dump(mode="json") for item in payload.evidenceRefs
                    ]
                if payload.source is not None:
                    path.source = payload.source
                if payload.confidence is not None:
                    path.confidence = Decimal(str(payload.confidence))
                path.updated_by = context.user.id
                path.trace_id = UUID(context.trace_id)
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.path.update",
                    "canonical_execution_graph_path",
                    path.id,
                    graph,
                    version,
                    {"changedFields": changed_fields, "stepCount": len(next_steps)},
                )
                path.audit_refs = [*path.audit_refs, audit_ref][-128:]
                if payload.steps is not None:
                    for step in existing_steps:
                        self.repository.delete(step)
                    self.repository.flush()
                    self._add_path_steps(path, version, payload.steps, context, audit_ref)
                path.request_hash = canonical_hash(
                    self._path_semantic_payload(path, payload.steps if payload.steps is not None else existing_steps)
                )
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(path)
            self.db.refresh(version)
            return self._path_mutation_response(scope, graph, version, path)
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise ExecutionGraphError("CEG_CONCURRENT_MODIFICATION", status_code=409) from exc

    def delete_path(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        path_id: UUID,
        *,
        lock_version: int,
        version_lock_version: int,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version_for_mutation(
            project_id, graph_id, version_id, context
        )
        self._require_mutable_version(version, version_lock_version)
        path = self.repository.find_path(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            path_id,
        )
        if path is None:
            raise ExecutionGraphError("CEG_PATH_NOT_FOUND", status_code=404)
        self._require_lock(path.lock_version, lock_version, "lockVersion")
        steps = self.repository.list_steps(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            path_id=path.id,
        )
        try:
            with self._topology_trace(
                context, "ceg.path.delete", graph.id, version.id, path.id
            ):
                audit_ref = self._write_topology_audit(
                    context,
                    "ceg.path.delete",
                    "canonical_execution_graph_path",
                    path.id,
                    graph,
                    version,
                    {"pathKey": path.path_key, "stepCount": len(steps)},
                )
                for step in steps:
                    self.repository.delete(step)
                # Flush versioned children before scheduling the parent.  The
                # database FK also cascades path deletion; without this
                # boundary PostgreSQL may delete the parent first and make the
                # ORM's child DELETE report a false optimistic-lock conflict.
                self.repository.flush()
                self.repository.delete(path)
                self.repository.flush()
                self._refresh_version_topology_hash(scope, graph, version, context, audit_ref)
                self.repository.flush()
            self.db.commit()
            self.db.refresh(version)
            return {
                "deleted": True,
                "pathId": str(path_id),
                "version": self._version_projection_summary(scope, graph, version),
            }
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise ExecutionGraphError("CEG_CONCURRENT_MODIFICATION", status_code=409) from exc

    def validate_version(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        payload: ValidateGraphVersionRequest,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope, graph, version = self._load_graph_version(
            project_id, graph_id, version_id, context
        )
        self._require_lock(version.lock_version, payload.lockVersion, "lockVersion")
        nodes, edges, paths, steps = self._topology_records(scope, graph, version)
        topology = build_graph_topology_material(
            nodes=nodes, edges=edges, paths=paths, steps=steps
        )
        topology_hash = build_graph_topology_hash(topology)
        expected_hash = build_graph_version_content_hash(
            graph=graph,
            parent_version_id=version.parent_version_id,
            source=version.source.value,
            source_refs=version.source_refs,
            schema_version=version.schema_version,
            applicability=version.applicability,
            metadata=version.metadata_json,
            topology=topology,
        )
        if expected_hash != version.content_hash:
            raise ExecutionGraphError("CEG_CONTENT_HASH_MISMATCH", status_code=409)
        return ExecutionGraphValidator(self.db).validate(
            version=version,
            nodes=nodes,
            edges=edges,
            paths=paths,
            steps=steps,
            topology_hash=topology_hash,
        )

    def list_graphs(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        page: int = 1,
        page_size: int = 50,
        status: str | None = None,
        environment_id: UUID | None = None,
    ) -> dict[str, Any]:
        scope = self._require_project_scope(project_id, context)
        if status is not None:
            try:
                GraphStatus(status)
            except ValueError as exc:
                raise ExecutionGraphError("CEG_STATUS_INVALID", status_code=422, field="status") from exc
        rows = self.repository.list_graphs(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            status=status,
            scope_type=GraphScope.ENVIRONMENT.value if environment_id else None,
            scope_id=environment_id,
        )
        return paginate([self._identity_projection(row) for row in rows], page, page_size)

    def get_graph(
        self,
        project_id: UUID,
        graph_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_project_scope(project_id, context)
        graph = self.repository.find_graph(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph_id,
        )
        if graph is None:
            raise ExecutionGraphError("CEG_GRAPH_NOT_FOUND", status_code=404)
        versions = self.repository.list_versions(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
        )
        return {
            **self._identity_projection(graph),
            "versions": [self._version_projection(row) for row in versions],
            "versionCount": len(versions),
            "readOnly": True,
            "writesCanonical": False,
        }

    def get_version(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_project_scope(project_id, context)
        graph = self.repository.find_graph(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph_id,
        )
        if graph is None:
            raise ExecutionGraphError("CEG_GRAPH_NOT_FOUND", status_code=404)
        version = self.repository.find_version(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version_id,
        )
        if version is None:
            raise ExecutionGraphError("CEG_VERSION_NOT_FOUND", status_code=404)
        return self._version_contract(graph, version)

    def _load_graph_version(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        context: ServiceContext,
        *,
        for_update: bool = False,
    ) -> tuple[ExecutionGraphScope, CanonicalExecutionGraph, CanonicalExecutionGraphVersion]:
        scope = self._require_project_scope(project_id, context)
        graph = self.repository.find_graph(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph_id,
            for_update=for_update,
        )
        if graph is None:
            raise ExecutionGraphError("CEG_GRAPH_NOT_FOUND", status_code=404)
        version = self.repository.find_version(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version_id,
            for_update=for_update,
        )
        if version is None:
            raise ExecutionGraphError("CEG_VERSION_NOT_FOUND", status_code=404)
        return scope, graph, version

    def _load_graph_version_for_mutation(
        self,
        project_id: UUID,
        graph_id: UUID,
        version_id: UUID,
        context: ServiceContext,
    ) -> tuple[ExecutionGraphScope, CanonicalExecutionGraph, CanonicalExecutionGraphVersion]:
        scope = self._require_project_scope(project_id, context)
        acquire_transaction_advisory_lock(
            self.db,
            "ceg-topology-mutation",
            f"{scope.tenant_id}:{scope.workspace_id}:{graph_id}:{version_id}",
        )
        graph = self.repository.find_graph(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph_id,
            for_update=True,
        )
        if graph is None:
            raise ExecutionGraphError("CEG_GRAPH_NOT_FOUND", status_code=404)
        version = self.repository.find_version(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version_id,
            for_update=True,
        )
        if version is None:
            raise ExecutionGraphError("CEG_VERSION_NOT_FOUND", status_code=404)
        return scope, graph, version

    @staticmethod
    def _require_mutable_version(
        version: CanonicalExecutionGraphVersion,
        expected_lock_version: int,
    ) -> None:
        ExecutionGraphService._require_lock(
            version.lock_version, expected_lock_version, "versionLockVersion"
        )
        if version.is_frozen or version.source == GraphSource.CANONICAL or version.status not in {
            GraphStatus.DRAFT,
            GraphStatus.CANDIDATE,
        }:
            raise ExecutionGraphError("CEG_VERSION_IMMUTABLE", status_code=409)

    @staticmethod
    def _require_lock(actual: int, expected: int, field: str) -> None:
        if actual != expected:
            raise ExecutionGraphError(
                "CEG_LOCK_VERSION_CONFLICT", status_code=409, field=field
            )

    def _topology_records(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
    ) -> tuple[
        list[CanonicalExecutionGraphNode],
        list[CanonicalExecutionGraphEdge],
        list[CanonicalExecutionGraphPath],
        list[CanonicalExecutionGraphPathStep],
    ]:
        return (
            self.repository.list_nodes(
                scope.tenant_id,
                scope.workspace_id,
                scope.project.id,
                graph.id,
                version.id,
            ),
            self.repository.list_edges(
                scope.tenant_id,
                scope.workspace_id,
                scope.project.id,
                graph.id,
                version.id,
            ),
            self.repository.list_paths(
                scope.tenant_id,
                scope.workspace_id,
                scope.project.id,
                graph.id,
                version.id,
            ),
            self.repository.list_steps(
                scope.tenant_id,
                scope.workspace_id,
                scope.project.id,
                graph.id,
                version.id,
            ),
        )

    def _refresh_version_topology_hash(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        context: ServiceContext,
        audit_ref: dict[str, Any],
    ) -> None:
        # The shared Session deliberately disables autoflush. Persist the
        # topology delta before rebuilding the authoritative version hash.
        self.repository.flush()
        nodes, edges, paths, steps = self._topology_records(scope, graph, version)
        topology = build_graph_topology_material(
            nodes=nodes, edges=edges, paths=paths, steps=steps
        )
        version.content_hash = build_graph_version_content_hash(
            graph=graph,
            parent_version_id=version.parent_version_id,
            source=version.source.value,
            source_refs=version.source_refs,
            schema_version=version.schema_version,
            applicability=version.applicability,
            metadata=version.metadata_json,
            topology=topology,
        )
        version.updated_by = context.user.id
        version.trace_id = UUID(context.trace_id)
        version.audit_refs = [*version.audit_refs, audit_ref][-128:]

    def _topology_trace(
        self,
        context: ServiceContext,
        action: str,
        graph_id: UUID,
        version_id: UUID,
        entity_id: UUID,
    ):
        return traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="ceg.structure",
            span_name=action,
            service_name="orchestrator-service",
            attributes={
                "graphId": str(graph_id),
                "versionId": str(version_id),
                "entityId": str(entity_id),
                "writesCanonical": False,
                "executesActions": False,
            },
            parent_span_id=context.parent_span_id,
        )

    def _write_topology_audit(
        self,
        context: ServiceContext,
        action: str,
        resource_type: str,
        resource_id: UUID,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        audit = write_audit_log(
            self.db,
            context.user.id,
            action,
            resource_type,
            str(resource_id),
            context.request_id,
            context.trace_id,
            details={
                "graphId": str(graph.id),
                "versionId": str(version.id),
                "scopeId": str(version.scope_id),
                "createsCanonical": False,
                **details,
            },
        )
        return {"type": "audit", "ref": f"audit://records/{audit.id}", "contentHash": None}

    def _node_mutation_response(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        node: CanonicalExecutionGraphNode,
    ) -> dict[str, Any]:
        return {
            "node": self._node_projection(node),
            "version": self._version_projection_summary(scope, graph, version),
        }

    def _edge_mutation_response(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        edge: CanonicalExecutionGraphEdge,
    ) -> dict[str, Any]:
        return {
            "edge": self._edge_projection(edge),
            "version": self._version_projection_summary(scope, graph, version),
        }

    def _path_mutation_response(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        path: CanonicalExecutionGraphPath,
    ) -> dict[str, Any]:
        steps = self.repository.list_steps(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            path_id=path.id,
        )
        return {
            "path": self._path_projection(path, steps),
            "version": self._version_projection_summary(scope, graph, version),
        }

    def _version_projection_summary(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
    ) -> dict[str, Any]:
        nodes, edges, paths, steps = self._topology_records(scope, graph, version)
        topology = build_graph_topology_material(
            nodes=nodes, edges=edges, paths=paths, steps=steps
        )
        return {
            "versionId": str(version.id),
            "graphId": str(graph.id),
            "version": version.version_number,
            "status": version.status.value,
            "source": version.source.value,
            "editable": (
                not version.is_frozen
                and version.source != GraphSource.CANONICAL
                and version.status in {GraphStatus.DRAFT, GraphStatus.CANDIDATE}
            ),
            "canonical": version.source == GraphSource.CANONICAL,
            "frozen": version.is_frozen,
            "lockVersion": version.lock_version,
            "contentHash": version.content_hash,
            "topologyHash": build_graph_topology_hash(topology),
            "nodeCount": len(nodes),
            "edgeCount": len(edges),
            "pathCount": len(paths),
            "stepCount": len(steps),
            "versionRef": version.version_ref,
            "writesGate": False,
            "writesMemory": False,
            "executesActions": False,
        }

    @staticmethod
    def _node_projection(node: CanonicalExecutionGraphNode) -> dict[str, Any]:
        return {
            "nodeId": str(node.id),
            "nodeRef": node.node_ref,
            "versionId": str(node.version_id),
            "clientKey": node.client_key,
            "semanticKey": node.semantic_key,
            "nodeType": node.node_type,
            "display": node.display_metadata,
            "attributes": node.attributes_json,
            "externalRefs": node.external_refs,
            "riskLevel": node.risk_level,
            "source": node.source,
            "confidence": float(node.confidence),
            "lockVersion": node.lock_version,
            "audit": ExecutionGraphService._audit_projection(node),
        }

    @staticmethod
    def _edge_projection(edge: CanonicalExecutionGraphEdge) -> dict[str, Any]:
        return {
            "edgeId": str(edge.id),
            "edgeRef": edge.edge_ref,
            "versionId": str(edge.version_id),
            "clientKey": edge.client_key,
            "edgeType": edge.edge_type,
            "sourceNodeId": str(edge.source_node_id),
            "targetNodeId": str(edge.target_node_id),
            "condition": edge.condition_json or None,
            "riskLevel": edge.risk_level,
            "reviewStatus": edge.review_status,
            "source": edge.source,
            "confidence": float(edge.confidence),
            "lockVersion": edge.lock_version,
            "audit": ExecutionGraphService._audit_projection(edge),
        }

    @staticmethod
    def _step_projection(step: CanonicalExecutionGraphPathStep) -> dict[str, Any]:
        return {
            "stepId": str(step.id),
            "stepRef": step.step_ref,
            "pathId": str(step.path_id),
            "versionId": str(step.version_id),
            "clientKey": step.client_key,
            "order": step.step_order,
            "nodeId": str(step.node_id),
            "viaEdgeId": str(step.via_edge_id) if step.via_edge_id else None,
            "conditions": step.conditions,
            "evidenceRefs": step.evidence_refs,
            "lockVersion": step.lock_version,
            "audit": ExecutionGraphService._audit_projection(step),
        }

    @staticmethod
    def _path_projection(
        path: CanonicalExecutionGraphPath,
        steps: list[CanonicalExecutionGraphPathStep],
    ) -> dict[str, Any]:
        return {
            "pathId": str(path.id),
            "pathRef": path.path_ref,
            "versionId": str(path.version_id),
            "clientKey": path.client_key,
            "pathKey": path.path_key,
            "name": path.name,
            "description": path.description,
            "entryNodeId": str(path.entry_node_id),
            "exitNodeId": str(path.exit_node_id),
            "preconditions": path.preconditions,
            "postconditions": path.postconditions,
            "riskLevel": path.risk_level,
            "applicability": path.applicability,
            "evidenceRefs": path.evidence_refs,
            "source": path.source,
            "confidence": float(path.confidence),
            "steps": [ExecutionGraphService._step_projection(item) for item in steps],
            "lockVersion": path.lock_version,
            "audit": ExecutionGraphService._audit_projection(path),
        }

    @staticmethod
    def _node_semantic_payload(node: CanonicalExecutionGraphNode) -> dict[str, Any]:
        return {
            "clientKey": node.client_key,
            "semanticKey": node.semantic_key,
            "nodeType": node.node_type,
            "display": node.display_metadata,
            "attributes": node.attributes_json,
            "externalRefs": node.external_refs,
            "riskLevel": node.risk_level,
            "source": node.source,
            "confidence": float(node.confidence),
        }

    @staticmethod
    def _edge_semantic_payload(edge: CanonicalExecutionGraphEdge) -> dict[str, Any]:
        return {
            "clientKey": edge.client_key,
            "edgeType": edge.edge_type,
            "sourceNodeId": str(edge.source_node_id),
            "targetNodeId": str(edge.target_node_id),
            "condition": edge.condition_json,
            "riskLevel": edge.risk_level,
            "source": edge.source,
            "confidence": float(edge.confidence),
        }

    @staticmethod
    def _path_semantic_payload(
        path: CanonicalExecutionGraphPath,
        steps: list[Any],
    ) -> dict[str, Any]:
        return {
            "clientKey": path.client_key,
            "pathKey": path.path_key,
            "name": path.name,
            "description": path.description,
            "entryNodeId": str(path.entry_node_id),
            "exitNodeId": str(path.exit_node_id),
            "preconditions": path.preconditions,
            "postconditions": path.postconditions,
            "riskLevel": path.risk_level,
            "applicability": path.applicability,
            "evidenceRefs": path.evidence_refs,
            "source": path.source,
            "confidence": float(path.confidence),
            "steps": [ExecutionGraphService._step_semantic_payload(item) for item in steps],
        }

    @staticmethod
    def _step_semantic_payload(step: Any) -> dict[str, Any]:
        conditions = getattr(step, "conditions", [])
        evidence_refs = getattr(step, "evidenceRefs", None)
        if evidence_refs is None:
            evidence_refs = getattr(step, "evidence_refs", [])
        return {
            "clientKey": getattr(step, "clientKey", getattr(step, "client_key", None)),
            "order": getattr(step, "order", getattr(step, "step_order", None)),
            "nodeId": str(getattr(step, "nodeId", getattr(step, "node_id", None))),
            "viaEdgeId": (
                str(getattr(step, "viaEdgeId", getattr(step, "via_edge_id", None)))
                if getattr(step, "viaEdgeId", getattr(step, "via_edge_id", None))
                else None
            ),
            "conditions": [
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                for item in conditions
            ],
            "evidenceRefs": [
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                for item in evidence_refs
            ],
        }

    @staticmethod
    def _edge_semantic_hash(
        edge_type: str,
        source_semantic_key: str,
        target_semantic_key: str,
        condition: dict[str, Any] | None,
    ) -> str:
        return canonical_hash(
            {
                "edgeType": edge_type,
                "sourceSemanticKey": source_semantic_key,
                "targetSemanticKey": target_semantic_key,
                "condition": condition,
            }
        )

    def _require_edge_nodes(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        source_node_id: UUID,
        target_node_id: UUID,
    ) -> tuple[CanonicalExecutionGraphNode, CanonicalExecutionGraphNode]:
        if source_node_id == target_node_id:
            raise ExecutionGraphError("CEG_EDGE_SELF_LOOP", status_code=422, field="targetNodeId")
        source = self.repository.find_node(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            source_node_id,
        )
        target = self.repository.find_node(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            version.id,
            target_node_id,
        )
        if source is None:
            raise ExecutionGraphError("CEG_EDGE_SOURCE_NOT_FOUND", status_code=422, field="sourceNodeId")
        if target is None:
            raise ExecutionGraphError("CEG_EDGE_TARGET_NOT_FOUND", status_code=422, field="targetNodeId")
        return source, target

    @staticmethod
    def _require_edge_relation(edge_type: str, source_type: str, target_type: str) -> None:
        if not edge_pair_allowed(edge_type, source_type, target_type):
            raise ExecutionGraphError(
                "CEG_EDGE_RELATION_NOT_ALLOWED", status_code=422, field="edgeType"
            )

    def _validate_path_components(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
        entry_node_id: UUID,
        exit_node_id: UUID,
        steps: list[Any],
    ) -> None:
        normalized = [self._step_semantic_payload(item) for item in steps]
        if not normalized:
            raise ExecutionGraphError("CEG_PATH_STEPS_REQUIRED", status_code=422, field="steps")
        orders = [int(item["order"]) for item in normalized]
        if orders != list(range(1, len(normalized) + 1)):
            raise ExecutionGraphError("CEG_PATH_ORDER_INVALID", status_code=422, field="steps")
        if UUID(normalized[0]["nodeId"]) != entry_node_id:
            raise ExecutionGraphError("CEG_PATH_ENTRY_MISMATCH", status_code=422, field="entryNodeId")
        if UUID(normalized[-1]["nodeId"]) != exit_node_id:
            raise ExecutionGraphError("CEG_PATH_EXIT_MISMATCH", status_code=422, field="exitNodeId")
        node_ids = [UUID(item["nodeId"]) for item in normalized]
        node_map: dict[UUID, CanonicalExecutionGraphNode] = {}
        for node_id in set(node_ids):
            node = self.repository.find_node(
                scope.tenant_id,
                scope.workspace_id,
                scope.project.id,
                graph.id,
                version.id,
                node_id,
            )
            if node is None:
                raise ExecutionGraphError("CEG_PATH_STEP_NODE_NOT_FOUND", status_code=422, field="steps")
            node_map[node_id] = node
        if normalized[0]["viaEdgeId"] is not None:
            raise ExecutionGraphError("CEG_PATH_DISCONNECTED", status_code=422, field="steps")
        for index, item in enumerate(normalized[1:], start=1):
            if item["viaEdgeId"] is None:
                raise ExecutionGraphError("CEG_PATH_DISCONNECTED", status_code=422, field="steps")
            edge = self.repository.find_edge(
                scope.tenant_id,
                scope.workspace_id,
                scope.project.id,
                graph.id,
                version.id,
                UUID(item["viaEdgeId"]),
            )
            if (
                edge is None
                or edge.source_node_id != node_ids[index - 1]
                or edge.target_node_id != node_ids[index]
            ):
                raise ExecutionGraphError("CEG_PATH_DISCONNECTED", status_code=422, field="steps")

    def _add_path_steps(
        self,
        path: CanonicalExecutionGraphPath,
        version: CanonicalExecutionGraphVersion,
        steps: list[Any],
        context: ServiceContext,
        audit_ref: dict[str, Any],
    ) -> None:
        for item in steps:
            material = self._step_semantic_payload(item)
            step_id = uuid4()
            self.repository.add(
                CanonicalExecutionGraphPathStep(
                    id=step_id,
                    step_ref=f"ceg-step://versions/{version.id}/paths/{path.id}/steps/{step_id}",
                    path_id=path.id,
                    version_id=version.id,
                    graph_id=version.graph_id,
                    tenant_id=version.tenant_id,
                    workspace_id=version.workspace_id,
                    project_id=version.project_id,
                    scope_id=version.scope_id,
                    client_key=material["clientKey"],
                    step_order=material["order"],
                    node_id=UUID(material["nodeId"]),
                    via_edge_id=UUID(material["viaEdgeId"]) if material["viaEdgeId"] else None,
                    conditions=material["conditions"],
                    evidence_refs=material["evidenceRefs"],
                    audit_refs=[audit_ref],
                    trace_id=UUID(context.trace_id),
                    created_by=context.user.id,
                    updated_by=context.user.id,
                )
            )

    def _validate_parent(
        self,
        scope: ExecutionGraphScope,
        graph: CanonicalExecutionGraph,
        parent_version_id: UUID | None,
        current_version: int,
    ) -> CanonicalExecutionGraphVersion | None:
        if current_version == 0:
            if parent_version_id is not None:
                raise ExecutionGraphError("CEG_FIRST_VERSION_PARENT_FORBIDDEN", status_code=409)
            return None
        if parent_version_id is None:
            raise ExecutionGraphError("CEG_PARENT_VERSION_REQUIRED", status_code=422, field="parentVersionId")
        parent = self.repository.find_version(
            scope.tenant_id,
            scope.workspace_id,
            scope.project.id,
            graph.id,
            parent_version_id,
        )
        if parent is None:
            raise ExecutionGraphError("CEG_PARENT_VERSION_NOT_FOUND", status_code=404)
        return parent

    def _require_project_scope(
        self,
        project_id: UUID,
        context: ServiceContext,
    ) -> ExecutionGraphScope:
        try:
            scope = ScopeAuthorizationService(self.db).resolve_project(project_id, context)
        except ScopeAuthorizationError as exc:
            code = "CEG_SCOPE_INVALID" if exc.status_code == 409 else "CEG_PROJECT_NOT_FOUND"
            raise ExecutionGraphError(code, status_code=exc.status_code, field=exc.field) from exc
        return ExecutionGraphScope(scope.project, scope.tenant_id, scope.workspace_id)

    def _resolve_environment_scope(
        self,
        project: Project,
        environment_id: UUID | None,
    ) -> tuple[ProjectEnvironment | None, GraphScope, UUID]:
        if environment_id is None:
            return None, GraphScope.PROJECT, project.id
        environment = self.db.scalar(
            select(ProjectEnvironment).where(
                ProjectEnvironment.id == environment_id,
                ProjectEnvironment.project_id == project.id,
            )
        )
        if environment is None:
            raise ExecutionGraphError("CEG_ENVIRONMENT_NOT_FOUND", status_code=404)
        return environment, GraphScope.ENVIRONMENT, environment.id

    def _version_contract(
        self,
        graph: CanonicalExecutionGraph,
        version: CanonicalExecutionGraphVersion,
    ) -> dict[str, Any]:
        project = self.db.get(Project, graph.project_id)
        if project is None:
            raise ExecutionGraphError("CEG_PROJECT_NOT_FOUND", status_code=404)
        scope = ExecutionGraphScope(project, graph.tenant_id, graph.workspace_id)
        nodes, edges, paths, steps = self._topology_records(scope, graph, version)
        topology_material = build_graph_topology_material(
            nodes=nodes, edges=edges, paths=paths, steps=steps
        )
        expected_hash = build_graph_version_content_hash(
            graph=graph,
            parent_version_id=version.parent_version_id,
            source=version.source.value,
            source_refs=version.source_refs,
            schema_version=version.schema_version,
            applicability=version.applicability,
            metadata=version.metadata_json,
            topology=topology_material,
        )
        if expected_hash != version.content_hash:
            raise ExecutionGraphError("CEG_CONTENT_HASH_MISMATCH", status_code=409)
        steps_by_path: dict[UUID, list[CanonicalExecutionGraphPathStep]] = {}
        for step in steps:
            steps_by_path.setdefault(step.path_id, []).append(step)
        payload = {
            "schemaVersion": CEG_SCHEMA_VERSION,
            "identity": self._identity_projection(graph),
            "version": self._version_projection(version),
            "topology": {
                "nodes": [self._node_projection(item) for item in nodes],
                "edges": [self._edge_projection(item) for item in edges],
                "canonicalPaths": [
                    self._path_projection(path, steps_by_path.get(path.id, []))
                    for path in paths
                ],
            },
            "projection": self._version_projection_summary(scope, graph, version),
        }
        return CanonicalExecutionGraphContract.model_validate(payload).model_dump(mode="json")

    @staticmethod
    def _identity_projection(graph: CanonicalExecutionGraph) -> dict[str, Any]:
        return {
            "graphId": str(graph.id),
            "graphRef": graph.graph_ref,
            "graphKey": graph.graph_key,
            "name": graph.name,
            "description": graph.description,
            "status": graph.status.value,
            "scope": ExecutionGraphService._scope_projection(graph),
            "retention": ExecutionGraphService._retention_projection(graph),
            "lockVersion": graph.lock_version,
            "audit": ExecutionGraphService._audit_projection(graph),
            "metadata": graph.metadata_json,
        }

    @staticmethod
    def _version_projection(version: CanonicalExecutionGraphVersion) -> dict[str, Any]:
        return {
            "versionId": str(version.id),
            "versionRef": version.version_ref,
            "graphId": str(version.graph_id),
            "version": version.version_number,
            "parentVersionId": str(version.parent_version_id) if version.parent_version_id else None,
            "status": version.status.value,
            "scope": ExecutionGraphService._scope_projection(version),
            "source": {"level": version.source.value, "refs": version.source_refs},
            "schemaVersion": version.schema_version,
            "contentHash": version.content_hash,
            "applicability": version.applicability,
            "frozen": version.is_frozen,
            "frozenAt": version.frozen_at.isoformat() if version.frozen_at else None,
            "frozenBy": str(version.frozen_by) if version.frozen_by else None,
            "retention": ExecutionGraphService._retention_projection(version),
            "lockVersion": version.lock_version,
            "audit": ExecutionGraphService._audit_projection(version),
            "metadata": version.metadata_json,
        }

    @staticmethod
    def _scope_projection(record: CanonicalExecutionGraph | CanonicalExecutionGraphVersion) -> dict[str, Any]:
        return {
            "type": record.scope_type.value,
            "tenantId": record.tenant_id,
            "workspaceId": record.workspace_id,
            "projectId": str(record.project_id),
            "environmentId": str(record.environment_id) if record.environment_id else None,
            "scopeId": str(record.scope_id),
        }

    @staticmethod
    def _retention_projection(record: CanonicalExecutionGraph | CanonicalExecutionGraphVersion) -> dict[str, Any]:
        return {
            "policy": record.retention_policy,
            "until": record.retention_until.isoformat() if record.retention_until else None,
            "status": record.retention_status,
            "legalHold": record.legal_hold,
        }

    @staticmethod
    def _audit_projection(
        record: CanonicalExecutionGraph
        | CanonicalExecutionGraphVersion
        | CanonicalExecutionGraphNode
        | CanonicalExecutionGraphEdge
        | CanonicalExecutionGraphPath
        | CanonicalExecutionGraphPathStep,
    ) -> dict[str, Any]:
        return {
            "createdBy": str(record.created_by) if record.created_by else None,
            "updatedBy": str(record.updated_by) if record.updated_by else None,
            "traceId": str(record.trace_id) if record.trace_id else None,
            "auditRefs": record.audit_refs,
            "createdAt": record.created_at.isoformat(),
            "updatedAt": record.updated_at.isoformat(),
        }

    @staticmethod
    def _normalized_source_refs(payload: CreateGraphVersionRequest) -> list[dict[str, Any]]:
        source = GraphSourceContract(level=payload.source, refs=payload.sourceRefs)
        refs = [item.model_dump(mode="json") for item in source.refs]
        return sorted(refs, key=lambda item: (str(item["type"]), str(item["ref"]), str(item.get("contentHash") or "")))

    @staticmethod
    def _idempotency_key(value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 255:
            raise ExecutionGraphError("CEG_IDEMPOTENCY_KEY_INVALID", status_code=422, field="idempotencyKey")
        return normalized

    @staticmethod
    def _require_same_request(actual_hash: str, expected_hash: str) -> None:
        if actual_hash != expected_hash:
            raise ExecutionGraphError("CEG_IDEMPOTENCY_CONFLICT", status_code=409, field="idempotencyKey")
__all__ = [
    "ExecutionGraphError",
    "ExecutionGraphRepository",
    "ExecutionGraphService",
    "build_graph_version_content_hash",
]

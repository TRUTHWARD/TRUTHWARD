# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any, Iterable
from uuid import UUID

from agentic_qa.domain.models import (
    CanonicalExecutionGraph,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
)
from agentic_qa.services.common import canonical_hash


EMPTY_GRAPH_TOPOLOGY: dict[str, list[dict[str, Any]]] = {
    "nodes": [],
    "edges": [],
    "canonicalPaths": [],
}


def _sorted_refs(refs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        (dict(item) for item in refs),
        key=lambda item: (
            str(item.get("type") or ""),
            str(item.get("ref") or ""),
            str(item.get("contentHash") or ""),
        ),
    )


def build_graph_topology_material(
    *,
    nodes: list[CanonicalExecutionGraphNode],
    edges: list[CanonicalExecutionGraphEdge],
    paths: list[CanonicalExecutionGraphPath],
    steps: list[CanonicalExecutionGraphPathStep],
) -> dict[str, list[dict[str, Any]]]:
    """Return UUID-independent semantic topology material for stable hashing."""

    node_keys = {item.id: item.semantic_key for item in nodes}
    edge_keys = {item.id: item.client_key for item in edges}
    steps_by_path: dict[UUID, list[CanonicalExecutionGraphPathStep]] = {}
    for step in steps:
        steps_by_path.setdefault(step.path_id, []).append(step)

    node_material = [
        {
            "clientKey": item.client_key,
            "semanticKey": item.semantic_key,
            "nodeType": item.node_type,
            "display": item.display_metadata,
            "attributes": item.attributes_json,
            "externalRefs": _sorted_refs(item.external_refs),
            "riskLevel": item.risk_level,
            "source": item.source,
            "confidence": float(item.confidence),
        }
        for item in nodes
    ]
    node_material.sort(key=lambda item: (item["semanticKey"], item["clientKey"]))

    edge_material = [
        {
            "clientKey": item.client_key,
            "edgeType": item.edge_type,
            "sourceSemanticKey": node_keys.get(
                item.source_node_id, f"missing:{item.source_node_id}"
            ),
            "targetSemanticKey": node_keys.get(
                item.target_node_id, f"missing:{item.target_node_id}"
            ),
            "condition": item.condition_json,
            "riskLevel": item.risk_level,
            "reviewStatus": item.review_status,
            "source": item.source,
            "confidence": float(item.confidence),
        }
        for item in edges
    ]
    edge_material.sort(key=lambda item: str(item["clientKey"]))

    path_material: list[dict[str, Any]] = []
    for path in paths:
        path_steps = sorted(steps_by_path.get(path.id, []), key=lambda item: item.step_order)
        path_material.append(
            {
                "clientKey": path.client_key,
                "pathKey": path.path_key,
                "name": path.name,
                "description": path.description,
                "entrySemanticKey": node_keys.get(
                    path.entry_node_id, f"missing:{path.entry_node_id}"
                ),
                "exitSemanticKey": node_keys.get(path.exit_node_id, f"missing:{path.exit_node_id}"),
                "preconditions": path.preconditions,
                "postconditions": path.postconditions,
                "riskLevel": path.risk_level,
                "applicability": path.applicability,
                "evidenceRefs": _sorted_refs(path.evidence_refs),
                "source": path.source,
                "confidence": float(path.confidence),
                "steps": [
                    {
                        "clientKey": step.client_key,
                        "order": step.step_order,
                        "nodeSemanticKey": node_keys.get(step.node_id, f"missing:{step.node_id}"),
                        "viaEdgeClientKey": edge_keys.get(step.via_edge_id)
                        if step.via_edge_id
                        else None,
                        "conditions": step.conditions,
                        "evidenceRefs": _sorted_refs(step.evidence_refs),
                    }
                    for step in path_steps
                ],
            }
        )
    path_material.sort(key=lambda item: (item["pathKey"], item["clientKey"]))
    return {
        "nodes": node_material,
        "edges": edge_material,
        "canonicalPaths": path_material,
    }


def build_graph_topology_hash(topology: dict[str, Any] | None = None) -> str:
    return canonical_hash(topology or EMPTY_GRAPH_TOPOLOGY)


def build_graph_version_content_hash(
    *,
    graph: CanonicalExecutionGraph,
    parent_version_id: UUID | None,
    source: str,
    source_refs: list[dict[str, Any]],
    schema_version: str,
    applicability: dict[str, Any],
    metadata: dict[str, Any],
    topology: dict[str, Any] | None = None,
) -> str:
    """Hash semantic CEG version content, excluding status/audit/lock/retention and UUIDs."""

    normalized_refs = _sorted_refs(source_refs)
    normalized_topology = topology or EMPTY_GRAPH_TOPOLOGY
    return canonical_hash(
        {
            "schemaVersion": schema_version,
            "scope": {
                "tenantId": graph.tenant_id,
                "workspaceId": graph.workspace_id,
                "projectId": str(graph.project_id),
                "environmentId": str(graph.environment_id) if graph.environment_id else None,
                "scopeType": graph.scope_type.value,
                "scopeId": str(graph.scope_id),
            },
            "parentVersionId": str(parent_version_id) if parent_version_id else None,
            "source": source,
            "sourceRefs": normalized_refs,
            "applicability": applicability,
            "metadata": metadata,
            "topologyContract": "ceg.topology.v1",
            "topology": normalized_topology,
        }
    )


__all__ = [
    "EMPTY_GRAPH_TOPOLOGY",
    "build_graph_topology_hash",
    "build_graph_topology_material",
    "build_graph_version_content_hash",
]

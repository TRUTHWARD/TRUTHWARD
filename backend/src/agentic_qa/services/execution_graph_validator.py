# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Iterable
from uuid import UUID

from sqlalchemy.orm import Session

from agentic_qa.domain.models import (
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphPath,
    CanonicalExecutionGraphPathStep,
    CanonicalExecutionGraphVersion,
    ExecutionArtifact,
    RequirementVersion,
    TestAsset,
)
from agentic_qa.schemas.execution_graph import (
    MAX_CEG_EDGES,
    MAX_CEG_NODES,
    MAX_CEG_PATHS,
    MAX_CEG_PATH_STEPS,
    GraphValidationResultContract,
)
from agentic_qa.services.execution_graph_hash import build_graph_topology_hash


GRAPH_NODE_TYPES = frozenset(
    {
        "requirement",
        "capability",
        "page",
        "component",
        "element",
        "action",
        "assertion",
        "data",
        "api",
        "code",
        "test",
        "evidence",
    }
)
_STRUCTURAL = frozenset({"requirement", "capability", "page", "component", "test"})
_EXECUTABLE = frozenset({"action", "assertion", "data", "api", "test"})
_NON_EVIDENCE = GRAPH_NODE_TYPES - {"evidence"}

EDGE_RELATION_REGISTRY: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "contains": (
        _STRUCTURAL,
        frozenset(
            {
                "capability",
                "page",
                "component",
                "element",
                "action",
                "assertion",
                "data",
                "api",
                "test",
            }
        ),
    ),
    "precedes": (_EXECUTABLE, _EXECUTABLE),
    "transitions_to": (frozenset({"page", "action", "api"}), frozenset({"page", "action", "api"})),
    "depends_on": (_NON_EVIDENCE, _NON_EVIDENCE),
    "implements": (
        frozenset({"component", "api", "code", "test"}),
        frozenset({"requirement", "capability"}),
    ),
    "verifies": (frozenset({"assertion", "test", "evidence"}), _NON_EVIDENCE),
    "produces": (frozenset({"action", "api", "code", "test"}), frozenset({"data", "evidence"})),
    "evidenced_by": (_NON_EVIDENCE, frozenset({"evidence"})),
    "changes": (frozenset({"action", "api", "code"}), _NON_EVIDENCE),
    "affects": (_NON_EVIDENCE, GRAPH_NODE_TYPES),
}

FORBIDDEN_CYCLE_EDGE_TYPES = frozenset({"contains", "precedes"})
DIAGNOSTIC_CYCLE_EDGE_TYPES = frozenset({"depends_on"})
ALLOWED_CYCLE_EDGE_TYPES = frozenset({"transitions_to", "affects"})
HIGH_RISK_EDGE_TYPES = frozenset({"changes", "affects"})


def edge_pair_allowed(edge_type: str, source_type: str, target_type: str) -> bool:
    relation = EDGE_RELATION_REGISTRY.get(edge_type)
    return bool(relation and source_type in relation[0] and target_type in relation[1])


def edge_requires_review(edge_type: str, risk_level: str) -> bool:
    return risk_level == "high" or edge_type in HIGH_RISK_EDGE_TYPES


def graph_has_cycle(edges: Iterable[tuple[UUID, UUID]]) -> bool:
    adjacency: dict[UUID, list[UUID]] = defaultdict(list)
    vertices: set[UUID] = set()
    for source_id, target_id in edges:
        adjacency[source_id].append(target_id)
        vertices.update((source_id, target_id))
    # Use an explicit DFS stack so validation remains safe at the supported
    # graph limits instead of depending on Python's recursion depth.
    state: dict[UUID, int] = {}
    for start in vertices:
        if state.get(start, 0) != 0:
            continue
        state[start] = 1
        stack: list[tuple[UUID, int]] = [(start, 0)]
        while stack:
            node_id, next_index = stack[-1]
            targets = adjacency.get(node_id, ())
            if next_index >= len(targets):
                state[node_id] = 2
                stack.pop()
                continue
            target_id = targets[next_index]
            stack[-1] = (node_id, next_index + 1)
            target_state = state.get(target_id, 0)
            if target_state == 1:
                return True
            if target_state == 0:
                state[target_id] = 1
                stack.append((target_id, 0))
    return False


def would_create_forbidden_cycle(
    existing: Iterable[CanonicalExecutionGraphEdge],
    *,
    edge_type: str,
    source_node_id: UUID,
    target_node_id: UUID,
    exclude_edge_id: UUID | None = None,
) -> bool:
    if edge_type not in FORBIDDEN_CYCLE_EDGE_TYPES:
        return False
    pairs = [
        (item.source_node_id, item.target_node_id)
        for item in existing
        if item.edge_type == edge_type and item.id != exclude_edge_id
    ]
    pairs.append((source_node_id, target_node_id))
    return graph_has_cycle(pairs)


class ExecutionGraphValidator:
    """Pure topology diagnostics plus bounded authoritative-ref existence checks."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def validate(
        self,
        *,
        version: CanonicalExecutionGraphVersion,
        nodes: list[CanonicalExecutionGraphNode],
        edges: list[CanonicalExecutionGraphEdge],
        paths: list[CanonicalExecutionGraphPath],
        steps: list[CanonicalExecutionGraphPathStep],
        topology_hash: str | None = None,
    ) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        node_by_id = {item.id: item for item in nodes}
        edge_by_id = {item.id: item for item in edges}
        steps_by_path: dict[UUID, list[CanonicalExecutionGraphPathStep]] = defaultdict(list)
        for step in steps:
            steps_by_path[step.path_id].append(step)

        self._validate_size(nodes, edges, paths, steps, issues)
        self._validate_nodes(nodes, edges, paths, steps, issues)
        self._validate_edges(edges, node_by_id, issues)
        self._validate_cycles(edges, issues)
        self._validate_paths(paths, steps_by_path, node_by_id, edge_by_id, issues)

        error_count = sum(item["severity"] == "error" for item in issues)
        warning_count = sum(item["severity"] == "warning" for item in issues)
        info_count = sum(item["severity"] == "info" for item in issues)
        review_count = sum(bool(item["reviewRequired"]) for item in issues)
        result = {
            "schemaVersion": "ceg.validation.v1",
            "versionId": str(version.id),
            "contentHash": version.content_hash,
            "topologyHash": topology_hash or build_graph_topology_hash(),
            "summary": {
                "valid": error_count == 0,
                "errorCount": error_count,
                "warningCount": warning_count,
                "infoCount": info_count,
                "reviewPendingCount": review_count,
            },
            "issues": issues,
        }
        return GraphValidationResultContract.model_validate(result).model_dump(mode="json")

    @staticmethod
    def _issue(
        issues: list[dict[str, Any]],
        code: str,
        severity: str,
        entity_type: str,
        entity_id: UUID | None,
        field: str | None,
        message_key: str,
        *,
        review_required: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        issues.append(
            {
                "code": code,
                "severity": severity,
                "entityType": entity_type,
                "entityId": str(entity_id) if entity_id else None,
                "field": field,
                "messageKey": message_key,
                "blocking": severity == "error",
                "reviewRequired": review_required,
                "details": details or {},
            }
        )

    def _validate_size(
        self,
        nodes: list[CanonicalExecutionGraphNode],
        edges: list[CanonicalExecutionGraphEdge],
        paths: list[CanonicalExecutionGraphPath],
        steps: list[CanonicalExecutionGraphPathStep],
        issues: list[dict[str, Any]],
    ) -> None:
        for count, limit, field in (
            (len(nodes), MAX_CEG_NODES, "nodes"),
            (len(edges), MAX_CEG_EDGES, "edges"),
            (len(paths), MAX_CEG_PATHS, "canonicalPaths"),
            (len(steps), MAX_CEG_PATH_STEPS, "pathSteps"),
        ):
            if count > limit:
                self._issue(
                    issues,
                    "CEG_GRAPH_SIZE_LIMIT_EXCEEDED",
                    "error",
                    "version",
                    None,
                    field,
                    "ceg.validation.graph.size_limit_exceeded",
                    details={"count": count, "limit": limit},
                )

    def _validate_nodes(
        self,
        nodes: list[CanonicalExecutionGraphNode],
        edges: list[CanonicalExecutionGraphEdge],
        paths: list[CanonicalExecutionGraphPath],
        steps: list[CanonicalExecutionGraphPathStep],
        issues: list[dict[str, Any]],
    ) -> None:
        semantic_keys: set[str] = set()
        referenced = {
            *(item.source_node_id for item in edges),
            *(item.target_node_id for item in edges),
            *(item.entry_node_id for item in paths),
            *(item.exit_node_id for item in paths),
            *(item.node_id for item in steps),
        }
        for node in nodes:
            if node.semantic_key in semantic_keys:
                self._issue(
                    issues,
                    "CEG_DUPLICATE_SEMANTIC_KEY",
                    "error",
                    "node",
                    node.id,
                    "semanticKey",
                    "ceg.validation.node.duplicate_semantic_key",
                    details={"semanticKey": node.semantic_key},
                )
            semantic_keys.add(node.semantic_key)
            if node.id not in referenced:
                self._issue(
                    issues,
                    "CEG_ISOLATED_NODE",
                    "warning",
                    "node",
                    node.id,
                    None,
                    "ceg.validation.node.isolated",
                    details={"semanticKey": node.semantic_key},
                )
            for external_ref in node.external_refs:
                self._validate_external_ref(node, external_ref, issues)

    def _validate_external_ref(
        self,
        node: CanonicalExecutionGraphNode,
        external_ref: dict[str, Any],
        issues: list[dict[str, Any]],
    ) -> None:
        ref_type = str(external_ref.get("type") or "")
        ref = str(external_ref.get("ref") or "")
        patterns: dict[str, tuple[re.Pattern[str], type]] = {
            "requirement": (
                re.compile(r"^requirement://versions/([0-9a-fA-F-]{36})$"),
                RequirementVersion,
            ),
            "test": (re.compile(r"^test://assets/([0-9a-fA-F-]{36})$"), TestAsset),
            "evidence": (
                re.compile(r"^evidence://artifacts/([0-9a-fA-F-]{36})$"),
                ExecutionArtifact,
            ),
            "artifact": (
                re.compile(r"^artifact://execution/([0-9a-fA-F-]{36})$"),
                ExecutionArtifact,
            ),
        }
        definition = patterns.get(ref_type)
        if definition is None:
            return
        match = definition[0].match(ref)
        if match is None:
            return
        try:
            record_id = UUID(match.group(1))
        except ValueError:
            record_id = None
        if record_id is None or self.db.get(definition[1], record_id) is None:
            self._issue(
                issues,
                "CEG_EXTERNAL_REF_NOT_FOUND",
                "error",
                "external_ref",
                node.id,
                "externalRefs",
                "ceg.validation.external_ref.not_found",
                details={"refType": ref_type, "ref": ref},
            )

    def _validate_edges(
        self,
        edges: list[CanonicalExecutionGraphEdge],
        node_by_id: dict[UUID, CanonicalExecutionGraphNode],
        issues: list[dict[str, Any]],
    ) -> None:
        for edge in edges:
            source = node_by_id.get(edge.source_node_id)
            target = node_by_id.get(edge.target_node_id)
            if source is None or target is None:
                self._issue(
                    issues,
                    "CEG_EDGE_ENDPOINT_NOT_FOUND",
                    "error",
                    "edge",
                    edge.id,
                    "sourceNodeId" if source is None else "targetNodeId",
                    "ceg.validation.edge.endpoint_not_found",
                )
                continue
            if source.id == target.id:
                self._issue(
                    issues,
                    "CEG_EDGE_SELF_LOOP",
                    "error",
                    "edge",
                    edge.id,
                    "targetNodeId",
                    "ceg.validation.edge.self_loop",
                )
            if not edge_pair_allowed(edge.edge_type, source.node_type, target.node_type):
                self._issue(
                    issues,
                    "CEG_EDGE_RELATION_NOT_ALLOWED",
                    "error",
                    "edge",
                    edge.id,
                    "edgeType",
                    "ceg.validation.edge.relation_not_allowed",
                    details={
                        "edgeType": edge.edge_type,
                        "sourceType": source.node_type,
                        "targetType": target.node_type,
                    },
                )
            if edge.review_status == "pending_review":
                self._issue(
                    issues,
                    "CEG_RELATION_REVIEW_PENDING",
                    "warning",
                    "edge",
                    edge.id,
                    "reviewStatus",
                    "ceg.validation.edge.review_pending",
                    review_required=True,
                )

    def _validate_cycles(
        self,
        edges: list[CanonicalExecutionGraphEdge],
        issues: list[dict[str, Any]],
    ) -> None:
        for edge_type in sorted(FORBIDDEN_CYCLE_EDGE_TYPES | DIAGNOSTIC_CYCLE_EDGE_TYPES):
            matching = [
                (item.source_node_id, item.target_node_id)
                for item in edges
                if item.edge_type == edge_type
            ]
            if not graph_has_cycle(matching):
                continue
            forbidden = edge_type in FORBIDDEN_CYCLE_EDGE_TYPES
            self._issue(
                issues,
                "CEG_FORBIDDEN_CYCLE" if forbidden else "CEG_DEPENDENCY_CYCLE",
                "error" if forbidden else "warning",
                "version",
                None,
                "edges",
                "ceg.validation.edge.forbidden_cycle"
                if forbidden
                else "ceg.validation.edge.dependency_cycle",
                details={"edgeType": edge_type},
            )

    def _validate_paths(
        self,
        paths: list[CanonicalExecutionGraphPath],
        steps_by_path: dict[UUID, list[CanonicalExecutionGraphPathStep]],
        node_by_id: dict[UUID, CanonicalExecutionGraphNode],
        edge_by_id: dict[UUID, CanonicalExecutionGraphEdge],
        issues: list[dict[str, Any]],
    ) -> None:
        for path in paths:
            path_steps = sorted(steps_by_path.get(path.id, []), key=lambda item: item.step_order)
            orders = [item.step_order for item in path_steps]
            if not path_steps or orders != list(range(1, len(path_steps) + 1)):
                self._issue(
                    issues,
                    "CEG_PATH_ORDER_INVALID",
                    "error",
                    "path",
                    path.id,
                    "steps",
                    "ceg.validation.path.order_invalid",
                    details={"orders": orders},
                )
                continue
            if path.entry_node_id != path_steps[0].node_id:
                self._issue(
                    issues,
                    "CEG_PATH_ENTRY_MISMATCH",
                    "error",
                    "path",
                    path.id,
                    "entryNodeId",
                    "ceg.validation.path.entry_mismatch",
                )
            if path.exit_node_id != path_steps[-1].node_id:
                self._issue(
                    issues,
                    "CEG_PATH_EXIT_MISMATCH",
                    "error",
                    "path",
                    path.id,
                    "exitNodeId",
                    "ceg.validation.path.exit_mismatch",
                )
            previous_node_id: UUID | None = None
            for index, step in enumerate(path_steps):
                if step.node_id not in node_by_id:
                    self._issue(
                        issues,
                        "CEG_PATH_STEP_NODE_NOT_FOUND",
                        "error",
                        "path_step",
                        step.id,
                        "nodeId",
                        "ceg.validation.path.step_node_not_found",
                    )
                if index == 0:
                    if step.via_edge_id is not None:
                        self._path_edge_issue(step, issues)
                else:
                    via_edge = edge_by_id.get(step.via_edge_id) if step.via_edge_id else None
                    if (
                        via_edge is None
                        or via_edge.source_node_id != previous_node_id
                        or via_edge.target_node_id != step.node_id
                    ):
                        self._path_edge_issue(step, issues)
                previous_node_id = step.node_id

    def _path_edge_issue(
        self,
        step: CanonicalExecutionGraphPathStep,
        issues: list[dict[str, Any]],
    ) -> None:
        self._issue(
            issues,
            "CEG_PATH_DISCONNECTED",
            "error",
            "path_step",
            step.id,
            "viaEdgeId",
            "ceg.validation.path.disconnected",
            details={"order": step.step_order},
        )


__all__ = [
    "ALLOWED_CYCLE_EDGE_TYPES",
    "DIAGNOSTIC_CYCLE_EDGE_TYPES",
    "EDGE_RELATION_REGISTRY",
    "ExecutionGraphValidator",
    "FORBIDDEN_CYCLE_EDGE_TYPES",
    "GRAPH_NODE_TYPES",
    "HIGH_RISK_EDGE_TYPES",
    "edge_pair_allowed",
    "edge_requires_review",
    "graph_has_cycle",
    "would_create_forbidden_cycle",
]

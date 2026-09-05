# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CEG_SCHEMA_VERSION: Literal["ceg.v1"] = "ceg.v1"
MAX_CEG_METADATA_BYTES = 16 * 1024
MAX_CEG_APPLICABILITY_BYTES = 32 * 1024
MAX_CEG_SOURCE_REFS = 128
MAX_CEG_NODE_ATTRIBUTES_BYTES = 16 * 1024
MAX_CEG_CONDITION_BYTES = 8 * 1024
MAX_CEG_NODES = 5_000
MAX_CEG_EDGES = 20_000
MAX_CEG_PATHS = 1_000
MAX_CEG_PATH_STEPS = 20_000

GraphStatusValue = Literal[
    "draft",
    "candidate",
    "under_review",
    "active",
    "superseded",
    "deprecated",
    "archived",
]
GraphScopeValue = Literal["project", "environment"]
GraphSourceValue = Literal["observed", "candidate", "canonical"]
GraphRetentionStatusValue = Literal["active", "archived", "purge_eligible", "legal_hold"]
GraphRefTypeValue = Literal[
    "execution",
    "trace",
    "replay",
    "evidence",
    "artifact",
    "requirement",
    "test",
    "manual",
    "import",
    "graph_version",
    "audit",
    "code",
    "api",
    "data",
]
GraphNodeTypeValue = Literal[
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
]
GraphEdgeTypeValue = Literal[
    "contains",
    "precedes",
    "transitions_to",
    "depends_on",
    "implements",
    "verifies",
    "produces",
    "evidenced_by",
    "changes",
    "affects",
]
GraphRiskValue = Literal["low", "medium", "high"]
GraphElementSourceValue = Literal["observed", "candidate", "imported", "manual", "canonical"]
GraphReviewStatusValue = Literal["not_required", "pending_review", "approved", "rejected"]


NODE_ATTRIBUTE_ALLOWLIST: dict[str, frozenset[str]] = {
    "requirement": frozenset({"requirementItemId", "version", "acceptanceCriterionIds"}),
    "capability": frozenset({"capabilityKey", "domain"}),
    "page": frozenset({"route", "pageKey"}),
    "component": frozenset({"componentKey", "role"}),
    "element": frozenset({"semanticRole", "accessibleName", "testId"}),
    "action": frozenset({"actionType", "intentKey"}),
    "assertion": frozenset({"assertionType", "expectedRef"}),
    "data": frozenset({"dataKind", "schemaRef", "classification"}),
    "api": frozenset({"method", "operationId", "routeTemplate"}),
    "code": frozenset({"repositoryRef", "path", "symbol"}),
    "test": frozenset({"testKind", "testCaseRef"}),
    "evidence": frozenset({"evidenceKind", "contentHash", "classification"}),
}


class _StrictGraphModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


class GraphScopeContract(_StrictGraphModel):
    type: GraphScopeValue
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: UUID
    environmentId: UUID | None = None
    scopeId: UUID

    @model_validator(mode="after")
    def validate_scope_identity(self) -> "GraphScopeContract":
        if self.type == "project":
            if self.environmentId is not None:
                raise ValueError("project Graph scope must not carry environmentId")
            if self.scopeId != self.projectId:
                raise ValueError("project Graph scopeId must match projectId")
        else:
            if self.environmentId is None:
                raise ValueError("environment Graph scope requires environmentId")
            if self.scopeId != self.environmentId:
                raise ValueError("environment Graph scopeId must match environmentId")
        return self


class StableGraphRef(_StrictGraphModel):
    type: GraphRefTypeValue
    ref: str = Field(
        min_length=4,
        max_length=500,
        pattern=r"^[a-z][a-z0-9+.-]*://[^\s]+$",
    )
    contentHash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_ref_scheme(self) -> "StableGraphRef":
        expected_scheme = {
            "execution": "execution://",
            "trace": "trace://",
            "replay": "replay://",
            "evidence": "evidence://",
            "artifact": "artifact://",
            "requirement": "requirement://",
            "test": "test://",
            "manual": "manual://",
            "import": "import://",
            "graph_version": "ceg-version://",
            "audit": "audit://",
            "code": "code://",
            "api": "api://",
            "data": "data://",
        }[self.type]
        if not self.ref.startswith(expected_scheme):
            raise ValueError(f"{self.type} ref must use {expected_scheme}")
        if any(marker in self.ref for marker in ("@", "?", "#", "=")):
            raise ValueError("stable Graph refs must not embed credentials or query material")
        return self


class GraphSourceContract(_StrictGraphModel):
    level: GraphSourceValue
    refs: list[StableGraphRef] = Field(min_length=1, max_length=MAX_CEG_SOURCE_REFS)

    @model_validator(mode="after")
    def validate_fact_boundary(self) -> "GraphSourceContract":
        ref_types = {item.type for item in self.refs}
        if self.level == "observed" and not ref_types.intersection({"execution", "trace"}):
            raise ValueError("observed Graph source requires an execution or trace ref")
        if self.level == "canonical" and not ref_types.intersection(
            {"evidence", "replay", "graph_version"}
        ):
            raise ValueError("canonical Graph source requires frozen validation evidence")
        return self


class GraphRetentionContract(_StrictGraphModel):
    policy: str = Field(min_length=1, max_length=80)
    until: datetime | None = None
    status: GraphRetentionStatusValue
    legalHold: bool

    @model_validator(mode="after")
    def validate_retention_state(self) -> "GraphRetentionContract":
        if self.legalHold != (self.status == "legal_hold"):
            raise ValueError("legalHold and retention status must agree")
        return self


class GraphAuditContract(_StrictGraphModel):
    createdBy: UUID | None
    updatedBy: UUID | None
    traceId: UUID | None
    auditRefs: list[StableGraphRef] = Field(max_length=128)
    createdAt: datetime
    updatedAt: datetime


class GraphIdentityContract(_StrictGraphModel):
    graphId: UUID
    graphRef: str = Field(pattern=r"^ceg://[^\s]+$", max_length=500)
    graphKey: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    status: GraphStatusValue
    scope: GraphScopeContract
    retention: GraphRetentionContract
    lockVersion: int = Field(ge=1)
    audit: GraphAuditContract
    metadata: dict[str, Any] = Field(max_length=64)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(value, "Graph metadata", MAX_CEG_METADATA_BYTES)


class GraphVersionContract(_StrictGraphModel):
    versionId: UUID
    versionRef: str = Field(pattern=r"^ceg-version://[^\s]+$", max_length=500)
    graphId: UUID
    version: int = Field(ge=1, le=2_147_483_647)
    parentVersionId: UUID | None = None
    status: GraphStatusValue
    scope: GraphScopeContract
    source: GraphSourceContract
    schemaVersion: Literal["ceg.v1"]
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    applicability: dict[str, Any] = Field(max_length=64)
    frozen: bool
    frozenAt: datetime | None
    frozenBy: UUID | None
    retention: GraphRetentionContract
    lockVersion: int = Field(ge=1)
    audit: GraphAuditContract
    metadata: dict[str, Any] = Field(max_length=64)

    @field_validator("applicability")
    @classmethod
    def validate_applicability(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(
            value,
            "Graph applicability",
            MAX_CEG_APPLICABILITY_BYTES,
        )

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(value, "Graph metadata", MAX_CEG_METADATA_BYTES)

    @model_validator(mode="after")
    def validate_canonical_boundary(self) -> "GraphVersionContract":
        if self.parentVersionId == self.versionId:
            raise ValueError("Graph version cannot be its own parent")
        if self.frozen != (self.frozenAt is not None):
            raise ValueError("frozen Graph version requires frozenAt and draft version must omit it")
        if not self.frozen and self.frozenBy is not None:
            raise ValueError("unfrozen Graph version must not carry frozenBy")
        if self.source.level == "canonical":
            if not self.frozen or self.status not in {
                "active",
                "superseded",
                "deprecated",
                "archived",
            }:
                raise ValueError("canonical Graph versions are immutable promoted versions")
        if self.status == "active" and (self.source.level != "canonical" or not self.frozen):
            raise ValueError("only frozen canonical Graph versions may be active")
        return self


class GraphDisplayMetadata(_StrictGraphModel):
    label: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    group: str | None = Field(default=None, max_length=120)
    tags: list[str] = Field(default_factory=list, max_length=32)
    iconKey: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 80 for item in normalized):
            raise ValueError("Graph display tags must be non-empty and at most 80 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("Graph display tags must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_redaction_boundary(self) -> "GraphDisplayMetadata":
        validate_safe_graph_mapping(
            self.model_dump(mode="json"),
            "Graph display metadata",
            MAX_CEG_METADATA_BYTES,
        )
        return self


class GraphConditionContract(_StrictGraphModel):
    predicateKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{1,127}$")
    operator: Literal["equals", "not_equals", "exists", "not_exists", "matches_ref", "in_ref"]
    expected: bool | int | float | None = None
    valueRef: StableGraphRef | None = None
    parameters: dict[str, Any] = Field(default_factory=dict, max_length=32)

    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(value, "Graph condition", MAX_CEG_CONDITION_BYTES)

    @model_validator(mode="after")
    def validate_operand(self) -> "GraphConditionContract":
        if self.operator in {"matches_ref", "in_ref"} and self.valueRef is None:
            raise ValueError(f"{self.operator} Graph condition requires valueRef")
        if self.operator in {"exists", "not_exists"} and (
            self.expected is not None or self.valueRef is not None
        ):
            raise ValueError(f"{self.operator} Graph condition must not carry an operand")
        return self


class GraphNodeContract(_StrictGraphModel):
    nodeId: UUID
    nodeRef: str = Field(pattern=r"^ceg-node://[^\s]+$", max_length=500)
    versionId: UUID
    clientKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    semanticKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    nodeType: GraphNodeTypeValue
    display: GraphDisplayMetadata
    attributes: dict[str, Any] = Field(default_factory=dict, max_length=32)
    externalRefs: list[StableGraphRef] = Field(default_factory=list, max_length=32)
    riskLevel: GraphRiskValue
    source: GraphElementSourceValue
    confidence: float = Field(ge=0.0, le=1.0)
    lockVersion: int = Field(ge=1)
    audit: GraphAuditContract

    @model_validator(mode="after")
    def validate_attributes(self) -> "GraphNodeContract":
        self.attributes = validate_graph_node_attributes(self.nodeType, self.attributes)
        if self.source == "canonical" and not self.nodeRef:
            raise ValueError("canonical Graph Node requires a stable nodeRef")
        return self


class GraphEdgeContract(_StrictGraphModel):
    edgeId: UUID
    edgeRef: str = Field(pattern=r"^ceg-edge://[^\s]+$", max_length=500)
    versionId: UUID
    clientKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    edgeType: GraphEdgeTypeValue
    sourceNodeId: UUID
    targetNodeId: UUID
    condition: GraphConditionContract | None = None
    riskLevel: GraphRiskValue
    reviewStatus: GraphReviewStatusValue
    source: GraphElementSourceValue
    confidence: float = Field(ge=0.0, le=1.0)
    lockVersion: int = Field(ge=1)
    audit: GraphAuditContract

    @model_validator(mode="after")
    def validate_endpoints(self) -> "GraphEdgeContract":
        if self.sourceNodeId == self.targetNodeId:
            raise ValueError("Graph Edge self-loops are forbidden")
        return self


class PathStepContract(_StrictGraphModel):
    stepId: UUID
    stepRef: str = Field(pattern=r"^ceg-step://[^\s]+$", max_length=500)
    pathId: UUID
    versionId: UUID
    clientKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    order: int = Field(ge=1, le=MAX_CEG_PATH_STEPS)
    nodeId: UUID
    viaEdgeId: UUID | None = None
    conditions: list[GraphConditionContract] = Field(default_factory=list, max_length=16)
    evidenceRefs: list[StableGraphRef] = Field(default_factory=list, max_length=32)
    lockVersion: int = Field(ge=1)
    audit: GraphAuditContract


class CanonicalPathContract(_StrictGraphModel):
    pathId: UUID
    pathRef: str = Field(pattern=r"^ceg-path://[^\s]+$", max_length=500)
    versionId: UUID
    clientKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    pathKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    entryNodeId: UUID
    exitNodeId: UUID
    preconditions: list[GraphConditionContract] = Field(default_factory=list, max_length=32)
    postconditions: list[GraphConditionContract] = Field(default_factory=list, max_length=32)
    riskLevel: GraphRiskValue
    applicability: dict[str, Any] = Field(default_factory=dict, max_length=64)
    evidenceRefs: list[StableGraphRef] = Field(default_factory=list, max_length=64)
    source: GraphElementSourceValue
    confidence: float = Field(ge=0.0, le=1.0)
    steps: list[PathStepContract] = Field(min_length=1, max_length=MAX_CEG_PATH_STEPS)
    lockVersion: int = Field(ge=1)
    audit: GraphAuditContract

    @field_validator("applicability")
    @classmethod
    def validate_applicability(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(
            value,
            "Canonical Path applicability",
            MAX_CEG_APPLICABILITY_BYTES,
        )

    @model_validator(mode="after")
    def validate_step_order_and_boundary(self) -> "CanonicalPathContract":
        validate_path_steps(self.steps, self.entryNodeId, self.exitNodeId)
        return self


class GraphTopologyContract(_StrictGraphModel):
    nodes: list[GraphNodeContract] = Field(max_length=MAX_CEG_NODES)
    edges: list[GraphEdgeContract] = Field(max_length=MAX_CEG_EDGES)
    canonicalPaths: list[CanonicalPathContract] = Field(max_length=MAX_CEG_PATHS)


class ValidationIssueContract(_StrictGraphModel):
    code: str = Field(pattern=r"^CEG_[A-Z0-9_]+$", max_length=120)
    severity: Literal["error", "warning", "info"]
    entityType: Literal["version", "node", "edge", "path", "path_step", "external_ref"]
    entityId: UUID | None = None
    field: str | None = Field(default=None, max_length=120)
    messageKey: str = Field(pattern=r"^ceg\.validation\.[a-z0-9_.-]+$", max_length=180)
    blocking: bool
    reviewRequired: bool = False
    details: dict[str, Any] = Field(default_factory=dict, max_length=32)


class GraphValidationSummary(_StrictGraphModel):
    valid: bool
    errorCount: int = Field(ge=0)
    warningCount: int = Field(ge=0)
    infoCount: int = Field(ge=0)
    reviewPendingCount: int = Field(ge=0)


class GraphValidationResultContract(_StrictGraphModel):
    schemaVersion: Literal["ceg.validation.v1"] = "ceg.validation.v1"
    versionId: UUID
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    topologyHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    summary: GraphValidationSummary
    issues: list[ValidationIssueContract] = Field(max_length=50_000)


class VersionProjectionContract(_StrictGraphModel):
    versionId: UUID
    graphId: UUID
    version: int = Field(ge=1)
    status: GraphStatusValue
    source: GraphSourceValue
    editable: bool
    canonical: bool
    frozen: bool
    lockVersion: int = Field(ge=1)
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    topologyHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    nodeCount: int = Field(ge=0)
    edgeCount: int = Field(ge=0)
    pathCount: int = Field(ge=0)
    stepCount: int = Field(ge=0)
    versionRef: str = Field(pattern=r"^ceg-version://[^\s]+$", max_length=500)
    writesGate: Literal[False] = False
    writesMemory: Literal[False] = False
    executesActions: Literal[False] = False


class CanonicalExecutionGraphContract(_StrictGraphModel):
    schemaVersion: Literal["ceg.v1"]
    identity: GraphIdentityContract
    version: GraphVersionContract
    topology: GraphTopologyContract
    projection: VersionProjectionContract

    @model_validator(mode="after")
    def validate_identity_version_scope(self) -> "CanonicalExecutionGraphContract":
        if self.identity.graphId != self.version.graphId:
            raise ValueError("Graph identity and version graphId must match")
        if self.identity.scope != self.version.scope:
            raise ValueError("Graph identity and version scope must match")
        if self.version.versionId != self.projection.versionId:
            raise ValueError("Graph version and Version Projection versionId must match")
        if self.identity.graphId != self.projection.graphId:
            raise ValueError("Graph identity and Version Projection graphId must match")
        if (
            self.version.version != self.projection.version
            or self.version.status != self.projection.status
            or self.version.source.level != self.projection.source
            or self.version.frozen != self.projection.frozen
            or self.version.lockVersion != self.projection.lockVersion
            or self.version.contentHash != self.projection.contentHash
        ):
            raise ValueError("Graph Version Projection must match authoritative version metadata")
        topology_version_ids = {
            *(item.versionId for item in self.topology.nodes),
            *(item.versionId for item in self.topology.edges),
            *(item.versionId for item in self.topology.canonicalPaths),
        }
        if topology_version_ids and topology_version_ids != {self.version.versionId}:
            raise ValueError("Graph topology records must belong to the projected version")
        step_count = sum(len(item.steps) for item in self.topology.canonicalPaths)
        if (
            self.projection.nodeCount != len(self.topology.nodes)
            or self.projection.edgeCount != len(self.topology.edges)
            or self.projection.pathCount != len(self.topology.canonicalPaths)
            or self.projection.stepCount != step_count
        ):
            raise ValueError("Graph Version Projection counts must match topology")
        node_ids = {item.nodeId for item in self.topology.nodes}
        edge_ids = {item.edgeId for item in self.topology.edges}
        if any(
            edge.sourceNodeId not in node_ids or edge.targetNodeId not in node_ids
            for edge in self.topology.edges
        ):
            raise ValueError("Graph Edge endpoints must reference Nodes in the same topology")
        for path in self.topology.canonicalPaths:
            if path.entryNodeId not in node_ids or path.exitNodeId not in node_ids:
                raise ValueError("Canonical Path boundaries must reference Nodes in the same topology")
            if any(step.nodeId not in node_ids for step in path.steps):
                raise ValueError("Path Steps must reference Nodes in the same topology")
            if any(step.viaEdgeId not in edge_ids for step in path.steps if step.viaEdgeId):
                raise ValueError("Path Steps must reference Edges in the same topology")
        return self


class CreateGraphNodeRequest(_StrictGraphModel):
    clientKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    semanticKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    nodeType: GraphNodeTypeValue
    display: GraphDisplayMetadata
    attributes: dict[str, Any] = Field(default_factory=dict, max_length=32)
    externalRefs: list[StableGraphRef] = Field(default_factory=list, max_length=32)
    riskLevel: GraphRiskValue = "low"
    source: Literal["observed", "candidate", "imported", "manual"] = "candidate"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    versionLockVersion: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_attributes(self) -> "CreateGraphNodeRequest":
        self.attributes = validate_graph_node_attributes(self.nodeType, self.attributes)
        return self


class UpdateGraphNodeRequest(_StrictGraphModel):
    semanticKey: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    nodeType: GraphNodeTypeValue | None = None
    display: GraphDisplayMetadata | None = None
    attributes: dict[str, Any] | None = Field(default=None, max_length=32)
    externalRefs: list[StableGraphRef] | None = Field(default=None, max_length=32)
    riskLevel: GraphRiskValue | None = None
    source: Literal["observed", "candidate", "imported", "manual"] | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    lockVersion: int = Field(ge=1)
    versionLockVersion: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_update(self) -> "UpdateGraphNodeRequest":
        mutable = self.model_fields_set - {"lockVersion", "versionLockVersion"}
        if not mutable:
            raise ValueError("Graph Node update requires at least one mutable field")
        for field_name in mutable:
            if getattr(self, field_name) is None:
                raise ValueError(f"Graph Node {field_name} must not be null")
        if self.attributes is not None:
            if self.nodeType is not None:
                self.attributes = validate_graph_node_attributes(self.nodeType, self.attributes)
            else:
                self.attributes = validate_safe_graph_mapping(
                    self.attributes,
                    "Graph Node attributes",
                    MAX_CEG_NODE_ATTRIBUTES_BYTES,
                )
        return self


class CreateGraphEdgeRequest(_StrictGraphModel):
    clientKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    edgeType: GraphEdgeTypeValue
    sourceNodeId: UUID
    targetNodeId: UUID
    condition: GraphConditionContract | None = None
    riskLevel: GraphRiskValue = "low"
    source: Literal["observed", "candidate", "imported", "manual"] = "candidate"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    versionLockVersion: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_endpoints(self) -> "CreateGraphEdgeRequest":
        if self.sourceNodeId == self.targetNodeId:
            raise ValueError("Graph Edge self-loops are forbidden")
        return self


class UpdateGraphEdgeRequest(_StrictGraphModel):
    edgeType: GraphEdgeTypeValue | None = None
    sourceNodeId: UUID | None = None
    targetNodeId: UUID | None = None
    condition: GraphConditionContract | None = None
    riskLevel: GraphRiskValue | None = None
    source: Literal["observed", "candidate", "imported", "manual"] | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    lockVersion: int = Field(ge=1)
    versionLockVersion: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_update(self) -> "UpdateGraphEdgeRequest":
        mutable = self.model_fields_set - {"lockVersion", "versionLockVersion"}
        if not mutable:
            raise ValueError("Graph Edge update requires at least one mutable field")
        for field_name in mutable - {"condition"}:
            if getattr(self, field_name) is None:
                raise ValueError(f"Graph Edge {field_name} must not be null")
        return self


class PathStepInput(_StrictGraphModel):
    clientKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    order: int = Field(ge=1, le=MAX_CEG_PATH_STEPS)
    nodeId: UUID
    viaEdgeId: UUID | None = None
    conditions: list[GraphConditionContract] = Field(default_factory=list, max_length=16)
    evidenceRefs: list[StableGraphRef] = Field(default_factory=list, max_length=32)


class CreateCanonicalPathRequest(_StrictGraphModel):
    clientKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,127}$")
    pathKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    entryNodeId: UUID
    exitNodeId: UUID
    preconditions: list[GraphConditionContract] = Field(default_factory=list, max_length=32)
    postconditions: list[GraphConditionContract] = Field(default_factory=list, max_length=32)
    riskLevel: GraphRiskValue = "low"
    applicability: dict[str, Any] = Field(default_factory=dict, max_length=64)
    evidenceRefs: list[StableGraphRef] = Field(default_factory=list, max_length=64)
    source: Literal["observed", "candidate", "imported", "manual"] = "candidate"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    steps: list[PathStepInput] = Field(min_length=1, max_length=MAX_CEG_PATH_STEPS)
    versionLockVersion: int = Field(ge=1)

    @field_validator("applicability")
    @classmethod
    def validate_applicability(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(
            value,
            "Canonical Path applicability",
            MAX_CEG_APPLICABILITY_BYTES,
        )

    @model_validator(mode="after")
    def validate_steps(self) -> "CreateCanonicalPathRequest":
        validate_path_steps(self.steps, self.entryNodeId, self.exitNodeId)
        return self


class UpdateCanonicalPathRequest(_StrictGraphModel):
    pathKey: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    entryNodeId: UUID | None = None
    exitNodeId: UUID | None = None
    preconditions: list[GraphConditionContract] | None = Field(default=None, max_length=32)
    postconditions: list[GraphConditionContract] | None = Field(default=None, max_length=32)
    riskLevel: GraphRiskValue | None = None
    applicability: dict[str, Any] | None = Field(default=None, max_length=64)
    evidenceRefs: list[StableGraphRef] | None = Field(default=None, max_length=64)
    source: Literal["observed", "candidate", "imported", "manual"] | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    steps: list[PathStepInput] | None = Field(default=None, min_length=1, max_length=MAX_CEG_PATH_STEPS)
    lockVersion: int = Field(ge=1)
    versionLockVersion: int = Field(ge=1)

    @field_validator("applicability")
    @classmethod
    def validate_applicability(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        return validate_safe_graph_mapping(
            value,
            "Canonical Path applicability",
            MAX_CEG_APPLICABILITY_BYTES,
        )

    @model_validator(mode="after")
    def validate_update(self) -> "UpdateCanonicalPathRequest":
        mutable = self.model_fields_set - {"lockVersion", "versionLockVersion"}
        if not mutable:
            raise ValueError("Canonical Path update requires at least one mutable field")
        for field_name in mutable - {"description"}:
            if getattr(self, field_name) is None:
                raise ValueError(f"Canonical Path {field_name} must not be null")
        if self.steps is not None and (self.entryNodeId is None or self.exitNodeId is None):
            raise ValueError("Canonical Path steps update requires entryNodeId and exitNodeId")
        if self.steps is not None:
            assert self.entryNodeId is not None
            assert self.exitNodeId is not None
            validate_path_steps(self.steps, self.entryNodeId, self.exitNodeId)
        return self


class ValidateGraphVersionRequest(_StrictGraphModel):
    lockVersion: int = Field(ge=1)


class CreateGraphIdentityRequest(_StrictGraphModel):
    projectId: UUID
    environmentId: UUID | None = None
    graphKey: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{2,127}$")
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    idempotencyKey: str = Field(min_length=1, max_length=255)
    retentionPolicy: str = Field(default="default", min_length=1, max_length=80)
    retentionUntil: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict, max_length=64)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(value, "Graph metadata", MAX_CEG_METADATA_BYTES)


class CreateGraphVersionRequest(_StrictGraphModel):
    graphId: UUID
    parentVersionId: UUID | None = None
    source: GraphSourceValue
    sourceRefs: list[StableGraphRef] = Field(min_length=1, max_length=MAX_CEG_SOURCE_REFS)
    schemaVersion: Literal["ceg.v1"] = CEG_SCHEMA_VERSION
    applicability: dict[str, Any] = Field(default_factory=dict, max_length=64)
    idempotencyKey: str = Field(min_length=1, max_length=255)
    retentionPolicy: str = Field(default="default", min_length=1, max_length=80)
    retentionUntil: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict, max_length=64)

    @field_validator("applicability")
    @classmethod
    def validate_applicability(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(
            value,
            "Graph applicability",
            MAX_CEG_APPLICABILITY_BYTES,
        )

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_safe_graph_mapping(value, "Graph metadata", MAX_CEG_METADATA_BYTES)

    @model_validator(mode="after")
    def validate_source_refs(self) -> "CreateGraphVersionRequest":
        GraphSourceContract(level=self.source, refs=self.sourceRefs)
        if self.source == "canonical":
            raise ValueError("P10 does not create canonical Graph versions; use the future promotion flow")
        return self


_SECRET_KEY_MARKERS = (
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "apikey",
    "api_key",
    "privatekey",
    "private_key",
    "cookie",
)
_SECRET_VALUE_PATTERN = re.compile(
    r"(?:-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bsk-[A-Za-z0-9_-]{16,}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@)",
    re.IGNORECASE,
)


def validate_safe_graph_mapping(
    value: dict[str, Any],
    label: str,
    max_bytes: int,
) -> dict[str, Any]:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")
    if _contains_secret(value):
        raise ValueError(f"{label} must not contain Secret or credential material")
    return value


def _contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9_]", "", str(key).lower())
            if any(marker in normalized for marker in _SECRET_KEY_MARKERS):
                return True
            if _contains_secret(child):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return isinstance(value, str) and _SECRET_VALUE_PATTERN.search(value) is not None


def validate_graph_node_attributes(
    node_type: str,
    value: dict[str, Any],
) -> dict[str, Any]:
    safe_value = validate_safe_graph_mapping(
        value,
        "Graph Node attributes",
        MAX_CEG_NODE_ATTRIBUTES_BYTES,
    )
    allowed = NODE_ATTRIBUTE_ALLOWLIST.get(node_type)
    if allowed is None:
        raise ValueError(f"unsupported Graph Node type: {node_type}")
    unsupported = sorted(set(safe_value) - allowed)
    if unsupported:
        raise ValueError(
            f"Graph Node attributes are not allowed for {node_type}: {', '.join(unsupported)}"
        )
    return safe_value


def validate_path_steps(
    steps: list[Any],
    entry_node_id: UUID,
    exit_node_id: UUID,
) -> None:
    orders = [item.order for item in steps]
    if orders != list(range(1, len(steps) + 1)):
        raise ValueError("Canonical Path step order must be contiguous and start at 1")
    client_keys = [item.clientKey for item in steps]
    if len(set(client_keys)) != len(client_keys):
        raise ValueError("Canonical Path step clientKey must be unique within the path")
    if steps[0].nodeId != entry_node_id:
        raise ValueError("Canonical Path entryNodeId must match the first Path Step")
    if steps[-1].nodeId != exit_node_id:
        raise ValueError("Canonical Path exitNodeId must match the final Path Step")
    if steps[0].viaEdgeId is not None:
        raise ValueError("Canonical Path first step must not carry viaEdgeId")
    if any(item.viaEdgeId is None for item in steps[1:]):
        raise ValueError("Canonical Path non-entry steps require viaEdgeId")


__all__ = [
    "CEG_SCHEMA_VERSION",
    "CanonicalPathContract",
    "CanonicalExecutionGraphContract",
    "CreateCanonicalPathRequest",
    "CreateGraphEdgeRequest",
    "CreateGraphIdentityRequest",
    "CreateGraphNodeRequest",
    "CreateGraphVersionRequest",
    "GraphConditionContract",
    "GraphDisplayMetadata",
    "GraphEdgeContract",
    "GraphAuditContract",
    "GraphIdentityContract",
    "GraphNodeContract",
    "GraphRetentionContract",
    "GraphScopeContract",
    "GraphSourceContract",
    "GraphTopologyContract",
    "GraphValidationResultContract",
    "GraphVersionContract",
    "PathStepContract",
    "PathStepInput",
    "StableGraphRef",
    "UpdateCanonicalPathRequest",
    "UpdateGraphEdgeRequest",
    "UpdateGraphNodeRequest",
    "ValidateGraphVersionRequest",
    "ValidationIssueContract",
    "VersionProjectionContract",
    "validate_graph_node_attributes",
    "validate_path_steps",
    "validate_safe_graph_mapping",
]

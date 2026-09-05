# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EffectiveCapability(_StrictModel):
    capability: str = Field(min_length=1)
    granted: bool
    source: Literal["edition", "role", "entitlement", "reserved", "inactive", "not_granted"]
    riskLevel: Literal["low", "medium", "high"]
    decisionRef: str = Field(min_length=1)


class EditionProjection(_StrictModel):
    schemaVersion: Literal["phase8.edition-projection.v1"] = "phase8.edition-projection.v1"
    edition: Literal["basic", "community", "pro", "enterprise"]
    authorizationRevision: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effectiveCapabilities: list[EffectiveCapability]
    backendAuthoritative: Literal[True] = True
    editionStringAuthorizes: Literal[False] = False


class ScopeContextProjection(_StrictModel):
    schemaVersion: Literal["phase8.scope-context.v1"] = "phase8.scope-context.v1"
    tenantId: str = Field(min_length=1, max_length=128)
    workspaceId: str = Field(min_length=1, max_length=128)
    projectId: str = Field(min_length=1)
    environmentId: str | None = None
    membershipRole: str | None = None
    accessSource: Literal["project_membership", "platform_admin", "service_role"]
    decisionRef: str = Field(min_length=1)
    serverDerived: Literal[True] = True


class GraphAutonomyReadiness(_StrictModel):
    policy: bool
    eligibility: bool
    replay: bool
    shadow: bool
    killSwitch: bool
    approval: bool
    complete: bool
    configurable: bool
    requiredCapability: Literal["graph.autonomy.configure"] = "graph.autonomy.configure"
    unavailableReasons: list[str]


class GovernanceModuleReadiness(_StrictModel):
    moduleId: str
    route: str
    readCapability: str
    governanceCapabilities: list[str]
    workflowImplemented: bool
    visible: bool
    governanceAvailable: bool
    readOnly: bool
    unavailableReason: str | None = None


class GovernanceReadiness(_StrictModel):
    schemaVersion: Literal["phase8.governance-readiness.v1"] = "phase8.governance-readiness.v1"
    scopeContext: ScopeContextProjection
    editionProjection: EditionProjection
    modules: list[GovernanceModuleReadiness]
    graphAutonomy: GraphAutonomyReadiness
    basicReadOnly: bool
    directSkillExecution: Literal[False] = False
    frontendAuthorizationBoundary: Literal["ux_only"] = "ux_only"
    backendAuthorizationBoundary: Literal["service_api"] = "service_api"


class GovernanceAggregation(_StrictModel):
    schemaVersion: Literal["phase8.governance-aggregation.v1"] = "phase8.governance-aggregation.v1"
    scopeContext: ScopeContextProjection
    projectCount: int = Field(ge=0)
    omittedUnauthorizedProjectCount: int = Field(ge=0)
    lessonTaxonomyCounts: dict[str, int]
    lessonStatusCounts: dict[str, int]
    improvementStatusCounts: dict[str, int]
    admissionModeCounts: dict[str, int]
    minimumVisibility: Literal["aggregate_only"] = "aggregate_only"
    rawEvidenceIncluded: Literal[False] = False
    projectIdentifiersIncluded: Literal[False] = False

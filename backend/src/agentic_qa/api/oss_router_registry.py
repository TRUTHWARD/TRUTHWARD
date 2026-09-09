# SPDX-License-Identifier: Apache-2.0
from collections.abc import Sequence

from fastapi import APIRouter

from agentic_qa.api.routers.auth import router as auth_router
from agentic_qa.api.routers.candidate_graph_queries import router as candidate_graph_queries_router
from agentic_qa.api.routers.change_set_queries import router as change_set_queries_router
from agentic_qa.api.routers.executions import router as executions_router
from agentic_qa.api.routers.exploratory_session_queries import router as exploratory_session_queries_router
from agentic_qa.api.routers.health import router as health_router
from agentic_qa.api.routers.impact_analysis_queries import router as impact_analysis_queries_router
from agentic_qa.api.routers.models import router as models_router
from agentic_qa.api.routers.observability import router as observability_router
from agentic_qa.api.routers.plans import router as plans_router
from agentic_qa.api.routers.project_setting_queries import router as project_setting_queries_router
from agentic_qa.api.routers.project_settings import router as project_settings_router
from agentic_qa.api.routers.skills import router as skills_router
from agentic_qa.api.routers.work_item_queries import router as work_item_queries_router
from agentic_qa.api.routers.work_items import router as work_items_router
from agentic_qa.api.routers.workflow_runs import router as workflow_runs_router


def _route_subset(source: APIRouter, *, names: set[str], label: str) -> APIRouter:
    """Copy an explicit endpoint allowlist into the Community composition."""

    available: dict[str, object] = {}
    for route in source.routes:
        route_name = getattr(route, "name", None)
        if isinstance(route_name, str):
            if route_name in available:
                raise RuntimeError(f"duplicate route name in {label}: {route_name}")
            available[route_name] = route
    missing = sorted(names - set(available))
    if missing:
        raise RuntimeError(f"missing Community routes in {label}: {', '.join(missing)}")

    subset = APIRouter()
    subset.routes.extend(
        route
        for route in source.routes
        if getattr(route, "name", None) in names
    )
    return subset


community_models_router = _route_subset(
    models_router,
    label="models",
    names={
        "create_model",
        "list_models",
        "get_model",
        "update_model",
        "delete_model",
        "health_check_model",
        "capability_scan_model",
    },
)
community_plans_router = _route_subset(
    plans_router,
    label="plans",
    names={
        "create_plan",
        "list_plans",
        "get_plan",
        "update_plan",
        "delete_plan",
        "analyze_plan_coverage",
    },
)
community_skills_router = _route_subset(
    skills_router,
    label="skills",
    names={
        "list_community_local_skill_manifests",
        "register_community_local_skill_manifest",
        "community_binding_lifecycle",
        "list_skills",
        "get_skill_product_features",
        "list_skill_runtime_adapters",
        "list_skill_versions",
        "get_skill_version",
        "get_skill",
        "list_skill_invocations",
        "get_skill_invocation",
        "list_skill_runs",
        "workflow_capability_graph",
        "list_capability_bindings",
        "create_capability_binding",
        "update_capability_binding",
        "list_connector_bindings",
        "create_connector_binding",
        "get_connector_binding",
        "update_connector_binding",
        "archive_connector_binding",
    },
)
community_executions_router = _route_subset(
    executions_router,
    label="executions",
    names={
        "create_execution",
        "create_regression_presentation",
        "list_executions",
        "get_execution",
        "get_progress",
        "cancel_execution",
        "list_tasks",
        "get_task",
        "list_artifacts",
        "list_logs",
        "list_metrics",
        "list_findings",
        "get_finding",
        "update_finding",
    },
)
community_observability_router = _route_subset(
    observability_router,
    label="observability",
    names={
        "list_traces",
        "get_trace",
        "minimum_observability_metrics",
        "observability_metrics",
        "quality_dashboard",
        "structured_logs",
        "audit_log_projection",
    },
)


# Read-only query modules stay separately listed so their query/command
# isolation remains machine-checkable.  The Community composition below adds
# only the bounded local mutation routers needed by the self-hosted core; it
# deliberately omits Enterprise IAM, approval, correction, promotion, managed
# replay repository, scheduler, and controlled-autonomy routes.
ISOLATED_OSS_QUERY_ROUTERS: Sequence[APIRouter] = (
    candidate_graph_queries_router,
    change_set_queries_router,
    exploratory_session_queries_router,
    impact_analysis_queries_router,
    project_setting_queries_router,
    work_item_queries_router,
)

COMMUNITY_OSS_ROUTERS: Sequence[APIRouter] = (
    auth_router,
    health_router,
    community_models_router,
    community_plans_router,
    project_setting_queries_router,
    project_settings_router,
    community_skills_router,
    community_executions_router,
    work_item_queries_router,
    work_items_router,
    workflow_runs_router,
    community_observability_router,
    candidate_graph_queries_router,
    change_set_queries_router,
    exploratory_session_queries_router,
    impact_analysis_queries_router,
)

__all__ = ["COMMUNITY_OSS_ROUTERS", "ISOLATED_OSS_QUERY_ROUTERS"]

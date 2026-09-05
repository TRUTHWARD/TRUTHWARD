# SPDX-License-Identifier: Apache-2.0
"""Physically isolated API composition for the Community OSS distribution."""

from agentic_qa.api.oss_router_registry import COMMUNITY_OSS_ROUTERS
from agentic_qa.apps.common import create_service_app
from agentic_qa.infra.settings import get_settings


settings = get_settings()
if settings.deployment_profile != "oss":
    raise RuntimeError("Community OSS API requires DEPLOYMENT_PROFILE=oss")

app = create_service_app("community-api-gateway", COMMUNITY_OSS_ROUTERS)

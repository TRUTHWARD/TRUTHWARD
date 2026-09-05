# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AgentCatalogItem(BaseModel):
    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)
    outputSchema: dict[str, Any] = Field(default_factory=dict)
    allowedTools: list[str] = Field(default_factory=list)
    allowedSkills: list[str] = Field(default_factory=list)
    preferredModelRole: str
    enabled: bool = True


class RunAgentRequest(BaseModel):
    input: dict[str, Any]


class AgentRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    executionId: UUID | None = Field(default=None, alias="execution_id")
    taskId: UUID | None = Field(default=None, alias="task_id")
    agentName: str = Field(alias="agent_name")
    status: str
    input: dict[str, Any] = Field(alias="input_payload")
    output: dict[str, Any] = Field(alias="output_payload")
    modelId: UUID | None = Field(default=None, alias="model_id")
    latencyMs: int | None = Field(default=None, alias="latency_ms")
    startedAt: datetime | None = Field(default=None, alias="started_at")
    endedAt: datetime | None = Field(default=None, alias="ended_at")
    createdAt: datetime = Field(alias="created_at")

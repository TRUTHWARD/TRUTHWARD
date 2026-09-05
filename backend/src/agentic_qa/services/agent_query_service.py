# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_qa.agents.generator import GeneratorAgent
from agentic_qa.agents.healer import HealerAgent
from agentic_qa.agents.judge import JudgeAgent
from agentic_qa.agents.perf import PerfAgent
from agentic_qa.agents.planner_v2 import PlannerAgent
from agentic_qa.agents.runner import RunnerAgent
from agentic_qa.agents.security import SecurityAgent
from agentic_qa.agents.triage import TriageAgent
from agentic_qa.domain.models import AgentRun
from agentic_qa.services.common import paginate_query, paginate_result


class AgentCatalogQueryService:
    """Read-only Agent catalog and run projection used by the OSS query boundary."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.catalog = {
            "PlannerAgent": PlannerAgent(),
            "GeneratorAgent": GeneratorAgent(),
            "RunnerAgent": RunnerAgent(),
            "TriageAgent": TriageAgent(),
            "HealerAgent": HealerAgent(),
            "PerfAgent": PerfAgent(),
            "SecurityAgent": SecurityAgent(),
            "JudgeAgent": JudgeAgent(),
        }

    def list_agents(self) -> dict[str, object]:
        items = [{**agent.metadata(), "enabled": True} for agent in self.catalog.values()]
        return {"items": items, "total": len(items)}

    def list_runs(
        self,
        page: int,
        page_size: int,
        agent_name: str | None = None,
        execution_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, object]:
        statement = select(AgentRun).order_by(AgentRun.created_at.desc())
        if agent_name:
            statement = statement.where(AgentRun.agent_name == agent_name)
        if execution_id:
            statement = statement.where(AgentRun.execution_id == UUID(str(execution_id)))
        if status:
            statement = statement.where(AgentRun.status == status)
        rows, total = paginate_query(self.db, statement, page, page_size)
        items = [
            {
                "id": str(row.id),
                "executionId": str(row.execution_id) if row.execution_id else None,
                "taskId": str(row.task_id) if row.task_id else None,
                "agentName": row.agent_name,
                "status": row.status.value,
                "input": row.input_payload,
                "output": row.output_payload,
                "modelId": str(row.model_id) if row.model_id else None,
                "latencyMs": row.latency_ms,
                "startedAt": row.started_at.isoformat() if row.started_at else None,
                "endedAt": row.ended_at.isoformat() if row.ended_at else None,
                "createdAt": row.created_at.isoformat(),
            }
            for row in rows
        ]
        return paginate_result(items, total, page, page_size)

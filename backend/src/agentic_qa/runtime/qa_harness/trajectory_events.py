# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentic_qa.runtime.qa_harness.contracts import BudgetSnapshot
from agentic_qa.runtime.qa_harness.stop_reasons import HarnessRunState, StopReason


class TrajectoryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    eventId: str
    runId: str
    sequence: int = Field(ge=1)
    turn: int = Field(ge=0)
    state: HarnessRunState
    occurredAt: datetime
    agentRef: str | None = None
    modelInvocationRef: str | None = None
    skillIntentRef: str | None = None
    skillInvocationRef: str | None = None
    observationRefs: list[str] = Field(default_factory=list)
    stopReason: StopReason | None = None
    budgetSnapshot: BudgetSnapshot
    metadata: dict[str, Any] = Field(default_factory=dict)


TrajectorySink = Callable[[TrajectoryEvent], str | None]


class TrajectoryRecorder:
    def __init__(self, run_id: str, sink: TrajectorySink | None = None) -> None:
        self._run_id = run_id
        self._sink = sink
        self._sequence = 0
        self.refs: list[str] = []

    def emit(
        self,
        *,
        turn: int,
        state: HarnessRunState,
        occurred_at: datetime,
        budget_snapshot: BudgetSnapshot,
        stop_reason: StopReason | None = None,
        agent_ref: str | None = None,
        model_invocation_ref: str | None = None,
        skill_intent_ref: str | None = None,
        skill_invocation_ref: str | None = None,
        observation_refs: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TrajectoryEvent:
        self._sequence += 1
        event = TrajectoryEvent(
            eventId=f"trajectory://{self._run_id}/{self._sequence}",
            runId=self._run_id,
            sequence=self._sequence,
            turn=turn,
            state=state,
            occurredAt=occurred_at,
            agentRef=agent_ref,
            modelInvocationRef=model_invocation_ref,
            skillIntentRef=skill_intent_ref,
            skillInvocationRef=skill_invocation_ref,
            observationRefs=observation_refs or [],
            stopReason=stop_reason,
            budgetSnapshot=budget_snapshot,
            metadata=metadata or {},
        )
        ref = self._sink(event) if self._sink else None
        self.refs.append(ref or event.eventId)
        return event


__all__ = ["TrajectoryEvent", "TrajectoryRecorder", "TrajectorySink"]

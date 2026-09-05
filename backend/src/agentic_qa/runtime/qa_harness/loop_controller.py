# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from agentic_qa.runtime.qa_harness.contracts import (
    BudgetSnapshot,
    HarnessRunContext,
    HarnessRunSpec,
    ObservationUsage,
    SkillIntent,
)
from agentic_qa.runtime.qa_harness.stop_reasons import StopReason


Clock = Callable[[], datetime]
CancellationProbe = Callable[[], bool]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LoopController:
    SUPPORTED_STAGES = {"PREPARE"}

    def __init__(
        self,
        spec: HarnessRunSpec,
        context: HarnessRunContext,
        *,
        clock: Clock,
        cancellation_probe: CancellationProbe,
    ) -> None:
        self.spec = spec
        self.context = context
        self.clock = clock
        self.cancellation_probe = cancellation_probe

    def preflight(self, *, starting_turn: bool = False) -> StopReason | None:
        if self.cancellation_probe():
            self.context.cancellationState = "cancelled"
            return StopReason.CANCELLED
        if self.clock() >= self.context.deadlineAt:
            return StopReason.DEADLINE_EXCEEDED
        if self.spec.lifecycleStage not in self.SUPPORTED_STAGES:
            return StopReason.LIFECYCLE_STAGE_UNSUPPORTED
        if starting_turn and self.context.currentTurn >= self.spec.maxTurns:
            return StopReason.BUDGET_EXHAUSTED
        return None

    def validate_intent(self, intent: SkillIntent) -> StopReason | None:
        if intent.extensionPointId not in self.spec.allowedExtensionPoints:
            return StopReason.EXTENSION_POINT_NOT_ALLOWED
        stage = intent.extensionPointId.split(".", 1)[0]
        if stage != self.spec.lifecycleStage:
            return StopReason.EXTENSION_POINT_NOT_ALLOWED
        if self.context.modelCallsUsed + intent.expectedModelCalls > self.spec.maxModelCalls:
            return StopReason.BUDGET_EXHAUSTED
        if (
            self.context.skillInvocationsUsed + intent.expectedSkillInvocations
            > self.spec.maxSkillInvocations
        ):
            return StopReason.BUDGET_EXHAUSTED
        if self.context.toolCallsUsed + intent.expectedToolCalls > self.spec.maxToolCalls:
            return StopReason.BUDGET_EXHAUSTED
        return None

    def consume(self, usage: ObservationUsage) -> StopReason | None:
        next_model = self.context.modelCallsUsed + usage.modelCalls
        next_skill = self.context.skillInvocationsUsed + usage.skillInvocations
        next_tool = self.context.toolCallsUsed + usage.toolCalls
        if (
            next_model > self.spec.maxModelCalls
            or next_skill > self.spec.maxSkillInvocations
            or next_tool > self.spec.maxToolCalls
        ):
            return StopReason.BUDGET_EXHAUSTED
        self.context.modelCallsUsed = next_model
        self.context.skillInvocationsUsed = next_skill
        self.context.toolCallsUsed = next_tool
        return None

    def budget_snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            turnsUsed=self.context.currentTurn,
            modelCallsUsed=self.context.modelCallsUsed,
            skillInvocationsUsed=self.context.skillInvocationsUsed,
            toolCallsUsed=self.context.toolCallsUsed,
            maxTurns=self.spec.maxTurns,
            maxModelCalls=self.spec.maxModelCalls,
            maxSkillInvocations=self.spec.maxSkillInvocations,
            maxToolCalls=self.spec.maxToolCalls,
        )


__all__ = ["CancellationProbe", "Clock", "LoopController", "utc_now"]

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Iterable

from agentic_qa.domain.enums import TestDomain
from agentic_qa.tools.k6_runner import K6Runner
from agentic_qa.tools.playwright_runner import PlaywrightRunner
from agentic_qa.tools.runner_protocols import RunnerAdapter
from agentic_qa.tools.sandbox_runners import SandboxPythonUnittestRunner, SandboxSemgrepRunner
from agentic_qa.tools.security_runners import NucleiRunner, SemgrepRunner, ZapRunner


class RunnerRegistry:
    def __init__(self, runners: Iterable[RunnerAdapter] | None = None) -> None:
        self._runners: dict[str, RunnerAdapter] = {}
        for runner in runners or self._default_runners():
            self.register(runner)

    def register(self, runner: RunnerAdapter) -> None:
        self._runners[runner.runner_id] = runner

    def get(self, runner_id: str) -> RunnerAdapter:
        try:
            return self._runners[runner_id]
        except KeyError as exc:
            raise ValueError(f"runner not registered: {runner_id}") from exc

    def default_runner_for_domain(self, domain: TestDomain, config: dict[str, object] | None = None) -> str:
        if isinstance(config, dict) and isinstance(config.get("runner"), str):
            return str(config["runner"])
        if domain == TestDomain.FUNCTIONAL:
            return "playwright"
        if domain == TestDomain.PERFORMANCE:
            return "k6"
        return "zap"

    def available_runner_ids(self) -> list[str]:
        return sorted(self._runners)

    @staticmethod
    def _default_runners() -> tuple[RunnerAdapter, ...]:
        return (
            PlaywrightRunner(),
            K6Runner(),
            ZapRunner(),
            SemgrepRunner(),
            NucleiRunner(),
            SandboxSemgrepRunner(),
            SandboxPythonUnittestRunner(),
        )

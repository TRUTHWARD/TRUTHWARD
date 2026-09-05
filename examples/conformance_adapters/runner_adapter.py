# SPDX-License-Identifier: Apache-2.0
"""Apache-2.0 reference RunnerAdapter for the public conformance kit."""

from __future__ import annotations

from datetime import datetime, timezone

from agentic_qa.domain.enums import ArtifactType, TestDomain
from agentic_qa.tools.runner_protocols import (
    RunnerArtifactRef,
    RunnerExecutionRequest,
    RunnerExecutionResult,
    RunnerLogRecord,
)


class ReferenceRunnerAdapter:
    runner_id = "public-reference-runner"
    domain = TestDomain.FUNCTIONAL
    supports_parallelism = False
    default_timeout_seconds = 30

    def run(self, request: RunnerExecutionRequest) -> RunnerExecutionResult:
        now = datetime(2026, 8, 3, tzinfo=timezone.utc)
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=self.domain,
            status="completed",
            tool_status="ok",
            exit_code=0,
            timed_out=False,
            started_at=now,
            ended_at=now,
            duration_ms=0,
            artifact_refs=[
                RunnerArtifactRef(
                    artifact_type=ArtifactType.REPORT,
                    uri="artifact://public-conformance/runner/report.json",
                    metadata={"contentEncoding": "external_ref"},
                )
            ],
            logs=[
                RunnerLogRecord(
                    level="info",
                    message="deterministic public conformance execution",
                )
            ],
            metadata={
                "adapterVersion": "1.0.0",
                "executionMode": "public_conformance_fixture",
            },
        )


def create_adapter() -> ReferenceRunnerAdapter:
    return ReferenceRunnerAdapter()

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations


class EvidenceCollector:
    def collect(
        self,
        artifacts: list[str] | None = None,
        metrics: dict[str, object] | None = None,
        logs: list[str] | None = None,
        findings: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        return {
            "artifacts": artifacts or [],
            "metrics": metrics or {},
            "logs": logs or [],
            "findings": findings or [],
        }

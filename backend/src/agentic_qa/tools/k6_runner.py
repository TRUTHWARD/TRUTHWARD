# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from uuid import uuid4

from agentic_qa.domain.enums import ArtifactType, TestDomain
from agentic_qa.infra.settings import get_settings
from agentic_qa.tools.command_runner import (
    CommandExecutionResult,
    ensure_artifact_dir,
    resolve_executable,
    run_command,
)
from agentic_qa.tools.runner_protocols import (
    RunnerAdapter,
    RunnerArtifactRef,
    RunnerExecutionRequest,
    RunnerExecutionResult,
    RunnerLogRecord,
    RunnerMetricRecord,
    utcnow,
)


PINNED_K6_VERSION = "2.0.0"
K6_THRESHOLD_EXIT_CODES = frozenset({99})
_K6_VERSION_PATTERN = re.compile(r"\bv(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\b")


def _decimal(value: object, default: str) -> Decimal:
    if value is None:
        return Decimal(default)
    return Decimal(str(value))


def _required_decimal(value: object) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return parsed if parsed.is_finite() else None


class K6Runner(RunnerAdapter):
    runner_id = "k6"
    domain = TestDomain.PERFORMANCE
    supports_parallelism = True
    default_timeout_seconds = 900

    def run(self, request: RunnerExecutionRequest) -> RunnerExecutionResult:
        custom_command = request.config.get("command")
        if isinstance(custom_command, list) and custom_command:
            return self._run_custom_command(request, custom_command)

        actual = self._run_named_actual(request)
        if actual is not None:
            return actual
        if request.config.get("actualExecution") is True:
            return self._actual_preflight_failure(
                request,
                "pinned k6 binary or script path is unavailable",
                tool_status="infra_error",
            )
        return self._run_simulated(
            request,
            reason="pinned k6 binary or script path not available",
        )

    def _run_simulated(
        self,
        request: RunnerExecutionRequest,
        reason: str,
    ) -> RunnerExecutionResult:
        started_at = utcnow()
        p95_value = _decimal(request.config.get("p95Ms"), "944")
        threshold_value = _decimal(request.config.get("thresholdP95Ms"), "800")
        baseline_value = _decimal(request.config.get("baselineP95Ms"), "760")
        report_uri = (
            f"s3://agentic-qa-artifacts/{request.execution_id}/{request.task_id}/k6-summary.json"
        )

        metric = RunnerMetricRecord(
            name="p95",
            value=p95_value,
            unit="ms",
            threshold_value=threshold_value,
            baseline_value=baseline_value,
            metadata={
                "source": self.runner_id,
                "runnerId": self.runner_id,
                "executionMode": "simulated",
                "actualExecution": False,
                "validationClass": "simulated",
                **self._baseline_comparison(p95_value, baseline_value),
            },
        )
        exceeded_threshold = p95_value > threshold_value
        tool_status = "threshold_exceeded" if exceeded_threshold else "ok"

        ended_at = utcnow()
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="completed",
            tool_status=tool_status,
            exit_code=0,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(
                1,
                int((ended_at - started_at).total_seconds() * 1000),
            ),
            artifact_refs=[
                RunnerArtifactRef(
                    artifact_type=ArtifactType.REPORT,
                    uri=report_uri,
                    summary="simulated k6 summary report reference",
                    metadata={
                        "source": self.runner_id,
                        "executionMode": "simulated",
                        "actualExecution": False,
                        "validationClass": "simulated",
                    },
                )
            ],
            raw_metrics=[metric],
            logs=[
                RunnerLogRecord(
                    level="info",
                    message=f"k6-task={request.task_type}",
                    context={
                        "runner": self.runner_id,
                        "thresholdExceeded": exceeded_threshold,
                        "mode": "simulated",
                    },
                )
            ],
            metadata={
                "executionMode": "simulated",
                "actualExecution": False,
                "validationClass": "simulated",
                "namedTool": self.runner_id,
                "namedToolExecuted": False,
                "customCommandExecuted": False,
                "fallbackReason": reason,
            },
        )

    def _run_named_actual(
        self,
        request: RunnerExecutionRequest,
    ) -> RunnerExecutionResult | None:
        script_path = request.config.get("scriptPath")
        if not isinstance(script_path, str):
            return None
        script = Path(script_path)
        if not script.is_file():
            return None

        executable = self._resolve_named_binary(request)
        if executable is None:
            return None

        version_result = run_command(
            [executable, "version"],
            timeout_seconds=min(max(1, request.timeout_seconds), 15),
        )
        binary_version = self._parse_version(version_result)
        if version_result.timed_out or version_result.exit_code != 0 or binary_version is None:
            return self._actual_preflight_failure(
                request,
                "k6 binary version probe failed",
                executable=executable,
                version_result=version_result,
            )
        if binary_version != PINNED_K6_VERSION:
            return self._actual_preflight_failure(
                request,
                (
                    f"k6 binary version {binary_version!r} does not match "
                    f"repository pin {PINNED_K6_VERSION!r}"
                ),
                executable=executable,
                binary_version=binary_version,
                version_result=version_result,
            )

        artifact_dir = ensure_artifact_dir(
            str(get_settings().runner_artifact_dir),
            str(request.execution_id),
            str(request.task_id),
        )
        suffix = uuid4().hex
        summary_path = artifact_dir / f"k6-summary-{suffix}.json"
        evidence_path = artifact_dir / f"k6-actual-report-{suffix}.json"
        load_profile = self._load_profile(request)
        threshold_value = _decimal(request.config.get("thresholdP95Ms"), "800")
        command = [
            executable,
            "run",
            "--summary-export",
            str(summary_path),
            str(script.resolve()),
        ]
        extra_args = request.config.get("args")
        if isinstance(extra_args, list):
            command[1:1] = [str(item) for item in extra_args]
        env = self._config_env(request)
        env.setdefault("K6_VUS", str(load_profile["vus"]))
        env.setdefault("K6_DURATION", str(load_profile["duration"]))
        env.setdefault("K6_P95_THRESHOLD_MS", str(threshold_value))
        metadata = self._named_metadata(
            executable=executable,
            binary_version=binary_version,
            load_profile=load_profile,
            actual_execution=True,
            named_tool_executed=True,
        )
        result = run_command(
            command,
            cwd=str(Path(request.config.get("workdir", script.parent)).resolve()),
            env=env,
            timeout_seconds=request.timeout_seconds,
        )
        return self._result_from_command(
            request=request,
            result=result,
            summary_path=summary_path,
            evidence_path=evidence_path,
            metadata=metadata,
            custom_command=False,
        )

    def _run_custom_command(
        self,
        request: RunnerExecutionRequest,
        custom_command: list[object],
    ) -> RunnerExecutionResult:
        artifact_dir = ensure_artifact_dir(
            str(get_settings().runner_artifact_dir),
            str(request.execution_id),
            str(request.task_id),
        )
        suffix = uuid4().hex
        summary_path = artifact_dir / f"k6-summary-{suffix}.json"
        command = [str(part).replace("{reportPath}", str(summary_path)) for part in custom_command]
        cwd = request.config.get("workdir")
        result = run_command(
            command,
            cwd=str(Path(cwd).resolve()) if isinstance(cwd, str) else None,
            env=self._config_env(request),
            timeout_seconds=request.timeout_seconds,
        )
        metadata = {
            "executionMode": "custom_command",
            "actualExecution": False,
            "validationClass": "custom_command_contract",
            "namedTool": self.runner_id,
            "namedToolExecuted": False,
            "customCommandExecuted": True,
            "command": result.command,
        }
        return self._result_from_command(
            request=request,
            result=result,
            summary_path=summary_path,
            evidence_path=None,
            metadata=metadata,
            custom_command=True,
        )

    def _result_from_command(
        self,
        *,
        request: RunnerExecutionRequest,
        result: CommandExecutionResult,
        summary_path: Path,
        evidence_path: Path | None,
        metadata: dict[str, Any],
        custom_command: bool,
    ) -> RunnerExecutionResult:
        if result.timed_out:
            return self._failed_command_result(
                request=request,
                result=result,
                tool_status="timeout",
                error="k6 execution timed out",
                metadata=metadata,
                timed_out=True,
            )

        metrics_payload = self._load_summary(summary_path)
        metric_record = (
            self._metric_from_summary(
                metrics_payload,
                request,
                summary_path,
                metadata,
            )
            if metrics_payload is not None
            else None
        )
        if metric_record is None:
            return self._failed_command_result(
                request=request,
                result=result,
                tool_status="tool_error",
                error="k6 summary report missing or malformed",
                metadata=metadata,
            )
        assert metrics_payload is not None

        threshold_exceeded = (
            metric_record.threshold_value is not None
            and metric_record.value > metric_record.threshold_value
        ) or self._summary_threshold_failed(metrics_payload)
        threshold_exit = (
            not custom_command
            and threshold_exceeded
            and result.exit_code in K6_THRESHOLD_EXIT_CODES
        )
        if result.exit_code != 0 and not threshold_exit:
            return self._failed_command_result(
                request=request,
                result=result,
                tool_status="tool_error",
                error=f"k6 process exited with code {result.exit_code}",
                metadata=metadata,
            )

        tool_status = "threshold_exceeded" if threshold_exceeded else "ok"
        common_artifact_metadata = {
            "source": self.runner_id,
            **{
                key: value
                for key, value in metadata.items()
                if key
                in {
                    "executionMode",
                    "actualExecution",
                    "validationClass",
                    "namedTool",
                    "namedToolExecuted",
                    "customCommandExecuted",
                    "binaryName",
                    "binaryVersion",
                    "pinnedVersion",
                    "pinnedBinary",
                    "vus",
                    "duration",
                }
            },
        }
        artifact_refs = [
            RunnerArtifactRef(
                artifact_type=ArtifactType.REPORT,
                uri=str(summary_path),
                summary="k6 raw summary report",
                metadata={
                    **common_artifact_metadata,
                    "rawMetricRef": str(summary_path),
                },
            )
        ]
        if evidence_path is not None:
            report = self._actual_evidence_report(
                request=request,
                result=result,
                metric=metric_record,
                metadata=metadata,
                tool_status=tool_status,
                summary_path=summary_path,
            )
            evidence_path.write_text(
                json.dumps(report, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            artifact_refs.append(
                RunnerArtifactRef(
                    artifact_type=ArtifactType.REPORT,
                    uri=str(evidence_path),
                    summary="k6 named-tool actual evidence report",
                    metadata={
                        **common_artifact_metadata,
                        "rawMetricRef": str(summary_path),
                    },
                )
            )
            metric_record.metadata["actualEvidenceRef"] = str(evidence_path)

        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="completed",
            tool_status=tool_status,
            exit_code=result.exit_code,
            timed_out=False,
            started_at=result.started_at,
            ended_at=result.ended_at,
            duration_ms=result.duration_ms,
            artifact_refs=artifact_refs,
            raw_metrics=[metric_record],
            logs=[
                RunnerLogRecord(
                    level="info",
                    message=f"k6-task={request.task_type}",
                    context={
                        "runner": self.runner_id,
                        "mode": metadata["executionMode"],
                        "thresholdExceeded": threshold_exceeded,
                    },
                ),
                RunnerLogRecord(
                    level="info",
                    message=result.stdout.strip() or "k6 command completed",
                    context={"runner": self.runner_id},
                ),
            ],
            metadata={
                **metadata,
                "command": result.command,
                "rawMetricRef": str(summary_path),
                "thresholdExceeded": threshold_exceeded,
            },
        )

    def _failed_command_result(
        self,
        *,
        request: RunnerExecutionRequest,
        result: CommandExecutionResult,
        tool_status: str,
        error: str,
        metadata: dict[str, Any],
        timed_out: bool = False,
    ) -> RunnerExecutionResult:
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="failed",
            tool_status=tool_status,
            exit_code=result.exit_code,
            timed_out=timed_out,
            started_at=result.started_at,
            ended_at=result.ended_at,
            duration_ms=result.duration_ms,
            logs=[
                RunnerLogRecord(
                    level="error",
                    message=error,
                    context={
                        "runner": self.runner_id,
                        "stderr": result.stderr,
                        "stdout": result.stdout,
                    },
                )
            ],
            error=error,
            metadata={**metadata, "command": result.command},
        )

    def _actual_preflight_failure(
        self,
        request: RunnerExecutionRequest,
        error: str,
        *,
        tool_status: str = "tool_error",
        executable: str | None = None,
        binary_version: str | None = None,
        version_result: CommandExecutionResult | None = None,
    ) -> RunnerExecutionResult:
        now = utcnow()
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="failed",
            tool_status=tool_status,
            exit_code=version_result.exit_code if version_result is not None else -1,
            timed_out=False,
            started_at=version_result.started_at if version_result is not None else now,
            ended_at=version_result.ended_at if version_result is not None else now,
            duration_ms=version_result.duration_ms if version_result is not None else 0,
            logs=[
                RunnerLogRecord(
                    level="error",
                    message=error,
                    context={
                        "runner": self.runner_id,
                        "pinnedVersion": PINNED_K6_VERSION,
                    },
                )
            ],
            error=error,
            metadata={
                "executionMode": "actual_preflight_failed",
                "actualExecution": False,
                "validationClass": "named_tool_actual",
                "namedTool": self.runner_id,
                "namedToolExecuted": False,
                "customCommandExecuted": False,
                "binaryName": Path(executable).name if executable else "k6",
                "binaryPath": executable,
                "binaryVersion": binary_version,
                "pinnedVersion": PINNED_K6_VERSION,
                "pinnedBinary": False,
            },
        )

    def _resolve_named_binary(self, request: RunnerExecutionRequest) -> str | None:
        explicit = request.config.get("binaryPath")
        if isinstance(explicit, str) and explicit:
            path = Path(explicit)
            return str(path.resolve()) if path.is_file() else None
        configured = get_settings().k6_binary_path
        if configured:
            path = Path(configured)
            return str(path.resolve()) if path.is_file() else None
        return resolve_executable(None, ["k6"])

    def _parse_version(
        self,
        version_result: CommandExecutionResult,
    ) -> str | None:
        output = f"{version_result.stdout}\n{version_result.stderr}"
        match = _K6_VERSION_PATTERN.search(output)
        return match.group("version") if match else None

    def _load_profile(self, request: RunnerExecutionRequest) -> dict[str, object]:
        raw_env = request.config.get("env")
        env = raw_env if isinstance(raw_env, dict) else {}
        vus = int(request.config.get("vus") or env.get("K6_VUS") or 1)
        duration = str(request.config.get("duration") or env.get("K6_DURATION") or "1s")
        return {"vus": vus, "duration": duration}

    def _named_metadata(
        self,
        *,
        executable: str,
        binary_version: str,
        load_profile: dict[str, object],
        actual_execution: bool,
        named_tool_executed: bool,
    ) -> dict[str, Any]:
        return {
            "executionMode": "actual",
            "actualExecution": actual_execution,
            "validationClass": "named_tool_actual",
            "namedTool": self.runner_id,
            "namedToolExecuted": named_tool_executed,
            "customCommandExecuted": False,
            "binaryName": Path(executable).name,
            "binaryPath": str(Path(executable).resolve()),
            "binaryVersion": binary_version,
            "pinnedVersion": PINNED_K6_VERSION,
            "pinnedBinary": binary_version == PINNED_K6_VERSION,
            "vus": int(str(load_profile["vus"])),
            "duration": str(load_profile["duration"]),
        }

    def _config_env(self, request: RunnerExecutionRequest) -> dict[str, str]:
        raw_env = request.config.get("env", {})
        if not isinstance(raw_env, dict):
            return {}
        return {str(key): str(value) for key, value in raw_env.items()}

    def _load_summary(self, summary_path: Path) -> dict[str, object] | None:
        if not summary_path.is_file():
            return None
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _metric_from_summary(
        self,
        summary_payload: dict[str, object],
        request: RunnerExecutionRequest,
        summary_path: Path,
        execution_metadata: dict[str, Any],
    ) -> RunnerMetricRecord | None:
        metrics = summary_payload.get("metrics")
        if not isinstance(metrics, dict):
            return None
        http_req_duration = metrics.get("http_req_duration")
        if not isinstance(http_req_duration, dict):
            return None
        nested_values = http_req_duration.get("values")
        values = nested_values if isinstance(nested_values, dict) else http_req_duration
        p95_value = _required_decimal(values.get("p(95)", values.get("p95")))
        if p95_value is None:
            return None

        threshold_value = _decimal(
            request.config.get("thresholdP95Ms"),
            "800",
        )
        baseline_value = _decimal(
            request.config.get("baselineP95Ms"),
            "760",
        )
        return RunnerMetricRecord(
            name="p95",
            value=p95_value,
            unit="ms",
            threshold_value=threshold_value,
            baseline_value=baseline_value,
            metadata={
                "source": self.runner_id,
                "runnerId": self.runner_id,
                "executionMode": execution_metadata["executionMode"],
                "actualExecution": execution_metadata["actualExecution"],
                "validationClass": execution_metadata["validationClass"],
                "rawMetricRef": str(summary_path),
                "summaryStats": self._summary_stats(metrics, values),
                "summaryThresholds": self._summary_thresholds(
                    http_req_duration,
                ),
                **self._baseline_comparison(p95_value, baseline_value),
            },
        )

    def _summary_threshold_failed(
        self,
        summary_payload: dict[str, object],
    ) -> bool:
        metrics = summary_payload.get("metrics")
        if not isinstance(metrics, dict):
            return False
        for raw_metric in metrics.values():
            if not isinstance(raw_metric, dict):
                continue
            thresholds = raw_metric.get("thresholds")
            if not isinstance(thresholds, dict):
                continue
            for outcome in thresholds.values():
                if isinstance(outcome, dict) and outcome.get("ok") is False:
                    return True
                if outcome is True:
                    return True
        return False

    def _summary_thresholds(
        self,
        http_req_duration: dict[str, object],
    ) -> dict[str, bool]:
        thresholds = http_req_duration.get("thresholds")
        if not isinstance(thresholds, dict):
            return {}
        results: dict[str, bool] = {}
        for name, outcome in thresholds.items():
            if isinstance(outcome, dict) and isinstance(
                outcome.get("ok"),
                bool,
            ):
                results[str(name)] = bool(outcome["ok"])
            elif isinstance(outcome, bool):
                # k6 v2 summary-export stores "threshold failed" booleans.
                results[str(name)] = not outcome
        return results

    def _summary_stats(
        self,
        metrics: dict[str, object],
        duration_values: dict[str, object],
    ) -> dict[str, float]:
        stats: dict[str, float] = {}
        for source_key, target_key in (
            ("avg", "avgMs"),
            ("min", "minMs"),
            ("med", "medianMs"),
            ("max", "maxMs"),
            ("p(90)", "p90Ms"),
            ("p(95)", "p95Ms"),
        ):
            value = _required_decimal(duration_values.get(source_key))
            if value is not None:
                stats[target_key] = float(value)
        http_reqs = metrics.get("http_reqs")
        if isinstance(http_reqs, dict):
            nested_values = http_reqs.get("values")
            request_values = nested_values if isinstance(nested_values, dict) else http_reqs
            for source_key, target_key in (("count", "requestCount"), ("rate", "requestRate")):
                value = _required_decimal(request_values.get(source_key))
                if value is not None:
                    stats[target_key] = float(value)
        return stats

    def _baseline_comparison(
        self,
        value: Decimal,
        baseline: Decimal,
    ) -> dict[str, object]:
        delta = value - baseline
        delta_percent = (delta / baseline) * Decimal("100") if baseline != 0 else None
        return {
            "baselineDeltaMs": float(delta),
            "baselineDeltaPercent": (float(delta_percent) if delta_percent is not None else None),
            "baselineRegression": value > baseline,
        }

    def _actual_evidence_report(
        self,
        *,
        request: RunnerExecutionRequest,
        result: CommandExecutionResult,
        metric: RunnerMetricRecord,
        metadata: dict[str, Any],
        tool_status: str,
        summary_path: Path,
    ) -> dict[str, object]:
        return {
            "schemaVersion": "tst-p1-021.k6-actual-report.v1",
            "actualExecution": True,
            "executionMode": "actual",
            "validationClass": "named_tool_actual",
            "namedTool": self.runner_id,
            "namedToolExecuted": True,
            "customCommandExecuted": False,
            "status": "completed",
            "toolStatus": tool_status,
            "exitCode": result.exit_code,
            "taskId": str(request.task_id),
            "executionId": str(request.execution_id),
            "binary": {
                "name": metadata["binaryName"],
                "path": metadata["binaryPath"],
                "version": metadata["binaryVersion"],
                "pinnedVersion": metadata["pinnedVersion"],
                "pinned": metadata["pinnedBinary"],
            },
            "loadProfile": {
                "vus": metadata["vus"],
                "duration": metadata["duration"],
            },
            "metric": {
                "name": metric.name,
                "value": float(metric.value),
                "unit": metric.unit,
                "thresholdValue": (
                    float(metric.threshold_value) if metric.threshold_value is not None else None
                ),
                "baselineValue": (
                    float(metric.baseline_value) if metric.baseline_value is not None else None
                ),
                "baselineDeltaMs": metric.metadata["baselineDeltaMs"],
                "baselineDeltaPercent": metric.metadata["baselineDeltaPercent"],
                "baselineRegression": metric.metadata["baselineRegression"],
            },
            "statistics": metric.metadata["summaryStats"],
            "thresholds": metric.metadata["summaryThresholds"],
            "rawMetricRef": str(summary_path),
        }

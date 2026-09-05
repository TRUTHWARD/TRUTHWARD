# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Any

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
    RunnerFindingRecord,
    RunnerLogRecord,
    utcnow,
)


PINNED_SECURITY_TOOL_VERSIONS: dict[str, str] = {
    "semgrep": "1.163.0",
    "nuclei": "3.8.0",
    "zap": "2.17.0",
}
_VERSION_PATTERN = re.compile(
    r"(?<!\d)v?(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?!\d)"
)


def _slugify(value: str) -> str:
    return value.lower().replace(" ", "-").replace("/", "-").replace("\\", "-")


@dataclass(slots=True)
class _SecurityDefaults:
    category: str
    severity: str
    title: str
    summary: str
    location_kind: str
    location_target: str


class _BaseSecurityRunner(RunnerAdapter):
    domain = TestDomain.SECURITY
    supports_parallelism = True
    default_timeout_seconds = 900

    def __init__(self, runner_id: str, defaults: _SecurityDefaults) -> None:
        self.runner_id = runner_id
        self.defaults = defaults

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
                (
                    f"pinned {self.runner_id} binary or required local target "
                    "configuration is unavailable"
                ),
                tool_status="infra_error",
            )
        return self._run_simulated(
            request,
            reason="security binary or required target configuration not available",
        )

    def _run_simulated(
        self,
        request: RunnerExecutionRequest,
        reason: str,
    ) -> RunnerExecutionResult:
        started_at = utcnow()
        report_uri = (
            f"s3://agentic-qa-artifacts/{request.execution_id}/{request.task_id}/"
            f"{self.runner_id}-report.json"
        )
        location_target = str(
            request.config.get("target") or self.defaults.location_target
        )
        common_metadata = {
            "runnerId": self.runner_id,
            "executionMode": "simulated",
            "actualExecution": False,
            "validationClass": "simulated",
        }
        finding = RunnerFindingRecord(
            source=self.runner_id,
            category=str(request.config.get("category") or self.defaults.category),
            severity=str(request.config.get("severity") or self.defaults.severity),
            title=str(request.config.get("title") or self.defaults.title),
            summary=str(request.config.get("summary") or self.defaults.summary),
            evidence=[{"type": "artifact_ref", "ref": report_uri}],
            location={
                "kind": str(
                    request.config.get("locationKind")
                    or self.defaults.location_kind
                ),
                "target": location_target,
                "file": request.config.get("file"),
                "line": request.config.get("line"),
                "column": request.config.get("column"),
            },
            confidence=float(request.config.get("confidence", 0.93)),
            dedupe_key=(
                f"{self.runner_id}:{self.defaults.category}:"
                f"{_slugify(location_target)}:{_slugify(self.defaults.title)}"
            ),
            raw_ref=report_uri,
            metadata={**common_metadata, "toolStatus": "findings_detected"},
        )

        if bool(request.config.get("simulateNoFindings")):
            findings: list[RunnerFindingRecord] = []
            tool_status = "ok"
        else:
            findings = [finding]
            tool_status = "findings_detected"

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
                    summary=f"{self.runner_id} simulated raw report reference",
                    metadata={"source": self.runner_id, **common_metadata},
                )
            ],
            raw_findings=findings,
            logs=[
                RunnerLogRecord(
                    level="warning" if findings else "info",
                    message=f"{self.runner_id}-task={request.task_type}",
                    context={
                        "runner": self.runner_id,
                        "findingCount": len(findings),
                        "mode": "simulated",
                    },
                )
            ],
            metadata={
                **common_metadata,
                "namedTool": self.runner_id,
                "namedToolExecuted": False,
                "customCommandExecuted": False,
                "actualCallPerformed": False,
                "fallbackReason": reason,
            },
        )

    def _run_named_actual(
        self,
        request: RunnerExecutionRequest,
    ) -> RunnerExecutionResult | None:
        executable = self._resolve_runner_executable(request)
        if executable is None:
            return None

        artifact_dir = ensure_artifact_dir(
            str(get_settings().runner_artifact_dir),
            str(request.execution_id),
            str(request.task_id),
        )
        command, report_path, cwd = self._build_named_command(
            executable,
            artifact_dir,
            request,
        )
        if command is None or report_path is None:
            return None

        version_command, version_cwd = self._version_command(
            executable,
            artifact_dir,
        )
        version_result = run_command(
            version_command,
            cwd=version_cwd,
            env=self._config_env(request, artifact_dir),
            timeout_seconds=min(max(1, request.timeout_seconds), 30),
        )
        binary_version = self._parse_version(version_result)
        if (
            version_result.timed_out
            or version_result.exit_code != 0
            or binary_version is None
        ):
            return self._actual_preflight_failure(
                request,
                f"{self.runner_id} binary version probe failed",
                executable=executable,
                version_result=version_result,
            )

        pinned_version = PINNED_SECURITY_TOOL_VERSIONS[self.runner_id]
        if binary_version != pinned_version:
            return self._actual_preflight_failure(
                request,
                (
                    f"{self.runner_id} binary version {binary_version!r} does not "
                    f"match repository pin {pinned_version!r}"
                ),
                executable=executable,
                binary_version=binary_version,
                version_result=version_result,
            )

        metadata = self._named_metadata(
            executable=executable,
            binary_version=binary_version,
        )
        result = run_command(
            command,
            cwd=cwd,
            env=self._config_env(request, artifact_dir),
            timeout_seconds=request.timeout_seconds,
        )
        return self._result_from_command(
            request=request,
            result=result,
            report_path=report_path,
            artifact_dir=artifact_dir,
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
        report_path = (
            artifact_dir
            / f"{self.runner_id}-report{self._report_extension()}"
        )
        target = str(request.config.get("target") or "")
        command = [
            str(part)
            .replace("{reportPath}", str(report_path))
            .replace("{target}", target)
            for part in custom_command
        ]
        cwd = request.config.get("workdir")
        result = run_command(
            command,
            cwd=str(Path(cwd).resolve()) if isinstance(cwd, str) else None,
            env=self._config_env(request, artifact_dir),
            timeout_seconds=request.timeout_seconds,
        )
        metadata: dict[str, Any] = {
            "executionMode": "custom_command",
            "actualExecution": False,
            "validationClass": "custom_command_contract",
            "namedTool": self.runner_id,
            "namedToolExecuted": False,
            "customCommandExecuted": True,
            "actualCallPerformed": False,
        }
        return self._result_from_command(
            request=request,
            result=result,
            report_path=report_path,
            artifact_dir=artifact_dir,
            metadata=metadata,
            custom_command=True,
        )

    def _result_from_command(
        self,
        *,
        request: RunnerExecutionRequest,
        result: CommandExecutionResult,
        report_path: Path,
        artifact_dir: Path,
        metadata: dict[str, Any],
        custom_command: bool,
    ) -> RunnerExecutionResult:
        command_metadata = {
            **metadata,
            "command": result.command,
            "exitCode": result.exit_code,
        }
        if result.timed_out:
            return self._failed_command_result(
                request=request,
                result=result,
                tool_status="timeout",
                error=f"{self.runner_id} execution timed out",
                metadata=command_metadata,
                timed_out=True,
            )

        raw_findings = self._parse_actual_report(report_path)
        if raw_findings is None:
            return self._failed_command_result(
                request=request,
                result=result,
                tool_status="tool_error",
                error=f"{self.runner_id} report missing or invalid",
                metadata=command_metadata,
                report_path=report_path,
            )

        expected_nonzero = self._is_expected_nonzero_exit(
            result.exit_code,
            raw_findings,
            custom_command=custom_command,
        )
        if result.exit_code != 0 and not expected_nonzero:
            return self._failed_command_result(
                request=request,
                result=result,
                tool_status="tool_error",
                error=(
                    f"{self.runner_id} exited with unexpected code "
                    f"{result.exit_code}"
                ),
                metadata=command_metadata,
                report_path=report_path,
            )

        tool_status = "findings_detected" if raw_findings else "ok"
        completed_metadata = {
            **command_metadata,
            "actualCallPerformed": not custom_command,
            "findingCount": len(raw_findings),
            "expectedNonzeroExit": expected_nonzero,
        }
        evidence_path: Path | None = None
        if not custom_command:
            evidence_path = artifact_dir / f"{self.runner_id}-actual-evidence.json"
            evidence_path.write_text(
                json.dumps(
                    self._actual_evidence_report(
                        request=request,
                        result=result,
                        report_path=report_path,
                        metadata=completed_metadata,
                        tool_status=tool_status,
                    ),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            completed_metadata["actualEvidenceRef"] = str(evidence_path)

        finding_metadata = self._record_metadata(completed_metadata)
        for finding in raw_findings:
            finding.metadata.update(finding_metadata)

        artifact_metadata = {
            "source": self.runner_id,
            **self._record_metadata(completed_metadata),
        }
        artifact_refs = [
            RunnerArtifactRef(
                artifact_type=ArtifactType.REPORT,
                uri=str(report_path),
                summary=f"{self.runner_id} raw report",
                metadata=artifact_metadata,
            )
        ]
        if evidence_path is not None:
            artifact_refs.append(
                RunnerArtifactRef(
                    artifact_type=ArtifactType.REPORT,
                    uri=str(evidence_path),
                    summary=f"{self.runner_id} named actual execution evidence",
                    metadata=artifact_metadata,
                )
            )

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
            raw_findings=raw_findings,
            logs=[
                RunnerLogRecord(
                    level="warning" if raw_findings else "info",
                    message=f"{self.runner_id}-task={request.task_type}",
                    context={
                        "runner": self.runner_id,
                        "mode": metadata["executionMode"],
                        "findingCount": len(raw_findings),
                        "exitCode": result.exit_code,
                        "expectedNonzeroExit": expected_nonzero,
                    },
                ),
                RunnerLogRecord(
                    level="info",
                    message=(
                        result.stdout.strip()
                        or f"{self.runner_id} command completed"
                    ),
                    context={"runner": self.runner_id},
                ),
            ],
            metadata=completed_metadata,
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
        report_path: Path | None = None,
    ) -> RunnerExecutionResult:
        artifact_refs: list[RunnerArtifactRef] = []
        if report_path is not None and report_path.is_file():
            artifact_refs.append(
                RunnerArtifactRef(
                    artifact_type=ArtifactType.REPORT,
                    uri=str(report_path),
                    summary=f"{self.runner_id} failed raw report",
                    metadata={
                        "source": self.runner_id,
                        **self._record_metadata(metadata),
                    },
                )
            )
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
            artifact_refs=artifact_refs,
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
            metadata=metadata,
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
        pinned_version = PINNED_SECURITY_TOOL_VERSIONS[self.runner_id]
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="failed",
            tool_status=tool_status,
            exit_code=(
                version_result.exit_code if version_result is not None else -1
            ),
            timed_out=False,
            started_at=(
                version_result.started_at if version_result is not None else now
            ),
            ended_at=(
                version_result.ended_at if version_result is not None else now
            ),
            duration_ms=(
                version_result.duration_ms if version_result is not None else 0
            ),
            logs=[
                RunnerLogRecord(
                    level="error",
                    message=error,
                    context={
                        "runner": self.runner_id,
                        "pinnedVersion": pinned_version,
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
                "actualCallPerformed": False,
                "binaryName": (
                    Path(executable).name if executable else self.runner_id
                ),
                "binaryPath": executable,
                "binaryVersion": binary_version,
                "pinnedVersion": pinned_version,
                "pinnedBinary": False,
            },
        )

    def _resolve_runner_executable(
        self,
        request: RunnerExecutionRequest,
    ) -> str | None:
        explicit = request.config.get("binaryPath")
        if isinstance(explicit, str) and explicit:
            path = Path(explicit)
            return str(path.resolve()) if path.is_file() else None

        settings = get_settings()
        configured = {
            "semgrep": settings.semgrep_binary_path,
            "nuclei": settings.nuclei_binary_path,
            "zap": settings.zap_binary_path,
        }[self.runner_id]
        if configured:
            path = Path(configured)
            return str(path.resolve()) if path.is_file() else None

        candidates = {
            "semgrep": ["semgrep", "pysemgrep"],
            "nuclei": ["nuclei"],
            "zap": ["zap", "zap.bat", "zap.sh"],
        }[self.runner_id]
        return resolve_executable(None, candidates)

    def _build_named_command(
        self,
        executable: str,
        artifact_dir: Path,
        request: RunnerExecutionRequest,
    ) -> tuple[list[str] | None, Path | None, str | None]:
        if self.runner_id == "semgrep":
            target_path = (
                request.config.get("targetPath") or request.config.get("target")
            )
            if not isinstance(target_path, str):
                return None, None, None
            semgrep_target = Path(target_path)
            if not semgrep_target.exists():
                return None, None, None
            rules = request.config.get("semgrepConfig")
            if not isinstance(rules, str) or not Path(rules).exists():
                return None, None, None
            report_path = artifact_dir / "semgrep-report.json"
            command = [
                executable,
                "scan",
                "--json",
                "--error",
                "--metrics=off",
                "--jobs=1",
                "--output",
                str(report_path),
                "--config",
                str(Path(rules).resolve()),
                str(semgrep_target.resolve()),
            ]
            default_workdir = semgrep_target.resolve().parent
            cwd = Path(request.config.get("workdir", default_workdir)).resolve()
            return command, report_path, str(cwd)

        if self.runner_id == "nuclei":
            nuclei_target = request.config.get("target")
            templates = request.config.get("templates")
            if not isinstance(nuclei_target, str) or not isinstance(templates, str):
                return None, None, None
            if not Path(templates).exists():
                return None, None, None
            report_path = artifact_dir / "nuclei-report.jsonl"
            command = [
                executable,
                "-u",
                nuclei_target,
                "-jsonl",
                "-o",
                str(report_path),
                "-t",
                str(Path(templates).resolve()),
                "-duc",
                "-ni",
                "-no-stdin",
                "-nc",
            ]
            cwd = Path(request.config.get("workdir", artifact_dir)).resolve()
            return command, report_path, str(cwd)

        if self.runner_id == "zap":
            zap_target = request.config.get("target")
            if not isinstance(zap_target, str):
                return None, None, None
            report_path = artifact_dir / "zap-report.json"
            zap_home = artifact_dir / "zap-home"
            zap_home.mkdir(parents=True, exist_ok=True)
            command = [
                executable,
                "-cmd",
                "-silent",
                "-dir",
                str(zap_home),
                "-quickurl",
                zap_target,
                "-quickout",
                str(report_path),
            ]
            default_workdir = (
                Path(executable).resolve().parent
                if Path(executable).exists()
                else artifact_dir
            )
            cwd = Path(request.config.get("workdir", default_workdir)).resolve()
            return command, report_path, str(cwd)

        return None, None, None

    def _version_command(
        self,
        executable: str,
        artifact_dir: Path,
    ) -> tuple[list[str], str | None]:
        if self.runner_id == "semgrep":
            return [executable, "--version"], None
        if self.runner_id == "nuclei":
            return [executable, "-version"], None

        version_home = artifact_dir / "zap-version-home"
        version_home.mkdir(parents=True, exist_ok=True)
        cwd = (
            str(Path(executable).resolve().parent)
            if Path(executable).exists()
            else None
        )
        return (
            [
                executable,
                "-cmd",
                "-silent",
                "-dir",
                str(version_home),
                "-version",
            ],
            cwd,
        )

    def _parse_version(
        self,
        version_result: CommandExecutionResult,
    ) -> str | None:
        output = f"{version_result.stdout}\n{version_result.stderr}"
        versions = [
            match.group("version") for match in _VERSION_PATTERN.finditer(output)
        ]
        pinned = PINNED_SECURITY_TOOL_VERSIONS[self.runner_id]
        if pinned in versions:
            return pinned
        return versions[-1] if versions else None

    def _named_metadata(
        self,
        *,
        executable: str,
        binary_version: str,
    ) -> dict[str, Any]:
        pinned_version = PINNED_SECURITY_TOOL_VERSIONS[self.runner_id]
        return {
            "executionMode": "actual",
            "actualExecution": True,
            "validationClass": "named_tool_actual",
            "namedTool": self.runner_id,
            "namedToolExecuted": True,
            "customCommandExecuted": False,
            "actualCallPerformed": True,
            "binaryName": Path(executable).name,
            "binaryPath": str(Path(executable).resolve()),
            "binaryVersion": binary_version,
            "pinnedVersion": pinned_version,
            "pinnedBinary": binary_version == pinned_version,
        }

    def _report_extension(self) -> str:
        if self.runner_id == "nuclei":
            return ".jsonl"
        return ".json"

    def _parse_actual_report(
        self,
        report_path: Path,
    ) -> list[RunnerFindingRecord] | None:
        if not report_path.is_file():
            return None
        try:
            if self.runner_id == "semgrep":
                payload = json.loads(report_path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict) or not isinstance(
                    payload.get("results"),
                    list,
                ):
                    return None
                return self._parse_semgrep_payload(payload, report_path)
            if self.runner_id == "nuclei":
                lines = [
                    line
                    for line in report_path.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if line.strip()
                ]
                return self._parse_nuclei_lines(lines, report_path)
            if self.runner_id == "zap":
                payload = json.loads(report_path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict):
                    return None
                if not isinstance(payload.get("site"), list) and not isinstance(
                    payload.get("alerts"),
                    list,
                ):
                    return None
                return self._parse_zap_payload(payload, report_path)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return None
        return None

    def _parse_semgrep_payload(
        self,
        payload: dict[str, object],
        report_path: Path,
    ) -> list[RunnerFindingRecord]:
        findings: list[RunnerFindingRecord] = []
        results = payload.get("results", [])
        assert isinstance(results, list)
        for item in results:
            if not isinstance(item, dict):
                raise ValueError("Semgrep result must be an object")
            extra = item.get("extra")
            start = item.get("start")
            extra_payload = extra if isinstance(extra, dict) else {}
            start_payload = start if isinstance(start, dict) else {}
            path = str(item.get("path") or self.defaults.location_target)
            check_id = str(item.get("check_id") or self.defaults.title)
            line = start_payload.get("line")
            column = start_payload.get("col")
            findings.append(
                RunnerFindingRecord(
                    source=self.runner_id,
                    category="sast",
                    severity=self._normalize_severity(
                        str(extra_payload.get("severity") or "medium")
                    ),
                    title=check_id,
                    summary=str(
                        extra_payload.get("message") or self.defaults.summary
                    ),
                    evidence=[{"type": "inline_fact", "ref": check_id}],
                    location={
                        "kind": "file",
                        "target": path,
                        "file": path,
                        "line": line,
                        "column": column,
                    },
                    confidence=0.9,
                    dedupe_key=(
                        f"{self.runner_id}:sast:{_slugify(path)}:"
                        f"{_slugify(check_id)}:{line or 0}:{column or 0}"
                    ),
                    raw_ref=str(report_path),
                    metadata={},
                )
            )
        return findings

    def _parse_nuclei_lines(
        self,
        lines: list[str],
        report_path: Path,
    ) -> list[RunnerFindingRecord]:
        findings: list[RunnerFindingRecord] = []
        for line in lines:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("Nuclei result must be an object")
            info = payload.get("info")
            info_payload = info if isinstance(info, dict) else {}
            target = str(
                payload.get("matched-at")
                or payload.get("host")
                or self.defaults.location_target
            )
            template_id = str(
                payload.get("template-id") or self.defaults.title
            )
            title = str(
                info_payload.get("name")
                or payload.get("template-id")
                or self.defaults.title
            )
            findings.append(
                RunnerFindingRecord(
                    source=self.runner_id,
                    category="template_scan",
                    severity=self._normalize_severity(
                        str(info_payload.get("severity") or "medium")
                    ),
                    title=title,
                    summary=str(
                        info_payload.get("description")
                        or info_payload.get("name")
                        or self.defaults.summary
                    ),
                    evidence=[{"type": "inline_fact", "ref": template_id}],
                    location={"kind": "url_endpoint", "target": target},
                    confidence=0.88,
                    dedupe_key=(
                        f"{self.runner_id}:template_scan:{_slugify(target)}:"
                        f"{_slugify(template_id)}"
                    ),
                    raw_ref=str(report_path),
                    metadata={},
                )
            )
        return findings

    def _parse_zap_payload(
        self,
        payload: dict[str, object],
        report_path: Path,
    ) -> list[RunnerFindingRecord]:
        alerts: list[dict[str, object]] = []
        sites = payload.get("site")
        if isinstance(sites, list):
            for site in sites:
                if not isinstance(site, dict):
                    raise ValueError("ZAP site must be an object")
                site_name = str(
                    site.get("@name") or self.defaults.location_target
                )
                site_alerts = site.get("alerts", [])
                if not isinstance(site_alerts, list):
                    raise ValueError("ZAP alerts must be a list")
                for alert in site_alerts:
                    if not isinstance(alert, dict):
                        raise ValueError("ZAP alert must be an object")
                    alerts.append({**alert, "_site": site_name})
        else:
            direct_alerts = payload.get("alerts", [])
            assert isinstance(direct_alerts, list)
            for alert in direct_alerts:
                if not isinstance(alert, dict):
                    raise ValueError("ZAP alert must be an object")
                alerts.append(dict(alert))

        findings: list[RunnerFindingRecord] = []
        for alert in alerts:
            site_name = str(
                alert.get("_site") or self.defaults.location_target
            )
            title = str(alert.get("alert") or self.defaults.title)
            summary = str(
                alert.get("desc")
                or alert.get("description")
                or self.defaults.summary
            )
            risk = str(alert.get("riskdesc") or alert.get("risk") or "medium")
            risk_label = risk.split("(", maxsplit=1)[0].strip()
            plugin_id = str(
                alert.get("pluginid") or alert.get("pluginId") or title
            )
            findings.append(
                RunnerFindingRecord(
                    source=self.runner_id,
                    category="dast",
                    severity=self._normalize_severity(risk_label),
                    title=title,
                    summary=summary,
                    evidence=[{"type": "inline_fact", "ref": plugin_id}],
                    location={
                        "kind": "url_endpoint",
                        "target": site_name,
                    },
                    confidence=0.9,
                    dedupe_key=(
                        f"{self.runner_id}:dast:{_slugify(site_name)}:"
                        f"{_slugify(plugin_id)}"
                    ),
                    raw_ref=str(report_path),
                    metadata={},
                )
            )
        return findings

    def _normalize_severity(self, raw: str) -> str:
        value = raw.lower()
        if "critical" in value:
            return "critical"
        if "high" in value or "error" in value:
            return "high"
        if "medium" in value or "warn" in value:
            return "medium"
        if "low" in value or "info" in value:
            return "low"
        return "medium"

    def _is_expected_nonzero_exit(
        self,
        exit_code: int,
        raw_findings: list[RunnerFindingRecord],
        *,
        custom_command: bool,
    ) -> bool:
        return (
            not custom_command
            and self.runner_id == "semgrep"
            and exit_code == 1
            and bool(raw_findings)
        )

    def _record_metadata(
        self,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        allowed = {
            "executionMode",
            "actualExecution",
            "validationClass",
            "namedTool",
            "namedToolExecuted",
            "customCommandExecuted",
            "actualCallPerformed",
            "binaryName",
            "binaryPath",
            "binaryVersion",
            "pinnedVersion",
            "pinnedBinary",
            "exitCode",
            "findingCount",
            "expectedNonzeroExit",
            "actualEvidenceRef",
        }
        return {key: value for key, value in metadata.items() if key in allowed}

    def _actual_evidence_report(
        self,
        *,
        request: RunnerExecutionRequest,
        result: CommandExecutionResult,
        report_path: Path,
        metadata: dict[str, Any],
        tool_status: str,
    ) -> dict[str, object]:
        return {
            "schemaVersion": "tst-p1-022.security-actual-report.v1",
            "actualExecution": True,
            "executionMode": "actual",
            "validationClass": "named_tool_actual",
            "namedTool": self.runner_id,
            "namedToolExecuted": True,
            "customCommandExecuted": False,
            "status": "completed",
            "toolStatus": tool_status,
            "exitCode": result.exit_code,
            "expectedNonzeroExit": metadata["expectedNonzeroExit"],
            "findingCount": metadata["findingCount"],
            "taskId": str(request.task_id),
            "executionId": str(request.execution_id),
            "binary": {
                "name": metadata["binaryName"],
                "path": metadata["binaryPath"],
                "version": metadata["binaryVersion"],
                "pinnedVersion": metadata["pinnedVersion"],
                "pinned": metadata["pinnedBinary"],
            },
            "command": result.command,
            "rawFindingRef": str(report_path),
        }

    def _config_env(
        self,
        request: RunnerExecutionRequest,
        artifact_dir: Path,
    ) -> dict[str, str]:
        raw_env = request.config.get("env", {})
        env = (
            {str(key): str(value) for key, value in raw_env.items()}
            if isinstance(raw_env, dict)
            else {}
        )
        if self.runner_id == "semgrep":
            if os.name == "nt":
                short_temp = (
                    Path.cwd()
                    / ".tmp"
                    / "sg"
                    / (
                        f"{request.execution_id.hex[:8]}-"
                        f"{request.task_id.hex[:8]}"
                    )
                ).resolve()
                short_temp.mkdir(parents=True, exist_ok=True)
                env.setdefault("TEMP", str(short_temp))
                env.setdefault("TMP", str(short_temp))
            config_home = artifact_dir / "semgrep-config"
            cache_home = artifact_dir / "semgrep-cache"
            config_home.mkdir(parents=True, exist_ok=True)
            cache_home.mkdir(parents=True, exist_ok=True)
            env.setdefault("XDG_CONFIG_HOME", str(config_home))
            env.setdefault("XDG_CACHE_HOME", str(cache_home))
            env.setdefault(
                "SEMGREP_LOG_FILE",
                str(config_home / ".semgrep" / "semgrep.log"),
            )
            env.setdefault(
                "SEMGREP_SETTINGS_FILE",
                str(config_home / ".semgrep" / "settings.yml"),
            )
            env.setdefault("SEMGREP_SEND_METRICS", "off")
            env.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
            env.setdefault("COLUMNS", "120")
            env.setdefault("LINES", "40")
            env.setdefault("PYTHONPATH", "")
        return env


class ZapRunner(_BaseSecurityRunner):
    def __init__(self) -> None:
        super().__init__(
            "zap",
            _SecurityDefaults(
                category="dast",
                severity="high",
                title="Missing authorization check",
                summary=(
                    "Endpoint is reachable without required authorization "
                    "validation."
                ),
                location_kind="url_endpoint",
                location_target="/api/orders/{id}",
            ),
        )


class SemgrepRunner(_BaseSecurityRunner):
    def __init__(self) -> None:
        super().__init__(
            "semgrep",
            _SecurityDefaults(
                category="sast",
                severity="medium",
                title="Unsanitized input sink",
                summary=(
                    "Code path reaches a sensitive sink without sanitization."
                ),
                location_kind="file",
                location_target="backend/app/security.py",
            ),
        )


class NucleiRunner(_BaseSecurityRunner):
    def __init__(self) -> None:
        super().__init__(
            "nuclei",
            _SecurityDefaults(
                category="template_scan",
                severity="medium",
                title="Exposed debug endpoint",
                summary=(
                    "A known template matched an exposed diagnostic surface."
                ),
                location_kind="url_endpoint",
                location_target="/debug",
            ),
        )

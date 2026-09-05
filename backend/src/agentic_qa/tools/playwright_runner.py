# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from agentic_qa.domain.enums import ArtifactType, TestDomain
from agentic_qa.infra.settings import get_settings
from agentic_qa.tools.command_runner import ensure_artifact_dir, resolve_executable, run_command
from agentic_qa.tools.runner_protocols import (
    RunnerAdapter,
    RunnerArtifactRef,
    RunnerExecutionRequest,
    RunnerExecutionResult,
    RunnerFindingRecord,
    RunnerLogRecord,
    utcnow,
)


class PlaywrightRunner(RunnerAdapter):
    runner_id = "playwright"
    domain = TestDomain.FUNCTIONAL
    supports_parallelism = True
    default_timeout_seconds = 600

    def run(self, request: RunnerExecutionRequest) -> RunnerExecutionResult:
        if self._actual_execution_requested(request):
            return self._run_named_playwright(request, mode="execute")
        started_at = utcnow()
        trace_uri = f"s3://agentic-qa-artifacts/{request.execution_id}/{request.task_id}/trace.zip"
        screenshot_uri = f"s3://agentic-qa-artifacts/{request.execution_id}/{request.task_id}/failed-page.png"
        ended_at = utcnow()
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="completed",
            tool_status="ok",
            exit_code=0,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            artifact_refs=[
                RunnerArtifactRef(
                    artifact_type=ArtifactType.TRACE,
                    uri=trace_uri,
                    summary="playwright trace",
                    metadata={
                        "source": self.runner_id,
                        "executionMode": "simulated",
                        "actualExecution": False,
                        "validationClass": "simulated",
                    },
                ),
                RunnerArtifactRef(
                    artifact_type=ArtifactType.SCREENSHOT,
                    uri=screenshot_uri,
                    summary="playwright screenshot",
                    metadata={
                        "source": self.runner_id,
                        "executionMode": "simulated",
                        "actualExecution": False,
                        "validationClass": "simulated",
                    },
                ),
            ],
            logs=[
                RunnerLogRecord(
                    level="info",
                    message=f"playwright-task={request.task_type}",
                    context={"runner": self.runner_id},
                )
            ],
            metadata={
                "executionMode": "simulated",
                "actualExecution": False,
                "validationClass": "simulated",
                "namedToolExecuted": False,
                "customCommandExecuted": False,
            },
        )

    def capture_visual_artifacts(self, request: RunnerExecutionRequest) -> RunnerExecutionResult:
        if self._actual_execution_requested(request):
            return self._run_named_playwright(request, mode="capture")
        custom_command = self._capture_custom_command_artifacts(request)
        if custom_command is not None:
            return custom_command
        return self._capture_generated_visual_artifacts(request, reason="playwright visual capture command not configured")

    def _capture_generated_visual_artifacts(self, request: RunnerExecutionRequest, reason: str) -> RunnerExecutionResult:
        started_at = utcnow()
        artifact_dir = ensure_artifact_dir(
            str(get_settings().runner_artifact_dir),
            str(request.execution_id),
            str(request.task_id),
        )
        screenshot_path = artifact_dir / "visual-pre-action.png"
        dom_path = artifact_dir / "dom-snapshot.json"
        accessibility_path = artifact_dir / "accessibility-tree.json"
        semantic_action = request.config.get("semanticAction") if isinstance(request.config.get("semanticAction"), dict) else {}
        target = semantic_action.get("semanticTarget") if isinstance(semantic_action.get("semanticTarget"), dict) else {}
        hints = semantic_action.get("targetHints") if isinstance(semantic_action.get("targetHints"), dict) else {}
        selector = str(hints.get("selector") or hints.get("css") or "")
        role = str(target.get("role") or "generic")
        name = str(target.get("name") or target.get("intent") or "visual target")
        target_url = str(request.config.get("targetUrl") or request.config.get("url") or "about:blank")

        screenshot_path.write_bytes(base64.b64decode(_ONE_PIXEL_PNG_BASE64))
        dom_path.write_text(
            json.dumps(
                {
                    "url": target_url,
                    "nodes": [
                        {
                            "selector": selector,
                            "role": role,
                            "name": name,
                            "text": name,
                            "visible": True,
                        }
                    ],
                    "redaction": {"status": "redacted"},
                },
                ensure_ascii=True,
            ),
            encoding="utf-8",
        )
        accessibility_path.write_text(
            json.dumps(
                {
                    "role": "document",
                    "name": target_url,
                    "children": [{"role": role, "name": name, "selector": selector}],
                    "redaction": {"status": "redacted"},
                },
                ensure_ascii=True,
            ),
            encoding="utf-8",
        )
        ended_at = utcnow()
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="completed",
            tool_status="ok",
            exit_code=0,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            artifact_refs=self._visual_artifact_refs(
                screenshot_path=screenshot_path,
                dom_path=dom_path,
                accessibility_path=accessibility_path,
                execution_mode="generated",
            ),
            logs=[
                RunnerLogRecord(
                    level="info",
                    message="playwright visual artifacts captured",
                    context={"runner": self.runner_id, "mode": "generated", "reason": reason},
                )
            ],
            metadata={
                "executionMode": "generated",
                "actualExecution": False,
                "validationClass": "simulated",
                "namedToolExecuted": False,
                "customCommandExecuted": False,
                "fallbackReason": reason,
            },
        )

    def _capture_custom_command_artifacts(self, request: RunnerExecutionRequest) -> RunnerExecutionResult | None:
        command_template = request.config.get("visualCaptureCommand") or request.config.get("command")
        if not isinstance(command_template, list) or not command_template:
            return None
        artifact_dir = ensure_artifact_dir(
            str(get_settings().runner_artifact_dir),
            str(request.execution_id),
            str(request.task_id),
        )
        screenshot_path = artifact_dir / "visual-pre-action.png"
        dom_path = artifact_dir / "dom-snapshot.json"
        accessibility_path = artifact_dir / "accessibility-tree.json"
        trace_path = artifact_dir / "trace.zip"
        target_url = str(request.config.get("targetUrl") or request.config.get("url") or "")
        replacements = {
            "{artifactDir}": str(artifact_dir),
            "{screenshotPath}": str(screenshot_path),
            "{domSnapshotPath}": str(dom_path),
            "{accessibilityTreePath}": str(accessibility_path),
            "{tracePath}": str(trace_path),
            "{targetUrl}": target_url,
        }
        command = [self._replace_placeholders(str(part), replacements) for part in command_template]
        cwd = request.config.get("workdir")
        result = run_command(
            command,
            cwd=str(Path(cwd).resolve()) if isinstance(cwd, str) else None,
            env=self._config_env(request),
            timeout_seconds=request.timeout_seconds,
        )
        if result.timed_out:
            return RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=self.runner_id,
                domain=request.domain,
                status="failed",
                tool_status="timeout",
                exit_code=result.exit_code,
                timed_out=True,
                started_at=result.started_at,
                ended_at=result.ended_at,
                duration_ms=result.duration_ms,
                logs=[
                    RunnerLogRecord(
                        level="error",
                        message="playwright visual capture timed out",
                        context={"stderr": result.stderr},
                    )
                ],
                error="playwright visual capture timed out",
                metadata={
                    "executionMode": "custom_command",
                    "actualExecution": False,
                    "validationClass": "custom_command_contract",
                    "namedToolExecuted": False,
                    "customCommandExecuted": True,
                    "command": result.command,
                },
            )
        missing = [
            str(path)
            for path in (screenshot_path, dom_path, accessibility_path)
            if not path.exists()
        ]
        if missing or result.exit_code != 0:
            return RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=self.runner_id,
                domain=request.domain,
                status="failed",
                tool_status="tool_error",
                exit_code=result.exit_code,
                timed_out=False,
                started_at=result.started_at,
                ended_at=result.ended_at,
                duration_ms=result.duration_ms,
                logs=[
                    RunnerLogRecord(
                        level="error",
                        message="playwright visual capture artifacts missing or command failed",
                        context={"missing": missing, "stdout": result.stdout, "stderr": result.stderr},
                    )
                ],
                error="playwright visual capture artifacts missing or command failed",
                metadata={
                    "executionMode": "custom_command",
                    "actualExecution": False,
                    "validationClass": "custom_command_contract",
                    "namedToolExecuted": False,
                    "customCommandExecuted": True,
                    "command": result.command,
                },
            )
        artifact_refs = self._visual_artifact_refs(
            screenshot_path=screenshot_path,
            dom_path=dom_path,
            accessibility_path=accessibility_path,
            execution_mode="custom_command",
        )
        if trace_path.exists():
            artifact_refs.append(
                RunnerArtifactRef(
                    artifact_type=ArtifactType.TRACE,
                    uri=str(trace_path),
                    summary="playwright trace",
                    metadata={
                        "source": self.runner_id,
                        "executionMode": "custom_command",
                        "actualExecution": False,
                        "validationClass": "custom_command_contract",
                    },
                )
            )
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="completed",
            tool_status="ok",
            exit_code=result.exit_code,
            timed_out=False,
            started_at=result.started_at,
            ended_at=result.ended_at,
            duration_ms=result.duration_ms,
            artifact_refs=artifact_refs,
            logs=[
                RunnerLogRecord(
                    level="info",
                    message=result.stdout.strip() or "playwright visual artifacts captured",
                    context={"runner": self.runner_id, "mode": "custom_command"},
                )
            ],
            metadata={
                "executionMode": "custom_command",
                "actualExecution": False,
                "validationClass": "custom_command_contract",
                "namedToolExecuted": False,
                "customCommandExecuted": True,
                "command": result.command,
            },
        )

    def _run_named_playwright(
        self,
        request: RunnerExecutionRequest,
        *,
        mode: str,
    ) -> RunnerExecutionResult:
        artifact_dir = ensure_artifact_dir(
            str(get_settings().runner_artifact_dir),
            str(request.execution_id),
            str(request.task_id),
        )
        input_path = artifact_dir / f"playwright-{mode}-request.json"
        report_path = artifact_dir / f"playwright-{mode}-report.json"
        plan, bindings, validation_error = self._actual_execution_plan(request, mode=mode)
        if validation_error:
            return self._failed_actual_preflight_result(request, validation_error)
        input_path.write_text(
            json.dumps(plan, ensure_ascii=True, sort_keys=True),
            encoding="utf-8",
        )

        repository_root = self._repository_root()
        runtime_script = repository_root / "tools" / "playwright" / "semantic_action_runner.mjs"
        node_executable = resolve_executable(None, ["node", "node.exe"])
        if node_executable is None or not runtime_script.exists():
            missing = "node executable" if node_executable is None else str(runtime_script)
            return self._failed_actual_preflight_result(
                request,
                f"named Playwright runtime dependency is missing: {missing}",
            )

        command = [
            node_executable,
            str(runtime_script),
            "--input",
            str(input_path),
            "--artifact-dir",
            str(artifact_dir),
            "--report",
            str(report_path),
        ]
        configured_browser_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
        child_env = {
            "PLAYWRIGHT_BROWSERS_PATH": configured_browser_path or str(repository_root / ".ms-playwright"),
            "AGENTIC_QA_PLAYWRIGHT_VALUE_BINDINGS_JSON": json.dumps(
                bindings,
                ensure_ascii=True,
            ),
        }
        command_result = run_command(
            command,
            cwd=str(repository_root),
            env=child_env,
            timeout_seconds=request.timeout_seconds,
        )
        redacted_stdout = self._redact_text(command_result.stdout, bindings.values())
        redacted_stderr = self._redact_text(command_result.stderr, bindings.values())

        report = self._read_actual_report(report_path)
        artifact_refs = self._actual_artifact_refs(report, report_path)
        if command_result.timed_out:
            return RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=self.runner_id,
                domain=request.domain,
                status="failed",
                tool_status="timeout",
                exit_code=command_result.exit_code,
                timed_out=True,
                started_at=command_result.started_at,
                ended_at=command_result.ended_at,
                duration_ms=command_result.duration_ms,
                artifact_refs=artifact_refs,
                logs=[
                    RunnerLogRecord(
                        level="error",
                        message="named Playwright execution timed out",
                        context={
                            "runner": self.runner_id,
                            "validationClass": "named_tool_actual",
                            "stderr": redacted_stderr,
                        },
                    )
                ],
                error="named Playwright execution timed out",
                metadata=self._actual_result_metadata(
                    report,
                    command=command_result.command,
                    actual_execution=bool(report),
                ),
            )

        report_error = self._validate_actual_report(report, artifact_refs, mode=mode)
        if report_error:
            return RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=self.runner_id,
                domain=request.domain,
                status="failed",
                tool_status="tool_error",
                exit_code=command_result.exit_code,
                timed_out=False,
                started_at=command_result.started_at,
                ended_at=command_result.ended_at,
                duration_ms=command_result.duration_ms,
                artifact_refs=artifact_refs,
                logs=[
                    RunnerLogRecord(
                        level="error",
                        message="named Playwright evidence validation failed",
                        context={
                            "runner": self.runner_id,
                            "validationClass": "named_tool_actual",
                            "reason": report_error,
                            "stdout": redacted_stdout,
                            "stderr": redacted_stderr,
                        },
                    )
                ],
                error=report_error,
                metadata=self._actual_result_metadata(
                    report,
                    command=command_result.command,
                    actual_execution=bool(report),
                ),
            )

        failure_kind = str(report.get("failureKind") or "")
        if failure_kind == "verification_failure":
            finding = self._verification_finding(request, report, artifact_refs)
            return RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=self.runner_id,
                domain=request.domain,
                status="completed",
                tool_status="findings_detected",
                exit_code=command_result.exit_code,
                timed_out=False,
                started_at=command_result.started_at,
                ended_at=command_result.ended_at,
                duration_ms=command_result.duration_ms,
                artifact_refs=artifact_refs,
                raw_findings=[finding],
                logs=[
                    RunnerLogRecord(
                        level="warning",
                        message="Playwright verification failed after actual Chromium execution",
                        context={
                            "runner": self.runner_id,
                            "actualExecution": True,
                            "verificationStatus": "failed",
                        },
                    )
                ],
                metadata=self._actual_result_metadata(
                    report,
                    command=command_result.command,
                    actual_execution=True,
                ),
            )

        if failure_kind == "timeout":
            return RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=self.runner_id,
                domain=request.domain,
                status="failed",
                tool_status="timeout",
                exit_code=command_result.exit_code,
                timed_out=True,
                started_at=command_result.started_at,
                ended_at=command_result.ended_at,
                duration_ms=command_result.duration_ms,
                artifact_refs=artifact_refs,
                logs=[
                    RunnerLogRecord(
                        level="error",
                        message="Playwright action timed out during actual Chromium execution",
                        context={
                            "runner": self.runner_id,
                            "actualExecution": True,
                            "stderr": redacted_stderr,
                        },
                    )
                ],
                error="Playwright action timed out during actual Chromium execution",
                metadata=self._actual_result_metadata(
                    report,
                    command=command_result.command,
                    actual_execution=True,
                ),
            )

        if command_result.exit_code != 0 or report.get("status") != "passed":
            error = str(report.get("failure") or "named Playwright actual execution failed")
            return RunnerExecutionResult(
                task_id=request.task_id,
                execution_id=request.execution_id,
                runner_id=self.runner_id,
                domain=request.domain,
                status="failed",
                tool_status="tool_error",
                exit_code=command_result.exit_code,
                timed_out=False,
                started_at=command_result.started_at,
                ended_at=command_result.ended_at,
                duration_ms=command_result.duration_ms,
                artifact_refs=artifact_refs,
                logs=[
                    RunnerLogRecord(
                        level="error",
                        message="named Playwright actual execution failed",
                        context={
                            "runner": self.runner_id,
                            "actualExecution": True,
                            "failureKind": failure_kind or "tool_error",
                            "stdout": redacted_stdout,
                            "stderr": redacted_stderr,
                        },
                    )
                ],
                error=error,
                metadata=self._actual_result_metadata(
                    report,
                    command=command_result.command,
                    actual_execution=True,
                ),
            )

        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="completed",
            tool_status="ok",
            exit_code=0,
            timed_out=False,
            started_at=command_result.started_at,
            ended_at=command_result.ended_at,
            duration_ms=command_result.duration_ms,
            artifact_refs=artifact_refs,
            logs=[
                RunnerLogRecord(
                    level="info",
                    message="named Playwright actual execution completed",
                    context={
                        "runner": self.runner_id,
                        "actualExecution": True,
                        "browser": report["browser"]["name"],
                        "browserVersion": report["browser"]["version"],
                        "playwrightVersion": report["playwrightVersion"],
                    },
                )
            ],
            metadata=self._actual_result_metadata(
                report,
                command=command_result.command,
                actual_execution=True,
            ),
        )

    def _actual_execution_plan(
        self,
        request: RunnerExecutionRequest,
        *,
        mode: str,
    ) -> tuple[dict[str, object], dict[str, str], str | None]:
        configured_actions = request.config.get("semanticActions")
        if isinstance(configured_actions, list):
            actions = configured_actions
        elif isinstance(request.config.get("semanticAction"), dict):
            actions = [request.config["semanticAction"]]
        else:
            actions = []
        if mode == "execute" and not actions:
            return {}, {}, "actual Playwright execution requires at least one SemanticAction"

        value_ref_env = request.config.get("valueRefEnv")
        secret_ref_env = request.config.get("secretRefEnv")
        value_ref_env = value_ref_env if isinstance(value_ref_env, dict) else {}
        secret_ref_env = secret_ref_env if isinstance(secret_ref_env, dict) else {}
        bindings: dict[str, str] = {}
        normalized_actions: list[dict[str, object]] = []
        allowed_action_types = {"navigate", "fill", "click", "assert_visible", "assert_text"}
        for index, raw_action in enumerate(actions):
            if not isinstance(raw_action, dict):
                return {}, {}, f"SemanticAction at index {index} must be an object"
            action_type = str(raw_action.get("actionType") or "")
            if action_type not in allowed_action_types:
                return {}, {}, f"unsupported SemanticAction actionType: {action_type}"
            normalized: dict[str, object] = {
                "schemaVersion": str(raw_action.get("schemaVersion") or "phase7.v1"),
                "actionId": str(raw_action.get("actionId") or f"action-{index + 1}"),
                "actionType": action_type,
                "semanticTarget": dict(raw_action.get("semanticTarget") or {}),
                "targetHints": dict(raw_action.get("targetHints") or {}),
                "locatorStrategy": dict(raw_action.get("locatorStrategy") or {}),
                "fallbackPolicy": dict(
                    raw_action.get("fallbackPolicy")
                    or {"allowCoordinateClick": False}
                ),
                "assertionIntent": dict(raw_action.get("assertionIntent") or {}),
                "riskLevel": str(raw_action.get("riskLevel") or "low"),
                "policyRefs": list(raw_action.get("policyRefs") or []),
            }
            if action_type == "fill":
                forbidden = [
                    key
                    for key in ("value", "textValue", "secret", "password")
                    if key in raw_action
                ]
                value_ref = raw_action.get("valueRef")
                secret_ref = raw_action.get("secretRef")
                if forbidden:
                    return (
                        {},
                        {},
                        "fill SemanticAction forbids inline plaintext fields: "
                        + ", ".join(forbidden),
                    )
                if bool(value_ref) == bool(secret_ref):
                    return {}, {}, "fill SemanticAction requires exactly one valueRef or secretRef"
                ref = str(value_ref or secret_ref)
                environment_name = (
                    value_ref_env.get(ref) if value_ref else secret_ref_env.get(ref)
                )
                if not environment_name or not isinstance(environment_name, str):
                    return {}, {}, f"fill reference has no controlled environment binding: {ref}"
                if environment_name not in os.environ:
                    return {}, {}, f"fill reference environment binding is unavailable: {ref}"
                bindings[ref] = os.environ[environment_name]
                normalized["valueRef" if value_ref else "secretRef"] = ref
            normalized_actions.append(normalized)

        target_url = str(
            request.config.get("targetUrl")
            or request.config.get("url")
            or ""
        )
        if mode == "capture" and not target_url:
            return {}, {}, "actual Playwright visual capture requires targetUrl"
        return (
            {
                "schemaVersion": "tst-p1-020.playwright-actual-request.v1",
                "mode": mode,
                "targetUrl": target_url,
                "actionTimeoutMs": int(request.config.get("actionTimeoutMs", 5000)),
                "navigationTimeoutMs": int(
                    request.config.get("navigationTimeoutMs", 5000)
                ),
                "semanticActions": normalized_actions,
            },
            bindings,
            None,
        )

    def _failed_actual_preflight_result(
        self,
        request: RunnerExecutionRequest,
        error: str,
    ) -> RunnerExecutionResult:
        started_at = utcnow()
        ended_at = utcnow()
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="failed",
            tool_status="tool_error",
            exit_code=-1,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(
                1,
                int((ended_at - started_at).total_seconds() * 1000),
            ),
            logs=[
                RunnerLogRecord(
                    level="error",
                    message=error,
                    context={
                        "runner": self.runner_id,
                        "actualExecution": False,
                        "validationClass": "named_tool_actual",
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
            },
        )

    def _read_actual_report(self, report_path: Path) -> dict[str, Any]:
        if not report_path.exists():
            return {}
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _validate_actual_report(
        self,
        report: dict[str, Any],
        artifact_refs: list[RunnerArtifactRef],
        *,
        mode: str,
    ) -> str | None:
        if not report:
            return "named Playwright report is missing or malformed"
        expected = {
            "schemaVersion": "tst-p1-020.playwright-actual-report.v1",
            "actualExecution": True,
            "executionMode": "actual",
            "validationClass": "named_tool_actual",
            "namedTool": "playwright",
            "namedToolExecuted": True,
            "customCommandExecuted": False,
        }
        mismatches = [
            key for key, value in expected.items() if report.get(key) != value
        ]
        if mismatches:
            return "named Playwright report metadata mismatch: " + ", ".join(mismatches)
        browser = report.get("browser")
        if not isinstance(browser, dict):
            return "named Playwright report browser metadata is missing"
        executable_path = Path(str(browser.get("executablePath") or ""))
        configured_browser_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
        pinned_root = Path(configured_browser_path or (self._repository_root() / ".ms-playwright")).resolve()
        try:
            executable_path.resolve().relative_to(pinned_root)
        except (OSError, ValueError):
            return "named Playwright execution did not use repository-pinned Chromium"
        if (
            browser.get("name") != "chromium"
            or not browser.get("version")
            or not browser.get("revision")
            or browser.get("pinned") is not True
            or not executable_path.exists()
            or not report.get("playwrightVersion")
        ):
            return "named Playwright report lacks verified binary/version evidence"
        artifact_types = {artifact.artifact_type for artifact in artifact_refs}
        required = {
            ArtifactType.SCREENSHOT,
            ArtifactType.DOM_SNAPSHOT,
            ArtifactType.ACCESSIBILITY_TREE,
            ArtifactType.TRACE,
            ArtifactType.REPORT,
        }
        if mode == "execute":
            required.update({ArtifactType.VIDEO, ArtifactType.HAR})
        missing = sorted(item.value for item in required - artifact_types)
        if missing:
            return "named Playwright execution evidence is missing: " + ", ".join(missing)
        return None

    def _actual_artifact_refs(
        self,
        report: dict[str, Any],
        report_path: Path,
    ) -> list[RunnerArtifactRef]:
        if not report:
            return []
        browser = report.get("browser") if isinstance(report.get("browser"), dict) else {}
        common_metadata = {
            "source": self.runner_id,
            "executionMode": "actual",
            "actualExecution": True,
            "validationClass": "named_tool_actual",
            "namedTool": self.runner_id,
            "namedToolExecuted": True,
            "customCommandExecuted": False,
            "playwrightVersion": report.get("playwrightVersion"),
            "browserName": browser.get("name"),
            "browserVersion": browser.get("version"),
            "browserRevision": browser.get("revision"),
            "redactionStatus": "redacted",
        }
        artifacts: list[RunnerArtifactRef] = []
        raw_artifacts = report.get("artifacts")
        if isinstance(raw_artifacts, list):
            for item in raw_artifacts:
                if not isinstance(item, dict):
                    continue
                raw_type = str(item.get("artifactType") or "")
                if raw_type not in ArtifactType._value2member_map_:
                    continue
                artifact_path = Path(str(item.get("path") or ""))
                if not artifact_path.exists() or artifact_path.stat().st_size <= 0:
                    continue
                artifacts.append(
                    RunnerArtifactRef(
                        artifact_type=ArtifactType(raw_type),
                        uri=str(artifact_path.resolve()),
                        summary=str(item.get("summary") or f"actual Playwright {raw_type}"),
                        metadata={
                            **common_metadata,
                            "byteSize": artifact_path.stat().st_size,
                        },
                    )
                )
        if report_path.exists() and report_path.stat().st_size > 0:
            artifacts.append(
                RunnerArtifactRef(
                    artifact_type=ArtifactType.REPORT,
                    uri=str(report_path.resolve()),
                    summary="named Playwright actual execution report",
                    metadata={
                        **common_metadata,
                        "byteSize": report_path.stat().st_size,
                    },
                )
            )
        return artifacts

    def _actual_result_metadata(
        self,
        report: dict[str, Any],
        *,
        command: list[str],
        actual_execution: bool,
    ) -> dict[str, Any]:
        browser = report.get("browser") if isinstance(report.get("browser"), dict) else {}
        return {
            "executionMode": "actual",
            "actualExecution": actual_execution,
            "validationClass": "named_tool_actual",
            "namedTool": self.runner_id,
            "namedToolExecuted": bool(report.get("namedToolExecuted")),
            "customCommandExecuted": False,
            "playwrightVersion": report.get("playwrightVersion"),
            "browserName": browser.get("name"),
            "browserVersion": browser.get("version"),
            "browserRevision": browser.get("revision"),
            "browserExecutablePath": browser.get("executablePath"),
            "pinnedChromium": browser.get("pinned") is True,
            "verificationStatus": (
                "failed"
                if report.get("failureKind") == "verification_failure"
                else "passed" if report.get("status") == "passed" else "not_completed"
            ),
            "artifactCount": len(report.get("artifacts") or []),
            "actionCount": len(report.get("actionResults") or []),
            "command": command,
        }

    def _verification_finding(
        self,
        request: RunnerExecutionRequest,
        report: dict[str, Any],
        artifact_refs: list[RunnerArtifactRef],
    ) -> RunnerFindingRecord:
        failed_actions = [
            item
            for item in report.get("actionResults", [])
            if isinstance(item, dict) and item.get("status") == "failed"
        ]
        failed_action = failed_actions[0] if failed_actions else {}
        report_ref = next(
            (
                artifact.uri
                for artifact in artifact_refs
                if artifact.artifact_type == ArtifactType.REPORT
            ),
            f"playwright://executions/{request.execution_id}/tasks/{request.task_id}/verification",
        )
        evidence = [
            {"type": "artifact_ref", "ref": artifact.uri}
            for artifact in artifact_refs
            if artifact.artifact_type
            in {
                ArtifactType.REPORT,
                ArtifactType.SCREENSHOT,
                ArtifactType.TRACE,
                ArtifactType.DOM_SNAPSHOT,
                ArtifactType.ACCESSIBILITY_TREE,
            }
        ]
        action_id = str(failed_action.get("actionId") or "unknown-action")
        return RunnerFindingRecord(
            source=self.runner_id,
            category="functional_ui",
            severity="high",
            title="Playwright verification failed",
            summary="A SemanticAction assertion failed during named Playwright Chromium execution.",
            evidence=evidence,
            location={
                "kind": "semantic_target",
                "target": action_id,
                "actionId": action_id,
            },
            confidence=1.0,
            dedupe_key=f"playwright:functional_ui:{request.task_id}:{action_id}",
            raw_ref=report_ref,
            metadata={
                "actualExecution": True,
                "validationClass": "named_tool_actual",
                "verificationStatus": "failed",
            },
        )

    def _actual_execution_requested(self, request: RunnerExecutionRequest) -> bool:
        return request.config.get("actualExecution") is True

    def _repository_root(self) -> Path:
        return Path(__file__).resolve().parents[4]

    def _redact_text(self, value: str, sensitive_values: Any) -> str:
        redacted = str(value)
        for sensitive_value in sensitive_values:
            if sensitive_value:
                redacted = redacted.replace(str(sensitive_value), "[REDACTED]")
        return redacted

    def _visual_artifact_refs(
        self,
        *,
        screenshot_path: Path,
        dom_path: Path,
        accessibility_path: Path,
        execution_mode: str,
    ) -> list[RunnerArtifactRef]:
        metadata = {
            "source": self.runner_id,
            "executionMode": execution_mode,
            "visualGrounding": True,
            "capture": "pre_action",
            "redactionStatus": "redacted",
            "actualExecution": execution_mode == "actual",
            "validationClass": (
                "named_tool_actual"
                if execution_mode == "actual"
                else "custom_command_contract"
                if execution_mode == "custom_command"
                else "simulated"
            ),
        }
        return [
            RunnerArtifactRef(
                artifact_type=ArtifactType.SCREENSHOT,
                uri=str(screenshot_path),
                summary="redacted playwright pre-action screenshot",
                metadata=metadata,
            ),
            RunnerArtifactRef(
                artifact_type=ArtifactType.DOM_SNAPSHOT,
                uri=str(dom_path),
                summary="redacted playwright DOM snapshot",
                metadata=metadata,
            ),
            RunnerArtifactRef(
                artifact_type=ArtifactType.ACCESSIBILITY_TREE,
                uri=str(accessibility_path),
                summary="redacted playwright accessibility tree",
                metadata=metadata,
            ),
        ]

    def _config_env(self, request: RunnerExecutionRequest) -> dict[str, str]:
        raw_env = request.config.get("env", {})
        if not isinstance(raw_env, dict):
            return {}
        return {str(key): str(value) for key, value in raw_env.items()}

    def _replace_placeholders(self, value: str, replacements: dict[str, str]) -> str:
        output = value
        for placeholder, replacement in replacements.items():
            output = output.replace(placeholder, replacement)
        return output


_ONE_PIXEL_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
)

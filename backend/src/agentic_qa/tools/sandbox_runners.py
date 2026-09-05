# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from typing import Any
from uuid import uuid4

from agentic_qa.domain.enums import ArtifactType, TestDomain
from agentic_qa.infra.artifact_storage import artifact_storage_adapter
from agentic_qa.infra.redaction import redact_sensitive_data, redact_sensitive_text
from agentic_qa.tools.command_runner import resolve_executable, utcnow
from agentic_qa.tools.runner_protocols import (
    RunnerArtifactRef,
    RunnerExecutionRequest,
    RunnerExecutionResult,
    RunnerFindingRecord,
    RunnerLogRecord,
)


SEMGREP_IMAGE = "semgrep/semgrep@sha256:7cad2bc2d1e44f87f0bf4be6d1fa23aa90fb72015bebc89fb91385d813987a03"
PYTHON_SMOKE_IMAGE = "python@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 50_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
_SAFE_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,254}$")


class _SandboxRunnerBase:
    supports_parallelism = False
    default_timeout_seconds = 300
    runner_id: str
    image: str
    recipe: str

    def run(self, request: RunnerExecutionRequest) -> RunnerExecutionResult:
        started_at = utcnow()
        temp_root: Path | None = None
        keep_temp_for_service_persistence = False
        container_name = f"agentic-qa-p21-{request.task_id.hex[:12]}-{uuid4().hex[:8]}"
        docker = resolve_executable(None, ["docker", "docker.exe"])
        try:
            config = self._validated_config(request.config)
            if docker is None:
                return self._unavailable(request, started_at, "docker CLI is unavailable")
            if not self._docker_daemon_available(docker):
                return self._unavailable(request, started_at, "docker daemon is unavailable")
            if not self._image_available(docker, self.image):
                return self._unavailable(
                    request,
                    started_at,
                    f"pinned sandbox image {self.image} is unavailable; images are never pulled implicitly",
                )

            archive = artifact_storage_adapter().read_artifact(str(config["sourceStorageRef"]))
            if len(archive) > MAX_ARCHIVE_BYTES:
                return self._tool_error(request, started_at, "source archive exceeds the 128 MiB limit")
            actual_hash = "sha256:" + hashlib.sha256(archive).hexdigest()
            if actual_hash != config["sourceContentHash"]:
                return self._tool_error(request, started_at, "source archive content hash mismatch")

            temp_root = Path(tempfile.mkdtemp(prefix="agentic-qa-p21-"))
            workspace = temp_root / "workspace"
            output = temp_root / "output"
            workspace.mkdir()
            output.mkdir()
            self._extract_tar_safely(archive, workspace)
            self._prepare_workspace(workspace)
            self._make_workspace_container_readable(temp_root, workspace)
            command = self._container_command(config, output)
            docker_command = self._docker_command(
                docker,
                container_name=container_name,
                workspace=workspace,
                profile=dict(config["sandboxProfile"]),
                command=command,
            )
            completed, timed_out = self._run_container(
                docker_command,
                timeout_seconds=int(config["sandboxProfile"]["timeoutSeconds"]),
            )
            if timed_out:
                keep_temp_for_service_persistence = True
                return self._timeout_result(request, started_at, completed, output)
            keep_temp_for_service_persistence = True
            return self._parse_result(request, started_at, completed, output)
        except (ValueError, tarfile.TarError, OSError) as exc:
            return self._tool_error(request, started_at, str(exc))
        finally:
            if docker is not None:
                try:
                    subprocess.run(
                        [docker, "rm", "-f", container_name],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    # Cleanup is best effort after a daemon failure.  The
                    # managed result above remains authoritative and callers
                    # must not see an unhandled local-runtime exception.
                    pass
            if temp_root is not None and not keep_temp_for_service_persistence:
                shutil.rmtree(temp_root, ignore_errors=True)

    def _validated_config(self, config: dict[str, Any]) -> dict[str, Any]:
        forbidden = {"command", "args", "workdir", "env", "scriptPath", "binaryPath"}
        if forbidden.intersection(config):
            raise ValueError("sandbox runner rejects arbitrary command, argument, path, and environment configuration")
        required = {"sourceStorageRef", "sourceContentHash", "sourceHeadSha", "sandboxProfile"}
        missing = sorted(required - set(config))
        if missing:
            raise ValueError("sandbox runner missing controlled config: " + ", ".join(missing))
        storage_ref = str(config["sourceStorageRef"])
        if not storage_ref.startswith("local://artifacts/"):
            raise ValueError("source must be loaded through Artifact Storage")
        profile = config["sandboxProfile"]
        if not isinstance(profile, dict):
            raise ValueError("sandboxProfile must be an object")
        invariants = {
            "engine": "docker",
            "networkMode": "none",
            "readOnlySource": True,
            "readOnlyRootFilesystem": True,
            "hostPathAccess": False,
            "dockerSocketAccess": False,
            "noNewPrivileges": True,
            "dropAllCapabilities": True,
            "cleanupRequired": True,
        }
        for key, expected in invariants.items():
            if profile.get(key) != expected:
                raise ValueError(f"sandbox invariant rejected: {key}")
        if profile.get("secretRefs") or profile.get("networkAllowlist"):
            raise ValueError("default P21 sandbox does not inject Secrets or enable network access")
        expected_project_id = str(config.get("projectId") or "")
        expected_namespace = f"local://artifacts/pr-source-archives-{expected_project_id}/{config['sourceHeadSha']}/"
        if not expected_project_id or not storage_ref.startswith(expected_namespace):
            raise ValueError("source archive is outside the managed project/head namespace")
        return config

    @staticmethod
    def _docker_daemon_available(docker: str) -> bool:
        try:
            result = subprocess.run(
                [docker, "info", "--format", "{{.OSType}}"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0 and result.stdout.strip() == "linux"

    @staticmethod
    def _image_available(docker: str, image: str) -> bool:
        try:
            result = subprocess.run(
                [docker, "image", "inspect", image, "--format", "{{.Id}}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0

    def _docker_command(
        self,
        docker: str,
        *,
        container_name: str,
        workspace: Path,
        profile: dict[str, Any],
        command: list[str],
    ) -> list[str]:
        mount_source = str(workspace.resolve())
        if "," in mount_source:
            raise ValueError("sandbox workspace path cannot contain a comma")
        return [
            docker,
            "run",
            "--name",
            container_name,
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(int(profile["pidsLimit"])),
            "--memory",
            f"{int(profile['memoryMB'])}m",
            "--cpus",
            str(float(profile["cpuLimit"])),
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={int(profile['tmpfsMB'])}m",
            "--env",
            "HOME=/tmp",
            "--env",
            "XDG_CONFIG_HOME=/tmp",
            "--env",
            "XDG_CACHE_HOME=/tmp",
            "--user",
            "65534:65534",
            "--mount",
            f"type=bind,source={mount_source},target=/workspace,readonly",
            "--workdir",
            "/workspace",
            self.image,
            *command,
        ]

    @staticmethod
    def _run_container(command: list[str], *, timeout_seconds: int) -> tuple[subprocess.CompletedProcess[bytes], bool]:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        output_overflow = threading.Event()

        def drain(name: str, stream) -> None:
            try:
                while chunk := stream.read(64 * 1024):
                    remaining = MAX_CAPTURE_BYTES - len(buffers[name])
                    if remaining > 0:
                        buffers[name].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        output_overflow.set()
            finally:
                stream.close()

        threads = [
            threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
            threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
        ]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        while process.poll() is None:
            if output_overflow.is_set():
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.02)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
        if output_overflow.is_set():
            raise ValueError("sandbox tool output exceeds the 16 MiB capture limit")
        return (
            subprocess.CompletedProcess(
                command,
                process.returncode if process.returncode is not None else -1,
                stdout=bytes(buffers["stdout"]),
                stderr=bytes(buffers["stderr"]),
            ),
            timed_out,
        )

    @staticmethod
    def _captured_bytes(value: object) -> bytes:
        if isinstance(value, bytes):
            payload = value
        else:
            payload = str(value or "").encode("utf-8", errors="replace")
        if len(payload) > MAX_CAPTURE_BYTES:
            raise ValueError("sandbox tool output exceeds the 16 MiB capture limit")
        return payload

    @classmethod
    def _captured_text(cls, value: object) -> str:
        return cls._captured_bytes(value).decode("utf-8", errors="replace")

    @staticmethod
    def _extract_tar_safely(archive: bytes, workspace: Path) -> None:
        total_size = 0
        seen: set[str] = set()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as bundle:
            members = bundle.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError("source archive member limit exceeded")
            for member in members:
                raw_name = member.name.replace("\\", "/")
                path = PurePosixPath(raw_name)
                if (
                    not raw_name
                    or raw_name.startswith("/")
                    or path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or "\x00" in raw_name
                ):
                    raise ValueError("source archive contains an unsafe path")
                folded = raw_name.casefold()
                if folded in seen:
                    raise ValueError("source archive contains duplicate case-insensitive paths")
                seen.add(folded)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise ValueError("source archive links and special files are forbidden")
                if not (member.isdir() or member.isfile()):
                    raise ValueError("source archive contains an unsupported member type")
                if member.size > MAX_FILE_BYTES:
                    raise ValueError("source archive contains an oversized file")
                total_size += member.size
                if total_size > MAX_EXTRACTED_BYTES:
                    raise ValueError("source archive expanded-size limit exceeded")
                target = (workspace / Path(*path.parts)).resolve()
                try:
                    target.relative_to(workspace.resolve())
                except ValueError as exc:
                    raise ValueError("source archive escaped the isolated workspace") from exc
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError("source archive member could not be read")
                with source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)

    def _container_command(self, config: dict[str, Any], output: Path) -> list[str]:
        raise NotImplementedError

    def _prepare_workspace(self, workspace: Path) -> None:
        return None

    @staticmethod
    def _make_workspace_container_readable(temp_root: Path, workspace: Path) -> None:
        """Expose only the read-only source tree to the fixed non-root container user."""
        entries = list(workspace.rglob("*"))
        for entry in entries:
            entry.chmod(0o555 if entry.is_dir() else 0o444)
        workspace.chmod(0o555)
        temp_root.chmod(0o711)

    def _parse_result(
        self,
        request: RunnerExecutionRequest,
        started_at,
        completed: subprocess.CompletedProcess[bytes],
        output: Path,
    ) -> RunnerExecutionResult:
        raise NotImplementedError

    def _native_log_artifact(self, output: Path, completed: subprocess.CompletedProcess[object]) -> RunnerArtifactRef:
        stdout = self._captured_bytes(completed.stdout)
        stderr = self._captured_bytes(completed.stderr)
        log_path = output / f"{self.runner_id}-native.log"
        log_path.write_text(
            json.dumps(
                {
                    "schemaVersion": "phase8.tool-native-digest.v1",
                    "runnerId": self.runner_id,
                    "exitCode": completed.returncode,
                    "stdoutBytes": len(stdout),
                    "stderrBytes": len(stderr),
                    "stdoutHash": "sha256:" + hashlib.sha256(stdout).hexdigest(),
                    "stderrHash": "sha256:" + hashlib.sha256(stderr).hexdigest(),
                    "rawOutputPersisted": False,
                    "redactionStatus": "redacted",
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return RunnerArtifactRef(
            artifact_type=ArtifactType.LOG,
            uri=log_path.resolve().as_uri(),
            summary=f"{self.runner_id} native sandbox output",
            metadata={
                "source": self.runner_id,
                "serviceManagedArtifactPayload": True,
                "cleanupRoot": str(output.parent.resolve()),
                "redactionStatus": "redacted",
                "sandboxed": True,
            },
        )

    def _base_metadata(self, *, version: str | None = None) -> dict[str, Any]:
        return {
            "executionMode": "sandboxed_actual",
            "actualExecution": True,
            "validationClass": "actual_tool",
            "sandboxed": True,
            "sandboxEngine": "docker",
            "networkMode": "none",
            "readOnlySource": True,
            "readOnlyRootFilesystem": True,
            "dockerSocketAccess": False,
            "hostPathAccess": False,
            "namedTool": self.runner_id,
            "namedToolExecuted": True,
            "customCommandExecuted": False,
            "binaryVersion": version,
            "image": self.image,
            "recipe": self.recipe,
        }

    def _unavailable(self, request: RunnerExecutionRequest, started_at, reason: str) -> RunnerExecutionResult:
        ended_at = utcnow()
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="failed",
            tool_status="infra_error",
            exit_code=-1,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            logs=[RunnerLogRecord(level="error", message=reason, context={"status": "unavailable"})],
            error=reason,
            metadata={**self._base_metadata(), "actualExecution": False, "namedToolExecuted": False, "availability": "unavailable"},
        )

    def _tool_error(self, request: RunnerExecutionRequest, started_at, reason: str) -> RunnerExecutionResult:
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
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            logs=[RunnerLogRecord(level="error", message=redact_sensitive_text(reason), context={"status": "rejected"})],
            error=redact_sensitive_text(reason),
            metadata={**self._base_metadata(), "actualExecution": False, "namedToolExecuted": False},
        )

    def _timeout_result(self, request: RunnerExecutionRequest, started_at, completed, output: Path) -> RunnerExecutionResult:
        ended_at = utcnow()
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="failed",
            tool_status="timeout",
            exit_code=-1,
            timed_out=True,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            artifact_refs=[self._native_log_artifact(output, completed)],
            logs=[RunnerLogRecord(level="error", message="sandbox execution timed out", context={"cleanupRequired": True})],
            error="sandbox execution timed out",
            metadata=self._base_metadata(),
        )

    def _runtime_failure(
        self,
        request: RunnerExecutionRequest,
        started_at,
        completed: subprocess.CompletedProcess[object],
        output: Path,
    ) -> RunnerExecutionResult:
        ended_at = utcnow()
        exit_code = int(completed.returncode)
        resource_limited = exit_code in {-15, -9, 137, 143}
        reason = "sandbox terminated by a resource limit" if resource_limited else "sandbox container runtime failed"
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="failed",
            tool_status="infra_error",
            exit_code=exit_code,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            artifact_refs=[self._native_log_artifact(output, completed)],
            logs=[RunnerLogRecord(level="error", message=reason, context={"exitCode": exit_code})],
            error=reason,
            metadata={**self._base_metadata(), "resourceLimitTermination": resource_limited},
        )


class SandboxSemgrepRunner(_SandboxRunnerBase):
    runner_id = "sandbox-semgrep"
    domain = TestDomain.SECURITY
    image = SEMGREP_IMAGE
    recipe = "semgrep-static-scan"

    def _prepare_workspace(self, workspace: Path) -> None:
        rules = workspace / ".agentic-qa-p21-rules.yml"
        if rules.exists():
            raise ValueError("source archive collides with the reserved P21 rule path")
        rules.write_text(
            """rules:
  - id: p21.python.subprocess-shell-true
    languages: [python]
    severity: ERROR
    message: subprocess execution with shell=True expands command injection risk
    patterns:
      - pattern-either:
          - pattern: subprocess.$F(..., shell=True, ...)
          - pattern: subprocess.$F(..., shell = True, ...)
  - id: p21.python.eval
    languages: [python]
    severity: WARNING
    message: dynamic eval executes untrusted expressions
    pattern: eval(...)
  - id: p21.javascript.eval
    languages: [javascript, typescript]
    severity: WARNING
    message: dynamic eval executes untrusted expressions
    pattern: eval(...)
""",
            encoding="utf-8",
        )

    def _container_command(self, config: dict[str, Any], output: Path) -> list[str]:
        return [
            "semgrep",
            "scan",
            "--config",
            "/workspace/.agentic-qa-p21-rules.yml",
            "--json",
            "--disable-version-check",
            "--metrics",
            "off",
            "/workspace",
        ]

    def _parse_result(self, request, started_at, completed, output: Path) -> RunnerExecutionResult:
        if completed.returncode in {-15, -9, 125, 126, 127, 137, 143}:
            return self._runtime_failure(request, started_at, completed, output)
        ended_at = utcnow()
        artifacts = [self._native_log_artifact(output, completed)]
        findings: list[RunnerFindingRecord] = []
        version: str | None = None
        try:
            payload = json.loads(self._captured_text(completed.stdout) or "{}")
            version = str(payload.get("version") or "1.163.0")
            for item in payload.get("results", []):
                if not isinstance(item, dict):
                    continue
                raw_extra = item.get("extra")
                extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
                raw_metadata = extra.get("metadata")
                metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
                raw_severity = str(extra.get("severity") or "WARNING").lower()
                severity = {"error": "high", "warning": "medium", "info": "low"}.get(raw_severity, "medium")
                path = str(item.get("path") or "unknown").replace("\\", "/")
                if path.startswith("/workspace/"):
                    path = path.removeprefix("/workspace/")
                raw_start = item.get("start")
                start: dict[str, Any] = raw_start if isinstance(raw_start, dict) else {}
                line = int(start.get("line") or 1)
                check_id = str(item.get("check_id") or "semgrep.unknown")
                message = redact_sensitive_text(str(extra.get("message") or check_id))
                findings.append(
                    RunnerFindingRecord(
                        source="semgrep",
                        category="sast",
                        severity=severity,
                        title=check_id[:255],
                        summary=message,
                        evidence=[{"type": "external_ref", "ref": f"semgrep://{check_id}/{path}:{line}"}],
                        location={"kind": "file", "file": path, "line": line},
                        confidence=float(metadata.get("confidence", 0.9)) if str(metadata.get("confidence", "")).replace(".", "", 1).isdigit() else 0.9,
                        dedupe_key=f"semgrep:{check_id}:{path}:{line}"[:255],
                        raw_ref=f"semgrep://{check_id}/{path}:{line}"[:255],
                        metadata=redact_sensitive_data({"checkId": check_id, "sandboxed": True}),
                    )
                )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            return self._failed_parse(request, started_at, completed, artifacts, f"semgrep output unavailable: {exc}")
        status = "completed" if completed.returncode == 0 else "failed"
        tool_status = "findings_detected" if findings else ("ok" if status == "completed" else "tool_error")
        error = None if status == "completed" else "semgrep sandbox execution failed"
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status=status,
            tool_status=tool_status,
            exit_code=completed.returncode,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            artifact_refs=artifacts,
            raw_findings=findings,
            logs=[RunnerLogRecord(level="info" if status == "completed" else "error", message="semgrep sandbox completed", context={"findingCount": len(findings)})],
            error=error,
            metadata=self._base_metadata(version=version or "1.163.0"),
        )

    def _failed_parse(self, request, started_at, completed, artifacts, reason):
        ended_at = utcnow()
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status="failed",
            tool_status="tool_error",
            exit_code=completed.returncode,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            artifact_refs=artifacts,
            logs=[RunnerLogRecord(level="error", message=reason, context={})],
            error=reason,
            metadata=self._base_metadata(version="1.163.0"),
        )


class SandboxPythonUnittestRunner(_SandboxRunnerBase):
    runner_id = "sandbox-python-unittest"
    domain = TestDomain.FUNCTIONAL
    image = PYTHON_SMOKE_IMAGE
    recipe = "python-unittest"

    def _container_command(self, config: dict[str, Any], output: Path) -> list[str]:
        module = config.get("testModule")
        if module is not None:
            module = str(module)
            if not _SAFE_MODULE.fullmatch(module):
                raise ValueError("python smoke testModule is not a safe dotted module name")
            return ["python", "-I", "-m", "unittest", module]
        return ["python", "-I", "-m", "unittest", "discover", "-s", ".", "-p", "test*.py"]

    def _parse_result(self, request, started_at, completed, output: Path) -> RunnerExecutionResult:
        if completed.returncode not in {0, 1}:
            return self._runtime_failure(request, started_at, completed, output)
        ended_at = utcnow()
        artifact = self._native_log_artifact(output, completed)
        status = "completed"
        error = None
        findings: list[RunnerFindingRecord] = []
        if completed.returncode != 0:
            findings.append(
                RunnerFindingRecord(
                    source="custom",
                    category="reliability",
                    severity="medium",
                    title="Selective smoke test failed",
                    summary="A platform-selected unittest smoke recipe failed inside the restricted sandbox.",
                    evidence=[{"type": "artifact_ref", "ref": artifact.uri}],
                    location={"kind": "service", "target": "sandbox-python-unittest"},
                    confidence=1.0,
                    dedupe_key=f"p21:python-unittest:{request.task_id}"[:255],
                    raw_ref=artifact.uri[:255],
                    metadata={"sandboxed": True, "recipe": self.recipe},
                )
            )
        return RunnerExecutionResult(
            task_id=request.task_id,
            execution_id=request.execution_id,
            runner_id=self.runner_id,
            domain=request.domain,
            status=status,
            tool_status="ok" if completed.returncode == 0 else "findings_detected",
            exit_code=completed.returncode,
            timed_out=False,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(1, int((ended_at - started_at).total_seconds() * 1000)),
            artifact_refs=[artifact],
            raw_findings=findings,
            logs=[RunnerLogRecord(level="info" if status == "completed" else "error", message="python unittest sandbox completed", context={"recipe": self.recipe})],
            error=error,
            metadata=self._base_metadata(version="3.14"),
        )


__all__ = ["SandboxPythonUnittestRunner", "SandboxSemgrepRunner"]

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import os
import shutil
import subprocess


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class CommandExecutionResult:
    command: list[str]
    cwd: str | None
    stdout: str
    stderr: str
    exit_code: int
    started_at: datetime
    ended_at: datetime
    timed_out: bool

    @property
    def duration_ms(self) -> int:
        return max(1, int((self.ended_at - self.started_at).total_seconds() * 1000))


def resolve_executable(configured_path: str | None, candidates: list[str]) -> str | None:
    if configured_path:
        path = Path(configured_path)
        if path.exists():
            return str(path)
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def ensure_artifact_dir(base_dir: str, execution_id: str, task_id: str) -> Path:
    path = Path(base_dir) / execution_id / task_id
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def run_command(
    command: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout_seconds: int = 900,
) -> CommandExecutionResult:
    started_at = utcnow()
    child_env = os.environ.copy()
    if env:
        child_env.update({key: str(value) for key, value in env.items()})
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=child_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        ended_at = utcnow()
        return CommandExecutionResult(
            command=command,
            cwd=cwd,
            stdout=_output_text(completed.stdout),
            stderr=_output_text(completed.stderr),
            exit_code=completed.returncode,
            started_at=started_at,
            ended_at=ended_at,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        ended_at = utcnow()
        return CommandExecutionResult(
            command=command,
            cwd=cwd,
            stdout=_output_text(exc.stdout),
            stderr=_output_text(exc.stderr),
            exit_code=-1,
            started_at=started_at,
            ended_at=ended_at,
            timed_out=True,
        )

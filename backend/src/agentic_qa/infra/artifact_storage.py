# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote

from agentic_qa.infra.settings import get_settings


class ArtifactStorageAdapter(ABC):
    """Storage boundary for service-owned artifact payloads."""

    adapter_name: str

    @abstractmethod
    def write_artifact(self, *, namespace: str, artifact_id: str, filename: str, payload: bytes) -> dict[str, object]:
        raise NotImplementedError

    @abstractmethod
    def read_artifact(self, storage_ref: str) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def delete_artifact(self, storage_ref: str) -> None:
        raise NotImplementedError


class LocalArtifactStorageAdapter(ArtifactStorageAdapter):
    adapter_name = "local"
    _scheme = "local://artifacts/"

    def __init__(self, root_dir: str | Path | None = None) -> None:
        configured_root = root_dir if root_dir is not None else get_settings().artifact_storage_dir
        self.root_dir = Path(configured_root).resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def write_artifact(self, *, namespace: str, artifact_id: str, filename: str, payload: bytes) -> dict[str, object]:
        content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
        safe_namespace = _safe_component(namespace)
        safe_artifact_id = _safe_component(artifact_id)
        safe_filename = _safe_filename(filename)
        target_dir = (self.root_dir / safe_namespace / safe_artifact_id).resolve()
        self._ensure_inside_root(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        target = (target_dir / f"{content_hash.removeprefix('sha256:')}.{safe_filename}").resolve()
        self._ensure_inside_root(target)
        target.write_bytes(payload)
        relative = target.relative_to(self.root_dir).as_posix()
        return {
            "storageRef": f"{self._scheme}{relative}",
            "contentHash": content_hash,
            "byteSize": len(payload),
            "adapter": self.adapter_name,
        }

    def read_artifact(self, storage_ref: str) -> bytes:
        target = self._path_from_ref(storage_ref)
        if not target.exists():
            raise FileNotFoundError("artifact not found")
        return target.read_bytes()

    def delete_artifact(self, storage_ref: str) -> None:
        target = self._path_from_ref(storage_ref)
        if target.exists():
            target.unlink()

    def _path_from_ref(self, storage_ref: str) -> Path:
        if not storage_ref.startswith(self._scheme):
            raise ValueError("unsupported local artifact storage ref")
        relative = storage_ref.removeprefix(self._scheme)
        _validate_relative_storage_ref(relative)
        target = (self.root_dir / relative).resolve()
        self._ensure_inside_root(target)
        return target

    def _ensure_inside_root(self, path: Path) -> None:
        try:
            path.relative_to(self.root_dir)
        except ValueError as exc:
            raise ValueError("artifact storage path escaped adapter root") from exc


def artifact_storage_adapter(adapter_name: str = "local") -> ArtifactStorageAdapter:
    if adapter_name == "local":
        return LocalArtifactStorageAdapter()
    raise ValueError(f"unsupported artifact storage adapter: {adapter_name}")


def _safe_component(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value)
    return safe.strip("._") or "artifact"


def _safe_filename(value: str) -> str:
    name = Path(value).name
    safe = "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in name)
    return safe.strip("._") or "upload.txt"


def _validate_relative_storage_ref(value: str) -> None:
    if not value or "\x00" in value or "\\" in value or "%" in value:
        raise ValueError("artifact storage ref contains an unsafe path encoding")
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    path = Path(decoded)
    windows_path = PureWindowsPath(decoded)
    if (
        path.is_absolute()
        or path.drive
        or windows_path.is_absolute()
        or windows_path.drive
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("artifact storage ref contains an unsafe path")

# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote
from uuid import uuid4

from agentic_qa.infra.settings import get_settings


class StorageAdapter(ABC):
    """Storage boundary for Replay Repository sections."""

    adapter_name: str

    @abstractmethod
    def write_section(self, *, replay_id: str, section_name: str, payload: bytes) -> dict[str, object]:
        raise NotImplementedError

    @abstractmethod
    def read_section(self, storage_ref: str) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def delete_section(self, storage_ref: str) -> None:
        raise NotImplementedError


class LocalReplayStorageAdapter(StorageAdapter):
    adapter_name = "local"
    _scheme = "local://replay-repository/"

    def __init__(self, root_dir: str | Path | None = None) -> None:
        configured_root = root_dir if root_dir is not None else get_settings().replay_repository_storage_dir
        self.root_dir = Path(configured_root).resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def write_section(self, *, replay_id: str, section_name: str, payload: bytes) -> dict[str, object]:
        content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
        safe_replay_id = _safe_component(replay_id)
        safe_section = _safe_component(section_name)
        target_dir = (self.root_dir / safe_replay_id).resolve()
        self._ensure_inside_root(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        target = (target_dir / f"{safe_section}.{content_hash.removeprefix('sha256:')}.json").resolve()
        self._ensure_inside_root(target)
        _atomic_write(target, payload)
        relative = target.relative_to(self.root_dir).as_posix()
        return {
            "storageRef": f"{self._scheme}{relative}",
            "contentHash": content_hash,
            "byteSize": len(payload),
            "compression": "none",
            "adapter": self.adapter_name,
        }

    def read_section(self, storage_ref: str) -> bytes:
        target = self._path_from_ref(storage_ref)
        if not target.exists():
            raise FileNotFoundError("replay repository section not found")
        return target.read_bytes()

    def delete_section(self, storage_ref: str) -> None:
        target = self._path_from_ref(storage_ref)
        if target.exists():
            target.unlink()

    def _path_from_ref(self, storage_ref: str) -> Path:
        if not storage_ref.startswith(self._scheme):
            raise ValueError("unsupported local replay storage ref")
        relative = storage_ref.removeprefix(self._scheme)
        _validate_relative_storage_ref(relative)
        target = (self.root_dir / relative).resolve()
        self._ensure_inside_root(target)
        return target

    def _ensure_inside_root(self, path: Path) -> None:
        try:
            path.relative_to(self.root_dir)
        except ValueError as exc:
            raise ValueError("replay storage path escaped adapter root") from exc


class ObjectReplayStorageAdapter(StorageAdapter):
    adapter_name = "object"

    def __init__(self, root_dir: str | Path | None = None, bucket: str | None = None) -> None:
        settings = get_settings()
        configured_root = root_dir if root_dir is not None else settings.replay_repository_object_storage_dir
        self.root_dir = Path(configured_root).resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.bucket = _safe_component(bucket or settings.replay_repository_object_storage_bucket)
        self._scheme = f"object://{self.bucket}/"

    def write_section(self, *, replay_id: str, section_name: str, payload: bytes) -> dict[str, object]:
        content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
        safe_replay_id = _safe_component(replay_id)
        safe_section = _safe_component(section_name)
        target_dir = (self.root_dir / self.bucket / safe_replay_id).resolve()
        self._ensure_inside_root(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        target = (target_dir / f"{safe_section}.{content_hash.removeprefix('sha256:')}.json").resolve()
        self._ensure_inside_root(target)
        _atomic_write(target, payload)
        relative = target.relative_to(self.root_dir / self.bucket).as_posix()
        return {
            "storageRef": f"{self._scheme}{relative}",
            "contentHash": content_hash,
            "byteSize": len(payload),
            "compression": "none",
            "adapter": self.adapter_name,
        }

    def read_section(self, storage_ref: str) -> bytes:
        target = self._path_from_ref(storage_ref)
        if not target.exists():
            raise FileNotFoundError("replay repository section not found")
        return target.read_bytes()

    def delete_section(self, storage_ref: str) -> None:
        target = self._path_from_ref(storage_ref)
        if target.exists():
            target.unlink()

    def _path_from_ref(self, storage_ref: str) -> Path:
        if not storage_ref.startswith(self._scheme):
            raise ValueError("unsupported object replay storage ref")
        relative = storage_ref.removeprefix(self._scheme)
        _validate_relative_storage_ref(relative)
        target = (self.root_dir / self.bucket / relative).resolve()
        self._ensure_inside_root(target)
        return target

    def _ensure_inside_root(self, path: Path) -> None:
        object_root = (self.root_dir / self.bucket).resolve()
        try:
            path.relative_to(object_root)
        except ValueError as exc:
            raise ValueError("replay object storage path escaped adapter root") from exc


def replay_storage_adapter(adapter_name: str = "local") -> StorageAdapter:
    if adapter_name == "local":
        return LocalReplayStorageAdapter()
    if adapter_name == "object":
        return ObjectReplayStorageAdapter()
    raise ValueError(f"unsupported replay storage adapter: {adapter_name}")


def _safe_component(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value)
    return safe.strip("._") or "section"


def _validate_relative_storage_ref(value: str) -> None:
    if not value or "\x00" in value or "\\" in value or "%" in value:
        raise ValueError("replay storage ref contains an unsafe path encoding")
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
        raise ValueError("replay storage ref contains an unsafe path")


def _atomic_write(target: Path, payload: bytes) -> None:
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()

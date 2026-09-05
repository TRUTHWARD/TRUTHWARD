# SPDX-License-Identifier: Apache-2.0
"""Source-only Community first-install launcher; never upgrades or resets a DB."""
from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check_python() -> None:
    text = (ROOT / "backend/pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'requires-python\s*=\s*">=(\d+)\.(\d+),<(\d+)\.(\d+)"', text)
    if not match:
        raise RuntimeError("Cannot resolve the supported Python range from backend/pyproject.toml")
    major, minor, upper_major, upper_minor = map(int, match.groups())
    supported = f">={major}.{minor},<{upper_major}.{upper_minor}"
    print(f"Python: {sys.executable}; version={sys.version.split()[0]}; range={supported}", flush=True)
    if not (major, minor) <= sys.version_info[:2] < (upper_major, upper_minor):
        raise RuntimeError(f"Unsupported Python; required {supported}")


def configure(database_port: int, redis_port: int) -> None:
    if not all(1024 <= port <= 65535 for port in (database_port, redis_port)):
        raise RuntimeError("Choose unprivileged ports between 1024 and 65535")
    if database_port == redis_port:
        raise RuntimeError("Database and Redis ports must differ")
    content = (ROOT / "community.env.example").read_text(encoding="utf-8")
    replacements = {
        "__POSTGRES_PASSWORD__": secrets.token_hex(24),
        "__REDIS_PASSWORD__": secrets.token_hex(24),
        "__POSTGRES_PORT__": str(database_port),
        "__REDIS_PORT__": str(redis_port),
    }
    for key, value in replacements.items():
        content = content.replace(key, value)
    # O_EXCL prevents overwriting an existing installation or following a symlink.
    try:
        fd = os.open(ROOT / ".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise RuntimeError(".env already exists; left unchanged. Use a fresh directory for first-install validation.") from None
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    print("Created .env with random database/Redis passwords. No application account was created.")


def runtime_settings():
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT / "backend/src"))
    from agentic_qa.infra.settings import get_settings

    settings = get_settings()
    if settings.deployment_profile != "oss":
        raise RuntimeError("This launcher requires DEPLOYMENT_PROFILE=oss; refusing the full profile")
    if settings.auto_create_tables:
        raise RuntimeError("Set AUTO_CREATE_TABLES=false; use init-db for the canonical PostgreSQL schema")
    return settings


def initialize_empty_database(settings) -> None:
    from apply_migrations import apply_migrations

    if not settings.database_url.startswith("postgresql+psycopg://"):
        raise RuntimeError("First installation requires PostgreSQL with the psycopg driver")
    apply_migrations(settings.database_url, fresh_schema=True)
    print("Canonical schema and migrations applied. Start the API, then create your administrator in the browser.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    config = subparsers.add_parser("configure", help="Create .env once, without overwriting existing files")
    config.add_argument("--database-port", type=int, default=55432)
    config.add_argument("--redis-port", type=int, default=56379)
    subparsers.add_parser("init-db", help="Initialize an empty PostgreSQL database; refuses existing tables")
    serve = subparsers.add_parser("serve", help="Start the Community API on loopback")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        check_python()
        if args.command == "configure":
            configure(args.database_port, args.redis_port)
        else:
            settings = runtime_settings()
            if args.command == "init-db":
                initialize_empty_database(settings)
            else:
                import uvicorn

                uvicorn.run("agentic_qa.apps.oss_api_gateway:app", host="127.0.0.1", port=args.port)
    except RuntimeError as exc:
        print(f"Community startup stopped: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 -- redact DSNs/SQL parameters at the CLI boundary
        # Driver exceptions can contain DSNs/SQL parameters. Do not print them.
        print(f"Community startup failed ({type(exc).__name__}); check local configuration and dependency availability", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

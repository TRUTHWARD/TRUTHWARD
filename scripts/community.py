# SPDX-License-Identifier: Apache-2.0
"""Source-only Community first-install launcher; never upgrades or resets a DB."""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def check_python(*, emit: bool = True) -> str:
    text = (ROOT / "backend/pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'requires-python\s*=\s*">=(\d+)\.(\d+),<(\d+)\.(\d+)"', text)
    if not match:
        raise RuntimeError("Cannot resolve the supported Python range from backend/pyproject.toml")
    major, minor, upper_major, upper_minor = map(int, match.groups())
    supported = f">={major}.{minor},<{upper_major}.{upper_minor}"
    if emit:
        print(f"Python: {sys.executable}; version={sys.version.split()[0]}; range={supported}", flush=True)
    if not (major, minor) <= sys.version_info[:2] < (upper_major, upper_minor):
        raise RuntimeError(f"Unsupported Python; required {supported}")
    return supported


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


def _doctor_item(check_id: str, status: str, *, required: bool, detail: str) -> dict[str, Any]:
    return {"id": check_id, "status": status, "required": required, "detail": detail}


def _command_check(check_id: str, command: list[str], *, required: bool) -> dict[str, Any]:
    executable = shutil.which(command[0])
    if not executable:
        return _doctor_item(check_id, "unavailable", required=required, detail="command is unavailable")
    try:
        result = subprocess.run(
            [executable, *command[1:]],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return _doctor_item(check_id, "unavailable", required=required, detail="version probe failed")
    if result.returncode != 0:
        return _doctor_item(check_id, "unavailable", required=required, detail="version probe failed")
    version = next((line.strip() for line in result.stdout.splitlines() if line.strip()), "available")
    return _doctor_item(check_id, "passed", required=required, detail=version[:120])


def _migration_inventory() -> dict[str, str]:
    from apply_migrations import load_migrations

    migrations = load_migrations(ROOT / "scripts/migrations")
    return {name: digest for name, digest, _ in migrations}


def _database_check(settings, migrations: dict[str, str]) -> dict[str, Any]:
    from psycopg import connect

    url = re.sub(r"^postgres(?:ql)?\+psycopg2?://", "postgresql://", settings.database_url)
    if not url.startswith(("postgresql://", "postgres://")):
        return _doctor_item(
            "database",
            "blocked",
            required=True,
            detail="Community requires the PostgreSQL psycopg connection form",
        )
    try:
        with connect(
            url,
            connect_timeout=5,
            application_name="truthward-community-doctor",
            options="-c default_transaction_read_only=on",
        ) as connection:
            connection.execute("SELECT 1").fetchone()
            rows = dict(
                connection.execute(
                    "SELECT migration_name, checksum FROM public.schema_migrations"
                ).fetchall()
            )
    except Exception as exc:  # noqa: BLE001 -- never expose driver text, DSN, or SQL values
        return _doctor_item(
            "database",
            "blocked",
            required=True,
            detail=f"read-only database verification failed ({type(exc).__name__})",
        )

    numbered_rows = {name: digest for name, digest in rows.items() if name != "000_db_schema.sql"}
    valid = (
        "000_db_schema.sql" in rows
        and numbered_rows == migrations
        and len(rows) == len(migrations) + 1
    )
    return _doctor_item(
        "database",
        "passed" if valid else "blocked",
        required=True,
        detail=(
            f"read-only connection and {len(rows)} migration ledger rows verified"
            if valid
            else "migration ledger is missing, stale, mismatched, or contains unknown entries"
        ),
    )


def community_doctor(settings=None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    try:
        supported = check_python(emit=False)
        checks.append(
            _doctor_item(
                "python",
                "passed",
                required=True,
                detail=f"version={sys.version.split()[0]}; range={supported}",
            )
        )
    except RuntimeError:
        checks.append(
            _doctor_item(
                "python",
                "blocked",
                required=True,
                detail="interpreter is outside the authoritative supported range",
            )
        )
    required_paths = {
        "environment-file": (ROOT / ".env", "file"),
        "compose-file": (ROOT / "compose.community.yml", "file"),
        "contract-schemas": (ROOT / "schemas/contracts", "directory"),
        "community-skills": (ROOT / "community-skills", "directory"),
    }
    for check_id, (path, kind) in required_paths.items():
        exists = path.is_file() if kind == "file" else path.is_dir()
        safe = exists and not path.is_symlink()
        checks.append(
            _doctor_item(
                check_id,
                "passed" if safe else "blocked",
                required=True,
                detail=f"required {kind} is present and is not a symlink" if safe else f"required {kind} is missing or unsafe",
            )
        )

    migrations: dict[str, str] = {}
    try:
        migrations = _migration_inventory()
        checks.append(
            _doctor_item(
                "migration-source",
                "passed",
                required=True,
                detail=f"{len(migrations)} numbered migration checksums verified",
            )
        )
    except Exception as exc:  # noqa: BLE001 -- report only safe type information
        checks.append(
            _doctor_item(
                "migration-source",
                "blocked",
                required=True,
                detail=f"migration source verification failed ({type(exc).__name__})",
            )
        )

    if settings is None:
        try:
            settings = runtime_settings()
            checks.append(
                _doctor_item(
                    "community-profile",
                    "passed",
                    required=True,
                    detail="DEPLOYMENT_PROFILE=oss and AUTO_CREATE_TABLES=false",
                )
            )
        except Exception as exc:  # noqa: BLE001 -- settings errors can contain sensitive values
            checks.append(
                _doctor_item(
                    "community-profile",
                    "blocked",
                    required=True,
                    detail=f"safe Community settings validation failed ({type(exc).__name__})",
                )
            )
            settings = None
    else:
        profile_valid = settings.deployment_profile == "oss" and settings.auto_create_tables is False
        checks.append(
            _doctor_item(
                "community-profile",
                "passed" if profile_valid else "blocked",
                required=True,
                detail=(
                    "DEPLOYMENT_PROFILE=oss and AUTO_CREATE_TABLES=false"
                    if profile_valid
                    else "Community profile or canonical migration setting is invalid"
                ),
            )
        )

    checks.extend(
        (
            _command_check("node", ["node", "--version"], required=True),
            _command_check("npm", ["npm", "--version"], required=True),
            _command_check("docker-compose", ["docker", "compose", "version"], required=False),
        )
    )
    if settings is not None and migrations:
        checks.append(_database_check(settings, migrations))
    else:
        checks.append(
            _doctor_item(
                "database",
                "not_run",
                required=True,
                detail="database verification requires valid settings and migration source",
            )
        )

    blocked = [item["id"] for item in checks if item["required"] and item["status"] != "passed"]
    return {
        "schemaVersion": "truthward.community-doctor.v1",
        "status": "ready" if not blocked else "blocked",
        "readOnly": True,
        "blockedChecks": blocked,
        "checks": checks,
    }


def run_doctor(*, json_output: bool = False) -> bool:
    report = community_doctor()
    if json_output:
        print(json.dumps(report, ensure_ascii=False, separators=(",", ":")))
    else:
        print(f"COMMUNITY_DOCTOR status={report['status']} readOnly=true")
        for item in report["checks"]:
            print(
                f"{item['status'].upper()} {item['id']} required={str(item['required']).lower()} "
                f"{item['detail']}"
            )
    return report["status"] == "ready"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    config = subparsers.add_parser("configure", help="Create .env once, without overwriting existing files")
    config.add_argument("--database-port", type=int, default=55432)
    config.add_argument("--redis-port", type=int, default=56379)
    subparsers.add_parser("init-db", help="Initialize an empty PostgreSQL database; refuses existing tables")
    doctor = subparsers.add_parser("doctor", help="Run credential-safe read-only installation checks")
    doctor.add_argument("--json", action="store_true", help="Emit one machine-readable JSON document")
    serve = subparsers.add_parser("serve", help="Start the Community API on loopback")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        if args.command == "doctor":
            return 0 if run_doctor(json_output=args.json) else 1
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

# SPDX-License-Identifier: Apache-2.0
"""Apply canonical PostgreSQL SQL using the installed Python driver."""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NUMBERED = re.compile(r"^[0-9]+_[A-Za-z0-9_]+\.sql$")
CHECKSUM = re.compile(r"^sha256:[0-9a-f]{64}$")
TRANSACTION = re.compile(r"^\s*(BEGIN|COMMIT|ROLLBACK)\s*;\s*$", re.MULTILINE)
LOCK_ID = 0x54525554484D4947  # Shared by both Python and PowerShell entry points.
LEDGER_SQL = """CREATE TABLE IF NOT EXISTS public.schema_migrations (
    migration_name VARCHAR(255) PRIMARY KEY,
    checksum VARCHAR(128) NOT NULL,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)"""


class MigrationError(RuntimeError):
    """Safe, credential-free migration failure for CLI callers."""


def checksum(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def executable_sql(data: bytes, *, schema: bool = False) -> str:
    text = data.decode("utf-8-sig")
    if re.search(r"^\s*\\", text, re.MULTILINE):
        raise MigrationError("psql meta-commands are unsupported in canonical SQL")
    boundaries = list(TRANSACTION.finditer(text))
    if schema:
        # DB_SCHEMA.sql owns a single outer BEGIN/COMMIT. Move that boundary to
        # the driver so the schema and its ledger row commit together. Keep all
        # function/DO bodies intact; never split SQL on semicolons.
        if [item.group(1) for item in boundaries] != ["BEGIN", "COMMIT"]:
            raise MigrationError("Canonical schema must have one outer BEGIN/COMMIT pair")
        before, after = text[:boundaries[0].start()], text[boundaries[1].end():]
        if any(line.strip() and not line.lstrip().startswith("--")
               for line in (before + "\n" + after).splitlines()):
            raise MigrationError("Canonical schema has SQL outside its transaction")
        return text[boundaries[0].end():boundaries[1].start()]
    if boundaries:
        raise MigrationError("Numbered migrations must use the runner's transaction")
    return text


def load_migrations(directory: Path, schema_file: Path | None = None) -> list[tuple[str, str, str]]:
    """Freeze and verify every file before connecting or changing the database."""
    manifest = directory / "MANIFEST.sha256"
    if not manifest.is_file() or manifest.is_symlink():
        raise MigrationError("Migration checksum manifest is missing or is a symlink")
    expected = {}
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or not CHECKSUM.fullmatch(parts[0]) or not NUMBERED.fullmatch(parts[1]):
            raise MigrationError(f"Invalid migration manifest line {number}")
        digest, name = parts
        if name in expected:
            raise MigrationError(f"Duplicate migration manifest entry: {name}")
        expected[name] = digest
    paths = sorted(path for path in directory.glob("*.sql") if NUMBERED.fullmatch(path.name))
    if not paths or {path.name for path in paths} != set(expected):
        raise MigrationError("Numbered migration files and checksum manifest do not match")
    frozen = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise MigrationError(f"Migration must be a regular file: {path.name}")
        data = path.read_bytes()
        digest = checksum(data)
        if digest != expected[path.name]:
            raise MigrationError(f"Migration checksum mismatch: {path.name}; restore the original file")
        frozen.append((path.name, digest, executable_sql(data)))
    if schema_file is not None:
        if schema_file.is_symlink() or not schema_file.is_file():
            raise MigrationError("Canonical schema must be a regular file")
        data = schema_file.read_bytes()
        frozen.insert(0, ("000_db_schema.sql", checksum(data), executable_sql(data, schema=True)))
    return frozen


def database_url(explicit: str = "") -> str:
    if explicit:
        return explicit
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    from dotenv import dotenv_values

    value = dotenv_values(ROOT / ".env").get("DATABASE_URL")
    if not value:
        raise MigrationError("DATABASE_URL is required in the environment or .env")
    return value


def apply_migrations(url: str, *, fresh_schema: bool = False,
                     migrations_dir: Path | None = None, schema_file: Path | None = None) -> dict[str, int]:
    from psycopg import Error, connect

    files = load_migrations(migrations_dir or ROOT / "scripts/migrations",
                            (schema_file or ROOT / "DB_SCHEMA.sql") if fresh_schema else None)
    url = re.sub(r"^postgres(?:ql)?\+psycopg2?://", "postgresql://", url)
    if not url.startswith(("postgresql://", "postgres://")):
        raise MigrationError("Migrations require a PostgreSQL connection URL")
    active_name = "database connection"
    result = {"applied": 0, "skipped": 0}
    try:
        with connect(url, autocommit=True, connect_timeout=10, application_name="truthward-migrations") as connection:
            connection.execute("SET search_path TO public")
            connection.execute("SET lock_timeout TO '10s'")
            connection.execute("SET statement_timeout TO '5min'")
            if not connection.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_ID,)).fetchone()[0]:
                raise MigrationError("Another migration runner holds the database lock; no changes applied")
            # The session lock covers the empty check, ledger validation and all
            # transactions. Disconnecting also releases it after any failure.
            if fresh_schema and connection.execute("""SELECT EXISTS (
                SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
                UNION ALL
                SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public' AND NOT EXISTS (
                    SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass
                    AND d.objid = p.oid AND d.deptype = 'e')
                UNION ALL
                SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
                WHERE n.nspname = 'public' AND t.typtype IN ('e', 'd', 'c', 'r')
                AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_type'::regclass
                    AND d.objid = t.oid AND d.deptype = 'e')
            )""").fetchone()[0]:
                raise MigrationError("Database is not empty; init-db never upgrades, resets or deletes existing data")
            ledger_exists = connection.execute("SELECT to_regclass('public.schema_migrations')").fetchone()[0]
            existing = dict(connection.execute(
                "SELECT migration_name, checksum FROM public.schema_migrations"
            ).fetchall()) if ledger_exists else {}
            # Check every already-applied numbered file before applying any new
            # file. The base schema is an evolving fresh-install snapshot; normal
            # upgrades retain its historical ledger row without replaying it.
            names = {name for name, _, _ in files} | {"000_db_schema.sql"}
            if set(existing) - names:
                raise MigrationError("Database ledger contains migrations absent from this source package")
            for name, digest, _ in files:
                if name in existing and existing[name] != digest:
                    raise MigrationError(f"Migration hash mismatch: {name}; do not edit the ledger")
            for name, digest, sql in files:
                if name in existing:
                    result["skipped"] += 1
                    print(f"SKIP {name}", flush=True)
                    continue
                active_name = name
                with connection.transaction():
                    connection.execute(LEDGER_SQL)
                    connection.execute(sql, prepare=False)
                    connection.execute(
                        "INSERT INTO public.schema_migrations (migration_name, checksum) VALUES (%s, %s)",
                        (name, digest),
                    )
                result["applied"] += 1
                print(f"PASS {name}", flush=True)
    except Error as exc:
        # Driver text may contain DSNs, SQL values or server details. Only the
        # stable SQLSTATE and source filename cross the CLI boundary.
        state = exc.sqlstate if re.fullmatch(r"[0-9A-Z]{5}", exc.sqlstate or "") else "unavailable"
        raise MigrationError(
            f"Migration stopped at {active_name} (SQLSTATE {state}); "
            "no automatic retry or reset. Inspect schema_migrations before recovery."
        ) from None
    print(f"MIGRATIONS PASS applied={result['applied']} skipped={result['skipped']}", flush=True)
    return result


def main() -> int:
    from community import check_python

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh-schema", action="store_true", help="Initialize an empty database only")
    parser.add_argument("--migrations-dir", type=Path)
    parser.add_argument("--schema-file", type=Path)
    args = parser.parse_args()
    try:
        check_python()
        apply_migrations(database_url(), fresh_schema=args.fresh_schema,
                         migrations_dir=args.migrations_dir, schema_file=args.schema_file)
    except MigrationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 -- redact connection/configuration errors
        print(f"Migration startup stopped ({type(exc).__name__}); check Python, configuration and source files", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

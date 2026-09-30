"""Productization Phase 10: run the suite's ControlDBs on PostgreSQL.

Set HYDRA_TEST_DATABASE_URL to a disposable local Postgres (for example the
`postgres:18` CI service) — never a real deployment: every test creates and
drops schemas there. Each ControlDB path maps to its own schema, so tests
stay as isolated as they are with one SQLite file each.
"""

from __future__ import annotations

import os
from pathlib import Path

POSTGRES_URL = os.getenv("HYDRA_TEST_DATABASE_URL") or None


def install_postgres_mode() -> None:
    if not POSTGRES_URL:
        return
    import api.control_db as control_db
    from api.db import PostgresBackend, SqliteBackend, schema_for_path

    def resolve(db_path: Path, database_url: str | None) -> PostgresBackend | SqliteBackend:
        del database_url
        return PostgresBackend(POSTGRES_URL, schema=schema_for_path(Path(db_path).resolve()))

    control_db._resolve_backend = resolve


def drop_test_schemas() -> None:
    """Drop every per-test schema (session teardown)."""
    if not POSTGRES_URL:
        return
    import psycopg
    from psycopg import sql

    with psycopg.connect(POSTGRES_URL, autocommit=True) as conn:
        names = [
            row[0]
            for row in conn.execute(
                "SELECT nspname FROM pg_namespace WHERE nspname LIKE 't\\_%%'"
            ).fetchall()
        ]
        for name in names:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))

"""Productization Phase 10: run the suite's ControlDBs on PostgreSQL.

Set HYDRA_TEST_DATABASE_URL to a disposable local Postgres (for example the
`postgres:18` CI service) — never a real deployment: every test creates and
drops schemas there. Each ControlDB path maps to its own schema, so tests
stay as isolated as they are with one SQLite file each.

The URL's own role is typically a superuser, which row-level security never
applies to (Phase 10c). So the suite runs every ControlDB as a separate,
ordinary role (`hydra_test_app`, a fresh random password per session),
exactly as production should; the admin URL only provisions that role and
drops the test schemas afterwards.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

POSTGRES_URL = os.getenv("HYDRA_TEST_DATABASE_URL") or None

# Drops every per-test schema (api.db.schema_for_path names them t_<hex>);
# the names come from the catalog and are quoted by the server (format %I).
_DROP_TEST_SCHEMAS_SQL = """
DO $$
DECLARE name text;
BEGIN
    FOR name IN SELECT nspname FROM pg_namespace WHERE nspname ~ '^t_[0-9a-f]{24}$' LOOP
        EXECUTE format('DROP SCHEMA %I CASCADE', name);
        COMMIT;  -- one schema per transaction: thousands of tables otherwise
                 -- exhaust max_locks_per_transaction
    END LOOP;
END $$
"""


# An ordinary role (no superuser, no BYPASSRLS): row-level security applies
# to it. The password arrives through a transaction-local setting (a bound
# parameter) and the server quotes it (format %L).
_PROVISION_APP_ROLE_SQL = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hydra_test_app') THEN
        CREATE ROLE hydra_test_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE;
    END IF;
    EXECUTE format('ALTER ROLE hydra_test_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD %L',
                   current_setting('hydra.test_password'));
    EXECUTE format('GRANT CREATE, TEMPORARY ON DATABASE %I TO hydra_test_app',
                   current_database());
END $$
"""


def _app_role_url() -> str:
    """Provisions the test application role; returns a URL that logs in
    as it."""
    import psycopg
    from psycopg.conninfo import make_conninfo

    if not POSTGRES_URL:
        raise RuntimeError("HYDRA_TEST_DATABASE_URL is not set")
    password = secrets.token_urlsafe(24)
    with psycopg.connect(POSTGRES_URL) as conn:
        conn.execute("SELECT set_config('hydra.test_password', %s, true)", (password,))
        conn.execute(_PROVISION_APP_ROLE_SQL)
    return make_conninfo(POSTGRES_URL, user="hydra_test_app", password=password)


def install_postgres_mode() -> None:
    if not POSTGRES_URL:
        return
    import api.control_db as control_db
    from api.db import PoolConfig, PostgresBackend, SqliteBackend, schema_for_path

    app_url = _app_role_url()

    def resolve(
        db_path: Path, database_url: str | None, pool: PoolConfig | None = None
    ) -> PostgresBackend | SqliteBackend:
        del database_url
        return PostgresBackend(app_url, schema=schema_for_path(Path(db_path).resolve()), pool=pool)

    control_db._resolve_backend = resolve


def drop_test_schemas() -> None:
    """Drop every per-test schema (session teardown)."""
    if not POSTGRES_URL:
        return
    import psycopg

    with psycopg.connect(POSTGRES_URL, autocommit=True) as conn:
        conn.execute(_DROP_TEST_SCHEMAS_SQL)

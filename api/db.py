"""Productization Phase 10: the control plane's database backends.

`ControlDB` runs on either backend with the same SQL:

- **SQLite** (a local file) — the CLI, local development and the fast test
  suite; the single-node mode the roadmap keeps viable.
- **PostgreSQL** (`HYDRA_API_DATABASE_URL`, e.g. DigitalOcean managed
  Postgres 18 with `sslmode=require`) — the production API: concurrent
  multi-tenant writers.

The SQL is written once, portably: `?` / `:name` placeholders,
`INSERT ... ON CONFLICT`, `COALESCE`, `substr`, `LIMIT ? OFFSET ?`, and
SQLite's `julianday()` / `instr()`, which the Postgres schema defines with
SQLite's semantics. The few statements that can't be shared exist as two
complete literal variants (never assembled from fragments); the dialect
object covers the write lock, schema DDL, column introspection and the
health query.

Postgres specifics, chosen for parity with SQLite's behavior:
- placeholders are translated `?` -> `%s`, `:name` -> `%(name)s` (quoted
  strings and `::` casts are left alone; a literal `%` is escaped);
- parameters are bound client-side (psycopg `ClientCursor`), so a
  `? IS NULL` test works with `None` exactly as in SQLite;
- Python booleans are stored as 0/1 in integer columns, as SQLite does;
- rows support `row["col"]`, `row[0]`, `row.keys()` and `dict(row)`, like
  `sqlite3.Row`;
- one connection pool per database URL, shared by every `ControlDB` on it;
  each checkout sets the `search_path` to the instance's schema (tests get
  a schema each; production uses `public`).
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from core.store import connect_sqlite

_SAFE_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


# SQLite built-ins the shared SQL uses, defined in Postgres with SQLite's
# exact semantics so the queries stay identical on both backends. Neither
# name exists in Postgres, so nothing built-in is shadowed.
_PG_COMPAT_FUNCTIONS = """
CREATE OR REPLACE FUNCTION julianday(ts text) RETURNS double precision
    LANGUAGE sql STABLE STRICT
    AS $$ SELECT extract(epoch FROM ts::timestamptz) / 86400.0 + 2440587.5 $$;
CREATE OR REPLACE FUNCTION instr(haystack text, needle text) RETURNS integer
    LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT strpos(haystack, needle) $$;
"""


# Productization Phase 10c: row-level security, a second layer under the
# application's own organization checks. Every table with an
# `organization_id` column gets a FORCEd policy (the table owner is subject
# to it too): while a request has an organization context
# (`hydra.organization_id`, set per transaction from
# `set_request_organization`), only that organization's rows are visible or
# writable. Without a context (workers, account-level endpoints,
# migrations) the policy allows everything, as the application did before.
# Idempotent: tables already protected are not altered (no locks taken).
_PG_ROW_LEVEL_SECURITY = """
CREATE OR REPLACE FUNCTION hydra_org_visible(org text) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$ SELECT coalesce(current_setting('hydra.organization_id', true), '') = ''
              OR org = current_setting('hydra.organization_id', true) $$;
DO $$
DECLARE tbl text;
BEGIN
    FOR tbl IN
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id'
        WHERE n.nspname = current_schema() AND c.relkind = 'r' AND NOT a.attisdropped
          AND NOT (c.relrowsecurity AND c.relforcerowsecurity AND EXISTS (
              SELECT 1 FROM pg_policies p WHERE p.schemaname = n.nspname
                AND p.tablename = c.relname AND p.policyname = 'hydra_organization_isolation'))
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
        EXECUTE format('DROP POLICY IF EXISTS hydra_organization_isolation ON %I', tbl);
        EXECUTE format(
            'CREATE POLICY hydra_organization_isolation ON %I '
            'USING (hydra_org_visible(organization_id)) '
            'WITH CHECK (hydra_org_visible(organization_id))', tbl);
    END LOOP;
END $$;
"""

_request_organization: ContextVar[str | None] = ContextVar(
    "hydra_request_organization", default=None
)


def set_request_organization(organization_id: str) -> None:
    """Scopes the rest of the current request (its context) to one
    organization, for the Postgres row-level security policies. Called once
    the caller's membership is verified (api/routers/org_access.py)."""
    _request_organization.set(organization_id)


def request_organization() -> str | None:
    return _request_organization.get()


class SqliteDialect:
    name = "sqlite"
    integrity_errors: tuple[type[Exception], ...] = (sqlite3.IntegrityError,)
    # A real read of the database file (a constant like SELECT 1 is answered
    # without opening it — see ControlDB.ping).
    ping_sql = "SELECT count(*) FROM sqlite_master"

    def begin_write(self, conn: Any, key: str) -> None:
        """Take the database write lock before reading what will be
        replaced (the whole file, on SQLite)."""
        del key
        conn.execute("BEGIN IMMEDIATE")

    def columns(self, conn: Any, table: str) -> set[str]:
        return {row[0] for row in conn.execute("SELECT name FROM pragma_table_info(?)", (table,))}

    def schema(self, sqlite_ddl: str) -> str:
        return sqlite_ddl


class PostgresDialect:
    name = "postgres"
    ping_sql = "SELECT count(*) FROM information_schema.tables"

    @property
    def integrity_errors(self) -> tuple[type[Exception], ...]:
        import psycopg

        return (psycopg.IntegrityError,)

    def begin_write(self, conn: Any, key: str) -> None:
        """A transaction-scoped advisory lock per logical resource, held
        until commit: the same "read, then write" exclusivity as SQLite's
        BEGIN IMMEDIATE, without locking unrelated writers."""
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", (key,))

    def columns(self, conn: Any, table: str) -> set[str]:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = ?",
            (table,),
        ).fetchall()
        return {row[0] for row in rows}

    def schema(self, sqlite_ddl: str) -> str:
        """The SQLite DDL, translated where Postgres differs (identity
        columns; DOUBLE PRECISION, since Postgres REAL is single precision),
        preceded by the SQLite-compatible functions the shared SQL uses."""
        ddl = _PG_COMPAT_FUNCTIONS + sqlite_ddl.replace(
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
        )
        return re.sub(r"\bREAL\b", "DOUBLE PRECISION", ddl) + _PG_ROW_LEVEL_SECURITY

    def row_security_enforced(self, conn: Any) -> bool:
        """False when the connected role bypasses row-level security
        (a superuser, or BYPASSRLS)."""
        row = conn.execute(
            "SELECT NOT (rolsuper OR rolbypassrls) FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
        return bool(row and row[0])


def _ident(name: str) -> str:
    if not _SAFE_IDENTIFIER.match(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


# SQL tokens that can contain a `?` or `:name` that is NOT a placeholder
# (string literals, quoted identifiers, comments, dollar-quoted bodies),
# then the tokens that are translated. Anything else is copied as is.
_SQL_TOKEN = re.compile(
    r"""
    (?P<skip>
        '(?:[^']|'')*'                                  # string literal
      | "(?:[^"]|"")*"                                  # quoted identifier
      | --[^\n]*                                        # line comment
      | /\*.*?\*/                                        # block comment
      | \$(?P<tag>(?:[A-Za-z_]\w*)?)\$.*?\$(?P=tag)\$    # dollar-quoted body
    )
    | (?P<cast>::)
    | (?P<qmark>\?)
    | :(?P<named>[A-Za-z_]\w*)
    """,
    re.DOTALL | re.VERBOSE,
)


def _translate_token(match: re.Match[str]) -> str:
    if match.group("skip") is not None:
        return match.group("skip")
    if match.group("cast") is not None:
        return "::"
    if match.group("qmark") is not None:
        return "%s"
    return f"%({match.group('named')})s"


@lru_cache(maxsize=4096)
def translate_placeholders(sql: str) -> str:
    """`?` -> `%s`, `:name` -> `%(name)s`, outside string literals, quoted
    identifiers, comments and dollar-quoted bodies; `::` casts are kept.
    Every literal `%` (anywhere: psycopg scans the whole text) becomes
    `%%`."""
    return _SQL_TOKEN.sub(_translate_token, sql.replace("%", "%%"))


class Row:
    """A result row readable like `sqlite3.Row`."""

    __slots__ = ("_names", "_values")

    def __init__(self, names: tuple[str, ...], values: tuple[Any, ...]) -> None:
        self._names = names
        self._values = values

    def keys(self) -> list[str]:
        return list(self._names)

    def __getitem__(self, key: int | str) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._values[self._names.index(key)]

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __eq__(self, other: object) -> bool:
        # As sqlite3.Row: equal to a row with the same columns and values.
        if not isinstance(other, Row):
            return NotImplemented
        return self._names == other._names and self._values == other._values

    def __hash__(self) -> int:
        return hash((self._names, self._values))


class _PgConnection:
    """What ControlDB code expects of a connection: execute / executemany
    returning a cursor, and executescript."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, sql: str, params: Any = None) -> Any:
        if params is None or (not isinstance(params, dict) and len(params) == 0):
            return self._conn.execute(sql)
        return self._conn.execute(translate_placeholders(sql), params)

    def executemany(self, sql: str, seq: Any) -> Any:
        cursor = self._conn.cursor()
        cursor.executemany(translate_placeholders(sql), list(seq))
        return cursor

    def executescript(self, script: str) -> None:
        self._conn.execute(script)


def _row_factory(cursor: Any) -> Any:
    names = tuple(column.name for column in (cursor.description or ()))
    return lambda values: Row(names, tuple(values))


@dataclass(frozen=True)
class PoolConfig:
    """Connection pool sizing (HYDRA_API_DATABASE_POOL_*). Keep
    max_size x API processes under the database's connection limit."""

    min_size: int = 1
    max_size: int = 10
    # Seconds a request waits for a free connection before failing.
    timeout: float = 30.0


@lru_cache(maxsize=8)
def _pool(url: str, config: PoolConfig) -> Any:
    import psycopg
    from psycopg import ClientCursor
    from psycopg.adapt import Dumper
    from psycopg_pool import ConnectionPool

    class BoolAsInt(Dumper):
        oid = psycopg.adapters.types["int8"].oid

        def dump(self, obj: Any) -> bytes:
            return b"1" if obj else b"0"

    def configure(conn: Any) -> None:
        conn.adapters.register_dumper(bool, BoolAsInt)

    return ConnectionPool(
        url,
        min_size=config.min_size,
        max_size=config.max_size,
        timeout=config.timeout,
        open=True,
        configure=configure,
        # A connection the server dropped (failover, maintenance, idle
        # timeout) is replaced before it is handed out.
        check=ConnectionPool.check_connection,
        kwargs={"cursor_factory": ClientCursor, "row_factory": _row_factory},
    )


class Backend:
    """How a ControlDB reaches its database."""

    def __init__(self, dialect: SqliteDialect | PostgresDialect) -> None:
        self.dialect = dialect

    @contextmanager
    def connect(self) -> Iterator[Any]:
        raise NotImplementedError


class SqliteBackend(Backend):
    def __init__(self, path: Path) -> None:
        super().__init__(SqliteDialect())
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[Any]:
        conn = connect_sqlite(self.path)
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


# Creates the schema named by the transaction-local setting
# `hydra.new_schema` (set from a bound parameter just before).
_CREATE_SCHEMA_SQL = """
DO $$ BEGIN
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', current_setting('hydra.new_schema'));
END $$
"""


class PostgresBackend(Backend):
    def __init__(self, url: str, *, schema: str = "public", pool: PoolConfig | None = None) -> None:
        super().__init__(PostgresDialect())
        self.url = url
        self.schema = _ident(schema)
        self.pool = pool or PoolConfig()
        if self.schema != "public":
            with _pool(url, self.pool).connection() as conn, conn.transaction():
                # The name travels as a bound parameter; the server quotes it
                # (format %I). No SQL is composed client-side.
                conn.execute("SELECT set_config('hydra.new_schema', %s, true)", (self.schema,))
                conn.execute(_CREATE_SCHEMA_SQL)

    @contextmanager
    def connect(self) -> Iterator[Any]:
        # One explicit transaction per connect(): committed when the caller's
        # block ends normally, rolled back if it raises (checked from an
        # independent session in tests/test_db_backends.py).
        with _pool(self.url, self.pool).connection() as conn, conn.transaction():
            # Transaction-local (`true`): nothing leaks to the connection's
            # next user — also behind a transaction-mode pooler (PgBouncer).
            conn.execute(
                "SELECT set_config('search_path', %s, true), "
                "set_config('hydra.organization_id', %s, true)",
                (self.schema, request_organization() or ""),
            )
            yield _PgConnection(conn)


def schema_for_path(path: Path) -> str:
    """A stable, safe schema name per database path (test isolation)."""
    return "t_" + hashlib.sha256(str(path).encode()).hexdigest()[:24]

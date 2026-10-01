"""Productization Phase 10b: move the control plane from SQLite to PostgreSQL.

An operator-run, offline tool (the API is stopped; see
docs/productization/10b_migration_runbook.md). Never imported by the
running service.

Usage (the target URL comes only from the environment, never argv, so it
stays out of shell history and process listings):

    HYDRA_API_DATABASE_URL=postgresql://... python -m api.migrate_control_db copy <control.db>
    HYDRA_API_DATABASE_URL=postgresql://... python -m api.migrate_control_db verify <control.db>

`copy`
    1. Takes an online backup of `<control.db>` into a temporary copy and
       brings the copy to the current schema. The source file is opened
       read-only and never modified — it stays the rollback path.
    2. Creates the schema in Postgres and refuses to continue unless every
       table there is empty.
    3. Copies every table, parents before children, in ONE transaction;
       identity sequences continue after the copied ids.
    4. Before committing, compares each table's row count and content
       digest (an order-independent hash of every row) between the copy
       and Postgres. Any difference rolls the whole transaction back:
       the result is a verified copy or an empty target, never a partial
       one.

`verify`
    The same per-table comparison, read-only, at any later time. Before a
    rollback it shows whether Postgres has taken writes since the copy
    (which a rollback to the SQLite file would lose).

No SQL is composed at runtime: each SQLite read is a literal statement
from `_SOURCE_SELECTS`; each Postgres table name is a bound parameter,
quoted by the server (`format('%I')`) in session-temporary helper
functions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from api.control_db import ControlDB
from api.db import SqliteBackend

# Every control-plane table, parents before children (foreign keys), each
# with its literal read statement. tests/test_migrate_control_db.py fails
# when this drifts from the schema, so a new table is added here on
# purpose, never silently left behind.
_SOURCE_SELECTS: dict[str, str] = {
    "account_creation_attempts": "SELECT * FROM account_creation_attempts",
    "accounts": "SELECT * FROM accounts",
    "organizations": "SELECT * FROM organizations",
    "rate_limit_buckets": "SELECT * FROM rate_limit_buckets",
    "wompi_unmatched_payments": "SELECT * FROM wompi_unmatched_payments",
    "wompi_webhook_events": "SELECT * FROM wompi_webhook_events",
    "account_organization_roles": "SELECT * FROM account_organization_roles",
    "api_keys": "SELECT * FROM api_keys",
    "assets": "SELECT * FROM assets",
    "capability_audit_log": "SELECT * FROM capability_audit_log",
    "cost_estimates": "SELECT * FROM cost_estimates",
    "domain_verifications": "SELECT * FROM domain_verifications",
    "integration_events": "SELECT * FROM integration_events",
    "monitored_domains": "SELECT * FROM monitored_domains",
    "monitoring_pending_notifications": "SELECT * FROM monitoring_pending_notifications",
    "monthly_usage": "SELECT * FROM monthly_usage",
    "observation_batches": "SELECT * FROM observation_batches",
    "organization_collection_settings": "SELECT * FROM organization_collection_settings",
    "organization_scope_exclusions": "SELECT * FROM organization_scope_exclusions",
    "provider_run_outcomes": "SELECT * FROM provider_run_outcomes",
    "scans": "SELECT * FROM scans",
    "subscriptions": "SELECT * FROM subscriptions",
    "ticketing_integrations": "SELECT * FROM ticketing_integrations",
    "webhooks": "SELECT * FROM webhooks",
    "wompi_pending_enrollments": "SELECT * FROM wompi_pending_enrollments",
    "asset_business_context": "SELECT * FROM asset_business_context",
    "asset_business_context_audit": "SELECT * FROM asset_business_context_audit",
    "asset_identifiers": "SELECT * FROM asset_identifiers",
    "candidate_assets": "SELECT * FROM candidate_assets",
    "certificate_events": "SELECT * FROM certificate_events",
    "change_events": "SELECT * FROM change_events",
    "evidence": "SELECT * FROM evidence",
    "exposures": "SELECT * FROM exposures",
    "integration_deliveries": "SELECT * FROM integration_deliveries",
    "relationships": "SELECT * FROM relationships",
    "technology_events": "SELECT * FROM technology_events",
    "candidate_asset_reviews": "SELECT * FROM candidate_asset_reviews",
    "exposure_evidence": "SELECT * FROM exposure_evidence",
    "exposure_history": "SELECT * FROM exposure_history",
    "exposure_remediation": "SELECT * FROM exposure_remediation",
    "exposure_risk_snapshots": "SELECT * FROM exposure_risk_snapshots",
    "observations": "SELECT * FROM observations",
    "relationship_evidence": "SELECT * FROM relationship_evidence",
    "remediation_events": "SELECT * FROM remediation_events",
    "ticketing_links": "SELECT * FROM ticketing_links",
}

# Session-temporary (pg_temp) helpers: the table name is a parameter and
# the server quotes it. They vanish with the session.
_PG_HELPERS = """
CREATE OR REPLACE FUNCTION pg_temp.hydra_copy_rows(tbl text, rows jsonb) RETURNS bigint
    LANGUAGE plpgsql AS $$
DECLARE copied bigint;
BEGIN
    EXECUTE format(
        'INSERT INTO %I SELECT * FROM jsonb_populate_recordset(NULL::%I, $1)', tbl, tbl
    ) USING rows;
    GET DIAGNOSTICS copied = ROW_COUNT;
    RETURN copied;
END $$;
CREATE OR REPLACE FUNCTION pg_temp.hydra_table_rows(tbl text) RETURNS SETOF jsonb
    LANGUAGE plpgsql AS $$
BEGIN
    RETURN QUERY EXECUTE format('SELECT to_jsonb(t) FROM %I t', tbl);
END $$;
CREATE OR REPLACE FUNCTION pg_temp.hydra_has_rows(tbl text) RETURNS boolean
    LANGUAGE plpgsql AS $$
DECLARE found boolean;
BEGIN
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I)', tbl) INTO found;
    RETURN found;
END $$;
"""

_BATCH_ROWS = 1000
_DIGEST_MODULUS = 2**256


class MigrationError(RuntimeError):
    """The migration cannot proceed or did not verify; nothing was committed."""


@dataclass(frozen=True)
class TableReport:
    table: str
    source_rows: int
    target_rows: int
    source_digest: str
    target_digest: str

    @property
    def matches(self) -> bool:
        return (self.source_rows, self.source_digest) == (self.target_rows, self.target_digest)


@dataclass(frozen=True)
class MigrationReport:
    tables: tuple[TableReport, ...]

    @property
    def matches(self) -> bool:
        return all(table.matches for table in self.tables)

    def render(self) -> str:
        width = max(len(table.table) for table in self.tables)
        lines = [f"{'table':<{width}}  {'sqlite':>9}  {'postgres':>9}  result"]
        for t in self.tables:
            result = "ok" if t.matches else "DIFFERS"
            lines.append(f"{t.table:<{width}}  {t.source_rows:>9}  {t.target_rows:>9}  {result}")
        total_source = sum(t.source_rows for t in self.tables)
        total_target = sum(t.target_rows for t in self.tables)
        lines.append(f"{'TOTAL':<{width}}  {total_source:>9}  {total_target:>9}")
        return "\n".join(lines)


class _Digest:
    """Row count plus an order-independent hash of every row (the sum of
    per-row SHA-256 values), so both sides compare without sorting."""

    def __init__(self) -> None:
        self.rows = 0
        self._total = 0

    def add(self, row: dict[str, Any]) -> None:
        canonical = json.dumps(
            {key: _normalize(value) for key, value in row.items()},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        self._total += int.from_bytes(hashlib.sha256(canonical.encode()).digest(), "big")
        self.rows += 1

    @property
    def hexdigest(self) -> str:
        return f"{self._total % _DIGEST_MODULUS:064x}"


def _normalize(value: Any) -> Any:
    # SQLite may hand back 5.0 where Postgres's JSON says 5; both mean 5.
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _upgraded_copy(source: Path, workdir: Path) -> Path:
    """An online backup of the source, brought to the current schema.
    The source is opened read-only and never written."""
    if not source.is_file():
        raise MigrationError(f"SQLite control database not found: {source}")
    copy = workdir / "control.db"
    reader = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
    writer = sqlite3.connect(copy)
    try:
        reader.backup(writer)
    finally:
        writer.close()
        reader.close()
    ControlDB(copy, backend=SqliteBackend(copy))  # idempotent schema upgrade
    return copy


def _check_source_tables(copy: Path) -> None:
    with sqlite3.connect(copy) as conn:
        present = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
            )
        }
    unknown = sorted(present - set(_SOURCE_SELECTS))
    if unknown:
        raise MigrationError(f"source tables this tool does not know how to copy: {unknown}")


def _check_columns(copy: Path, target: ControlDB, conn: Any) -> None:
    """Every source column must exist in Postgres (else its data would be
    dropped silently)."""
    missing: list[str] = []
    with sqlite3.connect(copy) as source:
        for table in _SOURCE_SELECTS:
            columns = {
                row[0] for row in source.execute("SELECT name FROM pragma_table_info(?)", (table,))
            }
            absent = columns - target.dialect.columns(conn, table)
            missing.extend(f"{table}.{column}" for column in sorted(absent))
    if missing:
        raise MigrationError(f"columns missing in the Postgres schema: {missing}")


def _source_batches(copy: Path, table: str) -> Iterator[list[dict[str, Any]]]:
    conn = sqlite3.connect(copy)
    try:
        cursor = conn.execute(_SOURCE_SELECTS[table])
        names = [column[0] for column in cursor.description]
        while batch := cursor.fetchmany(_BATCH_ROWS):
            yield [dict(zip(names, values, strict=True)) for values in batch]
    finally:
        conn.close()


def _source_digests(copy: Path) -> dict[str, _Digest]:
    digests: dict[str, _Digest] = {}
    for table in _SOURCE_SELECTS:
        digest = _Digest()
        for batch in _source_batches(copy, table):
            for row in batch:
                digest.add(row)
        digests[table] = digest
    return digests


def _target_digest(conn: Any, table: str) -> _Digest:
    digest = _Digest()
    cursor = conn.execute("SELECT pg_temp.hydra_table_rows(?)", (table,))
    while batch := cursor.fetchmany(_BATCH_ROWS):
        for row in batch:
            digest.add(row[0])
    return digest


def _compare(copy: Path, conn: Any) -> MigrationReport:
    source = _source_digests(copy)
    reports = []
    for table in _SOURCE_SELECTS:
        target = _target_digest(conn, table)
        reports.append(
            TableReport(
                table=table,
                source_rows=source[table].rows,
                target_rows=target.rows,
                source_digest=source[table].hexdigest,
                target_digest=target.hexdigest,
            )
        )
    return MigrationReport(tables=tuple(reports))


def _require_empty(conn: Any) -> None:
    populated = [
        table
        for table in _SOURCE_SELECTS
        if conn.execute("SELECT pg_temp.hydra_has_rows(?)", (table,)).fetchone()[0]
    ]
    if populated:
        raise MigrationError(
            f"the Postgres target already has data in {populated}; migrate only into an "
            "empty database"
        )


def _copy_rows(copy: Path, conn: Any) -> None:
    import psycopg

    for table in _SOURCE_SELECTS:
        try:
            for batch in _source_batches(copy, table):
                conn.execute(
                    "SELECT pg_temp.hydra_copy_rows(?, ?::jsonb)",
                    (table, json.dumps(batch, allow_nan=False)),
                )
        except (psycopg.Error, ValueError) as exc:
            # ValueError: a NaN/infinite float, which JSON (and so this
            # copy) cannot carry.
            raise MigrationError(f"{table}: Postgres rejected a row: {exc}") from exc


def _continue_identity_sequences(copy: Path, conn: Any) -> None:
    """AUTOINCREMENT tables: the next Postgres id follows the highest id
    SQLite ever issued (sqlite_sequence), so ids are never reused."""
    with sqlite3.connect(copy) as source:
        issued = source.execute("SELECT name, seq FROM sqlite_sequence").fetchall()
        for table, seq in issued:
            key = source.execute(
                "SELECT name FROM pragma_table_info(?) WHERE pk = 1", (table,)
            ).fetchone()[0]
            # `? = 1`: booleans are bound as 0/1 (api/db.py).
            conn.execute(
                "SELECT setval(pg_get_serial_sequence(?, ?), ?, ? = 1)",
                (table, key, max(int(seq), 1), int(seq) > 0),
            )


def _open_target(target: ControlDB) -> Any:
    if target.dialect.name != "postgres":
        raise MigrationError("the target must be a PostgreSQL database")
    return target.backend.connect()


def copy_control_db(source: Path, target: ControlDB) -> MigrationReport:
    """Copies `source` into the (empty) Postgres `target`; commits only
    when every table verifies. Raises MigrationError otherwise."""
    with tempfile.TemporaryDirectory(prefix="hydra-migrate-") as workdir:
        copy = _upgraded_copy(source, Path(workdir))
        _check_source_tables(copy)
        with _open_target(target) as conn:
            conn.executescript(_PG_HELPERS)
            _check_columns(copy, target, conn)
            _require_empty(conn)
            _copy_rows(copy, conn)
            _continue_identity_sequences(copy, conn)
            report = _compare(copy, conn)
            if not report.matches:
                # Leaving the block with an exception rolls everything back.
                raise MigrationError("verification failed:\n" + report.render())
    return report


def verify_control_db(source: Path, target: ControlDB) -> MigrationReport:
    """Read-only per-table comparison of `source` and the Postgres `target`."""
    with tempfile.TemporaryDirectory(prefix="hydra-verify-") as workdir:
        copy = _upgraded_copy(source, Path(workdir))
        _check_source_tables(copy)
        with _open_target(target) as conn:
            conn.executescript(_PG_HELPERS)
            return _compare(copy, conn)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=("copy", "verify"))
    parser.add_argument("control_db", type=Path, help="The SQLite control.db to read from.")
    args = parser.parse_args(argv)

    url = os.getenv("HYDRA_API_DATABASE_URL")
    if not url:
        print("HYDRA_API_DATABASE_URL is not set (the Postgres target).", file=sys.stderr)
        return 2
    target = ControlDB(args.control_db, database_url=url)
    try:
        if args.command == "copy":
            report = copy_control_db(args.control_db, target)
        else:
            report = verify_control_db(args.control_db, target)
    except MigrationError as exc:
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 1
    print(report.render())
    if not report.matches:
        print("Source and target DIFFER (see above).", file=sys.stderr)
        return 1
    print(f"{args.command}: every table matches.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Productization Phase 10: moving control-plane rows into and out of
PostgreSQL, shared by the SQLite migration (api/migrate_control_db.py) and
the logical backup / restore (api/control_export.py).

No SQL is composed at runtime: SQLite reads are the literal statements
below; on Postgres every table or column name is a bound parameter,
quoted by the server (`format('%I')`) inside session-temporary helper
functions.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

# Every control-plane table, parents before children (foreign keys), each
# with its literal SQLite read statement. tests/test_migrate_control_db.py
# fails when this drifts from the schema, so a new table is added here on
# purpose, never silently left out of a migration or a backup.
SQLITE_TABLE_READS: dict[str, str] = {
    "account_creation_attempts": "SELECT * FROM account_creation_attempts",
    "accounts": "SELECT * FROM accounts",
    "organizations": "SELECT * FROM organizations",
    "rate_limit_buckets": "SELECT * FROM rate_limit_buckets",
    "security_audit_log": "SELECT * FROM security_audit_log",
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

CONTROL_TABLES: tuple[str, ...] = tuple(SQLITE_TABLE_READS)

# Session-temporary (pg_temp) helpers: names are parameters and the server
# quotes them. They vanish with the session.
PG_HELPERS = """
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
CREATE OR REPLACE FUNCTION pg_temp.hydra_count(tbl text) RETURNS bigint
    LANGUAGE plpgsql AS $$
DECLARE counted bigint;
BEGIN
    EXECUTE format('SELECT count(*) FROM %I', tbl) INTO counted;
    RETURN counted;
END $$;
CREATE OR REPLACE FUNCTION pg_temp.hydra_newest(tbl text, col text) RETURNS text
    LANGUAGE plpgsql AS $$
DECLARE newest text;
BEGIN
    EXECUTE format('SELECT max(%I)::text FROM %I', col, tbl) INTO newest;
    RETURN newest;
END $$;
"""

BATCH_ROWS = 1000
_DIGEST_MODULUS = 2**256

# Identity (former AUTOINCREMENT) columns of the current schema and the last
# value their sequence issued (NULL: never used).
_IDENTITY_SEQUENCES_SQL = (
    "SELECT table_name, column_name, "
    "pg_sequence_last_value(pg_get_serial_sequence(table_name, column_name)::regclass) "
    "FROM information_schema.columns "
    "WHERE table_schema = current_schema() AND is_identity = 'YES' "
    "ORDER BY table_name"
)


class TransferError(RuntimeError):
    """The transfer cannot proceed or did not verify; nothing was committed."""


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
class TransferReport:
    tables: tuple[TableReport, ...]
    source_label: str = "sqlite"
    target_label: str = "postgres"

    @property
    def matches(self) -> bool:
        return all(table.matches for table in self.tables)

    def render(self) -> str:
        width = max([5, *(len(table.table) for table in self.tables)])
        lines = [f"{'table':<{width}}  {self.source_label:>9}  {self.target_label:>9}  result"]
        for t in self.tables:
            result = "ok" if t.matches else "DIFFERS"
            lines.append(f"{t.table:<{width}}  {t.source_rows:>9}  {t.target_rows:>9}  {result}")
        total_source = sum(t.source_rows for t in self.tables)
        total_target = sum(t.target_rows for t in self.tables)
        lines.append(f"{'TOTAL':<{width}}  {total_source:>9}  {total_target:>9}")
        return "\n".join(lines)


class Digest:
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


def require_empty(conn: Any, tables: Iterable[str] = CONTROL_TABLES) -> None:
    populated = [
        table
        for table in tables
        if conn.execute("SELECT pg_temp.hydra_has_rows(?)", (table,)).fetchone()[0]
    ]
    if populated:
        raise TransferError(
            f"the Postgres target already has data in {populated}; write only into an "
            "empty database"
        )


def copy_table(conn: Any, table: str, batches: Iterable[list[dict[str, Any]]]) -> None:
    import psycopg

    try:
        for batch in batches:
            conn.execute(
                "SELECT pg_temp.hydra_copy_rows(?, ?::jsonb)",
                (table, json.dumps(batch, allow_nan=False)),
            )
    except (psycopg.Error, ValueError) as exc:
        # ValueError: a NaN/infinite float, which JSON (and so this copy)
        # cannot carry.
        raise TransferError(f"{table}: Postgres rejected a row: {exc}") from exc


def table_batches(conn: Any, table: str) -> Iterator[list[dict[str, Any]]]:
    """Every row of `table` as dicts, streamed through a server-side cursor."""
    for batch in conn.stream("SELECT pg_temp.hydra_table_rows(?)", (table,), BATCH_ROWS):
        yield [row[0] for row in batch]


def table_digest(conn: Any, table: str) -> Digest:
    digest = Digest()
    for batch in table_batches(conn, table):
        for row in batch:
            digest.add(row)
    return digest


def identity_sequences(conn: Any) -> list[tuple[str, str, int | None]]:
    return [(row[0], row[1], row[2]) for row in conn.execute(_IDENTITY_SEQUENCES_SQL)]


def continue_sequence(conn: Any, table: str, column: str, last_value: int | None) -> None:
    """The next id follows `last_value` (None: the sequence starts fresh)."""
    issued = last_value or 0
    # `? = 1`: booleans are bound as 0/1 (api/db.py).
    conn.execute(
        "SELECT setval(pg_get_serial_sequence(?, ?), ?, ? = 1)",
        (table, column, max(issued, 1), issued > 0),
    )

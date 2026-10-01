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

No SQL is composed at runtime (see api/pg_transfer.py).
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import tempfile
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from typing import Any

from api.control_db import ControlDB
from api.db import SqliteBackend
from api.pg_transfer import (
    BATCH_ROWS,
    CONTROL_TABLES,
    PG_HELPERS,
    SQLITE_TABLE_READS,
    Digest,
    TableReport,
    TransferError,
    TransferReport,
    continue_sequence,
    copy_table,
    require_empty,
    table_digest,
)

# The 10b names, kept for callers and tests.
MigrationError = TransferError
MigrationReport = TransferReport


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
    with closing(sqlite3.connect(copy)) as conn:
        present = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
            )
        }
    unknown = sorted(present - set(CONTROL_TABLES))
    if unknown:
        raise MigrationError(f"source tables this tool does not know how to copy: {unknown}")


def _check_columns(copy: Path, target: ControlDB, conn: Any) -> None:
    """Every source column must exist in Postgres (else its data would be
    dropped silently)."""
    missing: list[str] = []
    with closing(sqlite3.connect(copy)) as source:
        for table in CONTROL_TABLES:
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
        cursor = conn.execute(SQLITE_TABLE_READS[table])
        names = [column[0] for column in cursor.description]
        while batch := cursor.fetchmany(BATCH_ROWS):
            yield [dict(zip(names, values, strict=True)) for values in batch]
    finally:
        conn.close()


def _source_digest(copy: Path, table: str) -> Digest:
    digest = Digest()
    for batch in _source_batches(copy, table):
        for row in batch:
            digest.add(row)
    return digest


def _compare(copy: Path, conn: Any) -> MigrationReport:
    reports = []
    for table in CONTROL_TABLES:
        source, target = _source_digest(copy, table), table_digest(conn, table)
        reports.append(
            TableReport(table, source.rows, target.rows, source.hexdigest, target.hexdigest)
        )
    return MigrationReport(tables=tuple(reports))


def _continue_identity_sequences(copy: Path, conn: Any) -> None:
    """AUTOINCREMENT tables: the next Postgres id follows the highest id
    SQLite ever issued (sqlite_sequence), so ids are never reused."""
    with closing(sqlite3.connect(copy)) as source:
        issued = source.execute("SELECT name, seq FROM sqlite_sequence").fetchall()
        for table, seq in issued:
            key = source.execute(
                "SELECT name FROM pragma_table_info(?) WHERE pk = 1", (table,)
            ).fetchone()[0]
            continue_sequence(conn, table, key, int(seq))


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
            conn.executescript(PG_HELPERS)
            _check_columns(copy, target, conn)
            require_empty(conn)
            for table in CONTROL_TABLES:
                copy_table(conn, table, _source_batches(copy, table))
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
            conn.executescript(PG_HELPERS)
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

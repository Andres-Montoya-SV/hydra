"""Productization Phase 10d: logical backup and restore of the PostgreSQL
control plane.

DigitalOcean's managed backups (daily, plus point-in-time recovery) protect
the database inside DigitalOcean. This export is the provider-independent
copy: plain files that the backup loop (api/backup_worker.py) writes into
each snapshot directory, uploads with it to S3-compatible storage, and
that `python -m api.restore_backup` loads into any empty PostgreSQL.

Snapshot layout, `<snapshot>/control/`:

    manifest.json          format, creation time, per table: rows, content
                           digest, columns; identity sequence positions
    <table>.jsonl.gz       one JSON object per row

- **Consistent:** every table is read in one REPEATABLE READ transaction,
  so the export is the database as of a single instant, even while the
  API keeps writing.
- **Verifiable:** the manifest is written last; a snapshot without one is
  incomplete. Restore re-hashes every file against the manifest before it
  writes anything, loads all tables in one transaction, and commits only
  when every table's rows and digest match the manifest.
- **Private:** files are created 0600 and the directory 0700. They hold
  the same data as the database (API-key hashes, emails, sealed secrets).

Usage (URL from HYDRA_API_DATABASE_URL only):

    python -m api.control_export export <dir>   # an ad-hoc export
    python -m api.control_export inspect        # rows and newest timestamp per table
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api.control_db import ControlDB
from api.pg_transfer import (
    BATCH_ROWS,
    CONTROL_TABLES,
    PG_HELPERS,
    Digest,
    TableReport,
    TransferError,
    TransferReport,
    continue_sequence,
    copy_table,
    identity_sequences,
    require_empty,
    table_batches,
    table_digest,
)

FORMAT = "hydra-control-export/1"
MANIFEST = "manifest.json"
# The timestamp columns `inspect` reports, most telling first.
_TIMESTAMP_COLUMNS = ("updated_at", "created_at", "observed_at", "recorded_at", "last_seen_at")


@dataclass(frozen=True)
class ExportedTable:
    name: str
    rows: int
    digest: str
    columns: tuple[str, ...]


@dataclass(frozen=True)
class Sequence:
    table: str
    column: str
    last_value: int | None


@dataclass(frozen=True)
class Manifest:
    format: str
    created_at: str
    tables: tuple[ExportedTable, ...]
    sequences: tuple[Sequence, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> Manifest:
        raw = json.loads(text)
        if raw.get("format") != FORMAT:
            raise TransferError(f"unsupported export format: {raw.get('format')!r}")
        return cls(
            format=raw["format"],
            created_at=raw["created_at"],
            tables=tuple(
                ExportedTable(t["name"], t["rows"], t["digest"], tuple(t["columns"]))
                for t in raw["tables"]
            ),
            sequences=tuple(Sequence(**s) for s in raw["sequences"]),
        )


@contextmanager
def _private_writer(path: Path) -> Iterator[io.TextIOWrapper]:
    """A new gzip text file, created 0600 (never briefly wider). GzipFile
    does not close the file it wraps, so all three layers are closed here."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with (
        os.fdopen(fd, "wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb") as compressed,
        io.TextIOWrapper(compressed, encoding="utf-8") as out,
    ):
        yield out


def _require_postgres(control_db: ControlDB) -> None:
    if control_db.dialect.name != "postgres":
        raise TransferError("the control plane is not on PostgreSQL")


def _export_table(conn: Any, control_db: ControlDB, dest: Path, table: str) -> ExportedTable:
    digest = Digest()
    with _private_writer(dest / f"{table}.jsonl.gz") as out:
        for batch in table_batches(conn, table):
            for row in batch:
                digest.add(row)
                out.write(json.dumps(row, allow_nan=False, separators=(",", ":")) + "\n")
    columns = tuple(sorted(control_db.dialect.columns(conn, table)))
    return ExportedTable(table, digest.rows, digest.hexdigest, columns)


def export_control_plane(control_db: ControlDB, dest: Path) -> Manifest:
    """Writes a consistent export of every control-plane table into `dest`
    (which must not exist yet). The manifest is written last."""
    _require_postgres(control_db)
    dest.mkdir(parents=True, mode=0o700)
    with control_db.backend.connect(snapshot=True) as conn:
        conn.executescript(PG_HELPERS)
        tables = tuple(_export_table(conn, control_db, dest, t) for t in CONTROL_TABLES)
        sequences = tuple(Sequence(*seq) for seq in identity_sequences(conn))
    manifest = Manifest(
        format=FORMAT,
        created_at=datetime.now(timezone.utc).isoformat(),
        tables=tables,
        sequences=sequences,
    )
    fd = os.open(dest / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(manifest.to_json())
    return manifest


def read_manifest(control_dir: Path) -> Manifest:
    path = control_dir / MANIFEST
    if not path.is_file():
        raise TransferError(f"no {MANIFEST} in {control_dir}: the export is incomplete")
    return Manifest.from_json(path.read_text(encoding="utf-8"))


def _file_batches(control_dir: Path, table: str) -> Iterator[list[dict[str, Any]]]:
    with gzip.open(control_dir / f"{table}.jsonl.gz", "rt", encoding="utf-8") as rows:
        batch: list[dict[str, Any]] = []
        for line in rows:
            batch.append(json.loads(line))
            if len(batch) == BATCH_ROWS:
                yield batch
                batch = []
        if batch:
            yield batch


def _verify_files(control_dir: Path, manifest: Manifest) -> None:
    """Every file must hash to its manifest entry before anything is written."""
    for table in manifest.tables:
        digest = Digest()
        try:
            for batch in _file_batches(control_dir, table.name):
                for row in batch:
                    digest.add(row)
        except (OSError, EOFError, ValueError) as exc:
            raise TransferError(f"{table.name}: unreadable export file: {exc}") from exc
        if (digest.rows, digest.hexdigest) != (table.rows, table.digest):
            raise TransferError(
                f"{table.name}: the export file does not match its manifest "
                f"({digest.rows} rows read, {table.rows} expected): corrupted or incomplete"
            )


def _check_columns(conn: Any, target: ControlDB, manifest: Manifest) -> None:
    missing = [
        f"{table.name}.{column}"
        for table in manifest.tables
        for column in sorted(set(table.columns) - target.dialect.columns(conn, table.name))
    ]
    if missing:
        raise TransferError(f"columns missing in the target schema: {missing}")


def _compare(conn: Any, manifest: Manifest) -> TransferReport:
    reports = []
    for table in manifest.tables:
        restored = table_digest(conn, table.name)
        reports.append(
            TableReport(table.name, table.rows, restored.rows, table.digest, restored.hexdigest)
        )
    return TransferReport(tables=tuple(reports), source_label="snapshot")


def restore_control_plane(control_dir: Path, target: ControlDB) -> TransferReport:
    """Loads an export into the empty Postgres `target`; commits only when
    every table matches the manifest. Raises TransferError otherwise."""
    _require_postgres(target)
    manifest = read_manifest(control_dir)
    _verify_files(control_dir, manifest)
    with target.backend.connect() as conn:
        conn.executescript(PG_HELPERS)
        _check_columns(conn, target, manifest)
        require_empty(conn, dict.fromkeys([*CONTROL_TABLES, *(t.name for t in manifest.tables)]))
        for table in manifest.tables:
            copy_table(conn, table.name, _file_batches(control_dir, table.name))
        for seq in manifest.sequences:
            continue_sequence(conn, seq.table, seq.column, seq.last_value)
        report = _compare(conn, manifest)
        if not report.matches:
            # Leaving the block with an exception rolls everything back.
            raise TransferError("verification failed:\n" + report.render())
    return report


@dataclass(frozen=True)
class TableState:
    table: str
    rows: int
    newest: str | None


def inspect_control_plane(control_db: ControlDB) -> list[TableState]:
    """Rows and the newest timestamp per table: after a point-in-time
    restore, confirms what the recovered database actually holds."""
    _require_postgres(control_db)
    states = []
    # One snapshot: every count and timestamp is from the same instant.
    with control_db.backend.connect(snapshot=True) as conn:
        conn.executescript(PG_HELPERS)
        for table in CONTROL_TABLES:
            rows = conn.execute("SELECT pg_temp.hydra_count(?)", (table,)).fetchone()[0]
            present = control_db.dialect.columns(conn, table)
            newest = [
                conn.execute("SELECT pg_temp.hydra_newest(?, ?)", (table, column)).fetchone()[0]
                for column in _TIMESTAMP_COLUMNS
                if column in present
            ]
            states.append(TableState(table, rows, max((n for n in newest if n), default=None)))
    return states


def _render_states(states: list[TableState]) -> str:
    width = max(len(state.table) for state in states)
    lines = [f"{'table':<{width}}  {'rows':>9}  newest"]
    lines += [f"{s.table:<{width}}  {s.rows:>9}  {s.newest or '-'}" for s in states]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=("export", "inspect"))
    parser.add_argument("dest", type=Path, nargs="?", help="export: a new directory")
    args = parser.parse_args(argv)

    url = os.getenv("HYDRA_API_DATABASE_URL")
    if not url:
        print("HYDRA_API_DATABASE_URL is not set.", file=sys.stderr)
        return 2
    control_db = ControlDB(Path("control.db"), database_url=url)
    try:
        if args.command == "inspect":
            print(_render_states(inspect_control_plane(control_db)))
            return 0
        if args.dest is None:
            parser.error("export needs a destination directory")
        manifest = export_control_plane(control_db, args.dest)
    except (TransferError, FileExistsError) as exc:
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 1
    total = sum(table.rows for table in manifest.tables)
    print(f"Exported {total} rows from {len(manifest.tables)} tables into {args.dest}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

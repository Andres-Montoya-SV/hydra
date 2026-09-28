"""Fase 20 (EASM roadmap): post-restore referential integrity check.

`api/backup_worker.py::backup_sqlite_file` uses `sqlite3.Connection.
backup()` — a whole-database, page-level copy — so a normal backup/
restore cycle captures every EASM table (`assets`, `observations`,
`evidence`, `change_events`, `candidate_assets`, `relationships`,
`exposures`, `certificate_events`, `technology_events`,
`observation_batches`, ...) atomically, in one consistent instant.
Restoring that snapshot back can never, on its own, produce a dangling
reference (an `exposures.asset_id` pointing at an `asset_id` that
doesn't exist) — everything in the file was consistent when it was
copied.

**Correction (Fase 21 cleanup, 2026-09-28)**: this module's own original
docstring claimed no connection anywhere enables SQLite's `REFERENCES`
enforcement — that was wrong, found and fixed while writing the Fase 21
README/architecture-doc updates. `core/store.py::configure_sqlite()`
(used by every connection `connect_sqlite()` returns — both
`api/control_db.py::ControlDB._connect()` and every per-account
`AssetStore`) DOES call `PRAGMA foreign_keys=ON`. An ordinary write
through Hydra's own code therefore already gets real, enforced
referential integrity; SQLite itself would reject a `DELETE` that left a
dangling reference. This module exists for cases OUTSIDE that
protection: a snapshot opened and hand-edited with a bare `sqlite3`
connection or an external tool that never enables the pragma (SQLite's
own default is OFF per-connection, regardless of what any other
connection to the same file does), byte-level file corruption, or a
partial/mixed restore an operator assembled by hand from files out of
different snapshots.

**The explicit decision this phase requires**: neither silently discard
an orphaned row (destroys history/evidence without an operator ever
knowing) nor block the restore outright (a restore is frequently an
emergency recovery action — refusing it over a data-quality issue
unrelated to the restore mechanism itself would make the cure worse than
the disease). `check_referential_integrity()` only ever REPORTS; nothing
in this module deletes or modifies a row. `api/restore_backup.py` prints
every finding, specifically, after a restore completes — the operator
decides what to do with it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

# (table, id_column, reference_column, referenced_table, referenced_id_column)
_CHECKS: tuple[tuple[str, str, str, str, str], ...] = (
    ("exposures", "exposure_id", "asset_id", "assets", "asset_id"),
    ("relationships", "relationship_id", "source_asset_id", "assets", "asset_id"),
    ("relationships", "relationship_id", "target_asset_id", "assets", "asset_id"),
    ("change_events", "change_event_id", "asset_id", "assets", "asset_id"),
    ("certificate_events", "certificate_event_id", "asset_id", "assets", "asset_id"),
    ("technology_events", "technology_event_id", "asset_id", "assets", "asset_id"),
    ("observations", "observation_id", "asset_id", "assets", "asset_id"),
    ("observations", "observation_id", "evidence_id", "evidence", "evidence_id"),
    ("evidence", "evidence_id", "asset_id", "assets", "asset_id"),
    ("exposure_evidence", "exposure_evidence_id", "exposure_id", "exposures", "exposure_id"),
    ("exposure_history", "event_id", "exposure_id", "exposures", "exposure_id"),
)


@dataclass(frozen=True)
class OrphanedRow:
    table: str
    row_id: str
    reference_column: str
    referenced_table: str
    missing_referenced_id: str


@dataclass(frozen=True)
class IntegrityReport:
    orphaned_rows: tuple[OrphanedRow, ...]

    @property
    def is_clean(self) -> bool:
        return len(self.orphaned_rows) == 0


def check_referential_integrity(control_db_path: Path) -> IntegrityReport:
    """Read-only — opens its own connection, never touches
    `api/control_db.py::ControlDB`'s own migration/schema-creation path
    (a restored snapshot is already a real, fully-migrated database; this
    only ever runs `SELECT`s against it)."""
    orphans: list[OrphanedRow] = []
    conn = sqlite3.connect(control_db_path)
    conn.row_factory = sqlite3.Row
    try:
        existing_tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        for table, id_col, ref_col, ref_table, ref_id_col in _CHECKS:
            if table not in existing_tables or ref_table not in existing_tables:
                continue  # an older/newer schema than this module knows about -- skip, don't guess
            rows = conn.execute(
                f"SELECT {id_col} AS row_id, {ref_col} AS ref_value FROM {table} "  # noqa: S608  # nosec B608
                f"WHERE {ref_col} IS NOT NULL AND {ref_col} NOT IN "
                f"(SELECT {ref_id_col} FROM {ref_table})"
            ).fetchall()
            for row in rows:
                orphans.append(
                    OrphanedRow(
                        table=table,
                        row_id=str(row["row_id"]),
                        reference_column=ref_col,
                        referenced_table=ref_table,
                        missing_referenced_id=str(row["ref_value"]),
                    )
                )
    finally:
        conn.close()
    return IntegrityReport(orphaned_rows=tuple(orphans))

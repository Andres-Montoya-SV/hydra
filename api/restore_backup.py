"""Restores a backup snapshot produced by `api/backup_worker.py` — the
one part of "Automated backups and a real deployment target" the task
called out as mattering most: an untested backup is not a backup.

Deliberately a SEPARATE module from `api/backup_worker.py`, never
imported by the running service — restoring is an operator-run,
offline recovery action taken against a stopped (or not-yet-started)
API process, never something the service does to itself automatically.

Usage:

    python -m api.restore_backup <backup-snapshot-dir> <target-data-dir>
    python -m api.restore_backup <backup-snapshot-dir> <target-data-dir> --force

A snapshot directory mirrors the real data directory's own relative
layout (`control.db` at its root, each account's `recon.db` at
`accounts/<account_id>/output/recon.db`) specifically so restoring is a
straight structural copy back — no SQLite-specific logic is needed
here (the files on disk are already consistent, at-rest snapshots
produced by `sqlite3.Connection.backup()`; a plain file copy of an
already-static file needs no special handling).

A snapshot taken while the control plane was on PostgreSQL (Productization
Phase 10d) holds `control/` (api/control_export.py) instead of
`control.db`. It is restored into the empty database at
HYDRA_API_DATABASE_URL, verified table by table against the export's
manifest, or not at all.

Refuses to overwrite an existing `<target-data-dir>/control.db` unless
`--force` is passed — restoring is the kind of operation you want to
fail loudly on an accidental wrong argument, not silently clobber a
live, running deployment's real data directory.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from api.control_db import ControlDB
from api.control_export import MANIFEST, restore_control_plane
from api.pg_transfer import TransferError, TransferReport
from api.restore_integrity import IntegrityReport, check_referential_integrity


class RestoreTargetExistsError(RuntimeError):
    """Raised when `target_data_dir` already has a `control.db` and
    `force=False` — the caller almost certainly pointed this at the
    wrong directory, or meant to pass `--force`."""


def _account_files(snapshot_dir: Path, target_data_dir: Path) -> list[tuple[Path, Path]]:
    """(snapshot recon.db, its place under target_data_dir) per account."""
    accounts_dir = snapshot_dir / "accounts"
    if not accounts_dir.is_dir():
        return []
    pairs = []
    for account_dir in sorted(accounts_dir.iterdir()):
        source = account_dir / "output" / "recon.db"
        if source.is_file():
            target = target_data_dir / "accounts" / account_dir.name / "output" / "recon.db"
            pairs.append((source, target))
    return pairs


def _restore_account_files(snapshot_dir: Path, target_data_dir: Path) -> int:
    pairs = _account_files(snapshot_dir, target_data_dir)
    for source, target in pairs:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return len(pairs)


def restore_postgres_backup(
    snapshot_dir: Path, target_data_dir: Path, target: ControlDB, *, force: bool = False
) -> TransferReport:
    """Productization Phase 10d: a snapshot taken while the control plane
    was on PostgreSQL (`control/`, api/control_export.py). The control plane
    goes into the empty Postgres `target`, verified against the manifest
    or not at all; the account files are copied as for SQLite snapshots."""
    if not snapshot_dir.is_dir():
        raise FileNotFoundError(f"Backup snapshot directory not found: {snapshot_dir}")
    existing = [t for _, t in _account_files(snapshot_dir, target_data_dir) if t.exists()]
    if existing and not force:
        raise RestoreTargetExistsError(
            f"{len(existing)} account recon.db file(s) already exist under {target_data_dir} "
            "— pass --force to overwrite them, or restore into an empty target-data-dir."
        )
    report = restore_control_plane(snapshot_dir / "control", target)
    restored_accounts = _restore_account_files(snapshot_dir, target_data_dir)
    print(
        f"Restored the control plane ({sum(t.target_rows for t in report.tables)} rows, "
        f"verified) and {restored_accounts} account recon.db file(s) from {snapshot_dir}."
    )
    return report


def restore_backup(
    snapshot_dir: Path, target_data_dir: Path, *, force: bool = False
) -> IntegrityReport:
    if not snapshot_dir.is_dir():
        raise FileNotFoundError(f"Backup snapshot directory not found: {snapshot_dir}")

    source_control_db = snapshot_dir / "control.db"
    if not source_control_db.is_file():
        raise FileNotFoundError(f"No control.db in snapshot: {source_control_db}")

    target_control_db = target_data_dir / "control.db"
    if target_control_db.exists() and not force:
        raise RestoreTargetExistsError(
            f"{target_control_db} already exists — pass --force to overwrite it, or "
            "restore into an empty target-data-dir."
        )

    target_data_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_control_db, target_control_db)
    restored_accounts = _restore_account_files(snapshot_dir, target_data_dir)

    print(
        f"Restored control.db and {restored_accounts} account recon.db file(s) from "
        f"{snapshot_dir} into {target_data_dir}."
    )

    # Fase 20 (EASM roadmap): report-only, never destructive or
    # restore-blocking — see this module's own docstring and
    # api/restore_integrity.py's for the full reasoning behind that
    # choice. Runs against the just-restored file, never the source
    # snapshot, so it reflects exactly what the target will actually see.
    report = check_referential_integrity(target_control_db)
    if report.is_clean:
        print("Referential integrity check: clean (no dangling references found).")
    else:
        print(
            f"Referential integrity check: {len(report.orphaned_rows)} dangling "
            "reference(s) found. Nothing was modified -- review before relying on "
            "this data:"
        )
        for orphan in report.orphaned_rows:
            print(
                f"  - {orphan.table}.{orphan.row_id} references "
                f"{orphan.referenced_table}.{orphan.missing_referenced_id} "
                f"(via {orphan.reference_column}), which does not exist."
            )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "snapshot_dir", type=Path, help="A backup snapshot directory to restore from."
    )
    parser.add_argument(
        "target_data_dir", type=Path, help="Where to restore into (an APISettings.data_dir)."
    )
    parser.add_argument(
        "--force", action="store_true", help="Overwrite an existing control.db at the target."
    )
    args = parser.parse_args(argv)

    try:
        if (args.snapshot_dir / "control" / MANIFEST).is_file():
            return _restore_into_postgres(args.snapshot_dir, args.target_data_dir, args.force)
        restore_backup(args.snapshot_dir, args.target_data_dir, force=args.force)
    except (FileNotFoundError, RestoreTargetExistsError, TransferError) as exc:
        print(f"Restore failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _restore_into_postgres(snapshot_dir: Path, target_data_dir: Path, force: bool) -> int:
    url = os.getenv("HYDRA_API_DATABASE_URL")
    if not url:
        print(
            "This snapshot holds a PostgreSQL control plane: set HYDRA_API_DATABASE_URL "
            "to the (empty) database to restore into.",
            file=sys.stderr,
        )
        return 2
    target = ControlDB(target_data_dir / "control.db", database_url=url)
    report = restore_postgres_backup(snapshot_dir, target_data_dir, target, force=force)
    print(report.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())

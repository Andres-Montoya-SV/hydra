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

Refuses to overwrite an existing `<target-data-dir>/control.db` unless
`--force` is passed — restoring is the kind of operation you want to
fail loudly on an accidental wrong argument, not silently clobber a
live, running deployment's real data directory.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


class RestoreTargetExistsError(RuntimeError):
    """Raised when `target_data_dir` already has a `control.db` and
    `force=False` — the caller almost certainly pointed this at the
    wrong directory, or meant to pass `--force`."""


def restore_backup(snapshot_dir: Path, target_data_dir: Path, *, force: bool = False) -> None:
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

    accounts_dir = snapshot_dir / "accounts"
    restored_accounts = 0
    if accounts_dir.is_dir():
        for account_dir in sorted(accounts_dir.iterdir()):
            source_recon_db = account_dir / "output" / "recon.db"
            if not source_recon_db.is_file():
                continue
            target_recon_db = (
                target_data_dir / "accounts" / account_dir.name / "output" / "recon.db"
            )
            target_recon_db.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_recon_db, target_recon_db)
            restored_accounts += 1

    print(
        f"Restored control.db and {restored_accounts} account recon.db file(s) from "
        f"{snapshot_dir} into {target_data_dir}."
    )


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
        restore_backup(args.snapshot_dir, args.target_data_dir, force=args.force)
    except (FileNotFoundError, RestoreTargetExistsError) as exc:
        print(f"Restore failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

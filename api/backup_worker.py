"""Automated backups (docs/PAID_API_DESIGN.md's "Automated backups and
a real deployment target" section) — every piece of durable state in
this service lives in SQLite (`control.db` plus one `recon.db` per
account, `api/tenancy.py`), and until this task, nothing ever backed
any of it up.

**Mechanism — SQLite's own online backup API, never a raw file copy**:
`sqlite3.Connection.backup()`, confirmed directly against Python's own
current docs before relying on it (not assumed from memory): "Works
even if the database is being accessed by other clients or
concurrently by the same connection" — this is SQLite's native
Online Backup API under the hood, built specifically to produce a
consistent snapshot regardless of concurrent writers, including a
database in WAL mode (`core.store.connect_sqlite`'s own default for
every DB this service touches). A raw `shutil.copy()` of a live
WAL-mode file has no such guarantee — it could copy the main db file
mid-write relative to the WAL, or between a checkpoint's own steps,
producing a file that looks copied but is not actually a consistent
snapshot.

**What gets backed up**: `control.db` (one file, the cross-tenant
control-plane database) and every account's own `recon.db`, discovered
via `ControlDB.list_account_ids()` — never a hardcoded glob/path
pattern that could silently miss a real account directory if the
layout ever changes. An account that has never actually run a scan has
no `recon.db` yet; skipped, not an error.

**Where backups go**: local disk first, always
(`api_settings.backup_root` — `<data_dir>/backups/<timestamp>/`,
mirroring each account's real relative path so `api/restore_backup.py`
is a straight structural copy back). Remote upload to S3-compatible
object storage is layered on top, entirely OPT-IN
(`api_settings.backup_s3_bucket` — `None` means local-only). Local
backups alone don't protect against the failure mode that matters
most for a single-host deployment — the disk itself dying — so remote
upload is what actually closes that gap once configured, but a fresh
deployment that hasn't provisioned a bucket yet still gets working
local backups, loudly logged as remote-upload-disabled rather than
silently incomplete.

**Retention**: `api_settings.backup_retention_count` (default 7 — one
week of daily snapshots, a real bounded policy rather than "forever" or
"none") most recent LOCAL snapshot directories are kept; older ones are
deleted after each successful backup run. `rotate_backups` always keeps
at least the single most recent snapshot regardless of how this is
configured — a retention count of `0` (or a negative number, a config
typo) must never be able to delete the only backup that exists.
Remote (S3) objects are never deleted by this job — object-storage
lifecycle rules (every S3-compatible provider supports these natively)
are the right tool for remote retention, not custom code duplicating
what the provider already does better.

**Schedule**: reuses the exact `asyncio.create_task` + shared
`stop_event` shape `api/scan_worker.py`/`api/reconciliation_worker.py`
already established, as its own independent daily-interval loop — a
third scheduler was explicitly not invented. The actual backup work
(SQLite backup(), local file I/O, an optional S3 upload) is genuinely
blocking, unlike the reconciliation loop's few small SQL statements, so
`run_backup_loop` runs it via `asyncio.to_thread` rather than directly
on the event loop — backing up many accounts' `recon.db` files plus a
real network upload could otherwise stall live request handling for
longer than the reconciliation job's own negligible per-cycle cost.

**Restore — the part that actually matters most**: a separate, standalone
module, `api/restore_backup.py` (`python -m api.restore_backup
<backup-dir> <target-data-dir>`), deliberately never imported by this
one — restoring is an operator-run, offline recovery action, not
something the running service ever does to itself automatically.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from api.health import LoopHeartbeats

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings

logger = logging.getLogger("hydra.api.backup")


def _timestamp() -> str:
    """Sortable lexicographically = chronologically (`YYYYMMDDTHHMMSSZ`)
    — `rotate_backups` relies on plain string sort, no need to parse
    dates back out of directory names."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def backup_sqlite_file(source_path: Path, dest_path: Path) -> None:
    """One `sqlite3.Connection.backup()` call — see this module's own
    docstring for why this, never a raw file copy. `dest_path`'s parent
    is created if needed; a destination file that doesn't exist yet is
    exactly what `sqlite3.connect` on a fresh path already handles
    (creates an empty database, which `.backup()` then populates).

    **Locked down to `0o600` after writing** — a real, confirmed gap
    found while verifying the backup/restore path end to end: `control.db`
    itself is created with `0o600` (`ControlDB.__init__`, owner
    read/write only), but `sqlite3.connect()` on a brand-new destination
    path creates it with the process's ordinary umask-derived permissions
    — `0o644` (world-readable) on a typical deployment. A backup
    snapshot contains the exact same sensitive rows the original does
    (API-key hashes, account emails, billing state) and must never be
    LESS protected than the file it was copied from."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    source_conn = sqlite3.connect(source_path)
    try:
        dest_conn = sqlite3.connect(dest_path)
        try:
            source_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    finally:
        source_conn.close()
    dest_path.chmod(0o600)


def _recon_db_path(api_settings: APISettings, account_id: str) -> Path:
    """The same relative layout `api/tenancy.py::account_db_path`
    resolves (`<account_root>/output/recon.db`), computed directly here
    instead of calling that function — `account_db_path` goes through
    `account_settings()`, which calls `Settings.ensure_directories()` as
    a side effect (creates directories on disk); a read-only backup
    pass over every account should never have a side effect on accounts
    it merely reads, especially ones with no `recon.db` at all yet."""
    return api_settings.account_root(account_id) / "output" / "recon.db"


def rotate_backups(backup_root: Path, *, keep_count: int) -> list[Path]:
    """Deletes local snapshot directories beyond the `keep_count` most
    recent, keeping AT LEAST one regardless of how `keep_count` is
    configured — `max(1, keep_count)` is not a suggestion, it's the
    floor a misconfigured `0`/negative value can never go under. Returns
    the list of directories actually deleted (for logging and tests)."""
    if not backup_root.is_dir():
        return []
    snapshots = sorted((p for p in backup_root.iterdir() if p.is_dir()), reverse=True)
    keep = max(1, keep_count)
    to_delete = snapshots[keep:]
    for snapshot in to_delete:
        shutil.rmtree(snapshot, ignore_errors=True)
    return to_delete


def _upload_snapshot_to_s3(
    snapshot_dir: Path,
    *,
    bucket: str,
    prefix: str,
    endpoint_url: str | None,
    region: str | None,
) -> None:
    """Uploads every file under `snapshot_dir`, preserving its relative
    path under `<prefix>/<snapshot_dir.name>/...` — mirrors the local
    layout so a remote listing reads the same way a local one does.
    Credentials are never a parameter here: `boto3.client` reads
    `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` from the process
    environment on its own, the same convention every S3-compatible
    provider's own docs recommend — this function never touches or logs
    them."""
    import boto3  # deferred: only needed when remote upload is actually configured
    from botocore.config import Config

    client_kwargs: dict[str, object] = {"endpoint_url": endpoint_url, "region_name": region}
    if endpoint_url:
        # Path-style addressing (`http://host/<bucket>/<key>`) rather
        # than AWS's own default virtual-hosted style
        # (`http://<bucket>.host/<key>`) — required for a bare-IP or
        # non-AWS custom endpoint (DigitalOcean Spaces, Backblaze B2,
        # Cloudflare R2, or this project's own local test server all
        # need this), since `<bucket>.<host>` would otherwise fail to
        # resolve as DNS. Only applied when a custom endpoint is
        # actually configured — real AWS S3 with no endpoint override
        # keeps using its own recommended default.
        client_kwargs["config"] = Config(s3={"addressing_style": "path"})
    client = boto3.client("s3", **client_kwargs)
    uploaded = 0
    for path in sorted(snapshot_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(snapshot_dir)
        key = f"{prefix}/{snapshot_dir.name}/{relative.as_posix()}"
        client.upload_file(str(path), bucket, key)
        uploaded += 1
    logger.info(
        "Uploaded %d backup file(s) to s3://%s/%s/%s.", uploaded, bucket, prefix, snapshot_dir.name
    )


def run_backup_job(*, api_settings: APISettings, control_db: ControlDB) -> Path:
    """Backs up `control.db` and every account's `recon.db` into one new
    local snapshot directory, optionally uploads it to S3-compatible
    storage if configured, then rotates old local snapshots. Returns the
    new snapshot directory's path.

    Runs as an ordinary, real backup with real consequences — there is
    no dry-run mode here (unlike the retention-purge job): backing up is
    never destructive, so there's nothing a rehearsal mode would be
    protecting against."""
    snapshot_dir = api_settings.backup_root / _timestamp()

    backup_sqlite_file(api_settings.control_db_path, snapshot_dir / "control.db")

    account_count = 0
    for account_id in control_db.list_account_ids():
        source = _recon_db_path(api_settings, account_id)
        if not source.exists():
            continue  # never scanned yet — nothing to back up
        dest = snapshot_dir / "accounts" / account_id / "output" / "recon.db"
        backup_sqlite_file(source, dest)
        account_count += 1

    logger.info(
        "Local backup created at %s (control.db + %d account recon.db file(s)).",
        snapshot_dir,
        account_count,
    )

    if api_settings.backup_s3_bucket:
        try:
            _upload_snapshot_to_s3(
                snapshot_dir,
                bucket=api_settings.backup_s3_bucket,
                prefix=api_settings.backup_s3_prefix,
                endpoint_url=api_settings.backup_s3_endpoint_url,
                region=api_settings.backup_s3_region,
            )
        except ImportError:
            logger.error(
                "HYDRA_API_BACKUP_S3_BUCKET is set but boto3 is not installed — remote "
                "upload skipped this cycle. The local backup above is still valid."
            )
        except Exception:
            # Any S3-side failure (bad credentials, network, wrong
            # endpoint) must never fail the LOCAL backup that already
            # succeeded above — logged loudly, not raised, matching the
            # project's own "a third-party dependency being unreliable
            # is never treated as fatal to the thing that already
            # worked" precedent (Part D.3's grace period, the Postmark
            # send-failure handling).
            logger.exception(
                "Remote backup upload to s3://%s/%s failed — the LOCAL backup at %s is "
                "still valid and was not affected.",
                api_settings.backup_s3_bucket,
                api_settings.backup_s3_prefix,
                snapshot_dir,
            )
    else:
        logger.warning(
            "HYDRA_API_BACKUP_S3_BUCKET is not configured — backups are LOCAL ONLY and "
            "would not survive this host's disk failing. Configure remote upload once a "
            "bucket is provisioned."
        )

    deleted = rotate_backups(
        api_settings.backup_root, keep_count=api_settings.backup_retention_count
    )
    if deleted:
        logger.info("Rotated out %d old local backup snapshot(s).", len(deleted))

    return snapshot_dir


async def run_backup_loop(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    stop_event: asyncio.Event,
    heartbeats: LoopHeartbeats,
) -> None:
    """Runs `run_backup_job` once immediately at startup (so a
    just-deployed host doesn't wait a full day for its first backup),
    then every `api_settings.backup_interval_seconds`, until
    `stop_event` fires. The actual work runs via `asyncio.to_thread` —
    real disk I/O across every account plus an optional real network
    upload is genuinely blocking, unlike the reconciliation loop's own
    few small SQL statements, so running it directly on the event loop
    could stall live request handling for longer than is acceptable."""
    while not stop_event.is_set():
        heartbeats.mark_alive("backup")  # GET /health's liveness signal, api/health.py
        await asyncio.to_thread(run_backup_job, api_settings=api_settings, control_db=control_db)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=api_settings.backup_interval_seconds)

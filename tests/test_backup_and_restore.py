"""Automated backups and restore (docs/PAID_API_DESIGN.md's "Automated
backups and a real deployment target" section) — the one task in this
project where "trust me, it works" is explicitly not acceptable: a real
backup, a real corruption/deletion of the original, a real restore, and
a real comparison of the actual row data, not just "the file exists."
"""

from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from api.backup_worker import (
    backup_sqlite_file,
    rotate_backups,
    run_backup_job,
)
from api.control_db import ControlDB
from api.restore_backup import RestoreTargetExistsError, restore_backup
from api.settings import APISettings

pytest.importorskip("boto3")

from _fake_s3_server import (  # noqa: E402
    FakeS3Handler,
    reset_fake_s3_state,
    start_fake_s3_server,
    stop_fake_s3_server,
)


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _seed_real_rows(control_db: ControlDB) -> str:
    """Covers every kind of durable, account-scoped row a real
    deployment accumulates — including the two the original version of
    this fixture predated (`api_keys`, `monitored_domains`) — so the
    backup/restore round trip is proven against the CURRENT schema, not
    just the one that existed when this test was first written."""
    account_id = control_db.create_account(email="backup-test@example.com")
    control_db.create_default_subscription(account_id, tier="pro")
    control_db.insert_api_key(
        key_id="backup-key-1",
        account_id=account_id,
        lookup_hash="backup-lookup-hash",
        verify_hash="backup-verify-hash",
        prefix="hydra_live_",
    )
    control_db.create_scan(
        scan_id="backup-scan-1", account_id=account_id, domain="backup.example", db_path="/tmp/x"
    )
    control_db.update_scan_status("backup-scan-1", "completed")
    verification = control_db.create_domain_verification(
        account_id=account_id,
        domain="backup.example",
        token="backup-verify-token",  # noqa: S106 - test fixture data, not a real secret
    )
    now = datetime.now(timezone.utc)
    control_db.mark_verification_succeeded(
        verification.verification_id,
        method="dns_txt",
        verified_at=now.isoformat(),
        expires_at=(now + timedelta(days=90)).isoformat(),
    )
    control_db.create_or_update_monitored_domain(
        account_id=account_id,
        domain="backup.example",
        speed2_enabled=True,
        passive_interval_hours=24,
        active_interval_hours=168,
    )
    return account_id


def _write_recon_db(path: Path, *, marker: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE marker (value TEXT)")
    conn.execute("INSERT INTO marker (value) VALUES (?)", (marker,))
    conn.commit()
    conn.close()


class TestBackupAndRestoreRoundTrip:
    def test_restored_control_db_matches_the_original_rows_exactly(
        self, api_settings: APISettings, control_db: ControlDB, tmp_path: Path
    ) -> None:
        account_id = _seed_real_rows(control_db)
        original_account = control_db.get_account(account_id)
        original_subscription = control_db.get_subscription(account_id)
        original_scan = control_db.get_owned_scan("backup-scan-1", account_id)
        original_key = control_db.get_key("backup-key-1", account_id)
        original_monitored = control_db.get_monitored_domain(account_id, "backup.example")

        snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)

        # A real, hard failure of the original — not a simulation.
        api_settings.control_db_path.unlink()
        for suffix in ("-wal", "-shm"):
            extra = Path(f"{api_settings.control_db_path}{suffix}")
            extra.unlink(missing_ok=True)
        assert not api_settings.control_db_path.exists()

        target_dir = tmp_path / "restored_api_data"
        restore_backup(snapshot_dir, target_dir)

        restored_db = ControlDB(target_dir / "control.db")
        restored_account = restored_db.get_account(account_id)
        restored_subscription = restored_db.get_subscription(account_id)
        restored_scan = restored_db.get_owned_scan("backup-scan-1", account_id)
        restored_key = restored_db.get_key("backup-key-1", account_id)
        restored_monitored = restored_db.get_monitored_domain(account_id, "backup.example")

        assert restored_key == original_key
        assert restored_monitored == original_monitored
        assert restored_account == original_account
        assert restored_subscription == original_subscription
        assert restored_scan == original_scan

    def test_restored_recon_db_matches_the_original_rows_exactly(
        self, api_settings: APISettings, control_db: ControlDB, tmp_path: Path
    ) -> None:
        account_id = control_db.create_account(email="recon-backup@example.com")
        control_db.create_default_subscription(account_id, tier="free")
        recon_db_path = api_settings.account_root(account_id) / "output" / "recon.db"
        _write_recon_db(recon_db_path, marker="original-marker-value")

        snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)

        recon_db_path.unlink()
        assert not recon_db_path.exists()

        target_dir = tmp_path / "restored_api_data"
        restore_backup(snapshot_dir, target_dir)

        restored_path = target_dir / "accounts" / account_id / "output" / "recon.db"
        conn = sqlite3.connect(restored_path)
        row = conn.execute("SELECT value FROM marker").fetchone()
        conn.close()
        assert row == ("original-marker-value",)

    def test_an_account_with_no_recon_db_yet_is_skipped_not_an_error(
        self, api_settings: APISettings, control_db: ControlDB
    ) -> None:
        control_db.create_account(email="never-scanned@example.com")
        snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)
        assert (snapshot_dir / "control.db").exists()
        assert not (snapshot_dir / "accounts").exists() or not any(
            (snapshot_dir / "accounts").iterdir()
        )

    def test_restore_refuses_to_overwrite_an_existing_target_without_force(
        self, api_settings: APISettings, control_db: ControlDB, tmp_path: Path
    ) -> None:
        _seed_real_rows(control_db)
        snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)

        target_dir = tmp_path / "restored_api_data"
        target_dir.mkdir()
        (target_dir / "control.db").write_text("pretend this is already a real deployment")

        with pytest.raises(RestoreTargetExistsError):
            restore_backup(snapshot_dir, target_dir)

    def test_restore_with_force_overwrites_the_existing_target(
        self, api_settings: APISettings, control_db: ControlDB, tmp_path: Path
    ) -> None:
        account_id = _seed_real_rows(control_db)
        snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)

        target_dir = tmp_path / "restored_api_data"
        target_dir.mkdir()
        (target_dir / "control.db").write_text("stale data that should be overwritten")

        restore_backup(snapshot_dir, target_dir, force=True)

        restored_db = ControlDB(target_dir / "control.db")
        assert restored_db.get_account(account_id) is not None


class TestBackupWhileAConcurrentWriterIsActive:
    def test_a_backup_taken_mid_write_is_still_a_valid_consistent_snapshot(
        self, api_settings: APISettings, control_db: ControlDB
    ) -> None:
        """The exact scenario the task called out: the retention-purge
        job (or any other writer) could be mid-DELETE/UPDATE while a
        backup runs. `sqlite3.Connection.backup()`'s own documented
        guarantee ("works even if the database is being accessed by
        other clients or concurrently") should cover this — verified
        here with a REAL concurrent writer thread, not assumed."""
        account_id = _seed_real_rows(control_db)
        stop_writing = threading.Event()

        def hammer() -> None:
            writer = ControlDB(api_settings.control_db_path)
            i = 0
            while not stop_writing.is_set():
                writer.create_scan(
                    scan_id=f"hammer-scan-{i}",
                    account_id=account_id,
                    domain="hammer.example",
                    db_path="/tmp/x",
                )
                writer.update_scan_status(f"hammer-scan-{i}", "completed")
                i += 1

        writer_thread = threading.Thread(target=hammer, daemon=True)
        writer_thread.start()
        try:
            time.sleep(0.05)  # let the writer get a real head start
            snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)
        finally:
            stop_writing.set()
            writer_thread.join(timeout=5)

        backup_path = snapshot_dir / "control.db"
        conn = sqlite3.connect(backup_path)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            assert integrity == "ok"
            # Queryable, real data — not just "the file exists and opens."
            row = conn.execute(
                "SELECT account_id FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
            assert row is not None
        finally:
            conn.close()


class TestRemoteUploadIsOptional:
    def test_no_bucket_configured_runs_local_only_and_logs_loudly(
        self,
        api_settings: APISettings,
        control_db: ControlDB,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _seed_real_rows(control_db)
        with caplog.at_level("WARNING", logger="hydra.api.backup"):
            snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)

        assert (snapshot_dir / "control.db").exists()
        full_log = "\n".join(r.message for r in caplog.records)
        assert "LOCAL ONLY" in full_log


class TestRemoteUploadAgainstARealFakeS3Server:
    @pytest.fixture
    def s3_server(self, monkeypatch: pytest.MonkeyPatch):
        reset_fake_s3_state()
        httpd, port, thread = start_fake_s3_server()
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake-access-key-id")  # noqa: S105
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-secret-access-key")  # noqa: S105
        try:
            yield f"http://127.0.0.1:{port}"
        finally:
            stop_fake_s3_server(httpd, thread)

    def test_remote_upload_actually_uploads_the_real_backup_bytes(
        self, api_settings: APISettings, control_db: ControlDB, s3_server: str
    ) -> None:
        api_settings.backup_s3_bucket = "hydra-test-bucket"
        api_settings.backup_s3_endpoint_url = s3_server
        api_settings.backup_s3_region = "us-east-1"
        _seed_real_rows(control_db)

        snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)

        expected_key = (
            f"/{api_settings.backup_s3_bucket}/hydra-backups/{snapshot_dir.name}/control.db"
        )
        assert expected_key in FakeS3Handler.uploads
        real_bytes_on_disk = (snapshot_dir / "control.db").read_bytes()
        assert FakeS3Handler.uploads[expected_key] == real_bytes_on_disk

    def test_a_remote_upload_failure_never_breaks_the_local_backup(
        self,
        api_settings: APISettings,
        control_db: ControlDB,
        s3_server: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        reset_fake_s3_state(fail_with_status=500)
        api_settings.backup_s3_bucket = "hydra-test-bucket"
        api_settings.backup_s3_endpoint_url = s3_server
        api_settings.backup_s3_region = "us-east-1"
        _seed_real_rows(control_db)

        with caplog.at_level("ERROR", logger="hydra.api.backup"):
            snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)

        assert (snapshot_dir / "control.db").exists()  # local backup unaffected
        full_log = "\n".join(r.message for r in caplog.records)
        assert "upload" in full_log.lower()


class TestRotateBackups:
    def _make_snapshot(self, backup_root: Path, name: str) -> Path:
        snapshot = backup_root / name
        snapshot.mkdir(parents=True)
        (snapshot / "control.db").write_text("x")
        return snapshot

    def test_keeps_only_the_n_most_recent(self, tmp_path: Path) -> None:
        backup_root = tmp_path / "backups"
        names = [f"2026010{i}T000000Z" for i in range(1, 6)]  # 5 snapshots
        for name in names:
            self._make_snapshot(backup_root, name)

        deleted = rotate_backups(backup_root, keep_count=2)

        remaining = {p.name for p in backup_root.iterdir()}
        assert remaining == {names[-1], names[-2]}
        assert {p.name for p in deleted} == set(names[:-2])

    def test_never_deletes_the_only_snapshot_even_with_keep_count_zero(
        self, tmp_path: Path
    ) -> None:
        backup_root = tmp_path / "backups"
        only = self._make_snapshot(backup_root, "20260101T000000Z")

        deleted = rotate_backups(backup_root, keep_count=0)

        assert deleted == []
        assert only.exists()

    def test_never_deletes_the_only_snapshot_even_with_a_negative_keep_count(
        self, tmp_path: Path
    ) -> None:
        backup_root = tmp_path / "backups"
        only = self._make_snapshot(backup_root, "20260101T000000Z")

        deleted = rotate_backups(backup_root, keep_count=-5)

        assert deleted == []
        assert only.exists()

    def test_no_backup_root_yet_is_a_silent_noop(self, tmp_path: Path) -> None:
        assert rotate_backups(tmp_path / "does-not-exist", keep_count=3) == []


class TestBackupSqliteFileDirectly:
    def test_produces_a_real_independent_valid_copy(self, tmp_path: Path) -> None:
        source = tmp_path / "source.db"
        conn = sqlite3.connect(source)
        conn.execute("CREATE TABLE t (v INTEGER)")
        conn.execute("INSERT INTO t VALUES (42)")
        conn.commit()
        conn.close()

        dest = tmp_path / "nested" / "dest.db"
        backup_sqlite_file(source, dest)

        assert dest.exists()
        dest_conn = sqlite3.connect(dest)
        row = dest_conn.execute("SELECT v FROM t").fetchone()
        dest_conn.close()
        assert row == (42,)

        # Independent — mutating the source afterward must never affect
        # the already-taken backup.
        conn = sqlite3.connect(source)
        conn.execute("UPDATE t SET v = 999")
        conn.commit()
        conn.close()
        dest_conn = sqlite3.connect(dest)
        row = dest_conn.execute("SELECT v FROM t").fetchone()
        dest_conn.close()
        assert row == (42,)


class TestBackupFilePermissions:
    """A real, confirmed gap found while verifying the backup/restore
    path for this task: `control.db` itself is created with `0o600`
    (`ControlDB.__init__`), but a fresh `sqlite3.connect()` on a
    brand-new backup destination file inherits the process's ordinary
    umask instead — `0o644` (world-readable) was the actually-observed
    result before this was fixed. A backup snapshot contains the exact
    same sensitive rows as the original (API-key hashes, account
    emails, billing state) and must never be less protected."""

    def test_a_fresh_backup_file_is_not_world_or_group_readable(self, tmp_path: Path) -> None:
        source = tmp_path / "source.db"
        conn = sqlite3.connect(source)
        conn.execute("CREATE TABLE t (v INTEGER)")
        conn.commit()
        conn.close()

        dest = tmp_path / "backup" / "dest.db"
        backup_sqlite_file(source, dest)

        mode = dest.stat().st_mode & 0o777
        assert mode == 0o600, f"backup file permissions were {oct(mode)}, expected 0o600"

    def test_run_backup_job_produces_a_locked_down_control_db_copy(
        self, api_settings: APISettings, control_db: ControlDB
    ) -> None:
        _seed_real_rows(control_db)
        snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)

        mode = (snapshot_dir / "control.db").stat().st_mode & 0o777
        assert mode == 0o600

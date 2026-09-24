"""Automatic billing enforcement and data retention purge
(docs/PAID_API_DESIGN.md's "Automatic billing enforcement and data
retention purge" section) — the grace-period-suspension job, the
retention-purge job, and the atomic `suspend_if_still_past_due` claim
that closes the race between this job and a payment webhook restoring
an account in a different worker process.
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from api.control_db import ControlDB
from api.reconciliation_worker import run_grace_period_job, run_retention_purge_job
from api.settings import APISettings
from api.subscriptions import GRACE_PERIOD_DAYS, restore_active_status, start_grace_period


class _RecordingEmailSender:
    """A test double, not a mock of internal calls — records exactly
    what a real `EmailSender` would have been asked to send, so tests
    can assert on the actual (to, account_id) pairs without caring how
    `PostmarkEmailSender`/`ConsoleEmailSender` format anything."""

    def __init__(self) -> None:
        self.verification_emails: list[tuple[str, str, str]] = []
        self.suspension_emails: list[tuple[str, str]] = []

    def send_verification_email(self, *, to: str, account_id: str, token: str) -> None:
        self.verification_emails.append((to, account_id, token))

    def send_account_suspended_email(self, *, to: str, account_id: str) -> None:
        self.suspension_emails.append((to, account_id))


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _set_scan_created_at(control_db: ControlDB, scan_id: str, created_at: str) -> None:
    """No `ControlDB` method backdates a scan's `created_at` — nothing
    in real production code ever needs to. Tests reach past the class
    directly (same file/connection `ControlDB` itself uses) purely to
    simulate "this scan was actually created N days ago" without
    needing to wait N real days."""
    with sqlite3.connect(control_db.db_path) as conn:
        conn.execute("UPDATE scans SET created_at = ? WHERE scan_id = ?", (created_at, scan_id))


@pytest.fixture
def control_db(tmp_path: Path) -> ControlDB:
    return ControlDB(tmp_path / "control.db")


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def account_id(control_db: ControlDB) -> str:
    account_id = control_db.create_account(email=f"test-{secrets.token_hex(8)}@example.com")
    control_db.create_default_subscription(account_id, tier="free")
    return account_id


class TestGracePeriodJob:
    def test_account_past_the_grace_window_gets_suspended_and_emailed(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        # Worked example from the task itself: a grace period that
        # started 2026-09-01 is expired on or after 2026-09-04's run
        # (GRACE_PERIOD_DAYS = 3). Today's real date is well past that,
        # so setting a literal several-days-ago start is genuinely
        # expired against real wall-clock time, no time-freezing needed.
        started = datetime.now(timezone.utc) - timedelta(days=GRACE_PERIOD_DAYS + 1)
        start_grace_period(control_db, account_id)  # exercises the real entry point too
        control_db.set_subscription_status(
            account_id, "past_due", grace_period_started_at=_iso(started)
        )

        sender = _RecordingEmailSender()
        suspended = run_grace_period_job(control_db=control_db, email_sender=sender)

        assert suspended == 1
        subscription = control_db.get_subscription(account_id)
        assert subscription is not None
        assert subscription.status == "suspended"
        account = control_db.get_account(account_id)
        assert sender.suspension_emails == [(account.email, account_id)]

    def test_account_still_within_the_grace_window_is_untouched(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        started = datetime.now(timezone.utc) - timedelta(days=1)  # well under 3 days
        control_db.set_subscription_status(
            account_id, "past_due", grace_period_started_at=_iso(started)
        )

        sender = _RecordingEmailSender()
        suspended = run_grace_period_job(control_db=control_db, email_sender=sender)

        assert suspended == 0
        assert control_db.get_subscription(account_id).status == "past_due"  # type: ignore[union-attr]
        assert sender.suspension_emails == []

    def test_an_account_that_paid_before_the_job_reran_is_never_suspended(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        started = datetime.now(timezone.utc) - timedelta(days=GRACE_PERIOD_DAYS + 1)
        control_db.set_subscription_status(
            account_id, "past_due", grace_period_started_at=_iso(started)
        )
        # The payment succeeded before this job ever ran.
        restore_active_status(control_db, account_id)

        sender = _RecordingEmailSender()
        suspended = run_grace_period_job(control_db=control_db, email_sender=sender)

        assert suspended == 0
        assert control_db.get_subscription(account_id).status == "active"  # type: ignore[union-attr]
        assert sender.suspension_emails == []

    def test_a_stale_candidate_list_never_suspends_an_account_that_paid_in_between(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        """Directly exercises the "gather once, re-check fresh per
        candidate" behavior the task required: `list_past_due_account_ids`
        is called once inside the job, but by the time the job gets
        around to acting on THIS account, it has already been resolved
        — the job must see that fresh state, not the stale snapshot."""
        started = datetime.now(timezone.utc) - timedelta(days=GRACE_PERIOD_DAYS + 1)
        control_db.set_subscription_status(
            account_id, "past_due", grace_period_started_at=_iso(started)
        )
        candidates = control_db.list_past_due_account_ids()
        assert account_id in candidates  # confirms the account WAS a candidate

        # A payment webhook resolves it after the candidate list was
        # gathered but (in a real deployment) before this job's own
        # per-account re-read runs.
        restore_active_status(control_db, account_id)

        sender = _RecordingEmailSender()
        suspended = run_grace_period_job(control_db=control_db, email_sender=sender)

        assert suspended == 0
        assert control_db.get_subscription(account_id).status == "active"  # type: ignore[union-attr]

    def test_suspended_account_with_no_email_on_file_still_gets_suspended(
        self, control_db: ControlDB
    ) -> None:
        account_id = control_db.create_account()  # no email
        control_db.create_default_subscription(account_id, tier="free")
        started = datetime.now(timezone.utc) - timedelta(days=GRACE_PERIOD_DAYS + 1)
        control_db.set_subscription_status(
            account_id, "past_due", grace_period_started_at=_iso(started)
        )

        sender = _RecordingEmailSender()
        suspended = run_grace_period_job(control_db=control_db, email_sender=sender)

        assert suspended == 1
        assert control_db.get_subscription(account_id).status == "suspended"  # type: ignore[union-attr]
        assert sender.suspension_emails == []

    def test_a_past_due_account_whose_grace_period_never_started_is_never_suspended(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        """Defensive: `grace_period_expired` itself returns False when
        `grace_period_started_at` is None (api/subscriptions.py) — a
        `'past_due'` row with no start timestamp should not exist in
        practice (`start_grace_period` always sets it), but the job must
        not crash or misbehave if it somehow does."""
        control_db.set_subscription_status(account_id, "past_due", grace_period_started_at=None)

        sender = _RecordingEmailSender()
        suspended = run_grace_period_job(control_db=control_db, email_sender=sender)

        assert suspended == 0
        assert control_db.get_subscription(account_id).status == "past_due"  # type: ignore[union-attr]


class TestSuspendIfStillPastDueAtomicity:
    def test_returns_false_once_the_row_has_already_moved_off_past_due(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        control_db.set_subscription_status(
            account_id, "past_due", grace_period_started_at=_iso(datetime.now(timezone.utc))
        )
        restore_active_status(control_db, account_id)

        assert control_db.suspend_if_still_past_due(account_id) is False
        assert control_db.get_subscription(account_id).status == "active"  # type: ignore[union-attr]

    def test_exactly_one_of_many_concurrent_callers_wins(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        control_db.set_subscription_status(
            account_id, "past_due", grace_period_started_at=_iso(datetime.now(timezone.utc))
        )

        n_callers = 20
        results: list[bool | None] = [None] * n_callers
        barrier = threading.Barrier(n_callers)

        def call(index: int) -> None:
            barrier.wait()
            results[index] = control_db.suspend_if_still_past_due(account_id)

        with ThreadPoolExecutor(max_workers=n_callers) as pool:
            list(pool.map(call, range(n_callers)))

        assert results.count(True) == 1
        assert results.count(False) == n_callers - 1
        assert control_db.get_subscription(account_id).status == "suspended"  # type: ignore[union-attr]


class TestRetentionPurgeJob:
    def test_an_old_terminal_scan_is_purged_row_and_files_both_gone(
        self, control_db: ControlDB, api_settings: APISettings, account_id: str
    ) -> None:
        control_db.create_scan(
            scan_id="old-scan", account_id=account_id, domain="old.example", db_path="/tmp/x"
        )
        control_db.update_scan_status("old-scan", "completed")
        # Free tier: 7-day retention (api/tiers.py) — 10 days ago is
        # unambiguously past it.
        old_created_at = _iso(datetime.now(timezone.utc) - timedelta(days=10))
        _set_scan_created_at(control_db, "old-scan", old_created_at)

        output_dir = api_settings.account_root(account_id) / "output" / "old-scan"
        output_dir.mkdir(parents=True)
        (output_dir / "subdomains.txt").write_text("old.example\n")

        purged = run_retention_purge_job(api_settings=api_settings, control_db=control_db)

        assert purged == 1
        assert control_db.get_owned_scan("old-scan", account_id) is None
        assert not output_dir.exists()

    def test_a_scan_inside_its_retention_window_is_not_purged(
        self, control_db: ControlDB, api_settings: APISettings, account_id: str
    ) -> None:
        control_db.create_scan(
            scan_id="recent-scan", account_id=account_id, domain="recent.example", db_path="/tmp/x"
        )
        control_db.update_scan_status("recent-scan", "completed")
        # Free tier: 7-day retention — 1 day ago is well inside it.
        recent_created_at = _iso(datetime.now(timezone.utc) - timedelta(days=1))
        _set_scan_created_at(control_db, "recent-scan", recent_created_at)

        purged = run_retention_purge_job(api_settings=api_settings, control_db=control_db)

        assert purged == 0
        assert control_db.get_owned_scan("recent-scan", account_id) is not None

    def test_a_running_scan_past_its_nominal_window_is_never_purged(
        self, control_db: ControlDB, api_settings: APISettings, account_id: str
    ) -> None:
        control_db.create_scan(
            scan_id="still-running",
            account_id=account_id,
            domain="running.example",
            db_path="/tmp/x",
        )
        control_db.update_scan_status("still-running", "running")
        # Deliberately far past Free's 7-day window by wall-clock time —
        # a long-running scan on an old account, exactly the scenario
        # the task called out.
        very_old = _iso(datetime.now(timezone.utc) - timedelta(days=30))
        _set_scan_created_at(control_db, "still-running", very_old)

        purged = run_retention_purge_job(api_settings=api_settings, control_db=control_db)

        assert purged == 0
        record = control_db.get_owned_scan("still-running", account_id)
        assert record is not None
        assert record.status == "running"

    def test_running_the_job_twice_in_a_row_is_a_safe_noop_the_second_time(
        self, control_db: ControlDB, api_settings: APISettings, account_id: str
    ) -> None:
        control_db.create_scan(
            scan_id="idempotent-scan",
            account_id=account_id,
            domain="idem.example",
            db_path="/tmp/x",
        )
        control_db.update_scan_status("idempotent-scan", "failed", error_message="boom")
        old_created_at = _iso(datetime.now(timezone.utc) - timedelta(days=10))
        _set_scan_created_at(control_db, "idempotent-scan", old_created_at)

        first = run_retention_purge_job(api_settings=api_settings, control_db=control_db)
        second = run_retention_purge_job(api_settings=api_settings, control_db=control_db)

        assert first == 1
        assert second == 0  # nothing left to purge; not an error, not a re-purge

    def test_dry_run_mode_logs_and_deletes_nothing(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        dry_run_settings = APISettings(
            data_dir=tmp_path / "api_data_dry", retention_purge_dry_run=True
        )
        control_db_2 = ControlDB(dry_run_settings.control_db_path)
        account = control_db_2.create_account(email="dry-run@example.com")
        control_db_2.create_default_subscription(account, tier="free")
        control_db_2.create_scan(
            scan_id="dry-run-scan", account_id=account, domain="dry.example", db_path="/tmp/x"
        )
        control_db_2.update_scan_status("dry-run-scan", "completed")
        old_created_at = _iso(datetime.now(timezone.utc) - timedelta(days=10))
        _set_scan_created_at(control_db_2, "dry-run-scan", old_created_at)

        output_dir = dry_run_settings.account_root(account) / "output" / "dry-run-scan"
        output_dir.mkdir(parents=True)
        (output_dir / "subdomains.txt").write_text("dry.example\n")

        with caplog.at_level("INFO", logger="hydra.api.reconciliation"):
            purged = run_retention_purge_job(api_settings=dry_run_settings, control_db=control_db_2)

        assert purged == 0
        assert control_db_2.get_owned_scan("dry-run-scan", account) is not None
        assert output_dir.exists()
        assert any("DRY RUN" in record.message for record in caplog.records)

    def test_a_real_backup_snapshot_is_never_touched_by_a_retention_purge_cycle(
        self, tmp_path: Path
    ) -> None:
        """Explicit scope confirmation the task called for: retention
        purge (`api_settings.account_root(account_id) / "output" /
        scan.scan_id`) and backups (`api_settings.backup_root`, i.e.
        `<data_dir>/backups/<timestamp>/`) are different directory
        trees entirely — but "different code paths" is a claim worth
        proving against a REAL backup snapshot, not just reading the
        two path-construction functions and trusting they never
        collide.

        Deliberately builds its own `api_settings`/`control_db` pair
        (never this file's own `control_db`/`api_settings` fixtures,
        which point at two DIFFERENT files — `tmp_path/control.db` vs.
        `tmp_path/api_data/control.db` — a pre-existing mismatch that
        happens not to matter for the other tests in this class, since
        none of them ever call `run_backup_job`, which is the first
        thing here to actually read `api_settings.control_db_path` off
        disk instead of taking `control_db` as a given in-memory
        object)."""
        from api.backup_worker import run_backup_job

        api_settings = APISettings(data_dir=tmp_path / "api_data")
        control_db = ControlDB(api_settings.control_db_path)
        account_id = control_db.create_account(email=f"test-{secrets.token_hex(8)}@example.com")
        control_db.create_default_subscription(account_id, tier="free")

        control_db.create_scan(
            scan_id="old-scan-near-backup",
            account_id=account_id,
            domain="old.example",
            db_path="/tmp/x",
        )
        control_db.update_scan_status("old-scan-near-backup", "completed")
        old_created_at = _iso(datetime.now(timezone.utc) - timedelta(days=10))
        _set_scan_created_at(control_db, "old-scan-near-backup", old_created_at)
        output_dir = api_settings.account_root(account_id) / "output" / "old-scan-near-backup"
        output_dir.mkdir(parents=True)
        (output_dir / "subdomains.txt").write_text("old.example\n")

        # A real backup snapshot, taken before the purge, containing
        # this same account's (about to be purged) control-plane row.
        snapshot_dir = run_backup_job(api_settings=api_settings, control_db=control_db)
        assert (snapshot_dir / "control.db").is_file()

        purged = run_retention_purge_job(api_settings=api_settings, control_db=control_db)

        assert purged == 1  # the old scan itself really was purged
        assert not output_dir.exists()
        # The backup snapshot — a completely separate directory tree —
        # is untouched: still present, still a valid, queryable SQLite
        # file with the pre-purge row still in it.
        assert snapshot_dir.is_dir()
        assert (snapshot_dir / "control.db").is_file()
        backup_db = ControlDB(snapshot_dir / "control.db")
        assert backup_db.get_owned_scan("old-scan-near-backup", account_id) is not None

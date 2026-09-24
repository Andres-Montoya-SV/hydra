"""Continuous monitoring's worker cycle (`api/monitoring_worker.py`) —
the two-speed (passive/active) harvest-then-enqueue loop, tested the same
way `tests/test_reconciliation_worker.py` tests its own scheduled jobs:
directly against a real `ControlDB`/`AssetStore`, no mocks standing in
for internal calls.
"""

from __future__ import annotations

import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import api.monitoring_worker as monitoring_worker_module
from api.control_db import ControlDB
from api.monitoring_worker import run_monitoring_cycle
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host, ScanRun
from core.store import AssetStore


class _RecordingEmailSender:
    def __init__(self) -> None:
        self.verification_emails: list[tuple[str, str, str]] = []
        self.suspension_emails: list[tuple[str, str]] = []
        self.monitoring_alerts: list[tuple[str, str, list[str], int]] = []

    def send_verification_email(self, *, to: str, account_id: str, token: str) -> None:
        self.verification_emails.append((to, account_id, token))

    def send_account_suspended_email(self, *, to: str, account_id: str) -> None:
        self.suspension_emails.append((to, account_id))

    def send_monitoring_alert(
        self, *, to: str, account_id: str, summary_lines: list[str], truncated_count: int
    ) -> None:
        self.monitoring_alerts.append((to, account_id, summary_lines, truncated_count))


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(
        data_dir=tmp_path / "api_data",
        monitoring_batch_size=10,
        monitoring_asset_count_ceiling=5,
        monitoring_cycle_time_budget_seconds=60.0,
    )


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


@pytest.fixture
def sender() -> _RecordingEmailSender:
    return _RecordingEmailSender()


def _account(control_db: ControlDB, *, tier: str = "pro") -> str:
    account_id = control_db.create_account(email=f"test-{secrets.token_hex(6)}@example.com")
    control_db.create_default_subscription(account_id, tier=tier)
    return account_id


def _verify_domain(control_db: ControlDB, account_id: str, domain: str) -> None:
    record = control_db.create_domain_verification(
        account_id=account_id,
        domain=domain,
        token="seeded-for-test",  # noqa: S106 - test fixture data, not a real secret
    )
    now = datetime.now(timezone.utc)
    control_db.mark_verification_succeeded(
        record.verification_id,
        method="dns_txt",
        verified_at=now.isoformat(),
        expires_at=(now + timedelta(days=90)).isoformat(),
    )


def _monitor(
    control_db: ControlDB, api_settings: APISettings, account_id: str, domain: str, *, speed2=False
):
    return control_db.create_or_update_monitored_domain(
        account_id=account_id,
        domain=domain,
        speed2_enabled=speed2,
        passive_interval_hours=api_settings.monitoring_passive_interval_hours,
        active_interval_hours=api_settings.monitoring_active_interval_hours,
    )


def _make_due(control_db: ControlDB, monitoring_id: str) -> None:
    """No public API backdates a schedule into the past — tests reach
    the same file/connection `ControlDB` itself uses to simulate "this
    domain's cadence has already elapsed" without waiting in real time."""
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    with sqlite3.connect(control_db.db_path) as conn:
        conn.execute(
            "UPDATE monitored_domains SET next_passive_due_at = ?, next_active_due_at = ? "
            "WHERE monitoring_id = ?",
            (past, past, monitoring_id),
        )


def _write_hosts(
    api_settings: APISettings, account_id: str, scan_id: str, domains: list[str]
) -> None:
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at=datetime.now(timezone.utc).isoformat()))
    for d in domains:
        store.upsert_host(scan_id, Host(domain=d, hostname=d))


class TestOptInAndVerificationGating:
    def test_a_due_domain_with_no_verification_is_paused_not_scanned(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        # Deliberately never verified.
        record = _monitor(control_db, api_settings, account_id, "unverified.example")
        _make_due(control_db, record.monitoring_id)

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        updated = control_db.get_monitored_domain(account_id, "unverified.example")
        assert updated.status == "paused_verification_lapsed"
        assert updated.pending_passive_scan_id is None

    def test_a_verified_domain_gets_a_scheduled_passive_scan_enqueued(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "verified.example")
        record = _monitor(control_db, api_settings, account_id, "verified.example")
        _make_due(control_db, record.monitoring_id)

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        updated = control_db.get_monitored_domain(account_id, "verified.example")
        assert updated.pending_passive_scan_id is not None
        scan = control_db.get_owned_scan(updated.pending_passive_scan_id, account_id)
        assert scan is not None
        assert scan.trigger_source == "scheduled_passive"
        assert scan.status == "queued"


class TestSpeed2TierGating:
    def test_free_tier_account_never_gets_a_speed2_scan_even_if_flagged_on(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db, tier="free")
        _verify_domain(control_db, account_id, "example.com")
        record = control_db.create_or_update_monitored_domain(
            account_id=account_id,
            domain="example.com",
            speed2_enabled=True,  # bypassing the router's own tier check on purpose
            passive_interval_hours=24,
            active_interval_hours=24,
        )
        _make_due(control_db, record.monitoring_id)

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.pending_active_scan_id is None

    def test_pro_tier_account_gets_a_scheduled_active_scan_enqueued_and_quota_consumed(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db, tier="pro")
        _verify_domain(control_db, account_id, "example.com")
        record = control_db.create_or_update_monitored_domain(
            account_id=account_id,
            domain="example.com",
            speed2_enabled=True,
            passive_interval_hours=24,
            active_interval_hours=24,
        )
        _make_due(control_db, record.monitoring_id)

        from api.subscriptions import current_period_key

        before = control_db.get_monthly_usage(account_id, current_period_key())
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        after = control_db.get_monthly_usage(account_id, current_period_key())

        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.pending_active_scan_id is not None
        scan = control_db.get_owned_scan(updated.pending_active_scan_id, account_id)
        assert scan.trigger_source == "scheduled_active"
        # Speed 2 consumes quota; Speed 1 (also enqueued this same cycle
        # for the same domain) never does.
        assert after.scans_used == before.scans_used + 1

    def test_exhausted_quota_skips_speed2_this_cycle_without_erroring(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db, tier="free")  # 1 scan/month
        control_db.set_tier(account_id, "pro")  # pro: 50/month, but drain it below
        from api.subscriptions import current_period_key

        for _ in range(50):
            control_db.increment_scan_usage(account_id, current_period_key())
        _verify_domain(control_db, account_id, "example.com")
        record = control_db.create_or_update_monitored_domain(
            account_id=account_id,
            domain="example.com",
            speed2_enabled=True,
            passive_interval_hours=24,
            active_interval_hours=24,
        )
        _make_due(control_db, record.monitoring_id)

        stats = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=sender
        )

        assert stats["skipped_errors"] == 0  # a quota skip is not an error
        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.pending_active_scan_id is None
        # Speed 1 is unaffected by Speed 2's quota exhaustion.
        assert updated.pending_passive_scan_id is not None


class TestHarvestingAndNotifications:
    def test_new_hosts_since_the_last_run_trigger_a_notification(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")

        # First cycle: establishes the baseline (never a notification).
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        first_scan_id = control_db.get_monitored_domain(
            account_id, "example.com"
        ).pending_passive_scan_id
        _write_hosts(api_settings, account_id, first_scan_id, ["a.example.com"])
        control_db.update_scan_status(first_scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        assert sender.monitoring_alerts == []
        baseline = control_db.get_monitored_domain(account_id, "example.com")
        assert baseline.last_asset_count == 1

        # Second cycle: a new host appears -> notification.
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        second_scan_id = control_db.get_monitored_domain(
            account_id, "example.com"
        ).pending_passive_scan_id
        _write_hosts(api_settings, account_id, second_scan_id, ["a.example.com", "b.example.com"])
        control_db.update_scan_status(second_scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        assert len(sender.monitoring_alerts) == 1
        _, _, lines, truncated = sender.monitoring_alerts[0]
        assert truncated == 0
        assert any("1 new host" in line for line in lines)
        final = control_db.get_monitored_domain(account_id, "example.com")
        assert final.last_asset_count == 2

    def test_asset_count_jump_past_ceiling_without_wildcard_is_flagged_needs_review(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        scan_id = control_db.get_monitored_domain(account_id, "example.com").pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id, ["a.example.com"])
        control_db.update_scan_status(scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        scan_id_2 = control_db.get_monitored_domain(
            account_id, "example.com"
        ).pending_passive_scan_id
        # api_settings.monitoring_asset_count_ceiling == 5 (fixture)
        _write_hosts(api_settings, account_id, scan_id_2, [f"h{i}.example.com" for i in range(10)])
        control_db.update_scan_status(scan_id_2, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.needs_review is True
        assert updated.status == "needs_review"
        assert len(sender.monitoring_alerts) == 1
        _, _, lines, _ = sender.monitoring_alerts[0]
        assert any("NEEDS REVIEW" in line for line in lines)

    def test_a_failed_scheduled_scan_is_rescheduled_without_touching_the_baseline(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        scan_id = control_db.get_monitored_domain(account_id, "example.com").pending_passive_scan_id
        control_db.update_scan_status(scan_id, "failed", error_message="boom")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.pending_passive_scan_id is None  # cleared, free to retry next cadence
        assert updated.last_asset_count is None  # baseline untouched by a failure
        assert sender.monitoring_alerts == []


class TestNeedsReviewPausesActiveScanning:
    """A `needs_review` domain must stop accruing Speed 2 (active) scans
    until a human explicitly acknowledges it — the whole point of the
    asset-count sanity ceiling is that automatic re-scanning of a
    likely-spurious huge attack surface stops, not that it keeps running
    on the same schedule with a label attached. Speed 1 (passive) is a
    deliberate exception: cheap, no active target traffic, and useful
    for an operator to watch whether the count settles back down on its
    own before they decide what to do."""

    def _flag_needs_review(
        self, control_db: ControlDB, api_settings: APISettings, account_id: str, domain: str
    ) -> None:
        """Drives a real domain into `needs_review` the same way
        production does — two real passive cycles, the second one's
        count jumping past the fixture's ceiling (5) — rather than
        hand-writing the status via SQL, so this helper exercises the
        exact mechanism under test, not a shortcut around it.

        Deliberately `speed2=False` throughout: enabling Speed 2 up
        front would let the FIRST (pre-flag) cycle enqueue a real active
        scan of its own before the domain ever becomes `needs_review`,
        which would leave a stray `pending_active_scan_id` around and
        confuse what a test checks afterward. Tests that need Speed 2
        enabled call `create_or_update_monitored_domain` themselves,
        AFTER this helper returns, to flip it on against an
        already-flagged domain — the actual scenario this whole task is
        about."""
        record = _monitor(control_db, api_settings, account_id, domain, speed2=False)
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=_RecordingEmailSender()
        )
        scan_id = control_db.get_monitored_domain(account_id, domain).pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id, ["a." + domain])
        control_db.update_scan_status(scan_id, "completed")
        run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=_RecordingEmailSender()
        )

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=_RecordingEmailSender()
        )
        scan_id_2 = control_db.get_monitored_domain(account_id, domain).pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id_2, [f"h{i}.{domain}" for i in range(10)])
        control_db.update_scan_status(scan_id_2, "completed")
        run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=_RecordingEmailSender()
        )

        flagged = control_db.get_monitored_domain(account_id, domain)
        assert flagged.status == "needs_review"
        assert flagged.needs_review is True

    def _enable_speed2(
        self, control_db: ControlDB, api_settings: APISettings, account_id: str, domain: str
    ) -> None:
        """Opts an already-`needs_review` domain into Speed 2 — the
        real-world order of events this task is actually about (a
        domain gets flagged, and only then does someone try to turn on
        active monitoring for it, or it was already on when the flag
        tripped)."""
        control_db.create_or_update_monitored_domain(
            account_id=account_id,
            domain=domain,
            speed2_enabled=True,
            passive_interval_hours=api_settings.monitoring_passive_interval_hours,
            active_interval_hours=api_settings.monitoring_active_interval_hours,
        )

    def test_needs_review_row_is_excluded_from_the_due_active_page(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = _account(control_db, tier="pro")
        _verify_domain(control_db, account_id, "example.com")
        self._flag_needs_review(control_db, api_settings, account_id, "example.com")
        self._enable_speed2(control_db, api_settings, account_id, "example.com")
        record = control_db.get_monitored_domain(account_id, "example.com")
        _make_due(control_db, record.monitoring_id)  # overdue AND speed2_enabled

        due_before = datetime.now(timezone.utc).isoformat()
        page = control_db.list_due_active_monitoring_page(
            due_before=due_before, cursor=None, limit=100
        )

        assert record.monitoring_id not in {r.monitoring_id for r in page}

    def test_a_full_cycle_never_enqueues_speed2_for_a_needs_review_domain(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db, tier="pro")
        _verify_domain(control_db, account_id, "example.com")
        self._flag_needs_review(control_db, api_settings, account_id, "example.com")
        self._enable_speed2(control_db, api_settings, account_id, "example.com")
        record = control_db.get_monitored_domain(account_id, "example.com")
        _make_due(control_db, record.monitoring_id)

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.pending_active_scan_id is None
        assert updated.status == "needs_review"

    def test_passive_speed1_keeps_running_while_needs_review(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db, tier="pro")
        _verify_domain(control_db, account_id, "example.com")
        self._flag_needs_review(control_db, api_settings, account_id, "example.com")
        record = control_db.get_monitored_domain(account_id, "example.com")
        _make_due(control_db, record.monitoring_id)

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        updated = control_db.get_monitored_domain(account_id, "example.com")
        # Speed 1 was enqueued normally despite needs_review — a real,
        # new pending passive scan, not skipped like Speed 2 was.
        assert updated.pending_passive_scan_id is not None

    def test_a_smaller_count_on_a_later_passive_cycle_does_not_auto_clear_needs_review(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db, tier="pro")
        _verify_domain(control_db, account_id, "example.com")
        self._flag_needs_review(control_db, api_settings, account_id, "example.com")
        record = control_db.get_monitored_domain(account_id, "example.com")

        # A later passive cycle reports a count back under the ceiling.
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        scan_id = control_db.get_monitored_domain(account_id, "example.com").pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id, ["a.example.com"])
        control_db.update_scan_status(scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.last_asset_count == 1  # the smaller count WAS recorded
        assert updated.status == "needs_review"  # but the flag stayed sticky
        assert updated.needs_review is True

    def test_acknowledge_clears_the_flag_and_the_next_cycle_resumes_speed2(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db, tier="pro")
        _verify_domain(control_db, account_id, "example.com")
        self._flag_needs_review(control_db, api_settings, account_id, "example.com")
        self._enable_speed2(control_db, api_settings, account_id, "example.com")
        record = control_db.get_monitored_domain(account_id, "example.com")
        _make_due(control_db, record.monitoring_id)

        cleared = control_db.clear_needs_review(account_id, "example.com")
        assert cleared is True
        acknowledged = control_db.get_monitored_domain(account_id, "example.com")
        assert acknowledged.status == "active"
        assert acknowledged.needs_review is False

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        resumed = control_db.get_monitored_domain(account_id, "example.com")
        assert resumed.pending_active_scan_id is not None

    def test_clear_needs_review_is_a_noop_when_not_currently_flagged(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = _account(control_db, tier="pro")
        _verify_domain(control_db, account_id, "example.com")
        _monitor(control_db, api_settings, account_id, "example.com")

        assert control_db.clear_needs_review(account_id, "example.com") is False


class TestErrorIsolationAndIdempotency:
    def test_one_accounts_missing_recon_db_never_blocks_another_accounts_cycle(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        broken_account = _account(control_db)
        _verify_domain(control_db, broken_account, "broken.example")
        broken_record = _monitor(control_db, api_settings, broken_account, "broken.example")
        _make_due(control_db, broken_record.monitoring_id)

        healthy_account = _account(control_db)
        _verify_domain(control_db, healthy_account, "healthy.example")
        healthy_record = _monitor(control_db, api_settings, healthy_account, "healthy.example")
        _make_due(control_db, healthy_record.monitoring_id)

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        broken_scan_id = control_db.get_monitored_domain(
            broken_account, "broken.example"
        ).pending_passive_scan_id
        healthy_scan_id = control_db.get_monitored_domain(
            healthy_account, "healthy.example"
        ).pending_passive_scan_id
        control_db.update_scan_status(broken_scan_id, "completed")
        control_db.update_scan_status(healthy_scan_id, "completed")
        _write_hosts(api_settings, healthy_account, healthy_scan_id, ["a.healthy.example"])
        # broken_account's recon.db is left with no row for broken_scan_id
        # at all — AssetStore.get_host_domains on it simply returns an
        # empty list (a real, valid SQLite query result), not an
        # exception, so this specific scenario exercises "harvests
        # cleanly to zero hosts" rather than a crash — the actually
        # interesting per-account isolation case (a corrupt/unreadable
        # recon.db) is exercised in test_scale.py instead, where it's
        # cheap to set up alongside the bulk-insert fixtures already
        # needed there.

        stats = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=sender
        )

        assert stats["skipped_errors"] == 0
        healthy_updated = control_db.get_monitored_domain(healthy_account, "healthy.example")
        assert healthy_updated.last_asset_count == 1
        broken_updated = control_db.get_monitored_domain(broken_account, "broken.example")
        assert broken_updated.last_asset_count == 0

    def test_running_a_cycle_twice_with_nothing_new_due_changes_nothing(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        _monitor(control_db, api_settings, account_id, "example.com")
        # Not backdated — not due yet.

        first = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=sender
        )
        second = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=sender
        )

        assert first == {"harvested": 0, "enqueued": 0, "skipped_errors": 0, "notified_accounts": 0}
        assert second == first

    def test_a_domain_stuck_pending_with_no_matching_scan_row_is_never_reprocessed_forever(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        """Defensive: `pending_passive_scan_id` pointing at a scan_id
        that somehow doesn't exist (should not happen in practice) must
        not crash the cycle — `_harvest_one` treats a missing scan the
        same as "not finished yet" and leaves it pending rather than
        raising, which `run_monitoring_cycle`'s per-row try/except would
        catch anyway, but this confirms the non-exceptional path too."""
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")
        control_db.mark_monitoring_scan_enqueued(
            record.monitoring_id, speed="passive", scan_id="does-not-exist"
        )

        stats = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=sender
        )

        assert stats["skipped_errors"] == 0
        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.pending_passive_scan_id == "does-not-exist"


class TestOptOut:
    def test_deleting_a_monitored_domain_stops_further_scheduling(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")
        assert control_db.delete_monitored_domain(account_id, "example.com") is True
        _ = record  # the row is gone; nothing left to make "due"

        stats = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=sender
        )

        assert stats["enqueued"] == 0
        assert control_db.get_monitored_domain(account_id, "example.com") is None


class TestCycleIsSafeToInterruptMidWay:
    """`run_monitoring_cycle`'s own module docstring claims the cycle is
    "safe to interrupt at any point" — proven here for real, not just
    asserted in prose. The enqueue phase's own page loop
    (`while not budget.exhausted(): page = list_due_..._page(...)`) is
    the exact mechanism under test: the budget is only re-checked BETWEEN
    pages, so a real, deterministic per-row delay (added to a genuine
    dependency `_try_enqueue_one` calls, `classify_scan_gate` — never the
    function under test itself) combined with a small `monitoring_batch_size`
    reliably stops the cycle after some pages but not all, without faking
    `time.monotonic()` or mocking away any monitoring logic."""

    def _slow_down_classify_scan_gate(self, monkeypatch: pytest.MonkeyPatch, delay: float) -> None:
        real = monitoring_worker_module.classify_scan_gate

        def slow(*args, **kwargs):
            time.sleep(delay)
            return real(*args, **kwargs)

        monkeypatch.setattr(monitoring_worker_module, "classify_scan_gate", slow)

    def _seed_domains(
        self, control_db: ControlDB, api_settings: APISettings, account_id: str, count: int
    ) -> list[str]:
        domains = [f"host{i}.interrupt-test.example" for i in range(count)]
        for domain in domains:
            _verify_domain(control_db, account_id, domain)
            record = _monitor(control_db, api_settings, account_id, domain)
            _make_due(control_db, record.monitoring_id)
        return domains

    def test_a_budget_exhausted_partway_through_enqueue_resumes_and_matches_one_clean_run(
        self, api_settings: APISettings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Scenario A: interrupted then resumed, against its OWN control_db.
        interrupted_settings = APISettings(
            data_dir=api_settings.data_dir,
            monitoring_batch_size=2,  # 6 domains -> 3 pages
            monitoring_asset_count_ceiling=api_settings.monitoring_asset_count_ceiling,
            monitoring_cycle_time_budget_seconds=0.08,  # ~1 page's worth of delay below
        )
        interrupted_db = ControlDB(interrupted_settings.data_dir / "control.db")
        account_a = _account(interrupted_db, tier="pro")
        domains = self._seed_domains(interrupted_db, interrupted_settings, account_a, 6)

        self._slow_down_classify_scan_gate(monkeypatch, delay=0.05)
        stats1 = run_monitoring_cycle(
            api_settings=interrupted_settings,
            control_db=interrupted_db,
            email_sender=_RecordingEmailSender(),
        )
        monkeypatch.undo()  # remove the slowdown before resuming

        mid_state = {
            d: interrupted_db.get_monitored_domain(account_a, d).pending_passive_scan_id
            for d in domains
        }
        touched_after_first_call = [d for d, scan_id in mid_state.items() if scan_id is not None]
        untouched_after_first_call = [d for d, scan_id in mid_state.items() if scan_id is None]
        assert 0 < len(touched_after_first_call) < 6, (
            "the tiny budget should have stopped the cycle after some pages but not all — "
            f"got {stats1}"
        )
        assert stats1["enqueued"] == len(touched_after_first_call)

        # The untouched rows must be completely UNCHANGED — no partial
        # write, still cleanly "due," never half-processed.
        for d in untouched_after_first_call:
            record = interrupted_db.get_monitored_domain(account_a, d)
            assert record.pending_passive_scan_id is None
            assert record.last_asset_count is None

        # Resume with a real, generous budget — must finish exactly the
        # rows the first call didn't reach, and never touch the
        # already-enqueued ones a second time (their scan_id must be
        # byte-identical before and after).
        stats2 = run_monitoring_cycle(
            api_settings=api_settings,  # generous default budget, no slowdown
            control_db=interrupted_db,
            email_sender=_RecordingEmailSender(),
        )
        assert stats2["enqueued"] == len(untouched_after_first_call)
        assert stats1["enqueued"] + stats2["enqueued"] == 6

        final_scan_ids = {
            d: interrupted_db.get_monitored_domain(account_a, d).pending_passive_scan_id
            for d in domains
        }
        assert all(scan_id is not None for scan_id in final_scan_ids.values())
        for d in touched_after_first_call:
            assert final_scan_ids[d] == mid_state[d], (
                f"{d} was already enqueued before the resume — its scan_id must not change "
                "(proof it was never re-enqueued/double-processed)"
            )

        # Scenario B: one single, uninterrupted cycle over an IDENTICAL
        # fresh seed (same domain names, same account shape), no
        # slowdown. The end state must match Scenario A's: every domain
        # gets exactly one real queued scan, tagged the same way.
        clean_db = ControlDB(Path(str(api_settings.data_dir) + "-clean") / "control.db")
        account_b = _account(clean_db, tier="pro")
        self._seed_domains(clean_db, api_settings, account_b, 6)
        stats_clean = run_monitoring_cycle(
            api_settings=api_settings, control_db=clean_db, email_sender=_RecordingEmailSender()
        )
        assert stats_clean["enqueued"] == 6

        for d in domains:
            interrupted_scan = interrupted_db.get_owned_scan(final_scan_ids[d], account_a)
            clean_record = clean_db.get_monitored_domain(account_b, d)
            clean_scan = clean_db.get_owned_scan(clean_record.pending_passive_scan_id, account_b)
            # Real timestamps differ between the two runs by construction
            # (two separate wall-clock cycles) — what "identical end
            # state" actually means here is the MEANINGFUL, observable
            # shape: exactly one real queued scan per domain, same
            # trigger source, same domain, never zero, never two.
            assert interrupted_scan.status == clean_scan.status == "queued"
            assert interrupted_scan.trigger_source == clean_scan.trigger_source
            assert interrupted_scan.domain == clean_scan.domain == d


class TestNoLostOrDuplicateNotificationAcrossAnInterruption:
    """Proves the durable-notification-outbox fix
    (`monitoring_pending_notifications`, `api/control_db.py`) with a REAL
    interruption, not a mock standing in for internal logic: a real
    `EmailSender` implementation whose `send_monitoring_alert` genuinely
    raises is passed into a real `run_monitoring_cycle` call. Since the
    harvest phase's DB write (`batch_record_monitoring_progress`, which
    durably records BOTH the row's new baseline AND the pending
    notification in one transaction) has already committed by the time
    `_flush_pending_notifications` reaches the send step, this raising
    sender interrupts EXACTLY at the real boundary the task asked for —
    after the write, at the send — not somewhere nothing could have gone
    wrong."""

    class _RaisingEmailSender(_RecordingEmailSender):
        def send_monitoring_alert(self, **kwargs) -> None:
            self.monitoring_alerts.append(
                (
                    kwargs["to"],
                    kwargs["account_id"],
                    kwargs["summary_lines"],
                    kwargs["truncated_count"],
                )
            )
            raise RuntimeError("simulated crash exactly at the send step")

    def test_a_crash_between_the_db_write_and_the_send_never_loses_the_notification(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = _account(control_db, tier="pro")
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")

        # First cycle: establish the baseline — never notification-worthy.
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=_RecordingEmailSender()
        )
        baseline_scan_id = control_db.get_monitored_domain(
            account_id, "example.com"
        ).pending_passive_scan_id
        _write_hosts(api_settings, account_id, baseline_scan_id, ["a.example.com"])
        control_db.update_scan_status(baseline_scan_id, "completed")
        run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=_RecordingEmailSender()
        )

        # Second cycle: a new host appears -> a real, notification-worthy
        # change. The email sender for THIS cycle genuinely raises, right
        # after the harvest's own DB write already committed.
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=_RecordingEmailSender()
        )
        scan_id = control_db.get_monitored_domain(account_id, "example.com").pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id, ["a.example.com", "b.example.com"])
        control_db.update_scan_status(scan_id, "completed")

        crashing_sender = self._RaisingEmailSender()
        with pytest.raises(RuntimeError, match="simulated crash"):
            run_monitoring_cycle(
                api_settings=api_settings, control_db=control_db, email_sender=crashing_sender
            )
        # The raising sender WAS invoked (an attempt was genuinely made)
        # but the notification must not be considered delivered — proven
        # below by it still being found and sent on the next cycle.
        assert len(crashing_sender.monitoring_alerts) == 1

        # The row's own baseline update DID survive (the DB write commits
        # before the raising send is ever reached).
        updated = control_db.get_monitored_domain(account_id, "example.com")
        assert updated.last_asset_count == 2

        # Resume: a working sender, nothing newly due. The durable outbox
        # (not this cycle's own harvest, which finds nothing new) is what
        # delivers the previously-interrupted notification — never lost.
        working_sender = _RecordingEmailSender()
        stats_resume = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=working_sender
        )
        assert stats_resume["notified_accounts"] == 1
        assert len(working_sender.monitoring_alerts) == 1
        _, _, lines, _ = working_sender.monitoring_alerts[0]
        assert any("1 new host" in line for line in lines)

        # A THIRD cycle, still nothing newly due: the same change must
        # NEVER be reported again — proves "at most once delivered
        # successfully," not just "eventually delivered."
        third_sender = _RecordingEmailSender()
        stats_third = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=third_sender
        )
        assert stats_third["notified_accounts"] == 0
        assert third_sender.monitoring_alerts == []


class TestEmailAndWebhookDeliveryShareTheSameOutboxRow:
    """`_flush_pending_notifications` reads each notify-worthy outcome
    from the SAME durable outbox row for both the email and the webhook
    (`_deliver_webhooks_for_outcome`) — never two independent "is this
    worth alerting" decisions that could disagree. Delivery MECHANICS
    (real HTTPS, real HMAC signing, retries, disable-after-N-failures)
    are already exhaustively covered against a real local server in
    `tests/test_webhook_delivery.py`; these tests stub
    `api.webhooks.deliver_event_to_subscribers` itself (the exact
    boundary `_deliver_webhooks_for_outcome` calls into) to verify the
    WIRING — that a webhook delivery is actually attempted, for the
    right account and the right event, driven by the same outcome as
    the email — and the failure-isolation guarantee around it, without
    re-testing delivery mechanics a second time."""

    def _register_webhook(self, control_db: ControlDB, account_id: str) -> None:
        from api.webhooks import generate_webhook_secret

        control_db.create_webhook(
            account_id=account_id,
            url="https://example.invalid/hook",
            secret=generate_webhook_secret(),
            event_types=("monitoring.changed", "monitoring.needs_review"),
        )

    def _cause_a_notification(
        self,
        control_db: ControlDB,
        api_settings: APISettings,
        sender,
        domain: str,
        tier: str = "pro",
    ) -> str:
        account_id = _account(control_db, tier=tier)
        _verify_domain(control_db, account_id, domain)
        record = _monitor(control_db, api_settings, account_id, domain)

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        first_scan_id = control_db.get_monitored_domain(account_id, domain).pending_passive_scan_id
        _write_hosts(api_settings, account_id, first_scan_id, ["a." + domain])
        control_db.update_scan_status(first_scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        second_scan_id = control_db.get_monitored_domain(account_id, domain).pending_passive_scan_id
        _write_hosts(api_settings, account_id, second_scan_id, ["a." + domain, "b." + domain])
        control_db.update_scan_status(second_scan_id, "completed")
        return account_id

    def test_a_notify_worthy_outcome_sends_both_an_email_and_a_webhook_for_the_same_change(
        self,
        control_db: ControlDB,
        api_settings: APISettings,
        sender: _RecordingEmailSender,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import api.webhooks as webhooks_module

        calls: list[tuple[str, str, str]] = []

        async def _recording_deliver(*, control_db, account_id, event, verify=True):
            calls.append((account_id, event.event_type, event.payload["domain"]))

        monkeypatch.setattr(webhooks_module, "deliver_event_to_subscribers", _recording_deliver)

        account_id = self._cause_a_notification(control_db, api_settings, sender, "example.com")
        self._register_webhook(control_db, account_id)

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        assert len(sender.monitoring_alerts) == 1
        assert calls == [(account_id, "monitoring.changed", "example.com")]

    def test_a_webhook_delivery_exception_does_not_prevent_that_accounts_email(
        self,
        control_db: ControlDB,
        api_settings: APISettings,
        sender: _RecordingEmailSender,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import api.webhooks as webhooks_module

        async def _raising_deliver(*, control_db, account_id, event, verify=True):
            raise RuntimeError("simulated webhook receiver outage")

        monkeypatch.setattr(webhooks_module, "deliver_event_to_subscribers", _raising_deliver)

        account_id = self._cause_a_notification(control_db, api_settings, sender, "example.com")
        self._register_webhook(control_db, account_id)

        stats = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=sender
        )

        assert stats["notified_accounts"] == 1
        assert len(sender.monitoring_alerts) == 1

    def test_a_webhook_failure_for_one_account_never_blocks_a_different_accounts_notification(
        self,
        control_db: ControlDB,
        api_settings: APISettings,
        sender: _RecordingEmailSender,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import api.webhooks as webhooks_module

        async def _always_raising_deliver(*, control_db, account_id, event, verify=True):
            raise RuntimeError("simulated webhook receiver outage")

        monkeypatch.setattr(
            webhooks_module, "deliver_event_to_subscribers", _always_raising_deliver
        )

        account_a = self._cause_a_notification(control_db, api_settings, sender, "a-example.com")
        self._register_webhook(control_db, account_a)
        account_b = self._cause_a_notification(control_db, api_settings, sender, "b-example.com")
        self._register_webhook(control_db, account_b)

        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        # Harvesting is cycle-wide, not scoped to one account, so which of
        # these two accounts' notifications actually gets flushed by which
        # of the several `run_monitoring_cycle` calls above (some inside
        # `_cause_a_notification`'s own setup, one here) is an
        # implementation detail — what must hold regardless is that BOTH
        # accounts were notified by email exactly once across the whole
        # sequence, proving account A's always-raising webhook delivery
        # never silently swallowed account B's notification too.
        notified_account_ids = [alert[1] for alert in sender.monitoring_alerts]
        assert notified_account_ids.count(account_a) == 1
        assert notified_account_ids.count(account_b) == 1

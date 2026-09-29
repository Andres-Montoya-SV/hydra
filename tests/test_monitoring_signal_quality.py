"""Productization Phase 05 — monitoring signal quality.

A collector failure must never be reported as hostnames disappearing (or,
one run later, as them all reappearing). Alongside that, the two new
read endpoints: per-scan collector outcomes, and per-domain alert history.
Worker tests drive the real `run_monitoring_cycle` against a real
`ControlDB`/`AssetStore`, the same harness `tests/test_monitoring_worker.py`
uses."""

from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.control_db import ControlDB
from api.main import create_app
from api.monitoring import regressed_providers
from api.monitoring_worker import run_monitoring_cycle
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host, ScanRun
from core.store import AssetStore

DOMAIN = "example.com"
HEALTHY = [("subfinder", "success_with_results", 2), ("ctlogs", "success_with_results", 2)]
CTLOGS_FAILED = [("subfinder", "success_with_results", 1), ("ctlogs", "failed", 0)]


class _Sender:
    def __init__(self) -> None:
        self.alerts: list[list[str]] = []

    def send_monitoring_alert(
        self, *, to, account_id, summary_lines, truncated_count
    ):  # noqa: ANN001
        self.alerts.append(summary_lines)


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data", monitoring_asset_count_ceiling=1000)


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _monitored_account(control_db: ControlDB, api_settings: APISettings) -> tuple[str, str]:
    account_id = control_db.create_account(email=f"sq-{secrets.token_hex(6)}@example.com")
    control_db.create_default_subscription(account_id, tier="pro")
    record = control_db.create_domain_verification(
        account_id=account_id, domain=DOMAIN, token="seeded-for-test"  # noqa: S106
    )
    now = datetime.now(timezone.utc)
    control_db.mark_verification_succeeded(
        record.verification_id,
        method="dns_txt",
        verified_at=now.isoformat(),
        expires_at=(now + timedelta(days=90)).isoformat(),
    )
    row = control_db.create_or_update_monitored_domain(
        account_id=account_id,
        domain=DOMAIN,
        speed2_enabled=False,
        passive_interval_hours=api_settings.monitoring_passive_interval_hours,
        active_interval_hours=api_settings.monitoring_active_interval_hours,
    )
    return account_id, row.monitoring_id


def _run_cycle(
    control_db: ControlDB,
    api_settings: APISettings,
    sender: _Sender,
    ids: tuple[str, str],
    *,
    hosts: list[str],
    outcomes: list[tuple[str, str, int]],
) -> str:
    """One full monitoring cycle: enqueue a scan, 'run' it (hosts + collector
    outcomes, exactly what the orchestrator records), then harvest it."""
    account_id, monitoring_id = ids
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    with sqlite3.connect(control_db.db_path) as conn:
        conn.execute(
            "UPDATE monitored_domains SET next_passive_due_at = ? WHERE monitoring_id = ?",
            (past, monitoring_id),
        )
    run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
    scan_id = control_db.get_monitored_domain(account_id, DOMAIN).pending_passive_scan_id
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at=datetime.now(timezone.utc).isoformat()))
    for host in hosts:
        store.upsert_host(scan_id, Host(domain=host, hostname=host))
    org = control_db.get_owned_scan(scan_id, account_id).organization_id
    control_db.record_provider_run_outcomes(
        organization_id=org, account_id=account_id, run_id=scan_id, outcomes=outcomes
    )
    control_db.update_scan_status(scan_id, "completed")
    run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
    return scan_id


class TestRegressedProviders:
    def test_a_contributing_collector_that_now_fails_is_regressed(self) -> None:
        previous = {"ctlogs": "success_with_results", "subfinder": "success_with_results"}
        current = {"ctlogs": "failed", "subfinder": "success_with_results"}
        assert regressed_providers(previous_outcomes=previous, current_outcomes=current) == [
            "ctlogs"
        ]

    def test_a_collector_that_was_already_failing_is_not(self) -> None:
        previous = {"amass": "unavailable"}
        current = {"amass": "unavailable"}
        assert regressed_providers(previous_outcomes=previous, current_outcomes=current) == []

    def test_a_collector_that_found_nothing_last_time_is_not(self) -> None:
        previous = {"gau": "success_no_results"}
        current = {"gau": "failed"}
        assert regressed_providers(previous_outcomes=previous, current_outcomes=current) == []

    def test_partial_and_unavailable_count_and_output_is_sorted(self) -> None:
        previous = {"z": "success_with_results", "a": "success_with_results"}
        current = {"z": "partial", "a": "unavailable"}
        assert regressed_providers(previous_outcomes=previous, current_outcomes=current) == [
            "a",
            "z",
        ]


class TestCollectorFailureIsNotAHostRemoval:
    def test_failed_collector_run_alerts_nothing_and_keeps_the_baseline(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        sender = _Sender()
        ids = _monitored_account(control_db, api_settings)
        baseline_scan = _run_cycle(
            control_db,
            api_settings,
            sender,
            ids,
            hosts=["a.example.com", "b.example.com"],
            outcomes=HEALTHY,
        )

        _run_cycle(
            control_db, api_settings, sender, ids, hosts=["a.example.com"], outcomes=CTLOGS_FAILED
        )

        assert sender.alerts == []
        row = control_db.get_monitored_domain(ids[0], DOMAIN)
        assert (row.last_asset_count, row.last_passive_scan_id) == (2, baseline_scan)

    def test_the_next_healthy_run_does_not_report_everything_as_added(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        sender = _Sender()
        ids = _monitored_account(control_db, api_settings)
        both = ["a.example.com", "b.example.com"]
        _run_cycle(control_db, api_settings, sender, ids, hosts=both, outcomes=HEALTHY)
        _run_cycle(
            control_db, api_settings, sender, ids, hosts=["a.example.com"], outcomes=CTLOGS_FAILED
        )

        healthy_scan = _run_cycle(
            control_db, api_settings, sender, ids, hosts=both, outcomes=HEALTHY
        )

        assert sender.alerts == []
        row = control_db.get_monitored_domain(ids[0], DOMAIN)
        assert (row.last_asset_count, row.last_passive_scan_id) == (2, healthy_scan)

    def test_a_genuine_removal_with_healthy_collectors_still_alerts(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        sender = _Sender()
        ids = _monitored_account(control_db, api_settings)
        _run_cycle(
            control_db,
            api_settings,
            sender,
            ids,
            hosts=["a.example.com", "b.example.com"],
            outcomes=HEALTHY,
        )

        _run_cycle(control_db, api_settings, sender, ids, hosts=["a.example.com"], outcomes=HEALTHY)

        assert len(sender.alerts) == 1
        history = control_db.list_monitoring_notifications(ids[0], DOMAIN)
        assert [(n.hosts_added, n.hosts_removed) for n in history] == [((), ("b.example.com",))]


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(APISettings(data_dir=tmp_path / "api")))


def _api_account(client: TestClient, email: str) -> tuple[str, str]:
    body = client.post("/accounts", json={"email": email}).json()
    return body["api_key"], body["account_id"]


class TestScanCollectionEndpoint:
    def test_reports_each_collector_and_flags_a_degraded_scan(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id = _api_account(client, "coll@example.com")
            db = client.app.state.control_db
            db.create_scan(scan_id="scan-1", account_id=account_id, domain=DOMAIN, db_path="x")
            org = db.get_owned_scan("scan-1", account_id).organization_id
            db.record_provider_run_outcomes(
                organization_id=org,
                account_id=account_id,
                run_id="scan-1",
                outcomes=CTLOGS_FAILED,
            )

            body = client.get("/scans/scan-1/collection", headers={"X-API-Key": key}).json()

            assert body["degraded"] is True
            outcomes = {o["provider"]: o for o in body["outcomes"]}
            assert outcomes["ctlogs"]["outcome"] == "failed"
            assert outcomes["subfinder"]["capability"] != "uncategorized"

    def test_a_clean_scan_is_not_degraded_and_foreign_accounts_get_404(
        self, tmp_path: Path
    ) -> None:
        with _client(tmp_path) as client:
            key, account_id = _api_account(client, "coll-clean@example.com")
            db = client.app.state.control_db
            db.create_scan(scan_id="scan-2", account_id=account_id, domain=DOMAIN, db_path="x")
            org = db.get_owned_scan("scan-2", account_id).organization_id
            db.record_provider_run_outcomes(
                organization_id=org, account_id=account_id, run_id="scan-2", outcomes=HEALTHY
            )
            foreign_key, _ = _api_account(client, "coll-foreign@example.com")

            mine = client.get("/scans/scan-2/collection", headers={"X-API-Key": key})
            theirs = client.get("/scans/scan-2/collection", headers={"X-API-Key": foreign_key})

            assert mine.json()["degraded"] is False
            assert theirs.status_code == 404


class TestNotificationHistoryEndpoint:
    def test_lists_alerts_with_their_reasons_and_is_account_scoped(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id = _api_account(client, "hist@example.com")
            db = client.app.state.control_db
            db.create_or_update_monitored_domain(
                account_id=account_id,
                domain=DOMAIN,
                speed2_enabled=False,
                passive_interval_hours=24,
                active_interval_hours=168,
            )
            with sqlite3.connect(db.db_path) as conn:
                conn.execute(
                    "INSERT INTO monitoring_pending_notifications (notification_id, account_id, "
                    "domain, speed, scan_id, hosts_added_json, hosts_removed_json, asset_count, "
                    "asset_digest, needs_review, review_reason, created_at, easm_citations_json) "
                    "VALUES ('n1', ?, ?, 'passive', 's1', '[\"new.example.com\"]', '[]', 3, "
                    "'d', 0, NULL, '2026-09-29T00:00:00+00:00', '[\"CERTIFICATE_REPLACED\"]')",
                    (account_id, DOMAIN),
                )
            foreign_key, _ = _api_account(client, "hist-foreign@example.com")

            mine = client.get(
                f"/domains/{DOMAIN}/monitoring/notifications", headers={"X-API-Key": key}
            )
            theirs = client.get(
                f"/domains/{DOMAIN}/monitoring/notifications", headers={"X-API-Key": foreign_key}
            )

            assert [(n["hosts_added"], n["citations"]) for n in mine.json()] == [
                (["new.example.com"], ["CERTIFICATE_REPLACED"])
            ]
            assert theirs.status_code == 404


class TestDegradedRunsAreLoggedOncePerCycle:
    def test_one_aggregated_warning_not_one_per_domain(
        self, control_db: ControlDB, api_settings: APISettings, caplog: pytest.LogCaptureFixture
    ) -> None:
        sender = _Sender()
        ids = _monitored_account(control_db, api_settings)
        _run_cycle(
            control_db,
            api_settings,
            sender,
            ids,
            hosts=["a.example.com", "b.example.com"],
            outcomes=HEALTHY,
        )
        caplog.clear()

        with caplog.at_level("DEBUG", logger="hydra.api.monitoring"):
            _run_cycle(
                control_db,
                api_settings,
                sender,
                ids,
                hosts=["a.example.com"],
                outcomes=CTLOGS_FAILED,
            )

        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        degraded_warnings = [m for m in warnings if "degraded" in m]
        assert degraded_warnings == [
            "1 monitored domain(s) had a degraded scan this cycle; hostname diffs "
            "skipped and baselines kept. Failing collectors: ctlogs (1)."
        ]
        per_domain = [
            r for r in caplog.records if "Degraded passive monitoring scan" in r.getMessage()
        ]
        assert per_domain and all(r.levelname == "DEBUG" for r in per_domain)


class TestOnlyHostnameCollectorsCanSuppressRemovals:
    def test_a_failed_vulnerability_scanner_does_not_hide_a_real_removal(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        sender = _Sender()
        ids = _monitored_account(control_db, api_settings)
        with_nuclei = [*HEALTHY, ("nuclei", "success_with_results", 3)]
        nuclei_failed = [*HEALTHY, ("nuclei", "failed", 0)]
        _run_cycle(
            control_db,
            api_settings,
            sender,
            ids,
            hosts=["a.example.com", "b.example.com"],
            outcomes=with_nuclei,
        )

        _run_cycle(
            control_db, api_settings, sender, ids, hosts=["a.example.com"], outcomes=nuclei_failed
        )

        # nuclei doesn't produce hostnames, so its failure can't explain b
        # disappearing: the removal is real and must still be reported.
        assert len(sender.alerts) == 1
        history = control_db.list_monitoring_notifications(ids[0], DOMAIN)
        assert history[0].hosts_removed == ("b.example.com",)

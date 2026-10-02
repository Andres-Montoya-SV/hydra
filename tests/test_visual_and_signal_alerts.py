"""Roadmap v2: Visual Intelligence (per-asset visual references and a
deterministic visual-change signal) and the monitoring alerts that were
still missing — candidate review, risk change, and visual change.

Everything runs against a real ControlDB / AssetStore; the monitoring test
drives the real `run_monitoring_cycle`."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from _org_helpers import RecordingSender
from fastapi.testclient import TestClient

from api.asset_identity import ReconciliationDecision
from api.candidate_assets import CandidateAssetDraft
from api.control_db import ControlDB
from api.exposure_identity import exposure_from_finding
from api.main import create_app
from api.monitoring_worker import (
    CANDIDATE_CITATION_LIMIT,
    _candidate_review_citations,
    _risk_change_citations,
    run_monitoring_cycle,
)
from api.settings import APISettings
from api.subscriptions import apply_tier_change
from api.tenancy import account_db_path
from core.assets import Host, HttpService, ScanRun
from core.store import AssetStore
from core.visual import SIGNIFICANCE_RULES, visual_changes

DOMAIN = "example.com"
_SEEDED_TOKEN = "seeded-for-test"  # noqa: S105 - test fixture, not a secret
URL = "https://example.com/"


def _svc(title: str | None = "Acme Login", favicon: str | None = "111", **kw) -> HttpService:
    return HttpService(url=kw.pop("url", URL), host=DOMAIN, title=title, favicon_hash=favicon, **kw)


class TestVisualChanges:
    def test_favicon_and_title_changes_are_reported_in_a_stable_order(self) -> None:
        changes = visual_changes([_svc()], [_svc(title="Parked Domain", favicon="999")])

        assert [(c.signal, c.before, c.after) for c in changes] == [
            ("favicon", "111", "999"),
            ("title", "Acme Login", "Parked Domain"),
        ]
        assert "favicon changed on https://example.com/" in changes[0].reason()

    def test_body_hash_and_screenshot_differences_are_never_a_change(self) -> None:
        before = _svc(body_hash="aaa", screenshot_path="shots/a.png")
        after = _svc(body_hash="bbb", screenshot_path="shots/b.png")
        assert visual_changes([before], [after]) == []

    def test_whitespace_and_case_in_titles_are_not_a_change(self) -> None:
        assert visual_changes([_svc(title="Acme  Login")], [_svc(title=" acme login ")]) == []

    def test_a_signal_missing_on_either_side_is_not_a_change(self) -> None:
        assert visual_changes([_svc(title=None, favicon=None)], [_svc()]) == []
        assert visual_changes([_svc()], [_svc(title=None, favicon=None)]) == []

    def test_urls_only_in_one_run_are_left_to_the_host_diff(self) -> None:
        assert visual_changes([_svc(url="https://example.com/old")], [_svc()]) == []


def _account(client: TestClient) -> tuple[dict[str, str], str, str]:
    account = client.post("/accounts", json={"email": f"v-{secrets.token_hex(4)}@x.test"}).json()
    org = client.app.state.control_db.list_organizations_for_account(account["account_id"])[0][0]
    return {"X-API-Key": account["api_key"]}, account["account_id"], org


def _record_run(
    client: TestClient, account_id: str, org: str, run_id: str, day: int, svc: HttpService
) -> None:
    db = client.app.state.control_db
    db.create_scan(
        scan_id=run_id, account_id=account_id, domain=DOMAIN, db_path="x", organization_id=org
    )
    store = AssetStore(account_db_path(client.app.state.api_settings, account_id))
    stamp = f"2026-09-{day:02d}T00:00:00+00:00"
    store.create_run(ScanRun(run_id=run_id, started_at=stamp, targets=[DOMAIN]))
    store.upsert_host(run_id, Host(domain=DOMAIN, http_services=[svc]))
    store.finish_run(run_id, host_count=1, alive_count=1, warnings=[], errors=[])
    db.apply_asset_reconciliation(
        organization_id=org,
        run_id=run_id,
        decisions=[
            ReconciliationDecision(
                asset_id=f"asset-{org}",
                asset_type="domain",
                identity_key=f"domain:{DOMAIN}",
                is_new=db.get_asset(org, f"asset-{org}") is None,
                identifiers=(),
            )
        ],
        observed_at=stamp,
    )


class TestVisualEndpoint:
    def test_references_and_changes_since_the_previous_run(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            headers, account_id, org = _account(client)
            _record_run(client, account_id, org, "run-1", 1, _svc())
            _record_run(
                client,
                account_id,
                org,
                "run-2",
                2,
                _svc(favicon="999", screenshot_path="browser_probe_screenshots/x.png"),
            )

            body = client.get(
                f"/organizations/{org}/assets/asset-{org}/visual", headers=headers
            ).json()

            assert (body["run_id"], body["previous_run_id"]) == ("run-2", "run-1")
            assert body["references"][0]["screenshot_artifact"] == (
                "browser_probe_screenshots/x.png"
            )
            assert [c["signal"] for c in body["changes"]] == ["favicon"]
            assert body["significance_rules"] == list(SIGNIFICANCE_RULES)

    def test_first_run_has_references_but_no_changes(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            headers, account_id, org = _account(client)
            _record_run(client, account_id, org, "run-1", 1, _svc())

            body = client.get(
                f"/organizations/{org}/assets/asset-{org}/visual", headers=headers
            ).json()

            assert body["previous_run_id"] is None
            assert body["changes"] == []
            assert body["references"][0]["title"] == "Acme Login"

    def test_a_previous_run_of_another_organization_is_never_compared(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            headers, account_id, org = _account(client)
            apply_tier_change(client.app.state.control_db, account_id, "pro")  # Free owns one org
            other = client.post("/organizations", headers=headers, json={"name": "Other"}).json()
            _record_run(client, account_id, other["organization_id"], "run-1", 1, _svc())
            _record_run(client, account_id, org, "run-2", 2, _svc(favicon="999"))

            body = client.get(
                f"/organizations/{org}/assets/asset-{org}/visual", headers=headers
            ).json()

            assert body["previous_run_id"] is None
            assert body["changes"] == []

    def test_foreign_account_gets_404(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            _, account_id, org = _account(client)
            _record_run(client, account_id, org, "run-1", 1, _svc())
            foreign, _, _ = _account(client)

            resp = client.get(f"/organizations/{org}/assets/asset-{org}/visual", headers=foreign)

            assert resp.status_code == 404


def _org(db: ControlDB) -> tuple[str, str]:
    account_id = db.create_account(email=f"sig-{secrets.token_hex(4)}@x.test")
    return account_id, db.default_organization_id_for_account(account_id)


def _candidate(db: ControlDB, org: str, run_id: str, value: str) -> str:
    candidate_id, _ = db.upsert_candidate_asset(
        organization_id=org,
        run_id=run_id,
        draft=CandidateAssetDraft(
            candidate_type="DOMAIN",
            normalized_value=value,
            display_value=value,
            scope_status="UNKNOWN",
            collection_status="DISCOVERED",
            authorization_status="DENY",
            reason="shared certificate",
            depth=1,
            priority=50,
            collector="ctlogs",
            source_entity_id="",
            parent_indicator_id=None,
            lineage_reference=run_id,
        ),
    )
    return candidate_id


class TestCandidateReviewAlerts:
    def test_new_pending_candidates_are_cited_and_capped(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "control.db")
        _, org = _org(db)
        for i in range(CANDIDATE_CITATION_LIMIT + 3):
            _candidate(db, org, "run-1", f"c{i:02d}.example.net")
        _candidate(db, org, "run-0", "older.example.net")

        citations = _candidate_review_citations(db, org, "run-1")

        assert len(citations) == CANDIDATE_CITATION_LIMIT + 1
        assert citations[0].startswith("CANDIDATE_REVIEW: c00.example.net (DOMAIN)")
        assert citations[-1] == "CANDIDATE_REVIEW: 3 more candidate(s) await review"
        assert not any("older.example.net" in c for c in citations)

    def test_reviewed_candidates_are_not_cited(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "control.db")
        account_id, org = _org(db)
        candidate_id = _candidate(db, org, "run-1", "gone.example.net")
        db.discard_candidate_asset(
            organization_id=org,
            candidate_asset_id=candidate_id,
            account_id=account_id,
            justification="not ours",
        )

        assert _candidate_review_citations(db, org, "run-1") == []


_FINDING = {
    "host": DOMAIN,
    "template_id": "admin-exposed",
    "severity": "high",
    "source": "nuclei",
    "url": "https://example.com/admin",
    "name": "Admin exposed",
}


def _observe(db: ControlDB, account_id: str, org: str, run_id: str, finding_id: int) -> str:
    if db.get_owned_scan(run_id, account_id) is None:
        db.create_scan(
            scan_id=run_id, account_id=account_id, domain=DOMAIN, db_path="x", organization_id=org
        )
    draft = exposure_from_finding(_FINDING, asset_id="asset-x")
    assert draft is not None
    exposure_id, _, _ = db.upsert_exposure(
        organization_id=org,
        account_id=account_id,
        run_id=run_id,
        finding_id=finding_id,
        draft=draft,
    )
    return exposure_id


class TestRiskChangeAlerts:
    def _setup(self, tmp_path: Path) -> tuple[ControlDB, str, str, str]:
        db = ControlDB(tmp_path / "control.db")
        account_id, org = _org(db)
        db.apply_asset_reconciliation(
            organization_id=org,
            run_id="seed",
            decisions=[
                ReconciliationDecision(
                    asset_id="asset-x",
                    asset_type="domain",
                    identity_key=f"domain:{DOMAIN}",
                    is_new=True,
                    identifiers=(),
                )
            ],
            observed_at="2026-09-01T00:00:00+00:00",
        )
        exposure_id = _observe(db, account_id, org, "run-1", 1)
        return db, account_id, org, exposure_id

    def test_first_classification_is_not_a_change(self, tmp_path: Path) -> None:
        db, _, org, _ = self._setup(tmp_path)
        assert _risk_change_citations(db, org, "run-1") == []

    def test_an_escalation_between_runs_is_cited_with_its_reasons(self, tmp_path: Path) -> None:
        db, account_id, org, exposure_id = self._setup(tmp_path)
        _risk_change_citations(db, org, "run-1")
        aged = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        with db._connect() as conn:
            conn.execute(
                "UPDATE exposures SET first_seen_at = ? WHERE exposure_id = ?", (aged, exposure_id)
            )
        _observe(db, account_id, org, "run-2", 2)

        citations = _risk_change_citations(db, org, "run-2")

        assert len(citations) == 1
        assert citations[0].startswith("RISK_CHANGED: Admin exposed high -> critical")
        assert "open for 40 day(s)" in citations[0]
        # A retried harvest of the same run compares the same pair again.
        assert _risk_change_citations(db, org, "run-2") == citations

    def test_an_unchanged_level_is_not_cited(self, tmp_path: Path) -> None:
        db, account_id, org, _ = self._setup(tmp_path)
        _risk_change_citations(db, org, "run-1")
        _observe(db, account_id, org, "run-2", 2)

        assert _risk_change_citations(db, org, "run-2") == []


def _monitored(db: ControlDB, settings: APISettings) -> tuple[str, str]:
    account_id = db.create_account(email=f"mon-{secrets.token_hex(4)}@x.test")
    db.create_default_subscription(account_id, tier="pro")
    record = db.create_domain_verification(
        account_id=account_id, domain=DOMAIN, token=_SEEDED_TOKEN
    )
    now = datetime.now(timezone.utc)
    db.mark_verification_succeeded(
        record.verification_id,
        method="dns_txt",
        verified_at=now.isoformat(),
        expires_at=(now + timedelta(days=90)).isoformat(),
    )
    row = db.create_or_update_monitored_domain(
        account_id=account_id,
        domain=DOMAIN,
        speed2_enabled=False,
        passive_interval_hours=settings.monitoring_passive_interval_hours,
        active_interval_hours=settings.monitoring_active_interval_hours,
    )
    return account_id, row.monitoring_id


def _cycle(db: ControlDB, settings: APISettings, ids: tuple[str, str], svc: HttpService) -> None:
    account_id, monitoring_id = ids
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    with db._connect() as conn:
        conn.execute(
            "UPDATE monitored_domains SET next_passive_due_at = ? " "WHERE monitoring_id = ?",
            (past, monitoring_id),
        )
    sender = RecordingSender()
    run_monitoring_cycle(api_settings=settings, control_db=db, email_sender=sender)
    scan_id = db.get_monitored_domain(account_id, DOMAIN).pending_passive_scan_id
    store = AssetStore(account_db_path(settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at=datetime.now(timezone.utc).isoformat()))
    store.upsert_host(scan_id, Host(domain=DOMAIN, hostname=DOMAIN, http_services=[svc]))
    db.update_scan_status(scan_id, "completed")
    run_monitoring_cycle(api_settings=settings, control_db=db, email_sender=sender)


def _notifications_after_two_cycles(
    tmp_path: Path, first: HttpService, second: HttpService
):  # noqa: ANN202
    settings = APISettings(data_dir=tmp_path / "api", monitoring_asset_count_ceiling=1000)
    db = ControlDB(settings.control_db_path)
    ids = _monitored(db, settings)
    _cycle(db, settings, ids, first)
    _cycle(db, settings, ids, second)
    return db.list_monitoring_notifications(ids[0], DOMAIN)


class TestVisualChangeReachesMonitoringAlerts:
    def test_a_favicon_swap_alone_fires_an_explained_alert(self, tmp_path: Path) -> None:
        notifications = _notifications_after_two_cycles(
            tmp_path, _svc(), _svc(favicon="999", body_hash="changed-every-time")
        )

        assert len(notifications) == 1
        assert notifications[0].citations == (
            "VISUAL_CHANGED: favicon changed on https://example.com/: '111' -> '999'",
        )

    def test_body_only_churn_never_alerts(self, tmp_path: Path) -> None:
        assert (
            _notifications_after_two_cycles(tmp_path, _svc(body_hash="a"), _svc(body_hash="b"))
            == []
        )

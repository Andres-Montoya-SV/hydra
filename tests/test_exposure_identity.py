"""Fase 08 Exposure identity tests."""

from api.exposure_identity import exposure_from_finding, normalize_exposure_location


def test_query_and_fragment_do_not_split_exposure_identity() -> None:
    a = normalize_exposure_location(
        "https://Admin.Example.com:443/login?next=/a#top", "admin.example.com"
    )
    b = normalize_exposure_location("https://admin.example.com/login?next=/b", "admin.example.com")
    assert a == b == "https://admin.example.com/login"


def test_non_default_port_remains_part_of_location_identity() -> None:
    assert (
        normalize_exposure_location("https://admin.example.com:8443/login?x=1", "admin.example.com")
        == "https://admin.example.com:8443/login"
    )


def test_info_finding_is_not_promoted_to_exposure() -> None:
    assert (
        exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "wildcard-dns-detected",
                "severity": "info",
                "name": "Wildcard DNS",
                "source": "wildcard_check",
            },
            asset_id="asset-1",
        )
        is None
    )


def test_security_finding_becomes_deterministic_exposure_draft() -> None:
    draft = exposure_from_finding(
        {
            "host": "admin.example.com",
            "template_id": "exposed-admin-panel",
            "severity": "HIGH",
            "name": "Exposed admin panel",
            "source": "nuclei",
            "url": "https://admin.example.com/login?session=redacted",
            "description": "Administrative interface is Internet reachable",
            "confidence_score": 120,
        },
        asset_id="asset-domain",
    )
    assert draft is not None
    assert draft.asset_id == "asset-domain"
    assert draft.source == "nuclei"
    assert draft.template_id == "exposed-admin-panel"
    assert draft.location == "https://admin.example.com/login"
    assert draft.severity == "high"
    assert draft.confidence_score == 100


def test_malformed_finding_fails_closed() -> None:
    assert exposure_from_finding({}, asset_id="asset-1") is None
    assert (
        exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "x",
                "severity": "high",
                "source": "",
            },
            asset_id="asset-1",
        )
        is None
    )


def test_five_runs_resolution_replay_and_reopening_keep_history(tmp_path):
    from api.asset_identity import ReconciliationDecision
    from api.control_db import ControlDB

    db = ControlDB(tmp_path / "control.db")
    account = db.create_account(email="exposure@example.com")
    org, _ = db.list_organizations_for_account(account)[0]
    db.apply_asset_reconciliation(
        organization_id=org,
        run_id="seed",
        decisions=[
            ReconciliationDecision(
                asset_id="asset",
                asset_type="domain",
                identity_key="domain:example.com",
                is_new=True,
                identifiers=(),
            )
        ],
        observed_at="2026-01-01",
    )
    draft = exposure_from_finding(
        {
            "host": "example.com",
            "template_id": "admin-exposed",
            "severity": "high",
            "source": "fixture",
        },
        asset_id="asset",
    )
    assert draft is not None
    for i in range(1, 7):
        db.create_scan(
            scan_id=f"run-{i}",
            account_id=account,
            organization_id=org,
            domain="example.com",
            db_path=str(tmp_path),
        )
    for i in range(1, 6):
        db.upsert_exposure(
            organization_id=org,
            account_id=account,
            run_id=f"run-{i}",
            finding_id=i,
            draft=draft,
            observed_at=f"2026-01-0{i}",
        )
    rows = db.list_exposures_for_organization(org)
    assert len(rows) == 1
    exposure_id = rows[0].exposure_id
    assert len(db.list_exposure_evidence(exposure_id)) == 5
    assert db.resolve_exposure(
        organization_id=org,
        exposure_id=exposure_id,
        resolved_at="2026-01-06",
        resolution_reason="Owner confirmed remediation",
    )
    # An idempotent replay must never reopen resolved exposures.
    for i in range(1, 6):
        _, created, evidence = db.upsert_exposure(
            organization_id=org,
            account_id=account,
            run_id=f"run-{i}",
            finding_id=i,
            draft=draft,
            observed_at=f"2026-01-0{i}",
        )
        assert not created and not evidence
    assert db.list_exposures_for_organization(org)[0].status == "resolved"
    db.upsert_exposure(
        organization_id=org,
        account_id=account,
        run_id="run-6",
        finding_id=6,
        draft=draft,
        observed_at="2026-01-07",
    )
    reopened = db.list_exposures_for_organization(org)[0]
    assert reopened.exposure_id == exposure_id and reopened.status == "reopened"
    assert reopened.resolution_reason == "Owner confirmed remediation"
    with db._connect() as conn:
        events = conn.execute(
            "SELECT event_type, reason FROM exposure_history "
            "WHERE exposure_id = ? ORDER BY happened_at",
            (exposure_id,),
        ).fetchall()
    assert [row["event_type"] for row in events] == ["observed"] * 5 + ["resolved", "reopened"]
    assert "fixture:admin-exposed" in events[0]["reason"]


def test_exposure_rejects_foreign_run_and_missing_rule(tmp_path):
    from dataclasses import replace

    import pytest

    from api.asset_identity import ReconciliationDecision
    from api.control_db import ControlDB

    db = ControlDB(tmp_path / "control.db")
    account = db.create_account(email="owner@example.com")
    org, _ = db.list_organizations_for_account(account)[0]
    other = db.create_account(email="foreign@example.com")
    other_org, _ = db.list_organizations_for_account(other)[0]
    db.create_scan(
        scan_id="foreign-run",
        account_id=other,
        organization_id=other_org,
        domain="example.com",
        db_path=str(tmp_path),
    )
    db.apply_asset_reconciliation(
        organization_id=org,
        run_id="seed",
        decisions=[
            ReconciliationDecision(
                asset_id="asset",
                asset_type="domain",
                identity_key="domain:example.com",
                is_new=True,
                identifiers=(),
            )
        ],
        observed_at="2026-01-01",
    )
    draft = exposure_from_finding(
        {
            "host": "example.com",
            "template_id": "admin-exposed",
            "severity": "high",
            "source": "fixture",
        },
        asset_id="asset",
    )
    assert draft is not None
    with pytest.raises(ValueError, match="does not belong"):
        db.upsert_exposure(
            organization_id=org, account_id=account, run_id="foreign-run", finding_id=1, draft=draft
        )
    with pytest.raises(ValueError, match="requires a finding"):
        db.upsert_exposure(
            organization_id=org,
            account_id=account,
            run_id="foreign-run",
            finding_id=1,
            draft=replace(draft, template_id=""),
        )
    assert db.list_exposures_for_organization(org) == []

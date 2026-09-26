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
    assert len(db.list_exposure_evidence(org, exposure_id)) == 5
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


def test_exposure_history_and_evidence_are_tenant_scoped(tmp_path):
    from api.asset_identity import ReconciliationDecision
    from api.control_db import ControlDB

    db = ControlDB(tmp_path / "control.db")
    account_a = db.create_account(email="exposure-a@example.com")
    org_a, _ = db.list_organizations_for_account(account_a)[0]
    account_b = db.create_account(email="exposure-b@example.com")
    org_b, _ = db.list_organizations_for_account(account_b)[0]

    db.apply_asset_reconciliation(
        organization_id=org_a,
        run_id="seed-a",
        decisions=[
            ReconciliationDecision(
                asset_id="asset-a",
                asset_type="domain",
                identity_key="domain:example.com",
                is_new=True,
                identifiers=(),
            )
        ],
        observed_at="2026-01-01",
    )
    db.create_scan(
        scan_id="run-a",
        account_id=account_a,
        organization_id=org_a,
        domain="example.com",
        db_path=str(tmp_path),
    )
    draft = exposure_from_finding(
        {
            "host": "example.com",
            "template_id": "admin-exposed",
            "severity": "high",
            "source": "fixture",
        },
        asset_id="asset-a",
    )
    assert draft is not None
    exposure_id, _, _ = db.upsert_exposure(
        organization_id=org_a,
        account_id=account_a,
        run_id="run-a",
        finding_id=1,
        draft=draft,
        observed_at="2026-01-02",
    )

    assert db.get_exposure_for_organization(org_a, exposure_id) is not None
    assert db.get_exposure_for_organization(org_b, exposure_id) is None
    assert len(db.list_exposure_evidence(org_a, exposure_id)) == 1
    assert db.list_exposure_evidence(org_b, exposure_id) == []
    assert len(db.list_exposure_history(org_a, exposure_id)) == 1
    assert db.list_exposure_history(org_b, exposure_id) == []


def test_exposure_inventory_is_bounded_and_filterable(tmp_path):
    from api.asset_identity import ReconciliationDecision
    from api.control_db import ControlDB

    db = ControlDB(tmp_path / "control.db")
    account = db.create_account(email="exposure-list@example.com")
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
    for i, severity in enumerate(("low", "high", "critical"), start=1):
        run_id = f"run-{i}"
        db.create_scan(
            scan_id=run_id,
            account_id=account,
            organization_id=org,
            domain="example.com",
            db_path=str(tmp_path),
        )
        draft = exposure_from_finding(
            {
                "host": "example.com",
                "template_id": f"detector-{i}",
                "severity": severity,
                "source": "fixture",
            },
            asset_id="asset",
        )
        assert draft is not None
        db.upsert_exposure(
            organization_id=org,
            account_id=account,
            run_id=run_id,
            finding_id=i,
            draft=draft,
            observed_at=f"2026-01-0{i + 1}",
        )

    assert len(db.list_exposures_for_organization(org, limit=2)) == 2
    critical = db.list_exposures_for_organization(org, severity="critical")
    assert len(critical) == 1
    assert critical[0].severity == "critical"
    by_asset = db.list_exposures_for_organization(org, asset_id="asset")
    assert len(by_asset) == 3


def test_provider_outcomes_are_durable_and_tenant_scoped(tmp_path):
    from api.control_db import ControlDB

    db = ControlDB(tmp_path / "control.db")
    account = db.create_account(email="provider-ledger@example.com")
    org, _ = db.list_organizations_for_account(account)[0]
    other = db.create_account(email="provider-ledger-other@example.com")
    other_org, _ = db.list_organizations_for_account(other)[0]
    db.create_scan(
        scan_id="run-provider",
        account_id=account,
        organization_id=org,
        domain="example.com",
        db_path=str(tmp_path),
    )

    db.record_provider_run_outcomes(
        organization_id=org,
        account_id=account,
        run_id="run-provider",
        outcomes=[
            ("nuclei", "success_no_results", 0),
            ("httpx", "success_with_results", 4),
            ("whatweb", "blocked_by_scope", 0),
        ],
    )

    rows = db.list_provider_run_outcomes(org, "run-provider")
    assert [(row.provider, row.outcome, row.output_lines) for row in rows] == [
        ("httpx", "success_with_results", 4),
        ("nuclei", "success_no_results", 0),
        ("whatweb", "blocked_by_scope", 0),
    ]
    assert db.list_provider_run_outcomes(other_org, "run-provider") == []


def test_provider_outcome_rejects_foreign_run(tmp_path):
    import pytest

    from api.control_db import ControlDB

    db = ControlDB(tmp_path / "control.db")
    owner = db.create_account(email="provider-owner@example.com")
    owner_org, _ = db.list_organizations_for_account(owner)[0]
    foreign = db.create_account(email="provider-foreign@example.com")
    foreign_org, _ = db.list_organizations_for_account(foreign)[0]
    db.create_scan(
        scan_id="foreign-provider-run",
        account_id=foreign,
        organization_id=foreign_org,
        domain="example.com",
        db_path=str(tmp_path),
    )

    with pytest.raises(ValueError, match="does not belong"):
        db.record_provider_run_outcomes(
            organization_id=owner_org,
            account_id=owner,
            run_id="foreign-provider-run",
            outcomes=[("nuclei", "success_no_results", 0)],
        )


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

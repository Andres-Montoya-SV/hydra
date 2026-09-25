"""Fase 04 (EASM roadmap) — the real, DB-backed half: `evidence`/
`observations` persistence (`api/control_db.py`) and the extended
`api/asset_backfill.py` pass that derives them from real scan history,
built directly on Fase 03's own asset reconciliation.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.control_db import ControlDB
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host, Port
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _run_completed_scan(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
    hosts: list[Host],
) -> str:
    scan_id = secrets.token_hex(16)
    control_db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain=domain,
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
    for host in hosts:
        store.upsert_host(scan_id, host)
    control_db.update_scan_status(scan_id, "completed")
    return scan_id


class TestEvidenceDeduplicationAcrossRepeatedRuns:
    def test_the_same_observation_repeated_across_5_runs_does_not_duplicate_evidence(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        run_ids = []
        for _ in range(5):
            run_ids.append(
                _run_completed_scan(
                    control_db,
                    api_settings,
                    account_id=account_id,
                    organization_id=organization_id,
                    domain="example.com",
                    hosts=[
                        Host(
                            domain="example.com",
                            ports=[
                                Port(host="example.com", port=443, source="naabu", service="https")
                            ],
                        )
                    ],
                )
            )

        summary = backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        # Exactly 2 assets total (the domain + the port), each created
        # once and touched on the other 4 runs (Fase 03's own guarantee).
        assert summary.assets_created == 2
        assert summary.assets_touched == 8

        # 5 domain_resolved + 5 port_open observations = 10 total, one
        # per run per fact — an observation IS expected once per run
        # (that is what gives historial); it is the EVIDENCE that must
        # not be duplicated.
        assert summary.observations_recorded == 10
        assert summary.observations_already_present == 0

        port_asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="port",
            identity_key="port:example.com:443:tcp",
        )
        assert port_asset is not None

        # 5 runs, identical port evidence every time -> exactly ONE
        # evidence row, its last_seen_run_id advancing to the LAST run.
        port_evidence_rows = [
            row for row in _all_evidence_for_asset(control_db, port_asset.asset_id)
        ]
        assert len(port_evidence_rows) == 1
        assert port_evidence_rows[0].last_seen_run_id == run_ids[-1]
        assert port_evidence_rows[0].first_seen_at is not None

    def test_a_changed_fact_on_a_later_run_creates_new_evidence_not_a_duplicate_of_the_old(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[
                Host(
                    domain="example.com",
                    ports=[Port(host="example.com", port=22, source="naabu", service="ssh")],
                )
            ],
        )
        # A later run sees the SAME port but a DIFFERENT detected service
        # (e.g. a service migration) -> genuinely different evidence,
        # correctly NOT deduplicated with the old fact.
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[
                Host(
                    domain="example.com",
                    ports=[Port(host="example.com", port=22, source="naabu", service="sftp-only")],
                )
            ],
        )

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        port_asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="port",
            identity_key="port:example.com:22:tcp",
        )
        assert port_asset is not None
        evidence_rows = _all_evidence_for_asset(control_db, port_asset.asset_id)
        assert len(evidence_rows) == 2
        assert {e.detail for e in evidence_rows} == {"ssh", "sftp-only"}


class TestFullTraceability:
    def test_an_observation_traces_to_its_run_id_and_its_backing_evidence_always(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        scan_id = _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="traced.example.com",
            hosts=[
                Host(
                    domain="traced.example.com",
                    ports=[
                        Port(
                            host="traced.example.com", port=8080, source="naabu", service="http-alt"
                        )
                    ],
                )
            ],
        )

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:traced.example.com",
        )
        assert asset is not None

        # Single query, no manual join against core/store.py's raw
        # tables: every observation for this asset, each already
        # carrying its own run_id and full evidence.
        results = control_db.list_observations_for_asset(asset.asset_id)
        assert len(results) == 1
        traced = results[0]
        assert traced.observation.run_id == scan_id
        assert traced.observation.observation_type == "domain_resolved"
        assert traced.evidence.asset_id == asset.asset_id
        assert traced.evidence.organization_id == organization_id

        # And the port asset (a DIFFERENT asset from the same host) has
        # its own, equally traceable observation.
        port_asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="port",
            identity_key="port:traced.example.com:8080:tcp",
        )
        assert port_asset is not None
        port_results = control_db.list_observations_for_asset(port_asset.asset_id)
        assert len(port_results) == 1
        assert port_results[0].observation.run_id == scan_id
        assert port_results[0].evidence.source == "naabu"
        assert port_results[0].evidence.detail == "http-alt"

    def test_replaying_the_backfill_never_creates_a_duplicate_observation(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        second_summary = backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        assert second_summary.observations_recorded == 0
        assert second_summary.observations_already_present == 1

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        assert asset is not None
        assert len(control_db.list_observations_for_asset(asset.asset_id)) == 1


class TestOrganizationIsolationForObservationsAndEvidence:
    """The same adversarial pattern Fase 03 required, applied here: two
    organizations observing the same shared host must never end up
    sharing an observation or evidence row."""

    def test_two_organizations_observing_the_same_shared_host_never_share_evidence_or_observations(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="consultant@example.com")
        org_a, _role = control_db.list_organizations_for_account(account_id)[0]
        org_b = control_db.create_organization(name="Client B Inc")
        control_db.add_account_organization_role(
            account_id=account_id, organization_id=org_b, role="owner"
        )

        shared_host = Host(
            domain="shared-cdn.example.net",
            ports=[Port(host="shared-cdn.example.net", port=443, source="naabu", service="https")],
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=org_a,
            domain="shared-cdn.example.net",
            hosts=[shared_host],
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=org_b,
            domain="shared-cdn.example.net",
            hosts=[shared_host],
        )

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=org_a
        )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=org_b
        )

        asset_a = control_db.get_asset_by_identity(
            organization_id=org_a, asset_type="domain", identity_key="domain:shared-cdn.example.net"
        )
        asset_b = control_db.get_asset_by_identity(
            organization_id=org_b, asset_type="domain", identity_key="domain:shared-cdn.example.net"
        )
        assert asset_a is not None and asset_b is not None
        assert asset_a.asset_id != asset_b.asset_id

        obs_a = control_db.list_observations_for_asset(asset_a.asset_id)
        obs_b = control_db.list_observations_for_asset(asset_b.asset_id)
        assert len(obs_a) == 1
        assert len(obs_b) == 1
        assert obs_a[0].observation.observation_id != obs_b[0].observation.observation_id
        assert obs_a[0].evidence.evidence_id != obs_b[0].evidence.evidence_id
        assert obs_a[0].observation.organization_id == org_a
        assert obs_b[0].observation.organization_id == org_b


def _all_evidence_for_asset(control_db: ControlDB, asset_id: str):
    """Distinct evidence rows attached to this asset's observations —
    deliberately deduplicated by `evidence_id` here, since
    `list_observations_for_asset` returns one row per OBSERVATION (one
    per run, by design), and several observations legitimately point at
    the SAME evidence row when nothing about the underlying fact
    changed."""
    seen: dict[str, object] = {}
    for o in control_db.list_observations_for_asset(asset_id):
        seen[o.evidence.evidence_id] = o.evidence
    return list(seen.values())

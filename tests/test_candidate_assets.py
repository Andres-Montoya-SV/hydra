"""Fase 06 Candidate Assets — pure identity and DB-backed cross-run projection."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.candidate_assets import candidate_from_indicator_row, normalize_candidate_value
from api.candidate_backfill import backfill_candidate_assets_for_organization
from api.control_db import ControlDB
from api.settings import APISettings
from api.tenancy import account_db_path
from core.intel.model import (
    CollectionStatus,
    CollectReason,
    Indicator,
    IndicatorKind,
    ScopeStatus,
)
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _completed_indicator_scan(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    indicator: Indicator,
) -> str:
    scan_id = secrets.token_hex(16)
    control_db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain="example.com",
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))

    class Snapshot:
        entities: dict = {}
        observations: list = []
        evidence: dict = {}
        relationships: dict = {}
        indicators = [indicator]
        hypotheses: list = []
        collection_attempts: list = []

    store.persist_registry(scan_id, {}, intel=Snapshot())
    control_db.update_scan_status(scan_id, "completed")
    return scan_id


def _indicator(
    value: str,
    *,
    kind: IndicatorKind = IndicatorKind.DOMAIN,
    scope: ScopeStatus = ScopeStatus.IN_SCOPE,
    status: CollectionStatus = CollectionStatus.ELIGIBLE,
    evidence_id: str = "opaque-lineage",
) -> Indicator:
    return Indicator(
        indicator_id=f"indicator-{secrets.token_hex(4)}",
        kind=kind,
        value=value,
        normalized_value=value.lower().rstrip("."),
        depth=1,
        parent_id=None,
        reason=CollectReason.CERTIFICATE_SAN,
        scope_status=scope,
        collection_status=status,
        evidence_id=evidence_id,
        priority=50,
        authorization_status="ALLOW" if scope is ScopeStatus.IN_SCOPE else "DENY",
        collector="test",
    )


class TestCandidateNormalization:
    def test_domain_is_case_and_trailing_dot_stable(self) -> None:
        assert normalize_candidate_value("DOMAIN", "API.Example.COM.") == "api.example.com"

    def test_ip_is_canonical(self) -> None:
        assert normalize_candidate_value("IP", "2001:0db8::1") == "2001:db8::1"

    def test_certificate_requires_real_sha256_fingerprint(self) -> None:
        assert normalize_candidate_value("CERTIFICATE", "AA:" * 31 + "AA") == "aa" * 32
        assert normalize_candidate_value("CERTIFICATE", "not-a-fingerprint") == ""

    def test_url_uses_hydras_canonical_http_url(self) -> None:
        assert (
            normalize_candidate_value("URL", "HTTPS://Example.COM:443/Admin/#fragment")
            == "https://example.com/Admin"
        )

    def test_unknown_scope_never_defaults_to_authorized(self) -> None:
        draft = candidate_from_indicator_row(
            {"kind": "DOMAIN", "value": "x.example.com", "scope_status": "UNKNOWN"}
        )
        assert draft is not None
        assert draft.scope_status == "UNKNOWN"
        assert draft.authorization_status == "DENY"


class TestCandidateBackfill:
    def test_same_candidate_across_runs_is_one_cross_run_row(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="candidate-owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        for _ in range(3):
            _completed_indicator_scan(
                control_db,
                api_settings,
                account_id=account_id,
                organization_id=organization_id,
                indicator=_indicator("API.Example.com."),
            )

        summary = backfill_candidate_assets_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )
        rows = control_db.list_candidate_assets_for_organization(organization_id)
        assert summary.candidates_created == 1
        assert summary.candidates_touched == 2
        assert len(rows) == 1
        assert rows[0].normalized_value == "api.example.com"

    def test_replaying_backfill_is_idempotent(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="candidate-replay@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _completed_indicator_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            indicator=_indicator("new.example.com"),
        )
        backfill_candidate_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        backfill_candidate_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        assert len(control_db.list_candidate_assets_for_organization(organization_id)) == 1

    def test_same_candidate_in_two_organizations_never_shares_identity(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_a = control_db.create_account(email="candidate-a@example.com")
        account_b = control_db.create_account(email="candidate-b@example.com")
        org_a, _ = control_db.list_organizations_for_account(account_a)[0]
        org_b, _ = control_db.list_organizations_for_account(account_b)[0]
        for account_id, organization_id in ((account_a, org_a), (account_b, org_b)):
            _completed_indicator_scan(
                control_db,
                api_settings,
                account_id=account_id,
                organization_id=organization_id,
                indicator=_indicator("shared.example.net"),
            )
            backfill_candidate_assets_for_organization(
                control_db=control_db,
                api_settings=api_settings,
                organization_id=organization_id,
            )
        row_a = control_db.list_candidate_assets_for_organization(org_a)[0]
        row_b = control_db.list_candidate_assets_for_organization(org_b)[0]
        assert row_a.candidate_asset_id != row_b.candidate_asset_id
        assert row_a.normalized_value == row_b.normalized_value

    def test_out_of_scope_candidate_is_persisted_without_becoming_authorized_or_asset(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="candidate-oos@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _completed_indicator_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            indicator=_indicator(
                "external.example.net",
                scope=ScopeStatus.OUT_OF_SCOPE,
                status=CollectionStatus.NOT_ALLOWED,
            ),
        )
        backfill_candidate_assets_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )
        candidate = control_db.list_candidate_assets_for_organization(organization_id)[0]
        assert candidate.scope_status == "OUT_OF_SCOPE"
        assert candidate.collection_status == "NOT_ALLOWED"
        assert candidate.authorization_status == "DENY"
        assert control_db.list_assets_for_organization(organization_id) == []

    def test_lineage_reference_is_preserved_as_opaque_text(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="candidate-lineage@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _completed_indicator_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            indicator=_indicator("lineage.example.com", evidence_id="could-be-observation-id"),
        )
        backfill_candidate_assets_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )
        candidate = control_db.list_candidate_assets_for_organization(organization_id)[0]
        assert candidate.lineage_reference == "could-be-observation-id"

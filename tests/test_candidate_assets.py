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

    def test_in_scope_without_explicit_authorization_still_fails_closed(self) -> None:
        draft = candidate_from_indicator_row(
            {"kind": "DOMAIN", "value": "inside.example.com", "scope_status": "IN_SCOPE"}
        )
        assert draft is not None
        assert draft.scope_status == "IN_SCOPE"
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


def _seed_candidate(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str = "candidate.example.com",
    reason: str = "shared certificate SAN",
) -> str:
    indicator = _indicator(domain)
    indicator = Indicator(**{**indicator.__dict__, "reason": CollectReason.CERTIFICATE_SAN})
    _completed_indicator_scan(
        control_db,
        api_settings,
        account_id=account_id,
        organization_id=organization_id,
        indicator=indicator,
    )
    backfill_candidate_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
    return control_db.list_candidate_assets_for_organization(organization_id)[0].candidate_asset_id


class TestPromotionRequiresOwnerRole:
    def test_a_viewer_cannot_promote(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner@example.com")
        viewer_account = control_db.create_account(email="viewer@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        control_db.add_account_organization_role(
            account_id=viewer_account, organization_id=organization_id, role="viewer"
        )
        candidate_id = _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )

        with pytest.raises(PermissionError):
            control_db.promote_candidate_asset(
                organization_id=organization_id,
                candidate_asset_id=candidate_id,
                account_id=viewer_account,
                justification="attempted by a viewer",
            )

    def test_an_outsider_with_no_role_at_all_cannot_promote(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner2@example.com")
        outsider_account = control_db.create_account(email="outsider@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        candidate_id = _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )

        with pytest.raises(PermissionError):
            control_db.promote_candidate_asset(
                organization_id=organization_id,
                candidate_asset_id=candidate_id,
                account_id=outsider_account,
                justification="attempted by an outsider",
            )

    def test_an_owner_can_promote(self, control_db: ControlDB, api_settings: APISettings) -> None:
        owner_account = control_db.create_account(email="owner3@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        candidate_id = _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )

        asset_id = control_db.promote_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_id,
            account_id=owner_account,
            justification="confirmed this is our own infrastructure",
        )
        asset = control_db.get_asset(organization_id, asset_id)
        assert asset is not None
        assert asset.asset_type == "domain"
        assert asset.identity_key == "domain:candidate.example.com"


class TestPromotionIsAudited:
    def test_promotion_records_who_when_and_why(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner4@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        candidate_id = _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )

        control_db.promote_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_id,
            account_id=owner_account,
            justification="verified via a phone call with the infra team",
        )

        reviews = control_db.list_candidate_asset_reviews(organization_id, candidate_id)
        assert len(reviews) == 1
        assert reviews[0].action == "promoted"
        assert reviews[0].account_id == owner_account
        assert reviews[0].justification == "verified via a phone call with the infra team"
        assert reviews[0].resulting_asset_id is not None
        assert reviews[0].created_at

        candidate = control_db.get_candidate_asset(organization_id, candidate_id)
        assert candidate.review_status == "promoted"
        assert candidate.promoted_asset_id == reviews[0].resulting_asset_id

    def test_discard_is_also_audited(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner5@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        candidate_id = _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )

        control_db.discard_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_id,
            account_id=owner_account,
            justification="unrelated third-party infrastructure",
        )

        reviews = control_db.list_candidate_asset_reviews(organization_id, candidate_id)
        assert len(reviews) == 1
        assert reviews[0].action == "discarded"
        assert reviews[0].account_id == owner_account
        assert reviews[0].justification == "unrelated third-party infrastructure"
        assert reviews[0].resulting_asset_id is None

        candidate = control_db.get_candidate_asset(organization_id, candidate_id)
        assert candidate.review_status == "discarded"
        assert candidate.discarded_signal_hash is not None

    def test_an_already_promoted_candidate_cannot_be_discarded_or_repromoted(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner6@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        candidate_id = _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )
        control_db.promote_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_id,
            account_id=owner_account,
            justification="first promotion",
        )

        with pytest.raises(ValueError):
            control_db.promote_candidate_asset(
                organization_id=organization_id,
                candidate_asset_id=candidate_id,
                account_id=owner_account,
                justification="second promotion attempt",
            )
        with pytest.raises(ValueError):
            control_db.discard_candidate_asset(
                organization_id=organization_id,
                candidate_asset_id=candidate_id,
                account_id=owner_account,
                justification="trying to discard after promoting",
            )


class TestDiscardedCandidateDoesNotReappearWithoutANewSignal:
    def test_the_exact_same_signal_observed_again_stays_discarded(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner7@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        candidate_id = _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )
        control_db.discard_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_id,
            account_id=owner_account,
            justification="not ours",
        )

        # A later cycle re-observes the EXACT same candidate again (same
        # domain, same reason, same scope/collection/authorization
        # status) — the discard must stand, silently, with no new review
        # row created.
        _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )

        candidate = control_db.get_candidate_asset(organization_id, candidate_id)
        assert candidate.review_status == "discarded"
        reviews = control_db.list_candidate_asset_reviews(organization_id, candidate_id)
        assert [r.action for r in reviews] == ["discarded"]

    def test_a_genuinely_different_signal_reopens_it_for_review(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner8@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        candidate_id = _seed_candidate(
            control_db, api_settings, account_id=owner_account, organization_id=organization_id
        )
        control_db.discard_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_id,
            account_id=owner_account,
            justification="looked unrelated at the time",
        )

        # A later cycle observes the SAME domain but now IN a materially
        # different scope/authorization state (e.g. scope classification
        # genuinely changed) — this is real, new information a human has
        # not judged yet, so it must reopen for review automatically.
        different_signal_indicator = _indicator(
            "candidate.example.com",
            scope=ScopeStatus.OUT_OF_SCOPE,
            status=CollectionStatus.NOT_ALLOWED,
        )
        _completed_indicator_scan(
            control_db,
            api_settings,
            account_id=owner_account,
            organization_id=organization_id,
            indicator=different_signal_indicator,
        )
        backfill_candidate_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        candidate = control_db.get_candidate_asset(organization_id, candidate_id)
        assert candidate.review_status == "pending"
        assert candidate.discarded_signal_hash is None
        reviews = control_db.list_candidate_asset_reviews(organization_id, candidate_id)
        assert [r.action for r in reviews] == ["discarded", "reopened"]
        assert reviews[1].account_id is None  # system-detected, not a human action


class TestCandidateNeverFeedsActiveScanningWithoutPromotion:
    """The phase's own required adversarial test: a candidate — promoted
    or not — must never be reachable through any query that feeds Speed 2
    (active scanning), because promotion creates ONLY an `assets` identity
    row, never a `monitored_domains`/`domain_verifications` row. Scanning
    authorization is, and remains, an entirely separate decision."""

    def test_an_unpromoted_candidate_never_appears_in_any_scan_authorization_query(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner9@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        _seed_candidate(
            control_db,
            api_settings,
            account_id=owner_account,
            organization_id=organization_id,
            domain="never-authorized.example.com",
        )

        # The real scan-authorization gate (`_require_verified_domain_or_403`
        # in api/routers/scans.py) checks exactly this list.
        verified = control_db.get_verified_domains_for_account(owner_account)
        assert verified == []

        # Speed 2's real due-list (api/monitoring_worker.py) reads only
        # from monitored_domains — a candidate can never appear there.
        due = control_db.list_due_active_monitoring_page(
            due_before="2099-01-01T00:00:00+00:00", cursor=None, limit=100
        )
        assert due == []

    def test_promoting_a_candidate_still_never_grants_scan_authorization(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        owner_account = control_db.create_account(email="owner10@example.com")
        organization_id, _ = control_db.list_organizations_for_account(owner_account)[0]
        candidate_id = _seed_candidate(
            control_db,
            api_settings,
            account_id=owner_account,
            organization_id=organization_id,
            domain="promoted-but-not-authorized.example.com",
        )

        control_db.promote_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_id,
            account_id=owner_account,
            justification="confirmed ownership out of band",
        )

        # Promotion created a real Asset (identity only) ...
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:promoted-but-not-authorized.example.com",
        )
        assert asset is not None

        # ... but STILL grants no scan authorization whatsoever. Only a
        # real POST /domains/{domain}/verify (domain_verifications) can.
        verified = control_db.get_verified_domains_for_account(owner_account)
        assert verified == []
        due = control_db.list_due_active_monitoring_page(
            due_before="2099-01-01T00:00:00+00:00", cursor=None, limit=100
        )
        assert due == []

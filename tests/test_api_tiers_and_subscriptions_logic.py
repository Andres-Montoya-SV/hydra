"""`api/tiers.py` / `api/subscriptions.py` — pure-function tests, no
database or network I/O. Full HTTP end-to-end behavior (the gate
actually blocking a request, the webhook actually activating a tier) is
covered in tests/test_api_subscription_endpoints.py; this file is
everything around the decision logic itself.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.control_db import ControlDB
from api.subscriptions import (
    AdversarialDecision,
    apply_tier_change,
    check_llm_budget,
    check_report_options,
    check_scan_quota,
    check_verified_domain_limit,
    current_period_key,
    effective_limits,
    get_or_create_subscription,
    next_tier_with_bigger_scan_quota,
    resolve_adversarial_provider,
)
from api.tiers import DEFAULT_ULTRA_RETENTION_DAYS, TIERS, retention_days_for, tier_limits


class TestTierTable:
    def test_free_has_no_llm_features_at_all(self) -> None:
        free = TIERS["free"]
        assert free.reportability is None
        assert free.hypotheses is None

    def test_free_has_exactly_the_tasks_documented_limits(self) -> None:
        free = TIERS["free"]
        assert free.scans_per_month == 1
        assert free.max_concurrent_verified_domains == 1
        assert free.report_formats == frozenset({"markdown"})
        assert free.report_languages == frozenset({"es"})
        assert free.retention_days == 7

    def test_medium_has_reportability_but_auto_degrades_adversarial(self) -> None:
        medium = TIERS["medium"]
        assert medium.reportability is not None
        assert medium.reportability.adversarial == "auto_degrade"
        assert medium.hypotheses is None

    def test_pro_and_ultra_have_full_cross_validation_available(self) -> None:
        assert TIERS["pro"].reportability.adversarial == "available"  # type: ignore[union-attr]
        assert TIERS["pro"].hypotheses.adversarial == "available"  # type: ignore[union-attr]
        assert TIERS["ultra"].reportability.adversarial == "available"  # type: ignore[union-attr]

    def test_only_ultra_has_white_label(self) -> None:
        assert not TIERS["free"].white_label_report
        assert not TIERS["medium"].white_label_report
        assert not TIERS["pro"].white_label_report
        assert TIERS["ultra"].white_label_report

    def test_ultra_has_no_hard_concurrent_domain_limit(self) -> None:
        assert TIERS["ultra"].max_concurrent_verified_domains is None

    def test_tier_limits_rejects_unknown_tier(self) -> None:
        with pytest.raises(ValueError):
            tier_limits("platinum")


class TestRetentionResolution:
    def test_fixed_tier_retention_ignores_any_override(self) -> None:
        assert retention_days_for(TIERS["medium"], retention_days_override=999) == 90

    def test_ultra_uses_override_when_set(self) -> None:
        assert retention_days_for(TIERS["ultra"], retention_days_override=42) == 42

    def test_ultra_falls_back_to_default_when_no_override_set(self) -> None:
        assert (
            retention_days_for(TIERS["ultra"], retention_days_override=None)
            == DEFAULT_ULTRA_RETENTION_DAYS
        )


class TestCurrentPeriodKey:
    def test_format_is_year_dash_month(self) -> None:
        assert current_period_key(datetime(2026, 3, 5, tzinfo=timezone.utc)) == "2026-03"

    def test_pads_single_digit_months(self) -> None:
        assert current_period_key(datetime(2026, 1, 1, tzinfo=timezone.utc)) == "2026-01"


class TestNextTierWithBiggerScanQuota:
    def test_free_upgrades_to_medium(self) -> None:
        assert next_tier_with_bigger_scan_quota("free") == "medium"

    def test_ultra_has_no_further_upgrade(self) -> None:
        assert next_tier_with_bigger_scan_quota("ultra") is None


class TestAdversarialResolution:
    def test_no_adversarial_requested_is_a_no_op(self) -> None:
        decision = resolve_adversarial_provider(TIERS["pro"].reportability, None)  # type: ignore[arg-type]
        assert decision == AdversarialDecision(used_adversarial_provider=None, degraded=False)

    def test_pro_gets_the_adversarial_provider_it_asked_for(self) -> None:
        decision = resolve_adversarial_provider(TIERS["pro"].reportability, "openai")  # type: ignore[arg-type]
        assert decision.used_adversarial_provider == "openai"
        assert decision.degraded is False

    def test_medium_silently_but_visibly_degrades_to_single_provider(self) -> None:
        """The task's own decision point (Task 5, test 4): Medium
        requesting cross-validation gets auto-degraded, not rejected —
        but `degraded` must always be True so the caller can surface it,
        never silently pretend nothing was requested."""
        decision = resolve_adversarial_provider(TIERS["medium"].reportability, "openai")  # type: ignore[arg-type]
        assert decision.used_adversarial_provider is None
        assert decision.degraded is True


@pytest.fixture
def control_db(tmp_path) -> ControlDB:
    return ControlDB(tmp_path / "control.db")


@pytest.fixture
def account_id(control_db: ControlDB) -> str:
    account_id = control_db.create_account()
    control_db.create_default_subscription(account_id, tier="free")
    return account_id


class TestGetOrCreateSubscription:
    def test_creates_a_free_default_when_none_exists(self, control_db: ControlDB) -> None:
        account_id = control_db.create_account()  # no subscription row inserted on purpose
        subscription = get_or_create_subscription(control_db, account_id)
        assert subscription.tier == "free"
        assert subscription.status == "active"

    def test_returns_the_existing_row_when_one_exists(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        control_db.set_tier(account_id, "pro")
        subscription = get_or_create_subscription(control_db, account_id)
        assert subscription.tier == "pro"


class TestScanQuota:
    def test_within_quota_is_ok(self, control_db: ControlDB, account_id: str) -> None:
        limits = effective_limits(get_or_create_subscription(control_db, account_id))
        ok, reason = check_scan_quota(control_db, account_id, limits)
        assert ok is True
        assert reason is None

    def test_at_quota_is_rejected_with_an_upgrade_suggestion(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        limits = effective_limits(get_or_create_subscription(control_db, account_id))
        control_db.increment_scan_usage(account_id, current_period_key())  # free = 1/month
        ok, reason = check_scan_quota(control_db, account_id, limits)
        assert ok is False
        assert reason is not None
        assert "medium" in reason.lower()

    def test_ultra_at_its_fair_use_ceiling_has_no_upgrade_suggestion(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        control_db.set_tier(account_id, "ultra")
        limits = effective_limits(get_or_create_subscription(control_db, account_id))
        for _ in range(limits.scans_per_month):
            control_db.increment_scan_usage(account_id, current_period_key())
        ok, reason = check_scan_quota(control_db, account_id, limits)
        assert ok is False
        assert "highest tier" in reason.lower()  # type: ignore[union-attr]


class TestVerifiedDomainLimit:
    def test_within_limit_is_ok(self, control_db: ControlDB, account_id: str) -> None:
        limits = effective_limits(get_or_create_subscription(control_db, account_id))
        ok, _ = check_verified_domain_limit(control_db, account_id, limits)
        assert ok is True

    def _verify(self, control_db: ControlDB, account_id: str, domain: str) -> None:
        record = control_db.create_domain_verification(
            account_id=account_id, domain=domain, token="tok"  # noqa: S106
        )
        now = datetime.now(timezone.utc)
        control_db.mark_verification_succeeded(
            record.verification_id,
            method="dns_txt",
            verified_at=now.isoformat(),
            expires_at=(now + timedelta(days=90)).isoformat(),
        )

    def test_at_limit_rejects_a_new_domain(self, control_db: ControlDB, account_id: str) -> None:
        limits = effective_limits(get_or_create_subscription(control_db, account_id))
        self._verify(control_db, account_id, "example.com")  # free's limit is 1
        ok, reason = check_verified_domain_limit(control_db, account_id, limits)
        assert ok is False
        assert "verified domain" in reason.lower()  # type: ignore[union-attr]

    def test_renewing_the_same_domain_is_never_blocked_by_its_own_slot(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        limits = effective_limits(get_or_create_subscription(control_db, account_id))
        self._verify(control_db, account_id, "example.com")
        ok, _ = check_verified_domain_limit(
            control_db, account_id, limits, renewing_domain="example.com"
        )
        assert ok is True

    def test_ultra_has_no_limit_to_hit(self, control_db: ControlDB, account_id: str) -> None:
        control_db.set_tier(account_id, "ultra")
        limits = effective_limits(get_or_create_subscription(control_db, account_id))
        for i in range(20):
            self._verify(control_db, account_id, f"example{i}.com")
        ok, _ = check_verified_domain_limit(control_db, account_id, limits)
        assert ok is True


class TestReportOptions:
    def test_free_cannot_get_docx(self) -> None:
        ok, reason = check_report_options(
            TIERS["free"], report_format="docx", language="es", white_label=False
        )
        assert ok is False
        assert "docx" in reason  # type: ignore[operator]

    def test_free_cannot_get_english(self) -> None:
        ok, _ = check_report_options(
            TIERS["free"], report_format="markdown", language="en", white_label=False
        )
        assert ok is False

    def test_pro_cannot_get_white_label(self) -> None:
        ok, reason = check_report_options(
            TIERS["pro"], report_format="markdown", language="en", white_label=True
        )
        assert ok is False
        assert "ultra" in reason.lower()  # type: ignore[union-attr]

    def test_ultra_gets_everything(self) -> None:
        ok, _ = check_report_options(
            TIERS["ultra"], report_format="docx", language="en", white_label=True
        )
        assert ok is True


class TestLlmBudget:
    def test_first_call_within_ceiling_is_ok(self, control_db: ControlDB, account_id: str) -> None:
        control_db.set_tier(account_id, "medium")
        ok, _ = check_llm_budget(
            control_db,
            account_id,
            feature="reportability",
            feature_limits=TIERS["medium"].reportability,  # type: ignore[arg-type]
            additional_cost_usd=5.0,
        )
        assert ok is True

    def test_a_call_that_would_exceed_the_ceiling_is_rejected(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        control_db.set_tier(account_id, "medium")
        control_db.add_llm_spend(
            account_id, current_period_key(), feature="reportability", amount_usd=9.0
        )
        ok, reason = check_llm_budget(
            control_db,
            account_id,
            feature="reportability",
            feature_limits=TIERS["medium"].reportability,  # type: ignore[arg-type]
            additional_cost_usd=5.0,
        )
        assert ok is False
        assert "budget" in reason.lower()  # type: ignore[union-attr]


class TestTierChange:
    def test_upgrade_applies_immediately_and_reports_no_excess(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        result = apply_tier_change(control_db, account_id, "pro")
        assert result.previous_tier == "free"
        assert result.new_tier == "pro"
        assert result.exceeds_domain_limit is False
        assert result.exceeds_scan_limit is False
        assert get_or_create_subscription(control_db, account_id).tier == "pro"

    def test_downgrade_reports_excess_domains_without_revoking_them(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        control_db.set_tier(account_id, "pro")  # allows 10 concurrent domains
        for i in range(4):
            record = control_db.create_domain_verification(
                account_id=account_id, domain=f"site{i}.example", token="t"  # noqa: S106
            )
            now = datetime.now(timezone.utc)
            control_db.mark_verification_succeeded(
                record.verification_id,
                method="dns_txt",
                verified_at=now.isoformat(),
                expires_at=(now + timedelta(days=90)).isoformat(),
            )

        result = apply_tier_change(control_db, account_id, "free")  # free allows only 1
        assert result.exceeds_domain_limit is True
        assert result.verified_domains_count == 4
        assert result.verified_domains_limit == 1
        # Nothing was revoked — all 4 are still active verifications.
        assert len(control_db.get_verified_domains_for_account(account_id)) == 4

    def test_downgrade_reports_excess_scans_without_resetting_the_counter(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        control_db.set_tier(account_id, "pro")  # allows 50/month
        for _ in range(5):
            control_db.increment_scan_usage(account_id, current_period_key())

        result = apply_tier_change(control_db, account_id, "free")  # free allows only 1/month
        assert result.exceeds_scan_limit is True
        assert result.scans_used_this_period == 5
        assert result.scans_limit == 1

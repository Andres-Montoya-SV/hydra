"""Pure-function tests for `api/monitoring.py` — the two-speed
continuous-monitoring model's decision logic, exercised without a
database, an event loop, or a running pipeline (the same split
`tests/test_api_domain_verification_logic.py` and
`tests/test_api_tiers_and_subscriptions_logic.py` already established
for their own modules).
"""

from __future__ import annotations

from api.monitoring import (
    MonitoringRunOutcome,
    classify_asset_jump,
    compute_asset_digest,
    passive_monitoring_plugin_names,
    passive_monitoring_settings_overrides,
    significance_rank,
)


class TestComputeAssetDigest:
    def test_same_set_different_order_produces_the_same_digest(self) -> None:
        assert compute_asset_digest(["b.example.com", "a.example.com"]) == compute_asset_digest(
            ["a.example.com", "b.example.com"]
        )

    def test_a_changed_set_produces_a_different_digest(self) -> None:
        digest_a = compute_asset_digest(["a.example.com", "b.example.com"])
        digest_b = compute_asset_digest(["a.example.com", "c.example.com"])
        assert digest_a != digest_b

    def test_empty_list_is_stable_and_distinct_from_a_nonempty_one(self) -> None:
        assert compute_asset_digest([]) == compute_asset_digest([])
        assert compute_asset_digest([]) != compute_asset_digest(["a.example.com"])


class TestClassifyAssetJump:
    def test_first_ever_run_is_never_flagged_even_if_already_huge(self) -> None:
        result = classify_asset_jump(
            previous_count=None, new_count=50_000, ceiling=5_000, wildcard_dns_detected=False
        )
        assert result.needs_review is False

    def test_growth_within_the_ceiling_is_never_flagged(self) -> None:
        result = classify_asset_jump(
            previous_count=100, new_count=4_999, ceiling=5_000, wildcard_dns_detected=False
        )
        assert result.needs_review is False

    def test_a_jump_past_the_ceiling_with_no_wildcard_explanation_is_flagged(self) -> None:
        result = classify_asset_jump(
            previous_count=100, new_count=50_000, ceiling=5_000, wildcard_dns_detected=False
        )
        assert result.needs_review is True
        assert "50000" in result.reason  # type: ignore[operator]

    def test_a_jump_past_the_ceiling_explained_by_wildcard_dns_is_not_flagged(self) -> None:
        result = classify_asset_jump(
            previous_count=100, new_count=50_000, ceiling=5_000, wildcard_dns_detected=True
        )
        assert result.needs_review is False
        assert result.reason is None


class TestPassiveMonitoringPluginNames:
    def test_only_genuinely_non_active_plugins_are_included(self) -> None:
        names = passive_monitoring_plugin_names()
        # Known genuinely-passive-source modules (active_collection is
        # False, either the base-class default or explicitly set).
        for expected in ("subfinder", "amass", "assetfinder", "ctlogs", "theharvester"):
            assert expected in names
        # Known active/target-touching modules must never leak in.
        for excluded in ("nuclei", "ffuf", "katana", "httpx", "dnsx", "naabu"):
            assert excluded not in names


class TestPassiveMonitoringSettingsOverrides:
    def test_turns_off_an_enabled_active_tool(self) -> None:
        overrides = passive_monitoring_settings_overrides(
            {"enable_nuclei": True, "enable_subfinder": True}
        )
        assert overrides == {"enable_nuclei": False}

    def test_never_turns_anything_on(self) -> None:
        overrides = passive_monitoring_settings_overrides({"enable_amass": False})
        assert overrides == {}

    def test_already_disabled_active_tools_produce_no_override(self) -> None:
        overrides = passive_monitoring_settings_overrides({"enable_ffuf": False})
        assert overrides == {}

    def test_non_enable_keys_are_ignored(self) -> None:
        overrides = passive_monitoring_settings_overrides({"strict_opsec": True})
        assert overrides == {}


class TestSignificanceRank:
    def _outcome(self, **kwargs) -> MonitoringRunOutcome:
        defaults = dict(
            monitoring_id="m1",
            account_id="a1",
            domain="example.com",
            speed="passive",
            scan_id="s1",
            hosts_added=[],
            hosts_removed=[],
            asset_count=10,
            asset_digest="d",
            needs_review=False,
            review_reason=None,
        )
        defaults.update(kwargs)
        return MonitoringRunOutcome(**defaults)

    def test_needs_review_always_sorts_before_new_hosts(self) -> None:
        review = self._outcome(domain="z-review.example.com", needs_review=True)
        growth = self._outcome(domain="a-growth.example.com", hosts_added=["new.example.com"])
        ordered = sorted([growth, review], key=significance_rank)
        assert ordered[0] is review

    def test_new_hosts_sorts_before_removed_hosts(self) -> None:
        growth = self._outcome(domain="a.example.com", hosts_added=["new.example.com"])
        shrink = self._outcome(domain="b.example.com", hosts_removed=["gone.example.com"])
        ordered = sorted([shrink, growth], key=significance_rank)
        assert ordered[0] is growth

    def test_same_rank_breaks_tie_by_domain_name_for_stable_output(self) -> None:
        one = self._outcome(domain="b.example.com", hosts_added=["x"])
        two = self._outcome(domain="a.example.com", hosts_added=["y"])
        ordered = sorted([one, two], key=significance_rank)
        assert [o.domain for o in ordered] == ["a.example.com", "b.example.com"]

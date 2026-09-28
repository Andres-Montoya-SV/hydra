"""Fase 21 (EASM roadmap) — pure tests for `core/risk_scoring.py`."""

from __future__ import annotations

from core.risk_scoring import (
    DAYS_OPEN_ESCALATION_THRESHOLD,
    RiskFactors,
    RiskLevel,
    classify_exposure_risk,
)


def _factors(**overrides: object) -> RiskFactors:
    base = dict(
        severity="medium",
        domain_verified=True,
        days_open=1,
        related_to_critical_asset=False,
        related_critical_asset_reason=None,
    )
    base.update(overrides)
    return RiskFactors(**base)  # type: ignore[arg-type]


class TestBaseSeverityMapping:
    def test_each_severity_maps_to_its_own_base_level(self) -> None:
        assert classify_exposure_risk(_factors(severity="low")).level == RiskLevel.LOW
        assert classify_exposure_risk(_factors(severity="medium")).level == RiskLevel.MEDIUM
        assert classify_exposure_risk(_factors(severity="high")).level == RiskLevel.HIGH
        assert classify_exposure_risk(_factors(severity="critical")).level == RiskLevel.CRITICAL


class TestExplanationIsAlwaysPresent:
    def test_every_classification_cites_concrete_reasons_not_just_the_label(self) -> None:
        result = classify_exposure_risk(_factors(severity="high"))
        assert len(result.reasons) >= 2
        assert any("severity" in r for r in result.reasons)

    def test_escalation_reasons_cite_the_concrete_trigger(self) -> None:
        result = classify_exposure_risk(
            _factors(severity="medium", days_open=DAYS_OPEN_ESCALATION_THRESHOLD)
        )
        assert result.level == RiskLevel.HIGH
        assert any(str(DAYS_OPEN_ESCALATION_THRESHOLD) in r for r in result.reasons)


class TestDaysOpenEscalation:
    def test_below_threshold_never_escalates(self) -> None:
        result = classify_exposure_risk(
            _factors(severity="low", days_open=DAYS_OPEN_ESCALATION_THRESHOLD - 1)
        )
        assert result.level == RiskLevel.LOW

    def test_at_threshold_escalates_exactly_one_level(self) -> None:
        result = classify_exposure_risk(
            _factors(severity="low", days_open=DAYS_OPEN_ESCALATION_THRESHOLD)
        )
        assert result.level == RiskLevel.MEDIUM

    def test_escalation_never_exceeds_critical(self) -> None:
        result = classify_exposure_risk(
            _factors(severity="critical", days_open=DAYS_OPEN_ESCALATION_THRESHOLD)
        )
        assert result.level == RiskLevel.CRITICAL


class TestRelatedToCriticalAssetEscalation:
    def test_relation_to_a_critical_asset_escalates_one_level(self) -> None:
        result = classify_exposure_risk(_factors(severity="low", related_to_critical_asset=True))
        assert result.level == RiskLevel.MEDIUM

    def test_both_escalation_triggers_stack(self) -> None:
        result = classify_exposure_risk(
            _factors(
                severity="low",
                days_open=DAYS_OPEN_ESCALATION_THRESHOLD,
                related_to_critical_asset=True,
            )
        )
        assert result.level == RiskLevel.HIGH


class TestDeterminism:
    def test_identical_factors_always_produce_identical_classification(self) -> None:
        factors = _factors(severity="high", days_open=45, related_to_critical_asset=True)
        first = classify_exposure_risk(factors)
        second = classify_exposure_risk(factors)
        assert first == second

    def test_unverified_scope_never_itself_escalates_or_deescalates(self) -> None:
        """Scope confirmation is informational (cited in the reasons),
        never a silent multiplier on the score -- an unconfirmed-scope
        candidate's exposure is exactly as real as a confirmed one; the
        phase only asks that the distinction be citable, not that it
        change the number."""
        verified = classify_exposure_risk(_factors(severity="medium", domain_verified=True))
        unverified = classify_exposure_risk(_factors(severity="medium", domain_verified=False))
        assert verified.level == unverified.level == RiskLevel.MEDIUM

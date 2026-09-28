"""Fase 17 (EASM roadmap) — pure tests for
`core/confidence_composition.py`.
"""

from __future__ import annotations

from core.confidence_composition import SourceObservation, compose_confidence


class TestCorrelatedSourcesNeverDoubleCount:
    def test_httpx_and_whatweb_agreeing_never_exceeds_the_stronger_ones_own_confidence(
        self,
    ) -> None:
        result = compose_confidence(
            [SourceObservation("httpx", 90), SourceObservation("whatweb", 85)]
        )
        assert result.score == 90
        assert result.contributing_sources == ("httpx",)

    def test_three_correlated_sources_agreeing_still_count_as_one_cluster(self) -> None:
        result = compose_confidence(
            [
                SourceObservation("httpx", 80),
                SourceObservation("whatweb", 75),
                SourceObservation("security_headers", 70),
            ]
        )
        assert result.score == 80
        assert len(result.contributing_sources) == 1


class TestIndependentSourcesCombine:
    def test_two_independent_sources_raise_confidence_beyond_either_alone(self) -> None:
        result = compose_confidence(
            [SourceObservation("ctlogs", 70), SourceObservation("httpx", 80)]
        )
        assert result.score > 80
        assert set(result.contributing_sources) == {"ctlogs", "httpx"}

    def test_deterministic_regardless_of_input_order(self) -> None:
        a = compose_confidence([SourceObservation("ctlogs", 70), SourceObservation("httpx", 80)])
        b = compose_confidence([SourceObservation("httpx", 80), SourceObservation("ctlogs", 70)])
        assert a == b

    def test_never_exceeds_100(self) -> None:
        result = compose_confidence(
            [
                SourceObservation("ctlogs", 99),
                SourceObservation("httpx", 99),
                SourceObservation("dnsx", 99),
            ]
        )
        assert result.score <= 100


class TestEdgeCases:
    def test_no_observations_returns_zero(self) -> None:
        result = compose_confidence([])
        assert result.score == 0
        assert result.contributing_sources == ()

    def test_a_single_observation_returns_its_own_confidence(self) -> None:
        result = compose_confidence([SourceObservation("dnsx", 65)])
        assert result.score == 65
        assert result.contributing_sources == ("dnsx",)

    def test_reason_is_never_empty(self) -> None:
        result = compose_confidence([SourceObservation("dnsx", 65)])
        assert result.reason.strip() != ""

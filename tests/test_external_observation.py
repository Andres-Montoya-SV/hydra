"""Fase 10 (EASM roadmap) — pure precedence/confidence-class logic
(`api/external_observation.py`). No database, no clock: fixed
`PrecedenceCandidate` fixtures, exact expected winners.
"""

from __future__ import annotations

from api.external_observation import (
    CONFIDENCE_CLASS_RANK,
    ObservationConfidenceClass,
    PrecedenceCandidate,
    reconcile_precedence,
)


class TestPrecedenceNeverLetsAnOldThirdPartyBeatANewerDirectObservation:
    def test_direct_current_wins_even_when_older_than_third_party(self) -> None:
        direct_but_old = PrecedenceCandidate(
            evidence_id="hydra-1",
            confidence_class=ObservationConfidenceClass.DIRECT_CURRENT,
            last_seen_at="2020-01-01T00:00:00+00:00",
        )
        third_party_but_new = PrecedenceCandidate(
            evidence_id="import-1",
            confidence_class=ObservationConfidenceClass.THIRD_PARTY_CURRENT,
            last_seen_at="2026-01-01T00:00:00+00:00",
        )
        winner = reconcile_precedence([direct_but_old, third_party_but_new])
        assert winner is direct_but_old

    def test_historical_never_beats_direct_current_regardless_of_recency(self) -> None:
        historical_but_new = PrecedenceCandidate(
            evidence_id="historical-1",
            confidence_class=ObservationConfidenceClass.HISTORICAL,
            last_seen_at="2026-06-01T00:00:00+00:00",
        )
        direct_but_old = PrecedenceCandidate(
            evidence_id="hydra-2",
            confidence_class=ObservationConfidenceClass.DIRECT_CURRENT,
            last_seen_at="2021-01-01T00:00:00+00:00",
        )
        assert reconcile_precedence([historical_but_new, direct_but_old]) is direct_but_old

    def test_customer_supplied_outranks_third_party_but_not_direct(self) -> None:
        customer = PrecedenceCandidate(
            evidence_id="customer-1",
            confidence_class=ObservationConfidenceClass.CUSTOMER_SUPPLIED,
            last_seen_at="2026-01-01T00:00:00+00:00",
        )
        third_party = PrecedenceCandidate(
            evidence_id="third-party-1",
            confidence_class=ObservationConfidenceClass.THIRD_PARTY_CURRENT,
            last_seen_at="2026-06-01T00:00:00+00:00",
        )
        assert reconcile_precedence([customer, third_party]) is customer

        direct = PrecedenceCandidate(
            evidence_id="direct-1",
            confidence_class=ObservationConfidenceClass.DIRECT_CURRENT,
            last_seen_at="2020-01-01T00:00:00+00:00",
        )
        assert reconcile_precedence([customer, direct]) is direct


class TestPrecedenceTieBreaking:
    def test_same_class_breaks_tie_by_recency(self) -> None:
        older = PrecedenceCandidate(
            evidence_id="e1",
            confidence_class=ObservationConfidenceClass.THIRD_PARTY_CURRENT,
            last_seen_at="2026-01-01T00:00:00+00:00",
        )
        newer = PrecedenceCandidate(
            evidence_id="e2",
            confidence_class=ObservationConfidenceClass.THIRD_PARTY_CURRENT,
            last_seen_at="2026-06-01T00:00:00+00:00",
        )
        assert reconcile_precedence([older, newer]) is newer

    def test_fully_identical_candidates_are_still_deterministic(self) -> None:
        a = PrecedenceCandidate(
            evidence_id="a",
            confidence_class=ObservationConfidenceClass.DIRECT_CURRENT,
            last_seen_at="2026-01-01T00:00:00+00:00",
        )
        b = PrecedenceCandidate(
            evidence_id="b",
            confidence_class=ObservationConfidenceClass.DIRECT_CURRENT,
            last_seen_at="2026-01-01T00:00:00+00:00",
        )
        first = reconcile_precedence([a, b])
        second = reconcile_precedence([b, a])
        assert first is second is b  # "b" > "a" lexically — stable regardless of input order

    def test_empty_input_returns_none(self) -> None:
        assert reconcile_precedence([]) is None

    def test_a_single_candidate_always_wins(self) -> None:
        only = PrecedenceCandidate(
            evidence_id="solo",
            confidence_class=ObservationConfidenceClass.HISTORICAL,
            last_seen_at="2020-01-01T00:00:00+00:00",
        )
        assert reconcile_precedence([only]) is only


class TestConfidenceClassRankCoversEveryClass:
    def test_every_enum_member_has_a_rank(self) -> None:
        for member in ObservationConfidenceClass:
            assert member in CONFIDENCE_CLASS_RANK

    def test_ranks_are_all_distinct(self) -> None:
        assert len(set(CONFIDENCE_CLASS_RANK.values())) == len(CONFIDENCE_CLASS_RANK)

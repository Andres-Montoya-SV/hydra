"""Fase 05 (EASM roadmap) — pure asset-lifecycle state machine
(`api/change_detection.py`). No database, no clock, no LLM: every test
is a fixed sequence of `RunObservationOutcome`s and an exact expected
`ChangeEvent` sequence — the "fixtures as the living spec" the phase's
own prompt asks for.
"""

from __future__ import annotations

from api.change_detection import (
    DEFAULT_MISSED_RUN_THRESHOLD,
    AssetLifecycleState,
    RunObservationOutcome,
    compute_asset_state_transitions,
    host_for_asset,
    observation_digest,
)

DIGEST_A = observation_digest([("domain_resolved", "dnsx", "", 80)])
DIGEST_B = observation_digest(
    [("domain_resolved", "dnsx", "", 80), ("port_open", "naabu", "https", 50)]
)


class TestEachOfTheFiveTransitions:
    def test_new_the_first_ever_observation(self) -> None:
        events = compute_asset_state_transitions(
            run_outcomes=[
                RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A)
            ]
        )
        assert [e.new_state for e in events] == [AssetLifecycleState.NEW]
        assert events[0].previous_state is None

    def test_unchanged_same_digest_produces_no_event(self) -> None:
        events = compute_asset_state_transitions(
            run_outcomes=[
                RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A),
                RunObservationOutcome(run_id="r2", observed=True, observation_digest=DIGEST_A),
            ]
        )
        # Only the NEW event from r1 — r2 changes nothing observable.
        assert [e.run_id for e in events] == ["r1"]

    def test_changed_a_different_digest_on_a_later_run(self) -> None:
        events = compute_asset_state_transitions(
            run_outcomes=[
                RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A),
                RunObservationOutcome(run_id="r2", observed=True, observation_digest=DIGEST_B),
            ]
        )
        assert [e.new_state for e in events] == [
            AssetLifecycleState.NEW,
            AssetLifecycleState.CHANGED,
        ]
        assert events[1].previous_digest == DIGEST_A
        assert events[1].new_digest == DIGEST_B

    def test_disappeared_after_the_threshold_of_consecutive_misses(self) -> None:
        events = compute_asset_state_transitions(
            run_outcomes=[
                RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A),
                RunObservationOutcome(run_id="r2", observed=False),
                RunObservationOutcome(run_id="r3", observed=False),
            ],
            missed_run_threshold=2,
        )
        assert [e.new_state for e in events] == [
            AssetLifecycleState.NEW,
            AssetLifecycleState.DISAPPEARED,
        ]
        assert events[1].run_id == "r3"

    def test_reappeared_after_being_disappeared(self) -> None:
        events = compute_asset_state_transitions(
            run_outcomes=[
                RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A),
                RunObservationOutcome(run_id="r2", observed=False),
                RunObservationOutcome(run_id="r3", observed=False),
                RunObservationOutcome(run_id="r4", observed=True, observation_digest=DIGEST_A),
            ],
            missed_run_threshold=2,
        )
        assert [e.new_state for e in events] == [
            AssetLifecycleState.NEW,
            AssetLifecycleState.DISAPPEARED,
            AssetLifecycleState.REAPPEARED,
        ]
        assert events[2].run_id == "r4"

    def test_reappeared_settles_back_to_unchanged_on_the_very_next_matching_observation(
        self,
    ) -> None:
        events = compute_asset_state_transitions(
            run_outcomes=[
                RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A),
                RunObservationOutcome(run_id="r2", observed=False),
                RunObservationOutcome(run_id="r3", observed=False),
                RunObservationOutcome(run_id="r4", observed=True, observation_digest=DIGEST_A),
                RunObservationOutcome(run_id="r5", observed=True, observation_digest=DIGEST_A),
            ],
            missed_run_threshold=2,
        )
        assert [e.new_state for e in events] == [
            AssetLifecycleState.NEW,
            AssetLifecycleState.DISAPPEARED,
            AssetLifecycleState.REAPPEARED,
        ]
        # r5 (same digest as r4) produces no event — REAPPEARED was a
        # one-run marker, not an ongoing status.


class TestFailToleranceNeverFalselyDeclaresDisappeared:
    def test_a_single_missed_run_never_marks_a_still_existing_asset_disappeared(self) -> None:
        events = compute_asset_state_transitions(
            run_outcomes=[
                RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A),
                RunObservationOutcome(run_id="r2", observed=False),  # a single timeout/failure
                RunObservationOutcome(run_id="r3", observed=True, observation_digest=DIGEST_A),
            ]
        )
        assert AssetLifecycleState.DISAPPEARED not in [e.new_state for e in events]
        # Only the initial NEW — r2's tolerated miss and r3's identical
        # re-observation produce no events at all.
        assert [e.new_state for e in events] == [AssetLifecycleState.NEW]

    def test_recovering_after_a_tolerated_miss_leaves_no_inconsistent_state(self) -> None:
        """A tolerated single miss must not leave any lingering
        "half-missed" state that a later, unrelated single miss could
        combine with to wrongly cross the threshold."""
        events = compute_asset_state_transitions(
            run_outcomes=[
                RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A),
                RunObservationOutcome(run_id="r2", observed=False),  # miss #1, tolerated
                RunObservationOutcome(
                    run_id="r3", observed=True, observation_digest=DIGEST_A
                ),  # recovers
                RunObservationOutcome(run_id="r4", observed=False),  # miss #1 again (counter reset)
            ],
            missed_run_threshold=2,
        )
        # A second, later single miss (r4) must NOT be treated as the
        # second of an old pair with r2 — the counter reset on r3's
        # successful observation.
        assert AssetLifecycleState.DISAPPEARED not in [e.new_state for e in events]

    def test_default_threshold_is_two_consecutive_misses(self) -> None:
        assert DEFAULT_MISSED_RUN_THRESHOLD == 2


class TestDeterminism:
    def test_running_the_engine_twice_on_the_same_input_produces_identical_output(self) -> None:
        outcomes = [
            RunObservationOutcome(run_id="r1", observed=True, observation_digest=DIGEST_A),
            RunObservationOutcome(run_id="r2", observed=False),
            RunObservationOutcome(run_id="r3", observed=False),
            RunObservationOutcome(run_id="r4", observed=True, observation_digest=DIGEST_B),
        ]
        first = compute_asset_state_transitions(run_outcomes=outcomes)
        second = compute_asset_state_transitions(run_outcomes=outcomes)
        assert first == second

    def test_observation_digest_is_order_independent(self) -> None:
        facts_forward = [("port_open", "naabu", "https", 50), ("domain_resolved", "dnsx", "", 80)]
        facts_backward = list(reversed(facts_forward))
        assert observation_digest(facts_forward) == observation_digest(facts_backward)

    def test_observation_digest_differs_for_genuinely_different_facts(self) -> None:
        assert observation_digest([("port_open", "naabu", "https", 50)]) != observation_digest(
            [("port_open", "naabu", "http", 50)]
        )


class TestHostForAsset:
    def test_domain_asset(self) -> None:
        assert (
            host_for_asset(asset_type="domain", identity_key="domain:example.com") == "example.com"
        )

    def test_port_asset(self) -> None:
        assert (
            host_for_asset(asset_type="port", identity_key="port:example.com:443:tcp")
            == "example.com"
        )

    def test_dns_record_asset_with_a_colon_containing_ipv6_value(self) -> None:
        assert (
            host_for_asset(
                asset_type="dns_record", identity_key="dns_record:example.com:AAAA:2001:db8::1"
            )
            == "example.com"
        )

    def test_url_asset(self) -> None:
        assert (
            host_for_asset(asset_type="url", identity_key="url:https://example.com/admin")
            == "example.com"
        )

    def test_unknown_asset_type_raises_rather_than_guessing(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            host_for_asset(asset_type="mystery", identity_key="mystery:whatever")

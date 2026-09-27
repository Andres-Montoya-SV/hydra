"""Fase 14 (EASM roadmap) — pure classifier tests for
`api/technology_events.py`.
"""

from __future__ import annotations

from api.technology_events import TechnologyEventType, classify_technology_transition


class TestClassifyTechnologyTransition:
    def test_no_previous_snapshot_reports_everything_as_added(self) -> None:
        events = classify_technology_transition(
            previous=None, current={"nginx": "1.24.0", "WordPress": None}
        )
        assert {e.event_type for e in events} == {TechnologyEventType.ADDED}
        assert {e.technology_name for e in events} == {"nginx", "WordPress"}

    def test_identical_snapshots_produce_no_events(self) -> None:
        snapshot = {"nginx": "1.24.0"}
        assert classify_technology_transition(previous=snapshot, current=snapshot) == []

    def test_a_new_technology_is_added(self) -> None:
        events = classify_technology_transition(
            previous={"nginx": "1.24.0"}, current={"nginx": "1.24.0", "WordPress": None}
        )
        assert len(events) == 1
        assert events[0].event_type == TechnologyEventType.ADDED
        assert events[0].technology_name == "WordPress"

    def test_a_disappeared_technology_is_removed(self) -> None:
        events = classify_technology_transition(
            previous={"nginx": "1.24.0", "WordPress": None}, current={"nginx": "1.24.0"}
        )
        assert len(events) == 1
        assert events[0].event_type == TechnologyEventType.REMOVED
        assert events[0].technology_name == "WordPress"

    def test_a_version_bump_is_version_changed(self) -> None:
        events = classify_technology_transition(
            previous={"nginx": "1.24.0"}, current={"nginx": "1.26.0"}
        )
        assert len(events) == 1
        assert events[0].event_type == TechnologyEventType.VERSION_CHANGED
        assert "1.24.0" in events[0].reason and "1.26.0" in events[0].reason

    def test_unversioned_to_versioned_is_reported_as_a_version_change(self) -> None:
        events = classify_technology_transition(
            previous={"nginx": None}, current={"nginx": "1.26.0"}
        )
        assert [e.event_type for e in events] == [TechnologyEventType.VERSION_CHANGED]

    def test_simultaneous_add_remove_and_version_change_all_reported(self) -> None:
        previous = {"nginx": "1.24.0", "WordPress": None, "jQuery": "3.6.0"}
        current = {"nginx": "1.26.0", "React": None, "jQuery": "3.6.0"}
        events = classify_technology_transition(previous=previous, current=current)
        by_type = {e.event_type: e.technology_name for e in events}
        assert by_type[TechnologyEventType.ADDED] == "React"
        assert by_type[TechnologyEventType.REMOVED] == "WordPress"
        assert by_type[TechnologyEventType.VERSION_CHANGED] == "nginx"
        assert len(events) == 3  # jQuery unchanged -- no event for it

    def test_every_event_cites_a_concrete_reason(self) -> None:
        events = classify_technology_transition(
            previous={"nginx": "1.24.0"}, current={"nginx": "1.26.0"}
        )
        for event in events:
            assert event.reason.strip() != ""

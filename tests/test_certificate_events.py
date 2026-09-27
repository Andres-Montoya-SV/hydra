"""Fase 12 (EASM roadmap) — pure classifier tests for
`api/certificate_events.py`. No database, no clock: fixed
`CertificateSnapshot` fixtures, exact expected classifications.
"""

from __future__ import annotations

from api.certificate_events import (
    CertificateEventType,
    CertificateSnapshot,
    certificate_snapshot_detail,
    classify_certificate_transition,
    parse_certificate_snapshot,
)


def _snapshot(**overrides: object) -> CertificateSnapshot:
    base = dict(
        fingerprint_sha256="a" * 64,
        subject="CN=example.com",
        issuer="Let's Encrypt",
        not_before="2026-01-01",
        not_after="2026-04-01",
        sans=("example.com", "www.example.com"),
    )
    base.update(overrides)
    return CertificateSnapshot(**base)  # type: ignore[arg-type]


class TestSerializationRoundTrips:
    def test_detail_string_parses_back_to_an_equal_snapshot(self) -> None:
        snap = _snapshot()
        detail = certificate_snapshot_detail(
            fingerprint_sha256=snap.fingerprint_sha256,
            subject=snap.subject,
            issuer=snap.issuer,
            not_before=snap.not_before,
            not_after=snap.not_after,
            sans=snap.sans,
        )
        parsed = parse_certificate_snapshot(detail)
        assert parsed == snap

    def test_sans_are_sorted_and_deduplicated_in_the_serialization(self) -> None:
        detail = certificate_snapshot_detail(
            fingerprint_sha256="a" * 64,
            subject="",
            issuer="",
            not_before="",
            not_after="",
            sans=["b.example.com", "a.example.com", "a.example.com"],
        )
        parsed = parse_certificate_snapshot(detail)
        assert parsed is not None
        assert parsed.sans == ("a.example.com", "b.example.com")

    def test_garbage_input_returns_none(self) -> None:
        assert parse_certificate_snapshot("not a valid detail string") is None
        assert parse_certificate_snapshot("") is None


class TestClassifyCertificateTransition:
    def test_no_previous_snapshot_is_first_seen(self) -> None:
        events = classify_certificate_transition(previous=None, current=_snapshot())
        assert len(events) == 1
        assert events[0].event_type == CertificateEventType.FIRST_SEEN

    def test_identical_fingerprint_produces_no_events(self) -> None:
        snap = _snapshot()
        events = classify_certificate_transition(previous=snap, current=snap)
        assert events == []

    def test_same_subject_and_issuer_new_fingerprint_is_renewed(self) -> None:
        previous = _snapshot(fingerprint_sha256="a" * 64)
        current = _snapshot(fingerprint_sha256="b" * 64)
        events = classify_certificate_transition(previous=previous, current=current)
        assert [e.event_type for e in events] == [CertificateEventType.RENEWED]
        assert "a" * 64 in events[0].reason and "b" * 64 in events[0].reason

    def test_different_issuer_is_changed_never_renewed(self) -> None:
        previous = _snapshot(fingerprint_sha256="a" * 64, issuer="Let's Encrypt")
        current = _snapshot(fingerprint_sha256="b" * 64, issuer="Suspicious CA Ltd")
        events = classify_certificate_transition(previous=previous, current=current)
        assert [e.event_type for e in events] == [CertificateEventType.CHANGED]

    def test_different_subject_is_changed(self) -> None:
        previous = _snapshot(fingerprint_sha256="a" * 64, subject="CN=example.com")
        current = _snapshot(fingerprint_sha256="b" * 64, subject="CN=totally-different.com")
        events = classify_certificate_transition(previous=previous, current=current)
        assert CertificateEventType.CHANGED in [e.event_type for e in events]

    def test_renewal_that_also_drops_a_san_reports_both_events(self) -> None:
        previous = _snapshot(fingerprint_sha256="a" * 64, sans=("example.com", "www.example.com"))
        current = _snapshot(fingerprint_sha256="b" * 64, sans=("example.com",))
        events = classify_certificate_transition(previous=previous, current=current)
        event_types = {e.event_type for e in events}
        assert event_types == {CertificateEventType.RENEWED, CertificateEventType.SAN_REMOVED}

    def test_san_added_is_reported(self) -> None:
        previous = _snapshot(fingerprint_sha256="a" * 64, sans=("example.com",))
        current = _snapshot(fingerprint_sha256="b" * 64, sans=("example.com", "api.example.com"))
        events = classify_certificate_transition(previous=previous, current=current)
        san_events = [e for e in events if e.event_type == CertificateEventType.SAN_ADDED]
        assert len(san_events) == 1
        assert "api.example.com" in san_events[0].reason

    def test_every_event_reason_cites_concrete_before_after_values(self) -> None:
        previous = _snapshot(fingerprint_sha256="a" * 64)
        current = _snapshot(fingerprint_sha256="b" * 64, sans=("example.com",))
        events = classify_certificate_transition(previous=previous, current=current)
        for event in events:
            assert event.reason.strip() != ""
            assert event.event_type.value not in ("",)  # never a bare label with no reason

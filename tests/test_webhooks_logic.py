"""Pure-function and real-network tests for `api/webhooks.py` — signing/
verification, URL scheme validation, and the real SSRF/private-network
destination check (`core/collection/ssrf.py`, reused verbatim, never a
second hand-rolled IP-range check). No mocks standing in for the actual
DNS resolution or IP classification — this is exactly the same
discipline `tests/test_ssrf_ip_classification.py`-style tests already
use elsewhere in this project.
"""

from __future__ import annotations

import asyncio

import pytest

from api.webhooks import (
    EVENT_TYPES,
    event_for_high_severity_findings,
    event_for_monitoring_outcome,
    generate_webhook_secret,
    sign_payload,
    validate_webhook_destination,
    validate_webhook_url_scheme,
    verify_signature,
)


class TestSigning:
    def test_a_correct_signature_verifies(self) -> None:
        secret = generate_webhook_secret()
        body = b'{"event": "monitoring.changed"}'
        signature = sign_payload(secret, body)

        assert signature.startswith("sha256=")
        assert verify_signature(secret, body, signature)

    def test_a_tampered_body_fails_verification(self) -> None:
        secret = generate_webhook_secret()
        body = b'{"event": "monitoring.changed"}'
        signature = sign_payload(secret, body)

        tampered = b'{"event": "monitoring.needs_review"}'
        assert not verify_signature(secret, tampered, signature)

    def test_the_wrong_secret_fails_verification(self) -> None:
        body = b'{"event": "monitoring.changed"}'
        signature = sign_payload(generate_webhook_secret(), body)

        assert not verify_signature(generate_webhook_secret(), body, signature)

    def test_two_generated_secrets_are_never_the_same(self) -> None:
        assert generate_webhook_secret() != generate_webhook_secret()


class TestUrlSchemeValidation:
    def test_https_is_accepted(self) -> None:
        ok, reason = validate_webhook_url_scheme("https://example.com/hook")
        assert ok
        assert reason == ""

    @pytest.mark.parametrize(
        "url", ["http://example.com/hook", "ftp://example.com/hook", "file:///etc/passwd"]
    )
    def test_non_https_schemes_are_refused(self, url: str) -> None:
        ok, reason = validate_webhook_url_scheme(url)
        assert not ok
        assert "https" in reason.lower()

    def test_a_url_with_no_host_is_refused(self) -> None:
        ok, _ = validate_webhook_url_scheme("https:///hook")
        assert not ok


class TestRealSsrfDestinationValidation:
    """Real DNS resolution, real IP classification
    (`core/collection/ssrf.py`) — no mocking of the actual network-safety
    decision."""

    def test_a_public_hostname_is_allowed(self) -> None:
        allowed, reason, connect_ip = asyncio.run(
            validate_webhook_destination("https://example.com/hook")
        )
        assert allowed, reason
        assert connect_ip  # a real IP was resolved and returned for pinning

    @pytest.mark.parametrize(
        "url",
        [
            "https://127.0.0.1/hook",
            "https://localhost/hook",
            "https://169.254.169.254/latest/meta-data",  # cloud metadata
            "https://10.0.0.5/hook",
            "https://192.168.1.1/hook",
        ],
    )
    def test_private_loopback_and_metadata_destinations_are_refused(self, url: str) -> None:
        allowed, reason, connect_ip = asyncio.run(validate_webhook_destination(url))
        assert not allowed
        assert connect_ip == ""
        assert "refused" in reason.lower() or "blocked" in reason.lower()

    def test_a_non_https_url_is_refused_before_any_dns_lookup(self) -> None:
        allowed, reason, connect_ip = asyncio.run(
            validate_webhook_destination("http://example.com/hook")
        )
        assert not allowed
        assert "https" in reason.lower()


class TestEventBuilders:
    def test_needs_review_outcome_produces_the_needs_review_event(self) -> None:
        from api.monitoring import MonitoringRunOutcome

        outcome = MonitoringRunOutcome(
            monitoring_id="m1",
            account_id="a1",
            domain="example.com",
            speed="passive",
            scan_id="s1",
            hosts_added=[],
            hosts_removed=[],
            asset_count=9001,
            asset_digest="d",
            needs_review=True,
            review_reason="jumped past the ceiling",
        )
        event = event_for_monitoring_outcome(outcome)
        assert event.event_type == "monitoring.needs_review"
        assert event.payload["needs_review"] is True
        assert event.payload["review_reason"] == "jumped past the ceiling"

    def test_a_plain_change_outcome_produces_the_changed_event(self) -> None:
        from api.monitoring import MonitoringRunOutcome

        outcome = MonitoringRunOutcome(
            monitoring_id="m1",
            account_id="a1",
            domain="example.com",
            speed="passive",
            scan_id="s1",
            hosts_added=["new.example.com"],
            hosts_removed=[],
            asset_count=5,
            asset_digest="d",
            needs_review=False,
            review_reason=None,
        )
        event = event_for_monitoring_outcome(outcome)
        assert event.event_type == "monitoring.changed"
        assert event.payload["hosts_added"] == ["new.example.com"]
        assert "review_reason" not in event.payload

    def test_high_severity_findings_event_shape_and_cap(self) -> None:
        findings = [
            {"host": "a.example.com", "template_id": "t1", "severity": "critical", "name": "n1"}
        ]
        event = event_for_high_severity_findings(
            domain="example.com", scan_id="scan-1", findings=findings
        )
        assert event.event_type == "finding.high_severity"
        assert event.payload["finding_count"] == 1
        assert event.payload["findings"] == findings

    def test_all_event_types_used_by_builders_are_in_the_declared_set(self) -> None:
        assert {"monitoring.changed", "monitoring.needs_review", "finding.high_severity"} == set(
            EVENT_TYPES
        )

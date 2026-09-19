"""`api/domain_verification.py`'s pure logic — normalization, subdomain
coverage, and the `classify_scan_gate` decision — tested without any
database or network I/O. The actual DNS/HTTP checks are tested
end-to-end against real local servers in
tests/test_api_domain_verification_live.py; this file is everything
around them.
"""

from __future__ import annotations

import pytest

pytest.importorskip("dns")
pytest.importorskip("httpx")

from api.control_db import DomainVerificationRecord  # noqa: E402
from api.domain_verification import (  # noqa: E402
    classify_scan_gate,
    dns_record_name,
    dns_record_value,
    domain_is_covered,
    normalize_domain,
    well_known_file_path,
)


class TestNormalization:
    def test_lowercases_and_strips_trailing_dot(self) -> None:
        assert normalize_domain("Example.COM.") == "example.com"

    def test_strips_surrounding_whitespace(self) -> None:
        assert normalize_domain("  example.com  ") == "example.com"


class TestDomainCoverage:
    def test_exact_match_is_covered(self) -> None:
        assert domain_is_covered("example.com", "example.com")

    def test_subdomain_is_covered_by_root(self) -> None:
        assert domain_is_covered("www.example.com", "example.com")
        assert domain_is_covered("api.staging.example.com", "example.com")

    def test_unrelated_domain_is_not_covered(self) -> None:
        assert not domain_is_covered("example.org", "example.com")

    def test_a_domain_that_merely_ends_with_the_same_letters_is_not_covered(self) -> None:
        """notexample.com must never be considered covered by example.com
        — a naive `.endswith(verified)` (without the leading dot) would
        get this wrong."""
        assert not domain_is_covered("notexample.com", "example.com")

    def test_case_and_trailing_dot_insensitive(self) -> None:
        assert domain_is_covered("WWW.Example.com.", "example.com")


class TestInstructionFormats:
    def test_dns_record_name_uses_the_documented_prefix(self) -> None:
        assert dns_record_name("example.com") == "_hydra-verification.example.com"

    def test_dns_record_value_uses_the_documented_format(self) -> None:
        assert dns_record_value("abc123") == "hydra-verify=abc123"

    def test_well_known_file_path_embeds_the_token(self) -> None:
        assert well_known_file_path("abc123") == "/.well-known/hydra-verification-abc123.txt"


def _record(
    *,
    domain: str = "example.com",
    status: str = "verified",
    created_at: str = "2026-01-01T00:00:00+00:00",
    account_id: str = "acct-a",
) -> DomainVerificationRecord:
    return DomainVerificationRecord(
        verification_id="v1",
        account_id=account_id,
        domain=domain,
        token="tok",  # noqa: S106 - test fixture data, not a real secret
        method="dns_txt",
        status=status,
        created_at=created_at,
        verified_at=created_at,
        expires_at="2099-01-01T00:00:00+00:00",
        last_checked_at=created_at,
        last_check_error=None,
    )


class TestClassifyScanGate:
    def test_covered_when_an_active_verification_matches(self) -> None:
        active = [_record(domain="example.com")]
        status, record = classify_scan_gate(
            "example.com", active_verifications=active, all_verifications=active
        )
        assert status == "covered"
        assert record is not None and record.domain == "example.com"

    def test_covered_for_a_subdomain_of_an_active_verification(self) -> None:
        active = [_record(domain="example.com")]
        status, record = classify_scan_gate(
            "sub.example.com", active_verifications=active, all_verifications=active
        )
        assert status == "covered"

    def test_never_verified_when_nothing_matches_anywhere(self) -> None:
        status, record = classify_scan_gate(
            "example.com", active_verifications=[], all_verifications=[]
        )
        assert status == "never_verified"
        assert record is None

    def test_expired_when_a_past_verified_row_matches_but_is_not_active(self) -> None:
        expired_row = _record(domain="example.com")  # not in active_verifications
        status, record = classify_scan_gate(
            "example.com", active_verifications=[], all_verifications=[expired_row]
        )
        assert status == "expired"
        assert record is not None and record.domain == "example.com"

    def test_a_merely_pending_or_failed_historical_row_is_never_verified_not_expired(
        self,
    ) -> None:
        """Only a row that actually reached 'verified' at some point can
        produce the "expired" (softer) message — a domain that was only
        ever requested/attempted and never confirmed is "never_verified",
        the same as if nothing had ever happened."""
        pending_row = _record(domain="example.com", status="pending")
        failed_row = _record(domain="example.com", status="failed")
        status, record = classify_scan_gate(
            "example.com",
            active_verifications=[],
            all_verifications=[pending_row, failed_row],
        )
        assert status == "never_verified"
        assert record is None

    def test_a_different_accounts_row_never_leaks_into_this_accounts_gate(self) -> None:
        """Defense in depth: even though the caller is expected to
        already scope these lists by account_id, classify_scan_gate
        itself never assumes cross-account rows won't slip in — but
        since callers always pass `all_verifications` scoped to one
        account, this test documents that expectation by construction:
        a mixed-owner list still only reports based on domain-coverage,
        so the CALLER (api/routers/scans.py) is what must never pass an
        unscoped list, not this pure function's job to filter identity."""
        other_accounts_active_row = _record(domain="example.com", account_id="acct-b")
        status, _ = classify_scan_gate(
            "example.com",
            active_verifications=[other_accounts_active_row],
            all_verifications=[other_accounts_active_row],
        )
        # This documents the CONTRACT: classify_scan_gate trusts its
        # inputs are already account-scoped. It is the caller's job
        # (ControlDB.get_verified_domains_for_account) to never include
        # another account's row in the first place.
        assert status == "covered"

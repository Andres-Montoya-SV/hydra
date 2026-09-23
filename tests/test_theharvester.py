"""`modules/theharvester.py` — the email/personnel OSINT plugin.

`tests/fixtures/theharvester_real_output.jsonl` is the REAL, unmodified
JSONL captured from an actual `uv run theHarvester -d example.com
-b crtsh,rapiddns -f out` run during this task's own development — real
confirmation of the `type`/`value`/`sources` record shape, and of the
"summary" first line. It has no `email`/`person` records (a placeholder
domain has none to find), so this module's hard organization-boundary
filter is exercised with a realistic, schema-accurate synthetic fixture
instead — clearly labeled as such below, never presented as the real
capture.
"""

from __future__ import annotations

import json
from pathlib import Path

from modules.theharvester import _email_domain_matches, _record_to_finding

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _real_fixture_lines() -> list[dict]:
    with open(FIXTURES_DIR / "theharvester_real_output.jsonl", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class TestAgainstTheRealCapturedFixture:
    def test_the_summary_line_is_never_treated_as_a_finding(self) -> None:
        records = _real_fixture_lines()
        summary = records[0]
        assert summary["type"] == "summary"
        assert _record_to_finding(summary, "example.com") is None

    def test_real_hostname_records_are_never_kept_even_though_the_tool_mixes_types(self) -> None:
        """The hard boundary: this plugin only ever reads `email`/
        `person` — every other real `type` (`hostname` here, confirmed
        live) is invisible, even though theHarvester's own JSONL mixes
        every type into one stream."""
        records = _real_fixture_lines()
        hostname_records = [r for r in records if r.get("type") == "hostname"]
        assert len(hostname_records) == 2  # confirms the fixture itself is what it claims to be
        for record in hostname_records:
            assert _record_to_finding(record, "example.com") is None


class TestOrganizationBoundaryFilter:
    """Synthetic, schema-accurate records — theHarvester's own
    `type`/`value`/`sources` shape (confirmed real above), with values
    chosen to exercise the domain-match boundary that example.com's own
    real run had nothing to test."""

    def test_a_real_work_email_is_kept(self) -> None:
        record = {"type": "email", "value": "julia@example.com", "sources": ["duckduckgo"]}
        finding = _record_to_finding(record, "example.com")
        assert finding is not None
        assert finding["type"] == "email"
        assert finding["value"] == "julia@example.com"

    def test_a_personal_off_domain_email_is_dropped(self) -> None:
        """The hard boundary this task required: an email mentioned on
        some indexed page about the org, but not AT the org, is never
        organization-associated evidence."""
        record = {"type": "email", "value": "julia@gmail.com", "sources": ["duckduckgo"]}
        assert _record_to_finding(record, "example.com") is None

    def test_a_subdomain_work_email_is_kept(self) -> None:
        record = {"type": "email", "value": "support@mail.example.com", "sources": ["yahoo"]}
        finding = _record_to_finding(record, "example.com")
        assert finding is not None

    def test_a_lookalike_domain_email_is_dropped(self) -> None:
        """`example.com.evil.example` ends with "example.com" as a
        SUBSTRING but is not a real subdomain of it — must be rejected,
        not string-matched."""
        record = {"type": "email", "value": "attacker@example.com.evil.example", "sources": []}
        assert _record_to_finding(record, "example.com") is None

    def test_a_person_name_is_kept_and_tagged_to_the_target_domain(self) -> None:
        record = {"type": "person", "value": "Julia Smith", "sources": ["duckduckgo"]}
        finding = _record_to_finding(record, "example.com")
        assert finding is not None
        assert finding["type"] == "person"
        assert finding["host"] == "example.com"

    def test_an_empty_value_is_never_kept(self) -> None:
        assert (
            _record_to_finding({"type": "email", "value": "", "sources": []}, "example.com") is None
        )

    def test_unhandled_types_are_always_dropped(self) -> None:
        for record_type in ("hostname", "ip", "asn", "url", "breach", "shodan-host"):
            record = {"type": record_type, "value": "something", "sources": []}
            assert _record_to_finding(record, "example.com") is None


class TestEmailDomainMatchesHelper:
    def test_exact_domain_match(self) -> None:
        assert _email_domain_matches("a@example.com", "example.com") is True

    def test_subdomain_match(self) -> None:
        assert _email_domain_matches("a@mail.example.com", "example.com") is True

    def test_off_domain_no_match(self) -> None:
        assert _email_domain_matches("a@gmail.com", "example.com") is False

    def test_lookalike_suffix_no_match(self) -> None:
        assert _email_domain_matches("a@notexample.com", "example.com") is False

    def test_no_at_sign_is_not_an_email(self) -> None:
        assert _email_domain_matches("not-an-email", "example.com") is False


class TestHardcodedSourceAllowlist:
    """The narrower alternative this module's own docstring commits to:
    a fixed, non-configurable 2-source list, never widened by settings
    or an env var — the boundary can't be silently broadened later by a
    config change."""

    def test_sources_constant_is_exactly_the_documented_safe_pair(self) -> None:
        from modules.theharvester import _SOURCES

        assert _SOURCES == "duckduckgo,yahoo"

    def test_no_settings_field_exists_to_override_the_source_list(self) -> None:
        from config.settings import Settings

        settings = Settings(project_root=Path("/tmp"))
        assert not hasattr(settings, "theharvester_sources")
        assert not hasattr(settings, "theharvester_b")

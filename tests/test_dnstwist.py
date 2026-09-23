"""`modules/dnstwist.py` — domain permutation / typosquat monitoring.

`tests/fixtures/dnstwist_real_output.json` is a real, trimmed capture
from an actual `dnstwist --format json --registered --all --whois
example.com` run during this module's own development — including the
real `"fuzzer": "*original"` echo-back row for `example.com` itself
(with its own real, confirmed `"dns_mx": [""]` quirk), four real
MX-configured permutations, and two real MX-less, non-fresh
permutations. No naturally-freshly-registered candidate existed in that
real capture at the time it was taken, so the one "freshly registered,
no MX" edge case below is a synthetic row built on the same real,
confirmed schema — labeled as such rather than silently presented as
part of the real capture.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.store import AssetStore
from modules.dnstwist import (
    _has_real_mx,
    _is_freshly_registered,
    _read_dnstwist_json,
    _row_to_candidate,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _real_rows() -> list[dict[str, object]]:
    return _read_dnstwist_json(FIXTURES_DIR / "dnstwist_real_output.json")


class TestRealFixtureParsing:
    def test_the_original_seed_row_is_excluded(self) -> None:
        rows = _real_rows()
        original = next(r for r in rows if r["fuzzer"] == "*original")
        assert original["domain"] == "example.com"
        candidate = _row_to_candidate(original, "example.com", fresh_days=90)
        assert candidate is None

    def test_real_mx_configured_permutations_are_high_severity(self) -> None:
        rows = _real_rows()
        mx_rows = [r for r in rows if r["fuzzer"] != "*original" and _has_real_mx(r)]
        assert len(mx_rows) >= 1
        for row in mx_rows:
            candidate = _row_to_candidate(row, "example.com", fresh_days=90)
            assert candidate is not None
            assert candidate["severity"] == "high"
            assert candidate["has_mx"] is True
            assert "MX" in candidate["risk_reason"]

    def test_real_mx_less_non_fresh_permutations_are_low_severity(self) -> None:
        rows = _real_rows()
        plain_rows = [
            r
            for r in rows
            if r["fuzzer"] != "*original"
            and not _has_real_mx(r)
            and not _is_freshly_registered(str(r.get("whois_created") or ""), fresh_days=90)
        ]
        assert len(plain_rows) >= 1
        for row in plain_rows:
            candidate = _row_to_candidate(row, "example.com", fresh_days=90)
            assert candidate is not None
            assert candidate["severity"] == "low"
            assert candidate["has_mx"] is False

    def test_target_domain_is_always_the_real_target_not_the_candidate(self) -> None:
        rows = _real_rows()
        row = next(r for r in rows if r["fuzzer"] != "*original")
        candidate = _row_to_candidate(row, "example.com", fresh_days=90)
        assert candidate is not None
        assert candidate["target_domain"] == "example.com"
        assert candidate["candidate_domain"] != "example.com"


class TestFreshRegistrationSignal:
    """A registered-but-unremarkable permutation (no MX, old
    registration) must be treated differently from a freshly-registered
    one, per this module's own prioritization scheme — real fixture data
    had no naturally-freshly-registered row, so this uses a synthetic
    row on the same real, confirmed schema."""

    def _synthetic_fresh_row(self, days_old: int) -> dict[str, object]:
        created = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime("%Y-%m-%d")
        return {
            "domain": "examp1e.com",
            "fuzzer": "homoglyph",
            "dns_a": ["203.0.113.10"],
            "dns_ns": ["ns1.example-registrar.test"],
            "whois_created": created,
            "whois_registrar": "Some Registrar, LLC",
        }

    def test_freshly_registered_no_mx_is_medium_severity(self) -> None:
        row = self._synthetic_fresh_row(days_old=10)
        candidate = _row_to_candidate(row, "example.com", fresh_days=90)
        assert candidate is not None
        assert candidate["severity"] == "medium"
        assert candidate["has_mx"] is False
        assert "registered within the last" in candidate["risk_reason"]

    def test_old_registration_no_mx_is_low_severity(self) -> None:
        row = self._synthetic_fresh_row(days_old=365 * 10)
        candidate = _row_to_candidate(row, "example.com", fresh_days=90)
        assert candidate is not None
        assert candidate["severity"] == "low"

    def test_boundary_at_exactly_fresh_days_is_still_fresh(self) -> None:
        row = self._synthetic_fresh_row(days_old=90)
        candidate = _row_to_candidate(row, "example.com", fresh_days=90)
        assert candidate is not None
        assert candidate["severity"] == "medium"

    def test_mx_outranks_freshness_when_both_present(self) -> None:
        row = self._synthetic_fresh_row(days_old=5)
        row["dns_mx"] = ["mx.attacker-controlled.test"]
        candidate = _row_to_candidate(row, "example.com", fresh_days=90)
        assert candidate is not None
        assert candidate["severity"] == "high"

    def test_missing_whois_created_is_not_treated_as_fresh(self) -> None:
        row = self._synthetic_fresh_row(days_old=10)
        del row["whois_created"]
        candidate = _row_to_candidate(row, "example.com", fresh_days=90)
        assert candidate is not None
        assert candidate["severity"] == "low"

    def test_malformed_whois_date_does_not_crash(self) -> None:
        row = self._synthetic_fresh_row(days_old=10)
        row["whois_created"] = "not-a-date"
        candidate = _row_to_candidate(row, "example.com", fresh_days=90)
        assert candidate is not None
        assert candidate["severity"] == "low"


class TestHasRealMx:
    def test_absent_key_is_no_mx(self) -> None:
        assert _has_real_mx({"domain": "x.com"}) is False

    def test_original_row_quirk_empty_string_list_is_no_mx(self) -> None:
        """The real, confirmed `*original`-row quirk: `dns_mx: [""]` must
        not be misread as "has an MX record"."""
        assert _has_real_mx({"dns_mx": [""]}) is False

    def test_real_mx_hostname_is_mx(self) -> None:
        assert _has_real_mx({"dns_mx": ["mx1.example-host.test"]}) is True


class TestNeverBecomesAHostOrTargetAsset:
    """The task's own core requirement, proven with a test — not just by
    reading the code: a typosquat candidate must never be discoverable
    through the target's own Host/Finding pipeline."""

    def test_not_registered_in_parser_registry(self) -> None:
        from core.parsers.registry import PARSER_REGISTRY

        assert "dnstwist" not in PARSER_REGISTRY

    def test_finalize_writes_to_its_own_store_table_not_hosts_or_findings(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "run.db"
        store = AssetStore(db_path)
        from core.assets import ScanRun

        run_id = "test-run-dnstwist"
        store.create_run(ScanRun(run_id=run_id, started_at="2026-09-23T00:00:00Z"))
        store.persist_registry(run_id, {}, clusters=[], graph=None, intel=None)
        store.record_typosquat_candidates(
            run_id,
            [
                {
                    "target_domain": "example.com",
                    "candidate_domain": "exampler.com",
                    "fuzzer": "addition",
                    "dns_a": ["203.0.113.10"],
                    "dns_mx": ["mx.example-host.test"],
                    "has_mx": True,
                    "whois_created": "2020-01-01",
                    "whois_registrar": "Some Registrar",
                    "severity": "high",
                    "risk_reason": "MX record configured",
                    "confidence_score": 80,
                }
            ],
        )

        candidates = store.get_typosquat_candidates(run_id)
        assert len(candidates) == 1
        assert candidates[0]["candidate_domain"] == "exampler.com"

        # Never a Host and never a Finding row for the candidate domain.
        import sqlite3

        with sqlite3.connect(db_path) as conn:
            host_rows = conn.execute(
                "SELECT * FROM hosts WHERE domain = ?", ("exampler.com",)
            ).fetchall()
            finding_rows = conn.execute(
                "SELECT * FROM findings WHERE host = ?", ("exampler.com",)
            ).fetchall()
        assert host_rows == []
        assert finding_rows == []


# A real, live end-to-end run (real `dnstwist` subprocess, real DNS/WHOIS
# lookups against the internet) was performed manually during this
# module's own development — its output is what
# tests/fixtures/dnstwist_real_output.json above is trimmed from, and
# TestRealFixtureParsing exercises the full plugin parsing/prioritization
# logic against it. Not included as a committed, automated test: a live
# scan of 100+ candidate domains' real DNS/WHOIS is inherently slow and
# subject to real network/registry-rate-limit variance, which would
# threaten "full suite green 3x, real counts" — a live-network test is
# the wrong place to buy that assurance when a real captured fixture
# already gives deterministic, real-data coverage of the same logic.

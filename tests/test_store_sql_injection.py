"""Snyk SQL Injection findings (4, all tracing to the same sink) — all
false positives, verified here with real adversarial payloads rather
than just asserted.

Snyk flagged `api/routers/reportability.py` (`compute_estimate`,
`run_assessment`) and `app.py` (both `cmd_assess_reportability` call
sites, one direct and one via `core/reportability/cli.py`). All four
call paths funnel into exactly one real sink:
`core/store.py::AssetStore.get_findings()`, which builds its `severity
IN (...)` clause with string concatenation:

    placeholders = ",".join("?" for _ in severity)
    query += f" AND severity IN ({placeholders})"

Snyk's static analyzer sees an f-string feeding `execute()` and flags
it without reasoning that `placeholders` is built ONLY from `len(severity)`
— it interpolates the literal character `?` repeated N times, never any
of `severity`'s actual string content. Every real value (`run_id`, `host`,
and every entry of `severity`) is passed through `execute(query, params)`
as a bound parameter, never string-interpolated. This is the textbook
"parameterized, but the placeholder COUNT is dynamic" pattern static
taint analysis without real dataflow reasoning routinely misflags.
"""

from __future__ import annotations

from pathlib import Path

from core.assets import Finding, Host, ScanRun
from core.store import AssetStore

RUN_ID = "run-sqli-test"


def _seeded_store(tmp_path: Path) -> AssetStore:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-01-01T00:00:00Z", targets=["x.test"]))
    host = Host(
        domain="admin.x.test",
        hostname="admin.x.test",
        findings=[
            Finding(
                host="admin.x.test",
                template_id="exposed-admin-panel",
                severity="high",
                name="Exposed admin panel",
                source="nuclei",
            ),
            Finding(
                host="admin.x.test",
                template_id="weak-tls",
                severity="low",
                name="Weak TLS config",
                source="sslyze",
            ),
        ],
    )
    store.persist_registry(RUN_ID, {host.domain: host})
    return store


class TestHostFilterIsNeverInterpolatedIntoSql:
    def test_a_classic_or_true_payload_as_host_matches_nothing(self, tmp_path: Path) -> None:
        store = _seeded_store(tmp_path)
        payload = "x' OR '1'='1"
        findings = store.get_findings(RUN_ID, host=payload)
        assert findings == []  # treated as a literal string, never as SQL

    def test_a_stacked_query_payload_as_host_never_executes_and_never_drops_the_table(
        self, tmp_path: Path
    ) -> None:
        store = _seeded_store(tmp_path)
        payload = "x'; DROP TABLE findings; --"
        findings = store.get_findings(RUN_ID, host=payload)
        assert findings == []
        # The table must still exist and still hold the real, unaffected rows.
        assert len(store.get_findings(RUN_ID)) == 2

    def test_a_real_host_still_matches_normally(self, tmp_path: Path) -> None:
        store = _seeded_store(tmp_path)
        findings = store.get_findings(RUN_ID, host="admin.x.test")
        assert len(findings) == 2


class TestSeverityFilterPlaceholdersAreCountOnlyNeverContent:
    def test_a_stacked_query_payload_inside_a_severity_value_never_executes(
        self, tmp_path: Path
    ) -> None:
        store = _seeded_store(tmp_path)
        payload = "high'; DROP TABLE findings; --"
        findings = store.get_findings(RUN_ID, severity=[payload])
        assert findings == []  # no severity actually equals this literal string
        assert len(store.get_findings(RUN_ID)) == 2  # table intact, real rows intact

    def test_a_union_select_payload_inside_a_severity_value_never_executes(
        self, tmp_path: Path
    ) -> None:
        store = _seeded_store(tmp_path)
        payload = "x' UNION SELECT sql FROM sqlite_master; --"
        findings = store.get_findings(RUN_ID, severity=[payload])
        assert findings == []

    def test_a_large_number_of_malicious_severity_values_only_changes_placeholder_count(
        self, tmp_path: Path
    ) -> None:
        """The dynamic part of the query IS `len(severity)` — proving that
        varying the LIST LENGTH (not content) never changes which columns
        or table the query touches, only how many `?` placeholders it
        binds against, all still real bound parameters."""
        store = _seeded_store(tmp_path)
        payloads = [f"sev{i}' OR '1'='1" for i in range(25)]
        findings = store.get_findings(RUN_ID, severity=payloads)
        assert findings == []
        assert len(store.get_findings(RUN_ID)) == 2

    def test_real_severities_still_match_normally(self, tmp_path: Path) -> None:
        store = _seeded_store(tmp_path)
        findings = store.get_findings(RUN_ID, severity=["high"])
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"


class TestRunIdIsAlsoNeverInterpolated:
    def test_a_malicious_run_id_matches_nothing_and_never_affects_other_runs(
        self, tmp_path: Path
    ) -> None:
        store = _seeded_store(tmp_path)
        payload = "run-sqli-test' OR '1'='1"
        findings = store.get_findings(payload)
        assert findings == []
        assert len(store.get_findings(RUN_ID)) == 2

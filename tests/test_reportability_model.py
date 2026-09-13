"""core/reportability/model.py + the reportability_assessments table
(core/store.py). See docs/REPORTABILITY_AGENT_DESIGN.md Part A.2/C.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.assets import Finding, Host, RiskLevel, ScanRun
from core.reportability.model import Eligibility, ReportabilityAssessment
from core.store import AssetStore


def test_eligibility_is_exactly_three_values() -> None:
    """Design Part A.2 is explicit: ELIGIBLE/NOT_ELIGIBLE/UNCERTAIN, never
    collapsed to a boolean. This test exists so narrowing or widening it
    silently is caught immediately."""
    assert {member.value for member in Eligibility} == {
        "ELIGIBLE",
        "NOT_ELIGIBLE",
        "UNCERTAIN",
    }


def test_assessment_to_dict_round_trips_enum_value() -> None:
    assessment = ReportabilityAssessment(
        finding_id=1,
        eligibility=Eligibility.NOT_ELIGIBLE,
        rule_citation="Findings on out-of-scope assets are not eligible.",
        program_rules_artifact="program_rules_snapshot.txt",
        model_used="claude-sonnet-5",
        citation_grounded=True,
        reasoning="Host is not in the program's scope table.",
    )
    data = assessment.to_dict()
    assert data["eligibility"] == "NOT_ELIGIBLE"
    assert data["source"] == "reportability_agent"
    assert data["citation_grounded"] is True


def test_empty_citation_requires_grounded_to_be_none() -> None:
    """'No rule applies' (empty citation) must never be conflated with
    'a citation was offered and failed to verify' (UNGROUNDED)."""
    with pytest.raises(ValueError, match="must be None when rule_citation is empty"):
        ReportabilityAssessment(
            finding_id=1,
            eligibility=Eligibility.UNCERTAIN,
            rule_citation="",
            program_rules_artifact="rules.txt",
            model_used="claude-sonnet-5",
            citation_grounded=True,
        )


def test_nonempty_citation_requires_grounded_to_be_set() -> None:
    with pytest.raises(ValueError, match="must be set"):
        ReportabilityAssessment(
            finding_id=1,
            eligibility=Eligibility.ELIGIBLE,
            rule_citation="Critical RCE findings are always eligible.",
            program_rules_artifact="rules.txt",
            model_used="claude-sonnet-5",
        )


def test_ungrounded_property_is_true_only_when_citation_check_failed() -> None:
    grounded = ReportabilityAssessment(
        finding_id=1,
        eligibility=Eligibility.ELIGIBLE,
        rule_citation="x",
        program_rules_artifact="rules.txt",
        model_used="claude-sonnet-5",
        citation_grounded=True,
    )
    ungrounded = ReportabilityAssessment(
        finding_id=2,
        eligibility=Eligibility.ELIGIBLE,
        rule_citation="fabricated text",
        program_rules_artifact="rules.txt",
        model_used="claude-sonnet-5",
        citation_grounded=False,
    )
    no_citation = ReportabilityAssessment(
        finding_id=3,
        eligibility=Eligibility.UNCERTAIN,
        rule_citation="",
        program_rules_artifact="rules.txt",
        model_used="claude-sonnet-5",
    )
    assert grounded.ungrounded is False
    assert ungrounded.ungrounded is True
    assert no_citation.ungrounded is False


def _seed_run_and_finding(tmp_path: Path, run_id: str = "run1") -> tuple[AssetStore, int]:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(ScanRun(run_id=run_id, started_at="2026-01-01T00:00:00Z", targets=["x.test"]))
    host = Host(
        domain="admin.x.test",
        hostname="admin.x.test",
        risk_level=RiskLevel.HIGH,
        risk_score=70,
        findings=[
            Finding(
                host="admin.x.test",
                template_id="exposed-admin-panel",
                severity="high",
                name="Exposed admin panel",
                source="nuclei",
            )
        ],
    )
    store.persist_registry(run_id, {host.domain: host})
    finding_id = store.get_findings(run_id)[0]["id"]
    return store, finding_id


class TestGetFindings:
    def test_returns_the_real_row_id(self, tmp_path: Path) -> None:
        store, finding_id = _seed_run_and_finding(tmp_path)
        rows = store.get_findings("run1")
        assert len(rows) == 1
        assert rows[0]["id"] == finding_id
        assert rows[0]["host"] == "admin.x.test"

    def test_filters_by_host(self, tmp_path: Path) -> None:
        store, _ = _seed_run_and_finding(tmp_path)
        assert store.get_findings("run1", host="admin.x.test")
        assert store.get_findings("run1", host="nope.x.test") == []

    def test_filters_by_severity(self, tmp_path: Path) -> None:
        store, _ = _seed_run_and_finding(tmp_path)
        assert store.get_findings("run1", severity=["high", "critical"])
        assert store.get_findings("run1", severity=["low"]) == []


class TestRecordAndReadReportabilityAssessments:
    def test_round_trips_through_sqlite(self, tmp_path: Path) -> None:
        store, finding_id = _seed_run_and_finding(tmp_path)
        assessment = ReportabilityAssessment(
            finding_id=finding_id,
            eligibility=Eligibility.NOT_ELIGIBLE,
            rule_citation="Findings on out-of-scope assets are not eligible.",
            program_rules_artifact="program_rules_snapshot.txt",
            model_used="claude-sonnet-5",
            citation_grounded=True,
            reasoning="Host is not in the program's scope table.",
        )
        store.record_reportability_assessments("run1", [assessment])

        rows = store.get_reportability_assessments("run1")
        assert len(rows) == 1
        row = rows[0]
        assert row["finding_id"] == finding_id
        assert row["eligibility"] == "NOT_ELIGIBLE"
        assert row["citation_grounded"] == 1
        assert row["source"] == "reportability_agent"
        assert row["model_used"] == "claude-sonnet-5"
        assert row["program_rules_artifact"] == "program_rules_snapshot.txt"
        assert row["assessed_at"]

    def test_empty_list_is_a_no_op(self, tmp_path: Path) -> None:
        store, _ = _seed_run_and_finding(tmp_path)
        store.record_reportability_assessments("run1", [])
        assert store.get_reportability_assessments("run1") == []

    def test_ungrounded_citation_persists_as_grounded_zero_not_null(self, tmp_path: Path) -> None:
        """NULL (no citation offered) and 0 (citation offered, failed to
        verify) must remain distinguishable in the persisted row — the
        dataclass invariant guarantees this at construction time, this
        test guarantees SQLite doesn't collapse the distinction on the way
        in or out."""
        store, finding_id = _seed_run_and_finding(tmp_path)
        assessment = ReportabilityAssessment(
            finding_id=finding_id,
            eligibility=Eligibility.ELIGIBLE,
            rule_citation="This exact sentence does not appear in the rules file.",
            program_rules_artifact="program_rules_snapshot.txt",
            model_used="claude-sonnet-5",
            citation_grounded=False,
        )
        store.record_reportability_assessments("run1", [assessment])
        row = store.get_reportability_assessments("run1")[0]
        assert row["citation_grounded"] == 0
        assert row["rule_citation"]

    def test_finding_id_is_a_real_foreign_key_to_findings(self, tmp_path: Path) -> None:
        """Unlike verification_flags' deliberately loose related_id, this
        must reference a real findings.id row."""
        store, finding_id = _seed_run_and_finding(tmp_path)
        assessment = ReportabilityAssessment(
            finding_id=finding_id,
            eligibility=Eligibility.ELIGIBLE,
            rule_citation="",
            program_rules_artifact="program_rules_snapshot.txt",
            model_used="claude-sonnet-5",
        )
        store.record_reportability_assessments("run1", [assessment])
        with store._connect() as conn:  # noqa: SLF001
            row = conn.execute(
                """SELECT f.host FROM reportability_assessments ra
                   JOIN findings f ON f.id = ra.finding_id
                   WHERE ra.run_id = ?""",
                ("run1",),
            ).fetchone()
        assert row["host"] == "admin.x.test"

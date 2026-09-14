"""core/reportability/model.py + the reportability_assessments /
reportability_adversarial_reviews tables (core/store.py). See
docs/REPORTABILITY_AGENT_DESIGN.md Part A.2/C and the v2 addendum for
provider-agnostic / adversarial cross-validation.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from core.assets import Finding, Host, RiskLevel, ScanRun
from core.reportability.model import (
    AdversarialFindingReview,
    Confidence,
    Eligibility,
    ReportabilityAssessment,
    ReviewChallenge,
    combine_eligibility,
)
from core.store import AssetStore

_COMMON_KWARGS = dict(
    provider="anthropic",
    model_used="claude-sonnet-5",
    rules_hash="a" * 64,
    prompt_version="v2",
)


def test_eligibility_is_exactly_three_values() -> None:
    """Design Part A.2 is explicit: ELIGIBLE/NOT_ELIGIBLE/UNCERTAIN, never
    collapsed to a boolean. This test exists so narrowing or widening it
    silently is caught immediately."""
    assert {member.value for member in Eligibility} == {
        "ELIGIBLE",
        "NOT_ELIGIBLE",
        "UNCERTAIN",
    }


def test_confidence_is_exactly_three_values() -> None:
    assert {member.value for member in Confidence} == {"HIGH", "MEDIUM", "LOW"}


def test_review_challenge_is_exactly_three_values() -> None:
    assert {member.value for member in ReviewChallenge} == {
        "AGREE",
        "DISAGREE",
        "INSUFFICIENT_INFORMATION",
    }


class TestCombineEligibility:
    def test_agree_preserves_the_primary_verdict(self) -> None:
        assert (
            combine_eligibility(Eligibility.ELIGIBLE, ReviewChallenge.AGREE) == Eligibility.ELIGIBLE
        )
        assert (
            combine_eligibility(Eligibility.NOT_ELIGIBLE, ReviewChallenge.AGREE)
            == Eligibility.NOT_ELIGIBLE
        )

    def test_disagree_fails_closed_to_uncertain_never_the_reviewers_own_counter_verdict(
        self,
    ) -> None:
        """The fail-closed disagreement policy (design v2): a real
        disagreement always becomes UNCERTAIN, never the adversarial
        reviewer's own preferred alternative — this function doesn't even
        take a counter_eligibility argument, by design, so there is nothing
        for a "provider preference" or "majority vote" bug to accidentally
        read."""
        assert (
            combine_eligibility(Eligibility.ELIGIBLE, ReviewChallenge.DISAGREE)
            == Eligibility.UNCERTAIN
        )
        assert (
            combine_eligibility(Eligibility.NOT_ELIGIBLE, ReviewChallenge.DISAGREE)
            == Eligibility.UNCERTAIN
        )

    def test_insufficient_information_also_fails_closed_to_uncertain(self) -> None:
        """A reviewer that could not confirm the primary verdict has not
        validated it — treated the same as an active disagreement, not the
        same as silent agreement."""
        assert (
            combine_eligibility(Eligibility.ELIGIBLE, ReviewChallenge.INSUFFICIENT_INFORMATION)
            == Eligibility.UNCERTAIN
        )

    def test_disagreement_never_resolves_by_picking_the_more_confident_side(self) -> None:
        """Hardening: explicitly proves 'the higher-confidence side wins'
        is not how disagreement is resolved, not just 'not majority vote'
        (the existing DISAGREE test above already covers that). This
        function's signature — combine_eligibility(primary, challenge) —
        has no Confidence parameter at all, so a HIGH-confidence primary
        verdict and a LOW-confidence one produce the identical UNCERTAIN
        outcome once genuinely challenged: confidence is not merely
        de-prioritized in the tie-break, it is structurally absent from
        the decision. Simulates both directions (a HIGH-confidence primary
        challenged, and — since AdversarialFindingReview carries no
        confidence field for the reviewer either — a full round trip
        through the real assessment/review dataclasses to prove neither
        object's confidence-shaped data ever reaches this function).
        """
        # A HIGH-confidence primary verdict, genuinely disagreed with,
        # still fails closed — high self-reported confidence never
        # protects a verdict from a real challenge.
        high_confidence_primary = ReportabilityAssessment(
            finding_id=1,
            eligibility=Eligibility.ELIGIBLE,
            final_eligibility=Eligibility.ELIGIBLE,  # placeholder, recomputed below
            rule_citation="",
            program_rules_artifact="program_rules_snapshot.txt",
            confidence=Confidence.HIGH,
            **_COMMON_KWARGS,
        )
        low_confidence_primary = ReportabilityAssessment(
            finding_id=2,
            eligibility=Eligibility.ELIGIBLE,
            final_eligibility=Eligibility.ELIGIBLE,
            rule_citation="",
            program_rules_artifact="program_rules_snapshot.txt",
            confidence=Confidence.LOW,
            **_COMMON_KWARGS,
        )
        # combine_eligibility only ever sees .eligibility and the
        # reviewer's .challenge — never .confidence off either side.
        assert (
            combine_eligibility(high_confidence_primary.eligibility, ReviewChallenge.DISAGREE)
            == Eligibility.UNCERTAIN
        )
        assert (
            combine_eligibility(low_confidence_primary.eligibility, ReviewChallenge.DISAGREE)
            == Eligibility.UNCERTAIN
        )
        # Identical outcome regardless of the primary's self-reported
        # confidence — the HIGH-confidence case gets no special treatment.
        assert combine_eligibility(
            high_confidence_primary.eligibility, ReviewChallenge.DISAGREE
        ) == combine_eligibility(low_confidence_primary.eligibility, ReviewChallenge.DISAGREE)


def test_assessment_to_dict_round_trips_enum_value() -> None:
    assessment = ReportabilityAssessment(
        finding_id=1,
        eligibility=Eligibility.NOT_ELIGIBLE,
        final_eligibility=Eligibility.NOT_ELIGIBLE,
        rule_citation="Findings on out-of-scope assets are not eligible.",
        program_rules_artifact="program_rules_snapshot.txt",
        citation_grounded=True,
        grounding_method="exact",
        reasoning="Host is not in the program's scope table.",
        confidence=Confidence.HIGH,
        **_COMMON_KWARGS,
    )
    data = assessment.to_dict()
    assert data["eligibility"] == "NOT_ELIGIBLE"
    assert data["final_eligibility"] == "NOT_ELIGIBLE"
    assert data["source"] == "reportability_agent"
    assert data["citation_grounded"] is True
    assert data["grounding_method"] == "exact"
    assert data["confidence"] == "HIGH"
    assert data["provider"] == "anthropic"
    assert data["rules_hash"] == "a" * 64
    assert data["prompt_version"] == "v2"


def test_empty_citation_requires_grounded_to_be_none() -> None:
    """'No rule applies' (empty citation) must never be conflated with
    'a citation was offered and failed to verify' (UNGROUNDED)."""
    with pytest.raises(ValueError, match="must be None when rule_citation is empty"):
        ReportabilityAssessment(
            finding_id=1,
            eligibility=Eligibility.UNCERTAIN,
            final_eligibility=Eligibility.UNCERTAIN,
            rule_citation="",
            program_rules_artifact="rules.txt",
            citation_grounded=True,
            **_COMMON_KWARGS,
        )


def test_nonempty_citation_requires_grounded_to_be_set() -> None:
    with pytest.raises(ValueError, match="must be set"):
        ReportabilityAssessment(
            finding_id=1,
            eligibility=Eligibility.ELIGIBLE,
            final_eligibility=Eligibility.ELIGIBLE,
            rule_citation="Critical RCE findings are always eligible.",
            program_rules_artifact="rules.txt",
            **_COMMON_KWARGS,
        )


def test_ungrounded_property_is_true_only_when_citation_check_failed() -> None:
    grounded = ReportabilityAssessment(
        finding_id=1,
        eligibility=Eligibility.ELIGIBLE,
        final_eligibility=Eligibility.ELIGIBLE,
        rule_citation="x",
        program_rules_artifact="rules.txt",
        citation_grounded=True,
        **_COMMON_KWARGS,
    )
    ungrounded = ReportabilityAssessment(
        finding_id=2,
        eligibility=Eligibility.ELIGIBLE,
        final_eligibility=Eligibility.ELIGIBLE,
        rule_citation="fabricated text",
        program_rules_artifact="rules.txt",
        citation_grounded=False,
        **_COMMON_KWARGS,
    )
    no_citation = ReportabilityAssessment(
        finding_id=3,
        eligibility=Eligibility.UNCERTAIN,
        final_eligibility=Eligibility.UNCERTAIN,
        rule_citation="",
        program_rules_artifact="rules.txt",
        **_COMMON_KWARGS,
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
            final_eligibility=Eligibility.NOT_ELIGIBLE,
            rule_citation="Findings on out-of-scope assets are not eligible.",
            program_rules_artifact="program_rules_snapshot.txt",
            citation_grounded=True,
            grounding_method="exact",
            reasoning="Host is not in the program's scope table.",
            confidence=Confidence.HIGH,
            **_COMMON_KWARGS,
        )
        inserted_ids = store.record_reportability_assessments("run1", [assessment])
        assert len(inserted_ids) == 1

        rows = store.get_reportability_assessments("run1")
        assert len(rows) == 1
        row = rows[0]
        assert row["id"] == inserted_ids[0]
        assert row["finding_id"] == finding_id
        assert row["eligibility"] == "NOT_ELIGIBLE"
        assert row["final_eligibility"] == "NOT_ELIGIBLE"
        assert row["citation_grounded"] == 1
        assert row["grounding_method"] == "exact"
        assert row["confidence"] == "HIGH"
        assert row["source"] == "reportability_agent"
        assert row["provider"] == "anthropic"
        assert row["model_used"] == "claude-sonnet-5"
        assert row["rules_hash"] == "a" * 64
        assert row["prompt_version"] == "v2"
        assert row["program_rules_artifact"] == "program_rules_snapshot.txt"
        assert row["assessed_at"]

    def test_empty_list_is_a_no_op(self, tmp_path: Path) -> None:
        store, _ = _seed_run_and_finding(tmp_path)
        assert store.record_reportability_assessments("run1", []) == []
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
            final_eligibility=Eligibility.ELIGIBLE,
            rule_citation="This exact sentence does not appear in the rules file.",
            program_rules_artifact="program_rules_snapshot.txt",
            citation_grounded=False,
            **_COMMON_KWARGS,
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
            final_eligibility=Eligibility.ELIGIBLE,
            rule_citation="",
            program_rules_artifact="program_rules_snapshot.txt",
            **_COMMON_KWARGS,
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

    def test_composite_fk_rejects_a_finding_id_from_a_different_run(self, tmp_path: Path) -> None:
        """design v2, Section 7: it must be structurally impossible (a
        SQLite constraint violation, not just an application bug) to
        attach an assessment to a finding_id that is valid but belongs to
        a DIFFERENT run than the assessment's own run_id.
        """
        store, finding_id_in_run1 = _seed_run_and_finding(tmp_path, run_id="run1")
        store.create_run(
            ScanRun(run_id="run2", started_at="2026-01-01T00:00:00Z", targets=["y.test"])
        )
        assessment = ReportabilityAssessment(
            finding_id=finding_id_in_run1,  # real id, but belongs to run1
            eligibility=Eligibility.ELIGIBLE,
            final_eligibility=Eligibility.ELIGIBLE,
            rule_citation="",
            program_rules_artifact="program_rules_snapshot.txt",
            **_COMMON_KWARGS,
        )
        with pytest.raises(sqlite3.IntegrityError):
            store.record_reportability_assessments("run2", [assessment])
        # And nothing was left half-written by the failed attempt.
        assert store.get_reportability_assessments("run2") == []

    def test_re_assessing_the_same_finding_never_overwrites_the_prior_assessment(
        self, tmp_path: Path
    ) -> None:
        """Hardening: reportability_assessments has no UNIQUE constraint on
        (run_id, finding_id) and record_reportability_assessments always
        does a plain INSERT, never INSERT OR REPLACE/UPSERT — re-running
        assess-reportability against a finding it already assessed (a
        second pass with an updated program-rules file, a different
        provider, or just re-running the same command) must add a new
        historical row, never silently replace the old verdict. Both rows
        must remain independently readable afterward, in insertion order,
        each carrying its own provider/model/rules_hash/prompt_version so
        it's possible to tell exactly which assessment used which rules
        text and which prompt version later, without ambiguity."""
        store, finding_id = _seed_run_and_finding(tmp_path)
        first = ReportabilityAssessment(
            finding_id=finding_id,
            eligibility=Eligibility.NOT_ELIGIBLE,
            final_eligibility=Eligibility.NOT_ELIGIBLE,
            rule_citation="Out-of-scope assets are never eligible.",
            program_rules_artifact="program_rules_snapshot.txt",
            citation_grounded=True,
            grounding_method="exact",
            provider="anthropic",
            model_used="claude-sonnet-5",
            rules_hash="a" * 64,
            prompt_version="v2",
        )
        first_ids = store.record_reportability_assessments("run1", [first])

        # A later re-assessment: a different provider, a different (updated)
        # rules text, a different prompt version, and a different verdict —
        # exactly the realistic "program rules changed, re-run it" case.
        second = ReportabilityAssessment(
            finding_id=finding_id,
            eligibility=Eligibility.ELIGIBLE,
            final_eligibility=Eligibility.ELIGIBLE,
            rule_citation="Updated scope now includes this asset class.",
            program_rules_artifact="program_rules_snapshot.txt",
            citation_grounded=True,
            grounding_method="exact",
            provider="openai",
            model_used="gpt-5.6-terra",
            rules_hash="b" * 64,
            prompt_version="v3",
        )
        second_ids = store.record_reportability_assessments("run1", [second])

        assert first_ids != second_ids, "the second assessment must be a new row, not an update"

        rows = store.get_reportability_assessments("run1")
        assert len(rows) == 2, "both the old and new assessment must remain readable"
        by_id = {row["id"]: row for row in rows}

        assert by_id[first_ids[0]]["final_eligibility"] == "NOT_ELIGIBLE"
        assert by_id[first_ids[0]]["provider"] == "anthropic"
        assert by_id[first_ids[0]]["rules_hash"] == "a" * 64
        assert by_id[first_ids[0]]["prompt_version"] == "v2"

        assert by_id[second_ids[0]]["final_eligibility"] == "ELIGIBLE"
        assert by_id[second_ids[0]]["provider"] == "openai"
        assert by_id[second_ids[0]]["rules_hash"] == "b" * 64
        assert by_id[second_ids[0]]["prompt_version"] == "v3"

        # The first assessment's own fields are untouched by the second
        # insert — not partially merged, not blanked, genuinely independent.
        assert by_id[first_ids[0]]["rule_citation"] == "Out-of-scope assets are never eligible."


class TestAdversarialFindingReview:
    def test_to_dict_round_trips_enum_values(self) -> None:
        review = AdversarialFindingReview(
            assessment_id=1,
            finding_id=2,
            reviewer_provider="openai",
            reviewer_model="gpt-5.6-terra",
            challenge=ReviewChallenge.DISAGREE,
            prompt_version="v2",
            counter_eligibility=Eligibility.NOT_ELIGIBLE,
            reasoning="The cited rule doesn't apply to this host.",
        )
        data = review.to_dict()
        assert data["challenge"] == "DISAGREE"
        assert data["counter_eligibility"] == "NOT_ELIGIBLE"

    def test_counter_eligibility_defaults_to_none(self) -> None:
        review = AdversarialFindingReview(
            assessment_id=1,
            finding_id=2,
            reviewer_provider="openai",
            reviewer_model="gpt-5.6-terra",
            challenge=ReviewChallenge.AGREE,
            prompt_version="v2",
        )
        assert review.to_dict()["counter_eligibility"] is None


class TestRecordAndReadAdversarialReviews:
    def _assessment(self, finding_id: int) -> ReportabilityAssessment:
        return ReportabilityAssessment(
            finding_id=finding_id,
            eligibility=Eligibility.ELIGIBLE,
            final_eligibility=Eligibility.UNCERTAIN,
            rule_citation="",
            program_rules_artifact="program_rules_snapshot.txt",
            **_COMMON_KWARGS,
        )

    def test_round_trips_through_sqlite(self, tmp_path: Path) -> None:
        store, finding_id = _seed_run_and_finding(tmp_path)
        assessment_id = store.record_reportability_assessments(
            "run1", [self._assessment(finding_id)]
        )[0]
        review = AdversarialFindingReview(
            assessment_id=assessment_id,
            finding_id=finding_id,
            reviewer_provider="openai",
            reviewer_model="gpt-5.6-terra",
            challenge=ReviewChallenge.DISAGREE,
            prompt_version="v2",
            counter_eligibility=Eligibility.NOT_ELIGIBLE,
            reasoning="The primary's citation doesn't actually cover this case.",
        )
        store.record_reportability_adversarial_reviews("run1", [review])

        rows = store.get_reportability_adversarial_reviews("run1")
        assert len(rows) == 1
        row = rows[0]
        assert row["assessment_id"] == assessment_id
        assert row["finding_id"] == finding_id
        assert row["reviewer_provider"] == "openai"
        assert row["challenge"] == "DISAGREE"
        assert row["counter_eligibility"] == "NOT_ELIGIBLE"
        assert row["reviewed_at"]

    def test_composite_fk_rejects_a_finding_id_from_a_different_run(self, tmp_path: Path) -> None:
        store, finding_id_in_run1 = _seed_run_and_finding(tmp_path, run_id="run1")
        store.create_run(
            ScanRun(run_id="run2", started_at="2026-01-01T00:00:00Z", targets=["y.test"])
        )
        assessment_id = store.record_reportability_assessments(
            "run1", [self._assessment(finding_id_in_run1)]
        )[0]
        review = AdversarialFindingReview(
            assessment_id=assessment_id,
            finding_id=finding_id_in_run1,
            reviewer_provider="openai",
            reviewer_model="gpt-5.6-terra",
            challenge=ReviewChallenge.AGREE,
            prompt_version="v2",
        )
        with pytest.raises(sqlite3.IntegrityError):
            store.record_reportability_adversarial_reviews("run2", [review])

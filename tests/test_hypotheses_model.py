"""core/hypotheses/model.py + the intel_llm_hypotheses/
intel_llm_hypothesis_evidence tables (core/store.py). See
docs/HYPOTHESIS_ENGINE_DESIGN.md Part C / Section 8.
"""

from __future__ import annotations

from pathlib import Path

from core.assets import ScanRun
from core.hypotheses.model import (
    CalibrationStatus,
    CitedEvidence,
    Confidence,
    ConfidenceBand,
    EvidenceKind,
    GroundingStatus,
    LlmHypothesis,
    ReasoningChallenge,
)
from core.store import AssetStore


def test_confidence_is_exactly_three_values() -> None:
    assert {member.value for member in Confidence} == {"HIGH", "MEDIUM", "LOW"}


def test_grounding_status_is_exactly_three_values() -> None:
    assert {member.value for member in GroundingStatus} == {
        "GROUNDED",
        "PARTIALLY_GROUNDED",
        "UNGROUNDED",
    }


def test_calibration_status_is_exactly_two_values() -> None:
    """Design Section 7.2: a hypothesis is either honest about the
    strength of its own cited evidence or it isn't — no middle ground the
    way grounding has PARTIALLY_GROUNDED (a mix of real/fake citations is
    a meaningfully distinct state; a mix of honest/dishonest strength
    claims is not — one overstatement is enough to distrust the whole
    hypothesis's self-characterization)."""
    assert {member.value for member in CalibrationStatus} == {"CALIBRATED", "OVERSTATED"}


def test_reasoning_challenge_is_exactly_three_values() -> None:
    assert {member.value for member in ReasoningChallenge} == {
        "SOUND",
        "OVERREACHES",
        "INSUFFICIENT_EVIDENCE",
    }


def test_evidence_kind_is_exactly_two_values() -> None:
    assert {member.value for member in EvidenceKind} == {"relationship", "entity"}


class TestCitedEvidenceToDict:
    def test_round_trips_enum_values(self) -> None:
        evidence = CitedEvidence(
            evidence_kind=EvidenceKind.RELATIONSHIP,
            cited_id="rel-1",
            exists_in_run=True,
            treated_as_strength=ConfidenceBand.HIGH,
            real_confidence_band="MEDIUM",
            overstated=True,
        )
        data = evidence.to_dict()
        assert data["evidence_kind"] == "relationship"
        assert data["treated_as_strength"] == "HIGH"
        assert data["real_confidence_band"] == "MEDIUM"
        assert data["overstated"] is True

    def test_none_strength_serializes_as_none_not_a_string(self) -> None:
        evidence = CitedEvidence(
            evidence_kind=EvidenceKind.ENTITY, cited_id="ent-1", exists_in_run=True
        )
        data = evidence.to_dict()
        assert data["treated_as_strength"] is None
        assert data["overstated"] is None


class TestLlmHypothesisTrustworthy:
    def _base(self, **overrides: object) -> LlmHypothesis:
        kwargs: dict[str, object] = dict(
            statement="These domains likely share commonly-provisioned infrastructure.",
            provider="anthropic",
            model_used="claude-sonnet-5",
            prompt_version="v1",
            grounding_status=GroundingStatus.GROUNDED,
            calibration_status=CalibrationStatus.CALIBRATED,
        )
        kwargs.update(overrides)
        return LlmHypothesis(**kwargs)

    def test_grounded_and_calibrated_with_no_review_is_trustworthy(self) -> None:
        assert self._base().trustworthy is True

    def test_ungrounded_is_never_trustworthy(self) -> None:
        assert self._base(grounding_status=GroundingStatus.UNGROUNDED).trustworthy is False

    def test_partially_grounded_is_never_trustworthy(self) -> None:
        assert self._base(grounding_status=GroundingStatus.PARTIALLY_GROUNDED).trustworthy is False

    def test_overstated_is_never_trustworthy_even_if_fully_grounded(self) -> None:
        """The whole point of the calibration check (design Section 7.2):
        a hypothesis citing entirely real evidence can still be untrustworthy
        because it mischaracterizes that evidence's strength."""
        assert self._base(calibration_status=CalibrationStatus.OVERSTATED).trustworthy is False

    def test_sound_reasoning_review_keeps_trustworthy(self) -> None:
        assert self._base(reasoning_review_challenge=ReasoningChallenge.SOUND).trustworthy is True

    def test_overreaches_reasoning_review_makes_it_untrustworthy(self) -> None:
        h = self._base(reasoning_review_challenge=ReasoningChallenge.OVERREACHES)
        assert h.trustworthy is False

    def test_insufficient_evidence_review_also_makes_it_untrustworthy(self) -> None:
        h = self._base(reasoning_review_challenge=ReasoningChallenge.INSUFFICIENT_EVIDENCE)
        assert h.trustworthy is False

    def test_to_dict_round_trips_enum_values(self) -> None:
        h = self._base(
            confidence=Confidence.HIGH,
            reasoning_review_challenge=ReasoningChallenge.SOUND,
            reasoning_review_provider="openai",
            reasoning_review_model="gpt-5.6-terra",
            evidence=[
                CitedEvidence(
                    evidence_kind=EvidenceKind.RELATIONSHIP,
                    cited_id="rel-1",
                    exists_in_run=True,
                    treated_as_strength=ConfidenceBand.HIGH,
                    real_confidence_band="HIGH",
                    overstated=False,
                )
            ],
        )
        data = h.to_dict()
        assert data["grounding_status"] == "GROUNDED"
        assert data["calibration_status"] == "CALIBRATED"
        assert data["confidence"] == "HIGH"
        assert data["reasoning_review_challenge"] == "SOUND"
        assert len(data["evidence"]) == 1


def _seed_run(tmp_path: Path, run_id: str = "run1") -> AssetStore:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(ScanRun(run_id=run_id, started_at="2026-01-01T00:00:00Z", targets=["x.test"]))
    return store


class TestRecordAndReadLlmHypotheses:
    def test_round_trips_through_sqlite_with_evidence(self, tmp_path: Path) -> None:
        store = _seed_run(tmp_path)
        hypothesis = LlmHypothesis(
            statement="Shared certificate suggests commonly-provisioned infrastructure.",
            provider="anthropic",
            model_used="claude-sonnet-5",
            prompt_version="v1",
            grounding_status=GroundingStatus.GROUNDED,
            calibration_status=CalibrationStatus.CALIBRATED,
            confidence=Confidence.HIGH,
            suggested_next_step="Worth an analyst's attention.",
            evidence=[
                CitedEvidence(
                    evidence_kind=EvidenceKind.RELATIONSHIP,
                    cited_id="rel-1",
                    exists_in_run=True,
                    treated_as_strength=ConfidenceBand.HIGH,
                    real_confidence_band="HIGH",
                    overstated=False,
                ),
                CitedEvidence(
                    evidence_kind=EvidenceKind.ENTITY,
                    cited_id="entity-1",
                    exists_in_run=True,
                ),
            ],
        )
        inserted_ids = store.record_llm_hypotheses("run1", [hypothesis])
        assert len(inserted_ids) == 1

        rows = store.get_llm_hypotheses("run1")
        assert len(rows) == 1
        row = rows[0]
        assert row["id"] == inserted_ids[0]
        assert row["statement"] == hypothesis.statement
        assert row["confidence"] == "HIGH"
        assert row["grounding_status"] == "GROUNDED"
        assert row["calibration_status"] == "CALIBRATED"
        assert row["provider"] == "anthropic"
        assert row["model_used"] == "claude-sonnet-5"
        assert row["prompt_version"] == "v1"
        assert row["generated_at"]
        assert len(row["evidence"]) == 2
        rel_evidence = next(e for e in row["evidence"] if e["evidence_kind"] == "relationship")
        assert rel_evidence["cited_id"] == "rel-1"
        assert rel_evidence["treated_as_strength"] == "HIGH"
        assert rel_evidence["exists_in_run"] == 1
        assert rel_evidence["overstated"] == 0
        entity_evidence = next(e for e in row["evidence"] if e["evidence_kind"] == "entity")
        assert entity_evidence["cited_id"] == "entity-1"
        assert entity_evidence["overstated"] is None

    def test_empty_list_is_a_no_op(self, tmp_path: Path) -> None:
        store = _seed_run(tmp_path)
        assert store.record_llm_hypotheses("run1", []) == []
        assert store.get_llm_hypotheses("run1") == []

    def test_hypothesis_with_no_evidence_persists_with_empty_evidence_list(
        self, tmp_path: Path
    ) -> None:
        store = _seed_run(tmp_path)
        hypothesis = LlmHypothesis(
            statement="An ungrounded hypothesis with nothing citable.",
            provider="anthropic",
            model_used="claude-sonnet-5",
            prompt_version="v1",
            grounding_status=GroundingStatus.UNGROUNDED,
            calibration_status=CalibrationStatus.CALIBRATED,
        )
        store.record_llm_hypotheses("run1", [hypothesis])
        row = store.get_llm_hypotheses("run1")[0]
        assert row["evidence"] == []

    def test_multiple_hypotheses_keep_independent_evidence_sets(self, tmp_path: Path) -> None:
        store = _seed_run(tmp_path)
        h1 = LlmHypothesis(
            statement="First.",
            provider="anthropic",
            model_used="claude-sonnet-5",
            prompt_version="v1",
            grounding_status=GroundingStatus.GROUNDED,
            calibration_status=CalibrationStatus.CALIBRATED,
            evidence=[
                CitedEvidence(
                    evidence_kind=EvidenceKind.RELATIONSHIP, cited_id="rel-1", exists_in_run=True
                )
            ],
        )
        h2 = LlmHypothesis(
            statement="Second.",
            provider="anthropic",
            model_used="claude-sonnet-5",
            prompt_version="v1",
            grounding_status=GroundingStatus.UNGROUNDED,
            calibration_status=CalibrationStatus.CALIBRATED,
            evidence=[
                CitedEvidence(
                    evidence_kind=EvidenceKind.RELATIONSHIP,
                    cited_id="rel-nonexistent",
                    exists_in_run=False,
                )
            ],
        )
        store.record_llm_hypotheses("run1", [h1, h2])
        rows = store.get_llm_hypotheses("run1")
        assert len(rows) == 2
        by_statement = {r["statement"]: r for r in rows}
        assert by_statement["First."]["evidence"][0]["cited_id"] == "rel-1"
        assert by_statement["Second."]["evidence"][0]["cited_id"] == "rel-nonexistent"

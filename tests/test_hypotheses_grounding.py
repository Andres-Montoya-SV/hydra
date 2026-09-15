"""core/hypotheses/grounding.py — the two mechanical grounding checks
(docs/HYPOTHESIS_ENGINE_DESIGN.md Section 6, Section 7.2). This is the
single most important test file for the hypothesis engine per this
implementation round's own explicit emphasis: "las dos verificaciones de
fundamento, no una."

Three canonical scenarios, each proven independently:
1. A correctly-calibrated hypothesis citing real evidence honestly.
2. A hypothesis citing REAL evidence but overstating its strength
   (GROUNDED + OVERSTATED) — proves grounding alone would have let this
   through; calibration is the check that catches it.
3. A hypothesis citing a fabricated relationship_id (UNGROUNDED) — proves
   a nonexistent citation is never miscounted as a calibration failure
   (a distinct, correctly-separated failure mode: overstated=None, not
   True, for a citation that doesn't exist at all).
"""

from __future__ import annotations

from core.hypotheses.evidence import RunEvidence
from core.hypotheses.grounding import (
    check_entity_citations,
    check_relationship_citations,
    compute_calibration_status,
    compute_grounding_status,
)
from core.hypotheses.model import CalibrationStatus, GroundingStatus
from core.hypotheses.schema import CitedRelationshipClaim
from core.intel.model import ConfidenceBand

_CERT_RELATIONSHIP = {
    "relationship_id": "rel-cert-1",
    "relationship_type": "SHARES_CERTIFICATE",
    "confidence": "HIGH",
}
_IP_RELATIONSHIP = {
    "relationship_id": "rel-ip-1",
    "relationship_type": "SHARES_IPV4",
    "confidence": "MEDIUM",
}
_EVIDENCE = RunEvidence(relationships=[_CERT_RELATIONSHIP, _IP_RELATIONSHIP], entities=[])


class TestScenario1GoodCalibratedHypothesis:
    """Design Section 7.2's own example: shared certificate treated as
    strong (HIGH, matching its real band), shared IP treated as weak
    (LOW, UNDERSTATING its real MEDIUM band — allowed, since only
    overstating is a problem)."""

    def test_existence_check_passes_for_both_real_citations(self) -> None:
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-cert-1",
                claimed_relationship_type="SHARES_CERTIFICATE",
                treated_as_strength=ConfidenceBand.HIGH,
            ),
            CitedRelationshipClaim(
                relationship_id="rel-ip-1",
                claimed_relationship_type="SHARES_IPV4",
                treated_as_strength=ConfidenceBand.LOW,
            ),
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert all(c.exists_in_run for c in citations)
        assert compute_grounding_status(citations) is GroundingStatus.GROUNDED

    def test_calibration_check_passes_when_strength_matches_or_understates(self) -> None:
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-cert-1",
                claimed_relationship_type="SHARES_CERTIFICATE",
                treated_as_strength=ConfidenceBand.HIGH,
            ),
            CitedRelationshipClaim(
                relationship_id="rel-ip-1",
                claimed_relationship_type="SHARES_IPV4",
                treated_as_strength=ConfidenceBand.LOW,
            ),
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert not any(c.overstated for c in citations)
        assert compute_calibration_status(citations) is CalibrationStatus.CALIBRATED

    def test_exact_match_to_the_real_band_is_calibrated_not_overstated(self) -> None:
        """Claiming exactly the real band (not just understating) must
        never itself count as an overstatement."""
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-ip-1",
                claimed_relationship_type="SHARES_IPV4",
                treated_as_strength=ConfidenceBand.MEDIUM,
            )
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert citations[0].overstated is False
        assert compute_calibration_status(citations) is CalibrationStatus.CALIBRATED


class TestScenario2OverstatedRealEvidence:
    """The adversarial case from design Section 7.2: a MEDIUM-confidence
    shared-IP relationship treated as if it were HIGH-confidence — real
    citation, dishonest characterization."""

    def test_grounded_but_overstated(self) -> None:
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-ip-1",
                claimed_relationship_type="SHARES_IPV4",
                treated_as_strength=ConfidenceBand.HIGH,
            )
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert compute_grounding_status(citations) is GroundingStatus.GROUNDED
        assert compute_calibration_status(citations) is CalibrationStatus.OVERSTATED
        assert citations[0].overstated is True
        assert citations[0].real_confidence_band == "MEDIUM"
        assert citations[0].treated_as_strength is ConfidenceBand.HIGH

    def test_one_overstated_citation_taints_the_whole_batch(self) -> None:
        """One honest citation plus one dishonest one must still fail
        calibration overall — never averaged away."""
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-cert-1",
                claimed_relationship_type="SHARES_CERTIFICATE",
                treated_as_strength=ConfidenceBand.HIGH,
            ),
            CitedRelationshipClaim(
                relationship_id="rel-ip-1",
                claimed_relationship_type="SHARES_IPV4",
                treated_as_strength=ConfidenceBand.VERY_HIGH,
            ),
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert compute_calibration_status(citations) is CalibrationStatus.OVERSTATED

    def test_relationship_type_mismatch_is_also_overstated(self) -> None:
        """Design Section 6: claiming a different relationship_type than
        the real row's own type is folded into the same OVERSTATED outcome
        as a confidence-level overstatement — 'exists but is
        misinterpreted' covers both."""
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-ip-1",
                claimed_relationship_type="SHARES_CERTIFICATE",  # real type is SHARES_IPV4
                treated_as_strength=ConfidenceBand.LOW,
            )
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert citations[0].exists_in_run is True
        assert citations[0].overstated is True
        assert compute_calibration_status(citations) is CalibrationStatus.OVERSTATED


class TestScenario3FabricatedCitation:
    """A relationship_id that does not exist for this run at all — the
    strict, no-fuzzy-tier existence check (design Section 6)."""

    def test_ungrounded(self) -> None:
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-does-not-exist",
                claimed_relationship_type="SHARES_CERTIFICATE",
                treated_as_strength=ConfidenceBand.HIGH,
            )
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert citations[0].exists_in_run is False
        assert compute_grounding_status(citations) is GroundingStatus.UNGROUNDED

    def test_fabricated_citation_overstated_is_none_not_true(self) -> None:
        """A distinct, correctly-separated failure mode: a citation that
        doesn't exist has no real band to compare against at all, so
        `overstated` must be None (not True) — never conflated with a
        calibration failure on real evidence."""
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-does-not-exist",
                claimed_relationship_type="SHARES_CERTIFICATE",
                treated_as_strength=ConfidenceBand.HIGH,
            )
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert citations[0].overstated is None
        assert citations[0].real_confidence_band is None
        # None-overstated citations must not spuriously flip calibration.
        assert compute_calibration_status(citations) is CalibrationStatus.CALIBRATED

    def test_partially_grounded_when_some_citations_are_real_and_some_are_not(self) -> None:
        claims = [
            CitedRelationshipClaim(
                relationship_id="rel-cert-1",
                claimed_relationship_type="SHARES_CERTIFICATE",
                treated_as_strength=ConfidenceBand.HIGH,
            ),
            CitedRelationshipClaim(
                relationship_id="rel-does-not-exist",
                claimed_relationship_type="SHARES_CERTIFICATE",
                treated_as_strength=ConfidenceBand.HIGH,
            ),
        ]
        citations = check_relationship_citations(claims, _EVIDENCE)
        assert compute_grounding_status(citations) is GroundingStatus.PARTIALLY_GROUNDED


class TestNoTreatedAsStrengthFailsClosed:
    def test_missing_treated_as_strength_is_overstated(self) -> None:
        """The schema requires treated_as_strength for a reason — a
        citation somehow missing it (e.g. a malformed/legacy payload) must
        fail closed as OVERSTATED, never silently pass calibration."""
        claim = CitedRelationshipClaim.model_construct(
            relationship_id="rel-cert-1",
            claimed_relationship_type="SHARES_CERTIFICATE",
            treated_as_strength=None,
        )
        citations = check_relationship_citations([claim], _EVIDENCE)
        assert citations[0].overstated is True


class TestCheckEntityCitations:
    def test_existing_entity_is_grounded_with_no_calibration_concept(self) -> None:
        evidence = RunEvidence(relationships=[], entities=[{"entity_id": "entity-1"}])
        citations = check_entity_citations(["entity-1"], evidence)
        assert citations[0].exists_in_run is True
        assert citations[0].overstated is None
        assert citations[0].treated_as_strength is None

    def test_nonexistent_entity_is_ungrounded(self) -> None:
        evidence = RunEvidence(relationships=[], entities=[])
        citations = check_entity_citations(["entity-ghost"], evidence)
        assert citations[0].exists_in_run is False
        assert compute_grounding_status(citations) is GroundingStatus.UNGROUNDED


class TestComputeGroundingStatusEdgeCases:
    def test_no_citations_at_all_is_ungrounded_not_grounded(self) -> None:
        """A hypothesis that cites nothing has nothing grounding it — an
        empty citation list must never default to GROUNDED."""
        assert compute_grounding_status([]) is GroundingStatus.UNGROUNDED

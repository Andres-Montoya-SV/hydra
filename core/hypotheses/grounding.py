"""The two mechanical grounding checks (docs/HYPOTHESIS_ENGINE_DESIGN.md
Section 6 and Section 7.2 — "the two grounding checks, not one" is this
implementation round's own explicit emphasis): does every entity/
relationship a hypothesis cites actually exist for this run, and does the
hypothesis's own claimed strength for each relationship citation exceed
what that relationship's real `ConfidenceBand` supports. Both are plain
data comparisons — no LLM judges its own citation here, matching
`core.verification.grounding.is_citation_grounded`'s own non-negotiable
discipline, adapted from text-matching to structured-data lookup.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.hypotheses.evidence import RunEvidence
from core.hypotheses.model import CalibrationStatus, CitedEvidence, EvidenceKind, GroundingStatus
from core.intel.model import ConfidenceBand

if TYPE_CHECKING:
    # Deferred: this module's own logic only ever duck-types `claim`
    # (attribute access), never constructs or isinstance-checks a
    # CitedRelationshipClaim — importing schema.py at module level would
    # make `core.hypotheses.grounding`, and therefore `core.hypotheses.cli`
    # (which imports this module), require pydantic just to import, which
    # is exactly the hard dependency cli.py's own docstring says must not
    # exist (schema.py/pydantic stay behind the provider construction
    # that's already deferred inside cmd_suggest_hypotheses's try/except).
    from core.hypotheses.schema import CitedRelationshipClaim

# Weakest to strongest — the ordinal scale both grounding checks compare
# on. A hypothesis is never penalized for UNDERSTATING a relationship's
# real strength (treating a HIGH-confidence relationship as merely
# MEDIUM is conservative, not a problem this check exists to catch);
# only OVERSTATING (claiming more than the real band supports) counts as
# a calibration failure, per design Section 7.2's own framing.
_BAND_RANK: dict[ConfidenceBand, int] = {
    ConfidenceBand.VERY_LOW: 0,
    ConfidenceBand.LOW: 1,
    ConfidenceBand.MEDIUM: 2,
    ConfidenceBand.HIGH: 3,
    ConfidenceBand.VERY_HIGH: 4,
}


def _real_band(value: object) -> ConfidenceBand | None:
    if not value:
        return None
    try:
        return ConfidenceBand(str(value))
    except ValueError:
        return None


def check_relationship_citations(
    claims: list[CitedRelationshipClaim], evidence: RunEvidence
) -> list[CitedEvidence]:
    """One `CitedEvidence` per relationship the hypothesis cited.

    Existence: does `relationship_id` appear in `evidence.relationships`
    for this run (the exact same evidence set the LLM was shown, gathered
    once by `core.hypotheses.evidence.gather_run_evidence` — not a second,
    potentially-different query).

    Calibration (design Section 7.2 / this round's Task 3): compares two
    independently-sourced signals about the SAME citation —
    `claim.treated_as_strength` (what the hypothesis's own structured
    output says it's treating this evidence as) against the real
    `ConfidenceBand` already computed by the correlation engine
    (`intel_relationships.confidence`). Overstated whenever the claimed
    rank exceeds the real rank, OR whenever the claim's own
    `claimed_relationship_type` doesn't match the real
    `relationship_type` — Section 6's "existence alone wouldn't catch"
    mischaracterization case folds into the same OVERSTATED outcome
    ("exists but is misinterpreted" covers both a confidence-level
    overstatement and a type mischaracterization equally). A citation
    with no `treated_as_strength` at all fails closed as OVERSTATED —
    never silently skipped, since the schema requires this field for a
    reason.
    """
    results: list[CitedEvidence] = []
    for claim in claims:
        real = evidence.relationship_by_id(claim.relationship_id)
        exists = real is not None
        real_band = _real_band(real.get("confidence")) if real else None
        overstated: bool | None
        if not exists:
            overstated = None
        elif claim.treated_as_strength is None:
            overstated = True
        elif claim.claimed_relationship_type and real is not None:
            real_type = str(real.get("relationship_type") or "")
            if claim.claimed_relationship_type != real_type:
                overstated = True
            else:
                claimed_rank = _BAND_RANK[claim.treated_as_strength]
                real_rank = _BAND_RANK.get(real_band) if real_band is not None else None
                overstated = real_rank is None or claimed_rank > real_rank
        else:
            claimed_rank = _BAND_RANK[claim.treated_as_strength]
            real_rank = _BAND_RANK.get(real_band) if real_band is not None else None
            overstated = real_rank is None or claimed_rank > real_rank
        results.append(
            CitedEvidence(
                evidence_kind=EvidenceKind.RELATIONSHIP,
                cited_id=claim.relationship_id,
                exists_in_run=exists,
                treated_as_strength=claim.treated_as_strength,
                real_confidence_band=real_band.value if real_band is not None else None,
                overstated=overstated,
            )
        )
    return results


def check_entity_citations(entity_ids: list[str], evidence: RunEvidence) -> list[CitedEvidence]:
    """One `CitedEvidence` per entity the hypothesis cited. Entities carry
    no `ConfidenceBand` (that concept only applies to relationships), so
    only existence is checked — `overstated` is always `None`, never a
    calibration failure."""
    return [
        CitedEvidence(
            evidence_kind=EvidenceKind.ENTITY,
            cited_id=entity_id,
            exists_in_run=evidence.entity_by_id(entity_id) is not None,
            treated_as_strength=None,
            real_confidence_band=None,
            overstated=None,
        )
        for entity_id in entity_ids
    ]


def compute_grounding_status(citations: list[CitedEvidence]) -> GroundingStatus:
    """Design Section 6: GROUNDED only if every citation exists;
    UNGROUNDED if none do (including a hypothesis with zero citations at
    all — a hypothesis that cites nothing has nothing grounding it);
    PARTIALLY_GROUNDED for a real mix, surfaced distinctly rather than
    collapsed into either extreme."""
    if not citations:
        return GroundingStatus.UNGROUNDED
    existing = [c for c in citations if c.exists_in_run]
    if not existing:
        return GroundingStatus.UNGROUNDED
    if len(existing) < len(citations):
        return GroundingStatus.PARTIALLY_GROUNDED
    return GroundingStatus.GROUNDED


def compute_calibration_status(citations: list[CitedEvidence]) -> CalibrationStatus:
    """OVERSTATED the moment any single citation is — one overstated
    citation is enough to mean a human should not take the hypothesis's
    characterization of its own evidence at face value, the same way one
    ungrounded citation is enough to make reportability distrust an
    entire assessment's citation rather than average it against the rest."""
    if any(c.overstated for c in citations if c.overstated is not None):
        return CalibrationStatus.OVERSTATED
    return CalibrationStatus.CALIBRATED

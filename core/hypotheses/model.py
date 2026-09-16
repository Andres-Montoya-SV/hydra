"""Data model for the hypothesis engine — see
docs/HYPOTHESIS_ENGINE_DESIGN.md Section 8 for why this is its own table
pair (`intel_llm_hypotheses`/`intel_llm_hypothesis_evidence`) rather than
a reuse of the existing, heuristic-populated `intel_hypotheses`.

Deliberately does not import anything from `core.reportability` — the
design (Part B) shares the LLM-calling layer, not the domain model; the
two features stay decoupled beyond that shared client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.intel.model import ConfidenceBand

# Re-exported so callers only need this module: a hypothesis's own
# per-citation "how strong is this evidence" claim is measured on the
# exact same scale the correlation engine already scores relationships
# on (docs/HYPOTHESIS_ENGINE_DESIGN.md Section 7.2's whole point is
# comparing the two), not a second, hypothesis-specific scale.
__all__ = [
    "ConfidenceBand",
    "Confidence",
    "GroundingStatus",
    "CalibrationStatus",
    "ReasoningChallenge",
    "ReasoningReviewStatus",
    "EvidenceKind",
    "CitedEvidence",
    "LlmHypothesis",
]


class Confidence(str, Enum):
    """The model's own self-reported confidence in the hypothesis as a
    whole (design Section A.2) — informational only, never mechanically
    checked (there is no ground truth for "how confident should you be,"
    only for "does the cited evidence exist and is it characterized
    correctly" — see GroundingStatus/CalibrationStatus below)."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class GroundingStatus(str, Enum):
    """Existence grounding (design Section 6): does every entity/
    relationship a hypothesis cites actually exist for this run_id in
    intel_relationships/intel_entities. A parameterized SQL lookup, no
    fuzzy tier — there is no legitimate reason for an LLM to cite an id
    that doesn't exist, unlike a paraphrased quote."""

    GROUNDED = "GROUNDED"
    PARTIALLY_GROUNDED = "PARTIALLY_GROUNDED"
    UNGROUNDED = "UNGROUNDED"


class CalibrationStatus(str, Enum):
    """Confidence-calibration check (design Section 7.2 / implementation
    round Task 3): a hypothesis can cite entirely real evidence
    (GROUNDED) while still treating a MEDIUM-confidence relationship as
    if it carried HIGH-confidence weight — "exists but is
    misinterpreted," meant to be flagged with the same severity as a
    fabricated citation. Computed mechanically (core/hypotheses/grounding.py)
    by comparing each citation's own `treated_as_strength` against the
    real `ConfidenceBand` on the underlying intel_relationships row —
    never judged by a second LLM."""

    CALIBRATED = "CALIBRATED"
    OVERSTATED = "OVERSTATED"


class ReasoningChallenge(str, Enum):
    """Reasoning-soundness review (design Part C, Section 4.2) — a second
    provider reviewing one already-produced hypothesis's statement against
    its own cited evidence, never an independently-generated second
    hypothesis compared for disagreement (design Section 4.3). SOUND is
    the only outcome that keeps the hypothesis's primary confidence;
    OVERREACHES and INSUFFICIENT_EVIDENCE both mean a human should not
    trust this hypothesis's reasoning at face value, mirroring
    reportability's ReviewChallenge fail-closed framing."""

    SOUND = "SOUND"
    OVERREACHES = "OVERREACHES"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ReasoningReviewStatus(str, Enum):
    """Coverage/integrity of the reasoning-soundness review batch itself
    (hardening round: "la revisión adversarial debe fallar cerrado ante
    índices incompletos/duplicados") — orthogonal to `ReasoningChallenge`,
    which is the per-hypothesis VERDICT a valid review gave. This tracks
    whether the review batch as a whole was even trustworthy enough to
    read a verdict from.

    NOT_REQUESTED: no `--adversarial-provider` was configured for this
    generation — absence of review must never, on its own, invalidate a
    hypothesis (a hypothesis with GROUNDED+CALIBRATED and no review
    requested is exactly as trustworthy as one whole design already
    intended for the pre-hardening-round behavior).

    COMPLETE: an adversarial provider was asked to review N hypotheses and
    returned exactly one valid review per hypothesis_index in range(N) —
    no duplicates, no missing, no out-of-range indices. Only in this case
    is the per-hypothesis `reasoning_review_challenge` trusted.

    INVALID: an adversarial provider was asked to review N hypotheses but
    the response was missing an index, duplicated one, or included one
    out of range — the hypotheses are still persisted (they were already
    real API spend, independently grounded/calibrated), but every one of
    them in this batch is forced untrustworthy: a provider that cannot
    reliably echo back which hypothesis it reviewed has given no reason to
    trust that any single verdict actually corresponds to the hypothesis
    it's attached to.
    """

    NOT_REQUESTED = "NOT_REQUESTED"
    COMPLETE = "COMPLETE"
    INVALID = "INVALID"


class EvidenceKind(str, Enum):
    """What kind of intel_* row a single citation refers to — a
    relationship (has a ConfidenceBand to calibrate against) or a bare
    entity (contextual support, e.g. the certificate entity itself
    alongside the SHARES_CERTIFICATE relationships that reference it; no
    calibration concept applies)."""

    RELATIONSHIP = "relationship"
    ENTITY = "entity"


@dataclass
class CitedEvidence:
    """One entity/relationship a hypothesis cited as support, plus the
    mechanical grounding-check result for that one citation. Persisted as
    one row in `intel_llm_hypothesis_evidence` per instance."""

    evidence_kind: EvidenceKind
    cited_id: str
    exists_in_run: bool
    # Only meaningful for evidence_kind=RELATIONSHIP: what strength the
    # hypothesis's own structured output claims this citation carries.
    # None for an ENTITY citation (entities have no ConfidenceBand to
    # calibrate against) or when the LLM simply didn't provide one.
    treated_as_strength: ConfidenceBand | None = None
    # The REAL confidence band found on the cited row, if it exists and
    # is a relationship. None if the citation doesn't exist, or is an
    # entity citation.
    real_confidence_band: str | None = None
    # True if treated_as_strength outranks real_confidence_band (an
    # overstatement), False if it does not, None when the comparison
    # doesn't apply (citation doesn't exist, is an entity, or the LLM
    # gave no treated_as_strength for a relationship citation — treated
    # as an automatic overstatement by the grounding check, never
    # silently skipped; see core/hypotheses/grounding.py).
    overstated: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_kind": self.evidence_kind.value,
            "cited_id": self.cited_id,
            "exists_in_run": self.exists_in_run,
            "treated_as_strength": (
                self.treated_as_strength.value if self.treated_as_strength else None
            ),
            "real_confidence_band": self.real_confidence_band,
            "overstated": self.overstated,
        }


@dataclass
class LlmHypothesis:
    """One LLM-proposed hypothesis, fully checked, ready to persist.
    `grounding_status`/`calibration_status` are always computed by
    `core/hypotheses/grounding.py` before construction — never left as a
    caller's guess."""

    statement: str
    provider: str
    model_used: str
    prompt_version: str
    grounding_status: GroundingStatus
    calibration_status: CalibrationStatus
    evidence: list[CitedEvidence] = field(default_factory=list)
    confidence: Confidence | None = None
    suggested_next_step: str = ""
    reasoning_review_challenge: ReasoningChallenge | None = None
    reasoning_review_status: ReasoningReviewStatus = ReasoningReviewStatus.NOT_REQUESTED
    reasoning_review_provider: str | None = None
    reasoning_review_model: str | None = None
    # Identifies which `suggest-hypotheses` invocation produced this row —
    # every hypothesis from the same call shares the same value (assigned
    # once by `core.store.AssetStore.record_llm_hypotheses`), so re-running
    # the command against the same run_id never conflates two separate
    # generations (hardening round, "identidad de generación"). None only
    # for an `LlmHypothesis` that hasn't been persisted yet.
    generation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "provider": self.provider,
            "model_used": self.model_used,
            "prompt_version": self.prompt_version,
            "grounding_status": self.grounding_status.value,
            "calibration_status": self.calibration_status.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "confidence": self.confidence.value if self.confidence is not None else None,
            "suggested_next_step": self.suggested_next_step,
            "reasoning_review_challenge": (
                self.reasoning_review_challenge.value
                if self.reasoning_review_challenge is not None
                else None
            ),
            "reasoning_review_status": self.reasoning_review_status.value,
            "reasoning_review_provider": self.reasoning_review_provider,
            "reasoning_review_model": self.reasoning_review_model,
            "generation_id": self.generation_id,
        }

    @property
    def trustworthy(self) -> bool:
        """The single "should a human treat this at face value" gate
        (design: overstated evidence "must be flagged the same as a
        fabricated citation"): both mechanical checks must pass, a
        requested-but-invalid reasoning review (missing/duplicate/
        out-of-range index — see `ReasoningReviewStatus`) must never be
        possible to read as trustworthy just because grounding/calibration
        happened to pass, and if a *valid* review ran, it must have
        returned SOUND. An absent review (never requested) does not, on
        its own, affect this — that is a distinct case from an invalid
        one. Never used to delete/hide an untrustworthy hypothesis — only
        to make sure it is never presented as equivalent to one that
        passed every check."""
        if self.grounding_status is not GroundingStatus.GROUNDED:
            return False
        if self.calibration_status is not CalibrationStatus.CALIBRATED:
            return False
        if self.reasoning_review_status is ReasoningReviewStatus.INVALID:
            return False
        if (
            self.reasoning_review_challenge is not None
            and self.reasoning_review_challenge is not ReasoningChallenge.SOUND
        ):
            return False
        return True

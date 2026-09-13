"""Data model for the reportability agent — see
docs/REPORTABILITY_AGENT_DESIGN.md Part A.2/C for the design this
implements, and the v2 addendum for the provider-agnostic / adversarial
cross-validation extensions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Eligibility(str, Enum):
    """Three-way, deliberately including UNCERTAIN as a first-class
    outcome (design Part A.2): program rules are often genuinely ambiguous
    about a specific finding shape, and a forced ELIGIBLE/NOT_ELIGIBLE
    binary would misrepresent confidence that doesn't exist. Do not
    collapse this to a boolean.
    """

    ELIGIBLE = "ELIGIBLE"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"
    UNCERTAIN = "UNCERTAIN"


class Confidence(str, Enum):
    """The model's own self-reported confidence in its verdict — a coarse,
    closed label, not a raw float. An LLM's numeric "0.87 confidence" is
    false precision it cannot actually justify; a three-way label is
    honest about the resolution this signal really has, matching this
    project's existing enum discipline (see `Eligibility` above).
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ReviewChallenge(str, Enum):
    """An adversarial reviewer's verdict on a *primary* assessment it was
    shown (design v2, adversarial cross-validation) — not a fresh,
    independent classification. AGREE and DISAGREE are self-explanatory;
    INSUFFICIENT_INFORMATION means the reviewer could not meaningfully
    confirm or challenge the primary's verdict from the material given.
    Both DISAGREE and INSUFFICIENT_INFORMATION fail closed to UNCERTAIN
    (see `combine_eligibility` below) — an adversarial check that could not
    confirm the primary's answer must never be treated the same as one
    that actively confirmed it.
    """

    AGREE = "AGREE"
    DISAGREE = "DISAGREE"
    INSUFFICIENT_INFORMATION = "INSUFFICIENT_INFORMATION"


def combine_eligibility(primary: Eligibility, challenge: ReviewChallenge) -> Eligibility:
    """The one place the fail-closed disagreement policy is implemented
    (design v2): never resolved by confidence, provider preference, or a
    majority vote — an adversarial AGREE is the only way `final_eligibility`
    can equal the primary verdict once adversarial review was requested at
    all. A genuine DISAGREE, or a reviewer that could not tell either way,
    both collapse to UNCERTAIN rather than silently falling back to
    trusting the primary alone — a review that could not confirm the
    primary's answer has not validated it.
    """
    if challenge is ReviewChallenge.AGREE:
        return primary
    return Eligibility.UNCERTAIN


@dataclass(frozen=True)
class ReportabilityAssessment:
    """One eligibility annotation for one persisted `Finding` (`finding_id`
    is the real `findings.id` row, a genuine foreign key — design Part
    C.1). `citation_grounded` is `None` exactly when `rule_citation` is the
    empty string (the model found no specific rule text to cite — a valid
    outcome, distinct from a citation that was offered and failed to
    verify); otherwise it is the real grounding-check result (design Part
    C.3), and a `False` here means `UNGROUNDED`, the single most important
    signal this whole system produces.

    `eligibility` is always the *primary* provider's raw verdict;
    `final_eligibility` is what every consumer should actually act on — it
    equals `eligibility` when no adversarial review ran, or the output of
    `combine_eligibility` when one did (design v2). Never read
    `eligibility` alone as "the answer" once adversarial review is in use.
    """

    finding_id: int
    eligibility: Eligibility
    final_eligibility: Eligibility
    rule_citation: str
    program_rules_artifact: str
    provider: str
    model_used: str
    rules_hash: str
    prompt_version: str
    confidence: Confidence | None = None
    citation_grounded: bool | None = None
    grounding_method: str = "none"
    reasoning: str | None = None
    source: str = "reportability_agent"

    def __post_init__(self) -> None:
        if self.rule_citation and self.citation_grounded is None:
            raise ValueError(
                "citation_grounded must be set (True/False) whenever rule_citation "
                "is non-empty — an ungrounded citation must never be indistinguishable "
                "from one that was never checked."
            )
        if not self.rule_citation and self.citation_grounded is not None:
            raise ValueError(
                "citation_grounded must be None when rule_citation is empty — "
                "there is nothing to have grounded."
            )

    @property
    def ungrounded(self) -> bool:
        """True exactly when a citation was offered and failed to verify —
        the case every consumer (CLI, report) must render with a visible
        warning, never at the same confidence as a grounded citation."""
        return self.citation_grounded is False

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "eligibility": self.eligibility.value,
            "final_eligibility": self.final_eligibility.value,
            "rule_citation": self.rule_citation,
            "citation_grounded": self.citation_grounded,
            "grounding_method": self.grounding_method,
            "reasoning": self.reasoning,
            "confidence": self.confidence.value if self.confidence is not None else None,
            "program_rules_artifact": self.program_rules_artifact,
            "provider": self.provider,
            "model_used": self.model_used,
            "rules_hash": self.rules_hash,
            "prompt_version": self.prompt_version,
            "source": self.source,
        }


@dataclass(frozen=True)
class AdversarialFindingReview:
    """One adversarial reviewer's challenge to one primary assessment
    (design v2). `assessment_id` is the real, already-persisted
    `reportability_assessments.id` row this review is about — assigned
    only after `AssetStore.record_reportability_assessments` returns, so
    this object is always constructed after the primary assessment it
    reviews already exists in the database.
    """

    assessment_id: int
    finding_id: int
    reviewer_provider: str
    reviewer_model: str
    challenge: ReviewChallenge
    prompt_version: str
    counter_eligibility: Eligibility | None = None
    reasoning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "finding_id": self.finding_id,
            "reviewer_provider": self.reviewer_provider,
            "reviewer_model": self.reviewer_model,
            "challenge": self.challenge.value,
            "counter_eligibility": (
                self.counter_eligibility.value if self.counter_eligibility is not None else None
            ),
            "reasoning": self.reasoning,
            "prompt_version": self.prompt_version,
        }

"""Data model for the reportability agent — see
docs/REPORTABILITY_AGENT_DESIGN.md Part A.2/C for the design this
implements.
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


@dataclass(frozen=True)
class ReportabilityAssessment:
    """One eligibility annotation for one persisted `Finding` (`finding_id`
    is the real `findings.id` row, a genuine foreign key — design Part
    C.1). `citation_grounded` is `None` exactly when `rule_citation` is the
    empty string (Claude found no specific rule text to cite — a valid
    outcome, distinct from a citation that was offered and failed to
    verify); otherwise it is the real grounding-check result (design Part
    C.3), and a `False` here means `UNGROUNDED`, the single most important
    signal this whole system produces.
    """

    finding_id: int
    eligibility: Eligibility
    rule_citation: str
    program_rules_artifact: str
    model_used: str
    citation_grounded: bool | None = None
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
            "rule_citation": self.rule_citation,
            "citation_grounded": self.citation_grounded,
            "reasoning": self.reasoning,
            "program_rules_artifact": self.program_rules_artifact,
            "source": self.source,
            "model_used": self.model_used,
        }

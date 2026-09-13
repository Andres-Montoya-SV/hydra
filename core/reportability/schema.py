"""Structured-output schemas sent to/received from the LLM APIs (design
Part B.3, v2 addendum for adversarial cross-validation) — Pydantic models.

For Claude, passed as `output_format` to `client.messages.parse()`; the
SDK converts this to `output_config.format` (a JSON Schema) internally —
confirmed by reading the installed `anthropic==1.5.0` SDK's own
`Messages.parse`/`Messages.count_tokens` source before writing this, not
assumed from the design doc alone.

For OpenAI, passed as `text_format` to `client.responses.parse()`; the
parsed result comes back on `response.output_parsed` — confirmed against
the current OpenAI API documentation (platform.openai.com/docs/guides/
structured-outputs) before writing core/reportability/openai_client.py,
since no `openai` package is installed in this environment to read SDK
source from directly.

Both providers are handed the *same* Pydantic model classes below — this
is what makes their outputs comparable without any provider-specific
parsing downstream.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

EligibilityLiteral = Literal["ELIGIBLE", "NOT_ELIGIBLE", "UNCERTAIN"]
ConfidenceLiteral = Literal["HIGH", "MEDIUM", "LOW"]
ReviewChallengeLiteral = Literal["AGREE", "DISAGREE", "INSUFFICIENT_INFORMATION"]


class FindingAssessment(BaseModel):
    """One finding's eligibility verdict. `rule_citation` must be a short,
    verbatim span of the rules text supplied in the same request — never a
    summary or paraphrase (design Part B.4: this is what makes mechanical
    grounding possible at all) — or the empty string when no specific rule
    applies to this finding. Never omit `rule_citation`; an empty string is
    a valid, deliberate answer, not a missing field.
    """

    finding_id: int = Field(
        description="The exact finding_id given for this finding in the request — copy it back unchanged."
    )
    eligibility: EligibilityLiteral
    confidence: ConfidenceLiteral = Field(
        description=(
            "Your own confidence in this verdict. Use LOW whenever the rules text leaves real "
            "room for doubt — do not default to HIGH to sound authoritative."
        )
    )
    rule_citation: str = Field(
        description=(
            "A short, verbatim quote from the rules text — copy the exact characters, "
            "never summarize or reword. Use an empty string only if no specific rule "
            "in the text applies to this finding."
        )
    )
    reasoning: str = Field(
        description="One or two sentences explaining the verdict. Informational only — never mechanically verified."
    )


class ReportabilityBatchResult(BaseModel):
    """The full structured response for one batch — one entry per finding
    in the request, in any order (matched back up by `finding_id`, not
    position)."""

    assessments: list[FindingAssessment]


class AdversarialFindingChallenge(BaseModel):
    """An adversarial reviewer's challenge to ONE primary assessment it was
    shown (design v2) — a review of that specific structured verdict, not a
    second, independent classification made from scratch. `counter_eligibility`
    is informational context for a human reader when `challenge` is
    DISAGREE; it is never used to pick a winner between two verdicts — see
    `core.reportability.model.combine_eligibility`, which only ever looks
    at `challenge` itself.
    """

    finding_id: int = Field(
        description="The exact finding_id this review is about — copy it back unchanged."
    )
    challenge: ReviewChallengeLiteral = Field(
        description=(
            "AGREE if the primary verdict and its citation are well-supported by the rules "
            "text and the finding as given. DISAGREE if you can point to a specific reason "
            "the primary verdict does not hold up. INSUFFICIENT_INFORMATION if you cannot "
            "meaningfully confirm or challenge it from what you were given — never guess "
            "AGREE just because nothing stood out."
        )
    )
    counter_eligibility: EligibilityLiteral | None = Field(
        default=None,
        description="Only when challenge=DISAGREE: what you believe the verdict should be instead.",
    )
    reasoning: str = Field(description="One or two sentences explaining the challenge verdict.")


class AdversarialBatchResult(BaseModel):
    """The full structured adversarial-review response for one batch — one
    challenge entry per finding_id in the primary batch it reviewed."""

    reviews: list[AdversarialFindingChallenge]

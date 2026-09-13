"""Structured-output schema sent to the Claude API (design Part B.3) —
Pydantic models, passed as `output_format` to `client.messages.parse()`.
The SDK converts this to `output_config.format` (a JSON Schema) internally
— confirmed by reading the installed `anthropic==1.5.0` SDK's own
`Messages.parse`/`Messages.count_tokens` source before writing this, not
assumed from the design doc alone.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

EligibilityLiteral = Literal["ELIGIBLE", "NOT_ELIGIBLE", "UNCERTAIN"]


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

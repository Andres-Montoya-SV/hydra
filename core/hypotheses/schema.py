"""Structured-output schemas sent to/received from the LLM APIs
(docs/HYPOTHESIS_ENGINE_DESIGN.md Part A.2, Section 6, Section 7.2) —
Pydantic models. Shares nothing with `core.reportability.schema` beyond
both being passed as `output_format`/`text_format` to the same shared
`core.llm.client` primitives (design Part B.2) — the reportability
agent's task (interpret program rules) and this one's (synthesize
correlated evidence) are different enough that a shared schema would
force one task's shape onto the other.

For Claude, passed as `output_format` to `client.messages.parse()`; for
OpenAI, passed as `text_format` to `client.responses.parse()` — same
verified API shapes `core.reportability.schema` already documents, via
the same shared `core.llm.client` module.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from core.hypotheses.model import Confidence, ReasoningChallenge
from core.intel.model import ConfidenceBand


class CitedRelationshipClaim(BaseModel):
    """One relationship the hypothesis cites as support. `relationship_id`
    must be a real, exact `relationship_id` from the evidence given in
    this request — never invented, never copied from memory of a
    different run. `treated_as_strength` and `claimed_relationship_type`
    are what makes the mechanical calibration check (design Section 7.2)
    possible at all: without them there is nothing to compare the real
    `ConfidenceBand`/`relationship_type` against except free prose.
    """

    relationship_id: str = Field(
        description="The exact relationship_id from the evidence you were given — copy it "
        "character-for-character. Never invent one."
    )
    claimed_relationship_type: str = Field(
        description="The exact relationship_type you believe this citation is (e.g. "
        "SHARES_CERTIFICATE, SHARES_IPV4) — copy it from the evidence given, not from memory."
    )
    treated_as_strength: ConfidenceBand = Field(
        description=(
            "How strong THIS SPECIFIC citation is to your argument, on the same "
            "VERY_HIGH/HIGH/MEDIUM/LOW/VERY_LOW scale the evidence itself is already scored on. "
            "This MUST NOT exceed the real confidence band already shown for this relationship "
            "in the evidence — you may treat it as weaker than its real band if your argument "
            "only needs it as corroborating support, but never as stronger. A MEDIUM-confidence "
            "shared-IP relationship must never be treated as HIGH-confidence evidence just "
            "because it supports your conclusion."
        )
    )


class HypothesisProposal(BaseModel):
    """One proposed hypothesis. `cited_relationship_ids`/`cited_entity_ids`
    are what the mechanical grounding check (design Section 6) verifies
    one citation at a time — never taken on the model's word."""

    statement: str = Field(
        description="One to three sentences of natural language for a human analyst to read — "
        "never a data-structure dump. Never use actor/owner/attribution language ('operated by "
        "the same actor', 'controlled by') — describe technical relationships only ('likely "
        "commonly-provisioned infrastructure', 'possible related infrastructure'). Never suggest "
        "or imply that new collection should be authorized or run."
    )
    cited_relationships: list[CitedRelationshipClaim] = Field(
        default_factory=list,
        description="Every intel_relationships row this statement is actually built from. A "
        "hypothesis with a factual claim but no citations here cannot be verified and will be "
        "treated as ungrounded.",
    )
    cited_entity_ids: list[str] = Field(
        default_factory=list,
        description="Any intel_entities entity_id values (e.g. a certificate entity) this "
        "statement also relies on, beyond the relationships above. Copy exact entity_id values "
        "from the evidence given — never invent one.",
    )
    confidence: Confidence = Field(
        description="Your own honest HIGH/MEDIUM/LOW confidence in this hypothesis given the "
        "evidence cited. Use LOW whenever the evidence leaves real room for doubt."
    )
    suggested_next_step: str = Field(
        default="",
        description="An optional, plain-language suggestion for what a human analyst might "
        "look at next (e.g. 'worth checking whether X and Y share infrastructure beyond what is "
        "already observed'). Never a structured, actionable instruction — never suggest running "
        "a specific tool, authorizing a specific target, or expanding scope. This is a note for "
        "a human, not a command.",
    )


class HypothesisBatchResult(BaseModel):
    """The full structured response for one batch — any number of
    hypotheses (unlike reportability's one-assessment-per-finding shape,
    there is no fixed count to validate a batch against; an empty list is
    a valid, honest answer when the evidence doesn't support a useful
    hypothesis)."""

    hypotheses: list[HypothesisProposal] = Field(default_factory=list)


class ReasoningSoundnessReview(BaseModel):
    """Reasoning-soundness review of ONE already-produced hypothesis
    (design Part C, Section 4.2) — never a fresh, independently-generated
    hypothesis to compare for disagreement (design Section 4.3 is
    explicit this is not what adversarial cross-validation means here).
    """

    hypothesis_index: int = Field(
        description="The exact index (0-based, in the order given) of the hypothesis you are "
        "reviewing — copy it back unchanged."
    )
    challenge: ReasoningChallenge = Field(
        description=(
            "SOUND: the statement's conclusion actually follows from the cited evidence, "
            "correctly characterizing how strong each piece of evidence really is. "
            "OVERREACHES: the statement draws a stronger conclusion than the cited evidence "
            "supports, even if every citation is real (e.g. treating a weak, corroborating "
            "signal as if it were independently conclusive). INSUFFICIENT_EVIDENCE: you cannot "
            "meaningfully judge whether the reasoning holds up from what you were given."
        )
    )
    reasoning: str = Field(
        description="One or two sentences explaining the challenge verdict. Informational only "
        "— never mechanically verified."
    )


class ReasoningSoundnessBatchResult(BaseModel):
    """The full structured adversarial-review response for one batch — one
    review entry per hypothesis_index in the batch it reviewed."""

    reviews: list[ReasoningSoundnessReview] = Field(default_factory=list)

"""Hard limits on a provider's structured hypothesis batch (hardening
round: "el proveedor no debe poder causar persistencia sin límite").
Distinct from `core.hypotheses.grounding`'s per-citation existence/
calibration checks — this module only asks "is this response small
enough to be a sane single batch," never whether its content is true.

Deliberately fixed constants, not settings/env-configurable: these bound
a structurally sane SINGLE provider response shape (a runaway or
adversarial provider trying to force unbounded persistence), not an
operator-tunable cost/scope knob — that role is already filled by
`HYPOTHESIS_MAX_RELATIONSHIPS_PER_BATCH`, which bounds INPUT size.

A violation here means the whole batch is structurally untrustworthy —
`validate_hypothesis_batch_limits` raises and the caller
(`core.hypotheses.cli`) refuses the entire call, persisting nothing,
mirroring `core.reportability.batch.validate_exact_batch`'s all-or-
nothing philosophy for a genuinely malformed response. This is
deliberately a different response than
`core.hypotheses.batch.find_reasoning_review_batch_defects`'s "persist
anyway, mark invalid" handling of an incomplete reasoning-review batch —
a structural limit violation on the PRIMARY batch is far more severe
than an optional secondary check coming back incomplete.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.hypotheses.errors import HypothesisBatchLimitError

if TYPE_CHECKING:
    from core.hypotheses.schema import HypothesisBatchResult

MAX_HYPOTHESES_PER_BATCH = 20
MAX_CITED_RELATIONSHIPS_PER_HYPOTHESIS = 20
MAX_CITED_ENTITIES_PER_HYPOTHESIS = 20
MAX_STATEMENT_LENGTH = 2000
MAX_SUGGESTED_NEXT_STEP_LENGTH = 1000


def validate_hypothesis_batch_limits(batch: HypothesisBatchResult) -> None:
    """Raises `HypothesisBatchLimitError` with a specific, actionable
    message the moment any hard limit is exceeded. Never truncates a list
    or a string and persists the truncated result — an out-of-bounds
    response is refused in full, not salvaged.
    """
    if len(batch.hypotheses) > MAX_HYPOTHESES_PER_BATCH:
        raise HypothesisBatchLimitError(
            f"Provider returned {len(batch.hypotheses)} hypotheses in one batch, exceeding "
            f"the hard limit of {MAX_HYPOTHESES_PER_BATCH}. Refusing to persist any of them "
            "rather than silently truncating the list."
        )
    for index, proposal in enumerate(batch.hypotheses):
        if len(proposal.statement) > MAX_STATEMENT_LENGTH:
            raise HypothesisBatchLimitError(
                f"hypotheses[{index}].statement is {len(proposal.statement)} characters "
                f"long, exceeding the hard limit of {MAX_STATEMENT_LENGTH}. Refusing to "
                "persist any hypothesis in this batch rather than silently truncating the "
                "text."
            )
        if len(proposal.suggested_next_step) > MAX_SUGGESTED_NEXT_STEP_LENGTH:
            raise HypothesisBatchLimitError(
                f"hypotheses[{index}].suggested_next_step is "
                f"{len(proposal.suggested_next_step)} characters long, exceeding the hard "
                f"limit of {MAX_SUGGESTED_NEXT_STEP_LENGTH}. Refusing to persist any "
                "hypothesis in this batch rather than silently truncating the text."
            )
        if len(proposal.cited_relationships) > MAX_CITED_RELATIONSHIPS_PER_HYPOTHESIS:
            raise HypothesisBatchLimitError(
                f"hypotheses[{index}] cites {len(proposal.cited_relationships)} "
                f"relationships, exceeding the hard limit of "
                f"{MAX_CITED_RELATIONSHIPS_PER_HYPOTHESIS}. Refusing to persist any "
                "hypothesis in this batch rather than silently truncating the citation list."
            )
        if len(proposal.cited_entity_ids) > MAX_CITED_ENTITIES_PER_HYPOTHESIS:
            raise HypothesisBatchLimitError(
                f"hypotheses[{index}] cites {len(proposal.cited_entity_ids)} entities, "
                f"exceeding the hard limit of {MAX_CITED_ENTITIES_PER_HYPOTHESIS}. Refusing "
                "to persist any hypothesis in this batch rather than silently truncating "
                "the citation list."
            )

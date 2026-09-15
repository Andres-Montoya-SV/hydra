"""Reasoning-soundness review batch completeness (hardening round: "la
revisión adversarial debe fallar cerrado ante índices incompletos/
duplicados"). Mirrors `core.reportability.batch.validate_exact_batch`'s
own discipline — same "requested N, must get exactly one valid entry per
requested id" check — adapted to `hypothesis_index` instead of
`finding_id`.

Deliberately does NOT raise: unlike reportability's primary batch (where
any defect voids the whole assessment and nothing is persisted),
reasoning review here is an optional, orthogonal check over hypotheses
that are already independently grounded/calibrated and already real API
spend. The caller (`core.hypotheses.cli`) decides what an invalid batch
means for persistence (docs/HYPOTHESIS_ENGINE_DESIGN.md hardening round:
persist the hypotheses regardless, but mark
`ReasoningReviewStatus.INVALID` and force `trustworthy` to `False`) —
this module only detects and describes the defects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.hypotheses.schema import ReasoningSoundnessReview


def find_reasoning_review_batch_defects(
    expected_count: int, reviews: list[ReasoningSoundnessReview]
) -> list[str]:
    """Returns a list of human-readable defect descriptions — empty if and
    only if `reviews` contains exactly one entry per index in
    `range(expected_count)`: no duplicates, no missing indices, no index
    outside that range (negative or >= expected_count). Never raises and
    never mutates `reviews` — a pure check the caller acts on.
    """
    if expected_count <= 0:
        # Nothing was requested — an empty or non-empty `reviews` list
        # would both be a provider echoing back something no one asked
        # for, but this module only ever runs when adversarial review WAS
        # requested for at least one hypothesis, so expected_count <= 0
        # here would itself be a caller bug, not a provider defect. Treat
        # defensively: any review at all is "out of range" (nothing was
        # in range).
        return (
            [f"received {len(reviews)} review(s) but 0 hypotheses were submitted for review"]
            if reviews
            else []
        )

    valid_range = range(expected_count)
    seen: set[int] = set()
    duplicates: set[int] = set()
    out_of_range: list[int] = []
    for review in reviews:
        idx = review.hypothesis_index
        if idx in seen:
            duplicates.add(idx)
        else:
            seen.add(idx)
        if idx not in valid_range:
            out_of_range.append(idx)

    missing = sorted(set(valid_range) - seen)

    defects: list[str] = []
    if duplicates:
        defects.append(f"duplicate hypothesis_index value(s): {sorted(duplicates)}")
    if out_of_range:
        defects.append(f"out-of-range hypothesis_index value(s): {sorted(out_of_range)}")
    if missing:
        defects.append(f"missing hypothesis_index value(s): {missing}")
    return defects

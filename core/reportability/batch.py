"""Exact-batch-validation (design v2, Section 6/24): a provider's
structured response must contain exactly one entry per requested
`finding_id`, no more, no fewer, no duplicates. This is checked once, in
one place, and reused for both the primary assessment batch and the
adversarial review batch — provider-agnostic, pure, no I/O.
"""

from __future__ import annotations

from core.reportability.errors import BatchValidationError


def validate_exact_batch(requested_ids: list[int], returned_items: list) -> None:
    """Raise `BatchValidationError` unless `returned_items` has exactly one
    entry per id in `requested_ids` (each item must expose a `.finding_id`
    attribute). Never silently drops or de-duplicates — any mismatch fails
    the whole batch, since a provider that got the ID bookkeeping wrong for
    part of a batch has given no reason to trust the rest of it either.
    """
    requested = set(requested_ids)
    returned_ids = [item.finding_id for item in returned_items]
    returned_set = set(returned_ids)
    duplicates = sorted({fid for fid in returned_ids if returned_ids.count(fid) > 1})
    missing = sorted(requested - returned_set)
    unexpected = sorted(returned_set - requested)
    if duplicates or missing or unexpected:
        problems = []
        if missing:
            problems.append(f"missing={missing}")
        if unexpected:
            problems.append(f"unexpected={unexpected}")
        if duplicates:
            problems.append(f"duplicated={duplicates}")
        raise BatchValidationError(
            "Provider batch response does not exactly match the requested finding_id "
            f"set ({', '.join(problems)}). Refusing to persist a partial or corrupted "
            "batch — nothing from this call has been written."
        )

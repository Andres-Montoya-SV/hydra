"""core/reportability/batch.py — exact-batch-validation (design v2,
Section 6/24). Pure, offline, no provider or network involved.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from core.reportability.batch import validate_exact_batch
from core.reportability.errors import BatchValidationError


@dataclass
class _Item:
    finding_id: int


def test_exact_match_passes() -> None:
    validate_exact_batch([1, 2, 3], [_Item(1), _Item(2), _Item(3)])


def test_exact_match_in_different_order_passes() -> None:
    """Matched by finding_id, not position (design Part B.2's own
    contract) — order must never matter."""
    validate_exact_batch([1, 2, 3], [_Item(3), _Item(1), _Item(2)])


def test_missing_id_rejects_the_whole_batch() -> None:
    with pytest.raises(BatchValidationError, match=r"missing=\[3\]"):
        validate_exact_batch([1, 2, 3], [_Item(1), _Item(2)])


def test_unexpected_id_rejects_the_whole_batch() -> None:
    with pytest.raises(BatchValidationError, match=r"unexpected=\[99\]"):
        validate_exact_batch([1, 2], [_Item(1), _Item(2), _Item(99)])


def test_duplicate_id_rejects_the_whole_batch() -> None:
    with pytest.raises(BatchValidationError, match=r"duplicated=\[1\]"):
        validate_exact_batch([1, 2], [_Item(1), _Item(1), _Item(2)])


def test_empty_batches_match() -> None:
    validate_exact_batch([], [])


def test_all_three_problems_reported_together() -> None:
    """missing + unexpected + duplicated can all be true in one malformed
    batch — the error message should surface all of it, not just the
    first problem found."""
    with pytest.raises(BatchValidationError) as exc_info:
        validate_exact_batch([1, 2, 3], [_Item(1), _Item(1), _Item(99)])
    message = str(exc_info.value)
    assert "missing=[2, 3]" in message
    assert "unexpected=[99]" in message
    assert "duplicated=[1]" in message

"""core/hypotheses/batch.py — reasoning-review batch completeness
(hardening round: "la revisión adversarial debe fallar cerrado ante
índices incompletos/duplicados"). Pure, offline, no provider or network
involved. See tests/test_hypotheses_cli.py::TestAdversarialReasoningReview
for the end-to-end persistence/trustworthy behavior this feeds into.
"""

from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from core.hypotheses.batch import find_reasoning_review_batch_defects  # noqa: E402
from core.hypotheses.schema import ReasoningSoundnessReview  # noqa: E402


def _review(index: int, challenge: str = "SOUND") -> ReasoningSoundnessReview:
    return ReasoningSoundnessReview(hypothesis_index=index, challenge=challenge, reasoning="x")


class TestCompleteBatch:
    def test_exactly_one_review_per_index_has_no_defects(self) -> None:
        reviews = [_review(0), _review(1), _review(2)]
        assert find_reasoning_review_batch_defects(3, reviews) == []

    def test_order_does_not_matter(self) -> None:
        reviews = [_review(2), _review(0), _review(1)]
        assert find_reasoning_review_batch_defects(3, reviews) == []

    def test_single_hypothesis_single_review(self) -> None:
        assert find_reasoning_review_batch_defects(1, [_review(0)]) == []


class TestMissingIndex:
    def test_one_missing_index_is_reported(self) -> None:
        defects = find_reasoning_review_batch_defects(3, [_review(0), _review(2)])
        assert any("missing hypothesis_index value(s): [1]" in d for d in defects)

    def test_all_missing_when_no_reviews_at_all(self) -> None:
        defects = find_reasoning_review_batch_defects(3, [])
        assert any("missing hypothesis_index value(s): [0, 1, 2]" in d for d in defects)


class TestDuplicateIndex:
    def test_duplicate_index_is_reported(self) -> None:
        defects = find_reasoning_review_batch_defects(3, [_review(0), _review(0), _review(2)])
        assert any("duplicate hypothesis_index value(s): [0]" in d for d in defects)

    def test_duplicate_also_implies_a_missing_index(self) -> None:
        """Two reviews for index 0 and none for index 1 must surface BOTH
        the duplicate and the resulting gap — never just one of the two
        real problems."""
        defects = find_reasoning_review_batch_defects(3, [_review(0), _review(0), _review(2)])
        assert any("duplicate" in d for d in defects)
        assert any("missing hypothesis_index value(s): [1]" in d for d in defects)


class TestOutOfRangeIndex:
    def test_index_beyond_expected_count_is_reported(self) -> None:
        defects = find_reasoning_review_batch_defects(2, [_review(0), _review(1), _review(5)])
        assert any("out-of-range hypothesis_index value(s): [5]" in d for d in defects)

    def test_negative_index_is_reported(self) -> None:
        defects = find_reasoning_review_batch_defects(3, [_review(-1), _review(1), _review(2)])
        assert any("out-of-range hypothesis_index value(s): [-1]" in d for d in defects)
        assert any("missing hypothesis_index value(s): [0]" in d for d in defects)

    def test_extra_review_beyond_requested_count_is_out_of_range(self) -> None:
        """More reviews than hypotheses requested, but with the extra one
        landing outside the valid range — this is what "extra revisión"
        looks like when it isn't also a duplicate of a valid index."""
        defects = find_reasoning_review_batch_defects(2, [_review(0), _review(1), _review(2)])
        assert any("out-of-range hypothesis_index value(s): [2]" in d for d in defects)
        assert not any("missing" in d for d in defects)


class TestNoReviewRequested:
    def test_zero_expected_and_zero_reviews_has_no_defects(self) -> None:
        assert find_reasoning_review_batch_defects(0, []) == []

    def test_zero_expected_but_a_review_arrived_anyway_is_a_defect(self) -> None:
        defects = find_reasoning_review_batch_defects(0, [_review(0)])
        assert defects


class TestAllProblemsReportedTogether:
    def test_duplicate_and_out_of_range_and_missing_all_surface(self) -> None:
        # requested 4 (indices 0-3); provider returns 0, 0 (dup), 9 (oob);
        # missing 1, 2, 3.
        defects = find_reasoning_review_batch_defects(4, [_review(0), _review(0), _review(9)])
        joined = "; ".join(defects)
        assert "duplicate" in joined
        assert "out-of-range" in joined
        assert "missing" in joined

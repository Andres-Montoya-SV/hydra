"""core/hypotheses/limits.py — hard structural limits on a provider's
hypothesis batch (hardening round: "el proveedor no debe poder causar
persistencia sin límite"). Pure, offline, no provider or network
involved.
"""

from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from core.hypotheses.errors import HypothesisBatchLimitError  # noqa: E402
from core.hypotheses.limits import (  # noqa: E402
    MAX_CITED_ENTITIES_PER_HYPOTHESIS,
    MAX_CITED_RELATIONSHIPS_PER_HYPOTHESIS,
    MAX_HYPOTHESES_PER_BATCH,
    MAX_STATEMENT_LENGTH,
    MAX_SUGGESTED_NEXT_STEP_LENGTH,
    validate_hypothesis_batch_limits,
)
from core.hypotheses.schema import (  # noqa: E402
    CitedRelationshipClaim,
    HypothesisBatchResult,
    HypothesisProposal,
)
from core.intel.model import ConfidenceBand  # noqa: E402


def _proposal(**overrides: object) -> HypothesisProposal:
    kwargs: dict[str, object] = dict(
        statement="A hypothesis statement.",
        cited_relationships=[],
        cited_entity_ids=[],
        confidence="HIGH",
        suggested_next_step="",
    )
    kwargs.update(overrides)
    return HypothesisProposal(**kwargs)


def _claim(i: int) -> CitedRelationshipClaim:
    return CitedRelationshipClaim(
        relationship_id=f"rel-{i}",
        claimed_relationship_type="SHARES_CERTIFICATE",
        treated_as_strength=ConfidenceBand.HIGH,
    )


class TestHypothesisCountLimit:
    def test_exactly_at_the_limit_passes(self) -> None:
        batch = HypothesisBatchResult(
            hypotheses=[_proposal() for _ in range(MAX_HYPOTHESES_PER_BATCH)]
        )
        validate_hypothesis_batch_limits(batch)  # must not raise

    def test_one_over_the_limit_raises(self) -> None:
        batch = HypothesisBatchResult(
            hypotheses=[_proposal() for _ in range(MAX_HYPOTHESES_PER_BATCH + 1)]
        )
        with pytest.raises(HypothesisBatchLimitError, match="exceeding the hard limit"):
            validate_hypothesis_batch_limits(batch)

    def test_empty_batch_passes(self) -> None:
        validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[]))


class TestCitedRelationshipsLimit:
    def test_exactly_at_the_limit_passes(self) -> None:
        proposal = _proposal(
            cited_relationships=[_claim(i) for i in range(MAX_CITED_RELATIONSHIPS_PER_HYPOTHESIS)]
        )
        validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[proposal]))

    def test_one_over_the_limit_raises(self) -> None:
        proposal = _proposal(
            cited_relationships=[
                _claim(i) for i in range(MAX_CITED_RELATIONSHIPS_PER_HYPOTHESIS + 1)
            ]
        )
        with pytest.raises(HypothesisBatchLimitError, match="cites .* relationships"):
            validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[proposal]))


class TestCitedEntitiesLimit:
    def test_exactly_at_the_limit_passes(self) -> None:
        proposal = _proposal(
            cited_entity_ids=[f"entity-{i}" for i in range(MAX_CITED_ENTITIES_PER_HYPOTHESIS)]
        )
        validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[proposal]))

    def test_one_over_the_limit_raises(self) -> None:
        proposal = _proposal(
            cited_entity_ids=[f"entity-{i}" for i in range(MAX_CITED_ENTITIES_PER_HYPOTHESIS + 1)]
        )
        with pytest.raises(HypothesisBatchLimitError, match="cites .* entities"):
            validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[proposal]))


class TestStatementLengthLimit:
    def test_exactly_at_the_limit_passes(self) -> None:
        proposal = _proposal(statement="x" * MAX_STATEMENT_LENGTH)
        validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[proposal]))

    def test_one_over_the_limit_raises(self) -> None:
        proposal = _proposal(statement="x" * (MAX_STATEMENT_LENGTH + 1))
        with pytest.raises(HypothesisBatchLimitError, match="statement is"):
            validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[proposal]))


class TestSuggestedNextStepLengthLimit:
    def test_exactly_at_the_limit_passes(self) -> None:
        proposal = _proposal(suggested_next_step="x" * MAX_SUGGESTED_NEXT_STEP_LENGTH)
        validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[proposal]))

    def test_one_over_the_limit_raises(self) -> None:
        proposal = _proposal(suggested_next_step="x" * (MAX_SUGGESTED_NEXT_STEP_LENGTH + 1))
        with pytest.raises(HypothesisBatchLimitError, match="suggested_next_step is"):
            validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[proposal]))


class TestNeverPartiallyAccepted:
    def test_a_valid_hypothesis_alongside_an_invalid_one_still_raises(self) -> None:
        """One good hypothesis plus one that breaks a limit must reject
        the WHOLE batch — never silently keep the good one and drop the
        bad one."""
        good = _proposal(statement="fine")
        bad = _proposal(statement="x" * (MAX_STATEMENT_LENGTH + 1))
        with pytest.raises(HypothesisBatchLimitError):
            validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[good, bad]))

    def test_error_identifies_which_hypothesis_index_violated_the_limit(self) -> None:
        good = _proposal(statement="fine")
        bad = _proposal(statement="x" * (MAX_STATEMENT_LENGTH + 1))
        with pytest.raises(HypothesisBatchLimitError, match=r"hypotheses\[1\]"):
            validate_hypothesis_batch_limits(HypothesisBatchResult(hypotheses=[good, bad]))


class TestStructurallyMalformedOutput:
    def test_missing_required_field_is_rejected_at_construction_not_silently_coerced(
        self,
    ) -> None:
        """A provider response missing a required field (e.g. `confidence`)
        never reaches `validate_hypothesis_batch_limits` at all — pydantic
        itself refuses to construct the object. This is the "estructuralmente
        malformado" case: fails closed one layer earlier than the hard
        limits, never coerced into a default and silently accepted."""
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            HypothesisProposal(
                statement="x",
                cited_relationships=[],
                cited_entity_ids=[],
                suggested_next_step="",
            )  # missing required `confidence`

    def test_invalid_confidence_value_is_rejected_at_construction(self) -> None:
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            HypothesisProposal(
                statement="x",
                cited_relationships=[],
                cited_entity_ids=[],
                confidence="EXTREMELY_HIGH",  # not a real Confidence value
                suggested_next_step="",
            )

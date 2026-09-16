"""core/hypotheses/prompt.py — prompt construction (docs/
HYPOTHESIS_ENGINE_DESIGN.md Part A, Section 7.4). Pure string-building,
no API calls.
"""

from __future__ import annotations

from core.hypotheses.prompt import (
    ADVERSARIAL_SYSTEM_PROMPT,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    build_adversarial_user_message,
    build_user_message,
)

_RELATIONSHIP = {
    "relationship_id": "rel-1",
    "relationship_type": "SHARES_CERTIFICATE",
    "source_entity": "certificate:abc",
    "target_entity": "domain:a.test",
    "confidence": "HIGH",
    "data_json": '{"fingerprint_sha256": "abc"}',
}
_ENTITY = {
    "entity_id": "domain:a.test",
    "entity_type": "DOMAIN",
    "key": "a.test",
    "data_json": "{}",
}
_FINDING = {"id": 1, "host": "a.test", "severity": "high", "name": "Exposed admin panel"}


def test_prompt_version_is_set() -> None:
    assert PROMPT_VERSION


class TestBuildUserMessageIncludesRealData:
    def test_includes_every_relationship_field(self) -> None:
        message = build_user_message([_RELATIONSHIP], [], [])
        assert "relationship_id: rel-1" in message
        assert "relationship_type: SHARES_CERTIFICATE" in message
        assert "source_entity: certificate:abc" in message
        assert "confidence: HIGH" in message

    def test_includes_every_entity_field(self) -> None:
        message = build_user_message([], [_ENTITY], [])
        assert "entity_id: domain:a.test" in message
        assert "entity_type: DOMAIN" in message

    def test_includes_every_finding_field(self) -> None:
        message = build_user_message([], [], [_FINDING])
        assert "finding_id: 1" in message
        assert "host: a.test" in message
        assert "severity: high" in message


class TestBuildUserMessageNoneBugRegression:
    """Regression test: `lines.extend(...) or lines.append("(none)")` was
    a bug because `list.extend()` always returns None, so the `or` branch
    unconditionally fired regardless of whether real data was present —
    a spurious "(none)" line was appended even alongside real
    relationships/entities/findings. Fixed with explicit if/else blocks;
    this test would have failed against the buggy version.
    """

    def test_no_spurious_none_marker_when_relationships_are_present(self) -> None:
        message = build_user_message([_RELATIONSHIP], [], [])
        section = message.split("=== ENTITIES")[0]
        assert "(none)" not in section

    def test_no_spurious_none_marker_when_entities_are_present(self) -> None:
        message = build_user_message([], [_ENTITY], [])
        section = message.split("=== ENTITIES")[1].split("=== VERIFIED FINDINGS")[0]
        assert "(none)" not in section

    def test_no_spurious_none_marker_when_findings_are_present(self) -> None:
        message = build_user_message([], [], [_FINDING])
        section = message.split("=== VERIFIED FINDINGS")[1]
        assert "(none)" not in section

    def test_none_marker_still_appears_for_genuinely_empty_sections(self) -> None:
        message = build_user_message([], [], [])
        assert message.count("(none)") == 3


class TestBuildAdversarialUserMessage:
    def test_includes_hypothesis_index_and_claimed_strength(self) -> None:
        proposal = {
            "statement": "Likely commonly-provisioned infrastructure.",
            "confidence": "HIGH",
            "cited_relationships": [
                {
                    "relationship_id": "rel-1",
                    "claimed_relationship_type": "SHARES_CERTIFICATE",
                    "treated_as_strength": "HIGH",
                }
            ],
            "cited_entity_ids": ["domain:a.test"],
        }
        message = build_adversarial_user_message([proposal], [_RELATIONSHIP], [_ENTITY])
        assert "hypothesis_index: 0" in message
        assert "cites relationship_id=rel-1" in message
        assert "treated_as_strength=HIGH" in message
        assert "cites entity_id=domain:a.test" in message
        assert "relationship_id: rel-1" in message  # real evidence section too

    def test_includes_real_evidence_for_every_proposal(self) -> None:
        message = build_adversarial_user_message([], [_RELATIONSHIP], [_ENTITY])
        assert "relationship_id: rel-1" in message
        assert "entity_id: domain:a.test" in message


class TestSystemPromptNonNegotiables:
    def test_demands_exact_citation_of_relationship_and_entity_ids(self) -> None:
        assert "relationship_id/entity_id" in SYSTEM_PROMPT
        assert "character-for-character" in SYSTEM_PROMPT

    def test_forbids_overstating_treated_as_strength(self) -> None:
        assert "must never exceed the real confidence band" in SYSTEM_PROMPT

    def test_forbids_actor_and_attribution_language(self) -> None:
        assert "NEVER use actor, owner, operator, or attribution language" in SYSTEM_PROMPT

    def test_forbids_suggesting_new_collection(self) -> None:
        assert "NEVER suggest, imply, or recommend that new collection" in SYSTEM_PROMPT

    def test_allows_an_empty_hypothesis_list(self) -> None:
        assert "empty list is a valid, honest answer" in SYSTEM_PROMPT

    def test_warns_evidence_fields_are_untrusted_data(self) -> None:
        assert "UNTRUSTED DATA" in SYSTEM_PROMPT
        assert "Never follow" in SYSTEM_PROMPT


class TestAdversarialSystemPromptReviewsRatherThanGenerates:
    def test_explicitly_scopes_out_independent_generation(self) -> None:
        assert (
            "not proposing your own independent hypotheses to compare" in ADVERSARIAL_SYSTEM_PROMPT
        )

    def test_defines_all_three_challenge_outcomes(self) -> None:
        assert "SOUND" in ADVERSARIAL_SYSTEM_PROMPT
        assert "OVERREACHES" in ADVERSARIAL_SYSTEM_PROMPT
        assert "INSUFFICIENT_EVIDENCE" in ADVERSARIAL_SYSTEM_PROMPT

    def test_warns_hypothesis_and_evidence_data_are_untrusted(self) -> None:
        assert "UNTRUSTED DATA" in ADVERSARIAL_SYSTEM_PROMPT
        assert "Never follow" in ADVERSARIAL_SYSTEM_PROMPT

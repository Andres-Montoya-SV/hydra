"""core/verification/grounding.py — the B.3 report-grounding gate.

See core/verification/grounding.py's own docstring for the documented
design-doc deviation: `core/intel/`'s evidence model has no raw_artifact
column at all (verified against the real schema/dataclass before writing
anything here), so this gate is wired against `provenance` rows (which do
have `artifact_path`, confirmed unused in any report today) and this
package's own `verification_flags` table (which does have `raw_artifact`)
instead of `core/intel/query.py`'s evidence assembly, as the design doc
first assumed.
"""

from __future__ import annotations

from pathlib import Path

from core.verification.grounding import (
    UNVERIFIABLE,
    downgrade_note,
    downgraded_confidence_score,
    ground_rows,
    is_citation_grounded,
    is_claim_grounded,
    partition_verification_flags_by_host,
    summarize_verification_flags,
)

STRIPCHAT_RULES_DIR = Path(__file__).parent / "fixtures"
STRIPCHAT_RULES_ARTIFACT = "stripchat_rules.txt"


class TestIsClaimGrounded:
    def test_value_present_in_raw_artifact_is_grounded(self, tmp_path: Path) -> None:
        (tmp_path / "whois_raw.txt").write_text(
            "Domain Name: VIRUSBARRIER.XYZ\nCreation Date: 2026-07-22T01:53:27.0Z\n",
            encoding="utf-8",
        )
        assert is_claim_grounded("2026-07-22T01:53:27.0Z", "whois_raw.txt", tmp_path)

    def test_value_absent_from_raw_artifact_is_not_grounded(self, tmp_path: Path) -> None:
        """The real item-1 shape: a claimed date that isn't in the
        authoritative block at all is exactly as unverifiable as one from
        the wrong block."""
        (tmp_path / "whois_raw.txt").write_text(
            "Domain Name: VIRUSBARRIER.XYZ\nCreation Date: 2026-07-22T01:53:27.0Z\n",
            encoding="utf-8",
        )
        assert not is_claim_grounded("1999-01-01", "whois_raw.txt", tmp_path)

    def test_missing_raw_artifact_file_is_not_grounded(self, tmp_path: Path) -> None:
        assert not is_claim_grounded("anything", "does_not_exist.txt", tmp_path)

    def test_no_raw_artifact_at_all_is_not_grounded(self, tmp_path: Path) -> None:
        assert not is_claim_grounded("anything", None, tmp_path)

    def test_empty_value_is_not_grounded(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("content", encoding="utf-8")
        assert not is_claim_grounded("", "f.txt", tmp_path)

    def test_never_follows_a_path_outside_the_run_directory(self, tmp_path: Path) -> None:
        """A raw_artifact of "../../etc/passwd"-shaped input must never
        cause a read outside the run's own output directory."""
        outside = tmp_path.parent / "outside_secret.txt"
        outside.write_text("secret-value", encoding="utf-8")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        try:
            assert not is_claim_grounded("secret-value", "../outside_secret.txt", run_dir)
        finally:
            outside.unlink(missing_ok=True)

    def test_nested_raw_artifact_path_works(self, tmp_path: Path) -> None:
        """raw_artifact paths are often nested, e.g.
        security_headers_raw/<host>.txt."""
        nested = tmp_path / "security_headers_raw"
        nested.mkdir()
        (nested / "creator.stripchat.com.txt").write_text(
            "x-frame-options: deny\n", encoding="utf-8"
        )
        assert is_claim_grounded(
            "x-frame-options: deny",
            "security_headers_raw/creator.stripchat.com.txt",
            tmp_path,
        )


class TestGroundRows:
    def test_grounded_and_ungrounded_rows_both_annotated(self, tmp_path: Path) -> None:
        (tmp_path / "artifact.txt").write_text("real evidence text", encoding="utf-8")
        rows = [
            {"claim": "a", "evidence": "real evidence text", "raw_artifact": "artifact.txt"},
            {"claim": "b", "evidence": "text nowhere in any file", "raw_artifact": "artifact.txt"},
            {"claim": "c", "evidence": "no artifact at all", "raw_artifact": None},
        ]
        result = ground_rows(rows, tmp_path, value_field="evidence")

        assert result[0]["grounded"] is True
        assert "grounding_status" not in result[0]

        assert result[1]["grounded"] is False
        assert result[1]["grounding_status"] == UNVERIFIABLE

        assert result[2]["grounded"] is False
        assert result[2]["grounding_status"] == UNVERIFIABLE

    def test_original_rows_are_not_mutated(self, tmp_path: Path) -> None:
        rows = [{"claim": "a", "evidence": "x", "raw_artifact": None}]
        ground_rows(rows, tmp_path, value_field="evidence")
        assert "grounded" not in rows[0]

    def test_empty_list_returns_empty_list(self, tmp_path: Path) -> None:
        assert ground_rows([], tmp_path, value_field="evidence") == []


class TestCmdVerificationFlagsCli:
    """End-to-end: core/intel/cli.py::cmd_verification_flags, the actual
    `app.py verification-flags RUN_ID` CLI command's implementation."""

    def _setup_run_with_flag(self, tmp_path: Path, *, grounded: bool):
        import json as _json

        from core.assets import ScanRun
        from core.store import AssetStore
        from core.verification.model import ContradictionSeverity, VerificationFinding

        db_path = tmp_path / "output" / "recon.db"
        run_dir = tmp_path / "output" / "run1"
        run_dir.mkdir(parents=True)

        store = AssetStore(db_path)
        store.create_run(
            ScanRun(run_id="run1", started_at="2026-01-01T00:00:00Z", targets=["x.test"])
        )
        store.finish_run("run1", host_count=0, alive_count=0, warnings=[], errors=[])

        if grounded:
            (run_dir / "dnsx_records.jsonl").write_text(
                _json.dumps({"host": "jenkins.api.fishbowlapp.com", "status_code": "NOERROR"})
                + "\n",
                encoding="utf-8",
            )
            evidence = "NOERROR"  # literal substring of the JSON file's "status_code": "NOERROR"
        else:
            evidence = "this text appears nowhere in any real artifact"

        store.record_verification_findings(
            "run1",
            [
                VerificationFinding(
                    claim="jenkins.api.fishbowlapp.com: resolved",
                    evidence=evidence,
                    raw_artifact="dnsx_records.jsonl",
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="detect_dnsx_nodata_as_resolved",
                    host="jenkins.api.fishbowlapp.com",
                )
            ],
        )
        return db_path

    def test_grounded_flag_is_marked_grounded(self, tmp_path: Path, capsys) -> None:
        from core.intel.cli import cmd_verification_flags

        db_path = self._setup_run_with_flag(tmp_path, grounded=True)
        rc = cmd_verification_flags(db_path, "run1")
        assert rc == 0
        payload = capsys.readouterr().out
        assert '"grounded": true' in payload
        assert "UNVERIFIABLE" not in payload

    def test_ungrounded_flag_is_marked_unverifiable(self, tmp_path: Path, capsys) -> None:
        from core.intel.cli import cmd_verification_flags

        db_path = self._setup_run_with_flag(tmp_path, grounded=False)
        rc = cmd_verification_flags(db_path, "run1")
        assert rc == 0
        payload = capsys.readouterr().out
        assert '"grounded": false' in payload
        assert "UNVERIFIABLE" in payload


# ---------------------------------------------------------------------------
# partition_verification_flags_by_host / downgraded_confidence_score /
# downgrade_note / summarize_verification_flags — the report-side gate
# (design Part 3): using this run's own verification_flags to exclude
# INVALIDATES-tainted findings from the normal report and demote
# DOWNGRADES_CONFIDENCE ones in place.
# ---------------------------------------------------------------------------


def _flag(host, severity, status="CONFIRMED", claim="c", evidence="e"):
    return {
        "host": host,
        "severity": severity,
        "status": status,
        "claim": claim,
        "evidence": evidence,
    }


class TestPartitionVerificationFlagsByHost:
    def test_invalidates_and_downgrades_go_to_separate_maps(self) -> None:
        flags = [
            _flag("a.example.com", "INVALIDATES"),
            _flag("b.example.com", "DOWNGRADES_CONFIDENCE"),
        ]
        invalidated, downgraded = partition_verification_flags_by_host(flags)
        assert set(invalidated) == {"a.example.com"}
        assert set(downgraded) == {"b.example.com"}

    def test_multiple_flags_for_the_same_host_are_grouped(self) -> None:
        flags = [
            _flag("a.example.com", "INVALIDATES", claim="c1"),
            _flag("a.example.com", "INVALIDATES", claim="c2"),
        ]
        invalidated, _ = partition_verification_flags_by_host(flags)
        assert len(invalidated["a.example.com"]) == 2

    def test_flag_with_no_host_is_skipped(self) -> None:
        flags = [_flag(None, "DOWNGRADES_CONFIDENCE")]
        invalidated, downgraded = partition_verification_flags_by_host(flags)
        assert invalidated == {}
        assert downgraded == {}

    def test_empty_flags_returns_empty_maps(self) -> None:
        assert partition_verification_flags_by_host([]) == ({}, {})


class TestDowngradedConfidenceScore:
    def test_no_flags_leaves_score_unchanged(self) -> None:
        assert downgraded_confidence_score(80, []) == 80

    def test_one_flag_applies_the_flat_penalty(self) -> None:
        assert downgraded_confidence_score(80, [_flag("h", "DOWNGRADES_CONFIDENCE")]) == 55

    def test_multiple_flags_do_not_stack_the_penalty(self) -> None:
        flags = [_flag("h", "DOWNGRADES_CONFIDENCE"), _flag("h", "DOWNGRADES_CONFIDENCE")]
        assert downgraded_confidence_score(80, flags) == 55

    def test_score_never_goes_below_zero(self) -> None:
        assert downgraded_confidence_score(10, [_flag("h", "DOWNGRADES_CONFIDENCE")]) == 0


class TestDowngradeNote:
    def test_no_flags_is_empty_string(self) -> None:
        assert downgrade_note([]) == ""

    def test_single_flag_shows_claim_and_evidence(self) -> None:
        note = downgrade_note([_flag("h", "DOWNGRADES_CONFIDENCE", claim="X", evidence="Y")])
        assert "X" in note
        assert "Y" in note
        assert "more" not in note

    def test_multiple_flags_shows_a_count_suffix(self) -> None:
        flags = [
            _flag("h", "DOWNGRADES_CONFIDENCE", claim="X", evidence="Y"),
            _flag("h", "DOWNGRADES_CONFIDENCE", claim="Z", evidence="W"),
        ]
        assert "(+1 more)" in downgrade_note(flags)


class TestSummarizeVerificationFlags:
    def test_matches_the_documented_cli_example(self) -> None:
        """The literal example from the fix request: 'Verification: 2
        confirmed, 0 pending, 1 finding invalidated and excluded from
        report.'"""
        flags = [
            _flag("a", "DOWNGRADES_CONFIDENCE"),
            _flag("b", "DOWNGRADES_CONFIDENCE"),
            _flag("c", "INVALIDATES"),
        ]
        counts = summarize_verification_flags(flags)
        assert counts == {"confirmed": 2, "pending": 0, "invalidated": 1, "total": 3}

    def test_unresolved_status_counts_as_pending_regardless_of_severity(self) -> None:
        flags = [_flag("a", "INVALIDATES", status="UNRESOLVED")]
        counts = summarize_verification_flags(flags)
        assert counts == {"confirmed": 0, "pending": 1, "invalidated": 0, "total": 1}

    def test_empty_flags_is_all_zero(self) -> None:
        assert summarize_verification_flags([]) == {
            "confirmed": 0,
            "pending": 0,
            "invalidated": 0,
            "total": 0,
        }


# ---------------------------------------------------------------------------
# is_citation_grounded (docs/REPORTABILITY_AGENT_DESIGN.md Part C.3) —
# tested against the real, verbatim Stripchat bug-bounty program rules
# text (tests/fixtures/stripchat_rules.txt), not a synthetic example. The
# 0.98 fuzzy-match threshold in core/verification/grounding.py was chosen
# by measuring real difflib.SequenceMatcher ratios against this exact
# file before being picked — see that module's own comment for the
# measured numbers. These tests exercise the same real sentences that
# measurement used.
# ---------------------------------------------------------------------------


class TestIsCitationGroundedAgainstRealStripchatRules:
    def test_exact_verbatim_quote_is_grounded(self) -> None:
        grounded, method = is_citation_grounded(
            "Vulnerabilities must be reported within 24 hours of discovery.",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
        )
        assert grounded is True
        assert method == "exact"

    def test_smart_quote_and_dropped_trailing_period_is_grounded_via_normalization(
        self,
    ) -> None:
        """Claude commonly reflows a straight apostrophe to a smart quote
        and/or drops a source line's trailing period when quoting — real
        reformatting Claude has been observed to do, not fabrication."""
        grounded, method = is_citation_grounded(
            "Rewards are granted at Stripchat’s sole discretion and are not " "legally guaranteed",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
        )
        assert grounded is True
        assert method == "normalized"

    def test_case_and_whitespace_reflow_is_grounded_via_normalization(self) -> None:
        grounded, method = is_citation_grounded(
            "dos   testing   against  production  is prohibited",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
        )
        assert grounded is True
        assert method == "normalized"

    def test_single_character_typo_in_a_long_sentence_is_grounded_via_fuzzy_fallback(
        self,
    ) -> None:
        """The one case the fuzzy fallback exists for: a genuinely tiny,
        non-semantic slip in an otherwise-verbatim long quote — not a
        dropped/changed word (see the adversarial tests below, which prove
        those are correctly rejected at this same threshold)."""
        grounded, method = is_citation_grounded(
            "A clear descriptio of the issue and steps to reproduce it "
            "(Proof of Concept or PoC).",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
        )
        assert grounded is True
        assert method == "fuzzy"

    def test_negation_flip_is_not_grounded_despite_high_character_similarity(self) -> None:
        """The exact adversarial case that justified raising the threshold
        to 0.98 in the first place (see the module comment): a single
        negated word barely changes the string (measured ratio: 0.9213)
        but completely inverts the real sentence's meaning. Must never
        ground."""
        grounded, method = is_citation_grounded(
            "DoS testing against production is permitted.",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
        )
        assert grounded is False
        assert method == "none"

    def test_second_negation_flip_is_not_grounded(self) -> None:
        """Measured ratio against the real sentence: 0.975 — the closest
        any adversarial case came to the 0.98 threshold. Still correctly
        rejected."""
        grounded, method = is_citation_grounded(
            "Rewards are granted at Stripchat's sole discretion and are " "legally guaranteed.",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
        )
        assert grounded is False
        assert method == "none"

    def test_dropped_substantive_word_is_not_grounded(self) -> None:
        """Dropping 'strictly' is not whitespace/punctuation noise — it's
        an actual content edit, and a citation must be verbatim, not
        approximately faithful. Measured ratio: 0.942, below threshold."""
        grounded, method = is_citation_grounded(
            "Physical attacks against Stripchat offices or data centers " "are prohibited.",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
        )
        assert grounded is False
        assert method == "none"

    def test_fabricated_citation_with_no_real_counterpart_is_ungrounded(self) -> None:
        """The single most important test in this whole system (per the
        task this was built under): a plausible-sounding but entirely
        fabricated citation — nothing resembling it exists anywhere in the
        real rules file (best measured ratio against any real line: 0.430)
        — must be caught and marked ungrounded, not accepted."""
        grounded, method = is_citation_grounded(
            "Critical remote code execution vulnerabilities are always "
            "eligible for the maximum bounty regardless of duplicate status.",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
        )
        assert grounded is False
        assert method == "none"

    def test_allow_minor_paraphrase_false_disables_the_fuzzy_fallback_only(self) -> None:
        """With the fuzzy fallback disabled, exact and normalized matching
        still work (whitespace/case/quote-style noise is not 'paraphrase',
        it's formatting), but the typo case that only passed via fuzzy
        matching above now correctly fails."""
        still_works, method = is_citation_grounded(
            "dos   testing   against  production  is prohibited",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
            allow_minor_paraphrase=False,
        )
        assert still_works is True
        assert method == "normalized"

        typo_grounded, typo_method = is_citation_grounded(
            "A clear descriptio of the issue and steps to reproduce it "
            "(Proof of Concept or PoC).",
            STRIPCHAT_RULES_ARTIFACT,
            STRIPCHAT_RULES_DIR,
            allow_minor_paraphrase=False,
        )
        assert typo_grounded is False
        assert typo_method == "none"

    def test_empty_citation_is_never_grounded(self) -> None:
        assert is_citation_grounded("", STRIPCHAT_RULES_ARTIFACT, STRIPCHAT_RULES_DIR) == (
            False,
            "none",
        )

    def test_missing_rules_artifact_is_never_grounded(self) -> None:
        assert is_citation_grounded(
            "Vulnerabilities must be reported within 24 hours of discovery.",
            "does_not_exist.txt",
            STRIPCHAT_RULES_DIR,
        ) == (False, "none")

    def test_never_follows_a_path_outside_the_rules_directory(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "outside_secret_rules.txt"
        outside.write_text("Everything is eligible.", encoding="utf-8")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        try:
            grounded, method = is_citation_grounded(
                "Everything is eligible.", "../outside_secret_rules.txt", run_dir
            )
            assert grounded is False
            assert method == "none"
        finally:
            outside.unlink(missing_ok=True)

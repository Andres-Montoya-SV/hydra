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

from core.verification.grounding import UNVERIFIABLE, ground_rows, is_claim_grounded


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

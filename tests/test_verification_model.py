"""core/verification/model.py + the verification_flags table
(core/store.py). See docs/VERIFICATION_AGENT_DESIGN.md Part B.2/C.
"""

from __future__ import annotations

from pathlib import Path

from core.assets import ScanRun
from core.store import AssetStore
from core.verification.model import ContradictionSeverity, VerificationFinding, VerificationStatus


def test_contradiction_severity_is_exactly_two_values() -> None:
    """Design Part B.2 is explicit: two values, not a numeric scale. This
    test exists so widening it silently is caught immediately."""
    assert {member.value for member in ContradictionSeverity} == {
        "INVALIDATES",
        "DOWNGRADES_CONFIDENCE",
    }


def test_verification_finding_to_dict_round_trips_enum_values() -> None:
    finding = VerificationFinding(
        claim="x-frame-options: missing",
        evidence="x_frame_options: deny",
        raw_artifact="security_headers_raw/host.txt",
        severity=ContradictionSeverity.INVALIDATES,
        detector="detect_security_headers_key_mismatch",
        host="host.example.com",
    )
    data = finding.to_dict()
    assert data["severity"] == "INVALIDATES"
    assert data["status"] == "CONFIRMED"
    assert data["host"] == "host.example.com"
    assert data["raw_artifact"] == "security_headers_raw/host.txt"


def test_verification_finding_defaults_to_confirmed_status() -> None:
    finding = VerificationFinding(
        claim="c",
        evidence="e",
        raw_artifact=None,
        severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
        detector="detect_naabu_nmap_port_disagreement",
    )
    assert finding.status is VerificationStatus.CONFIRMED
    assert finding.host is None
    assert finding.related_table is None


def test_unresolved_status_has_no_related_row_by_convention(tmp_path: Path) -> None:
    """Item 9 (test-count discrepancy): an UNRESOLVED flag is run-scoped,
    with no single row to blame — related_table/related_id stay None."""
    finding = VerificationFinding(
        claim="test count discrepancy (518 vs 511) never fully explained",
        evidence="no confirmed root cause identified",
        raw_artifact=None,
        severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
        detector="none — no detector exists for this catalog item by design",
        status=VerificationStatus.UNRESOLVED,
    )
    assert finding.status is VerificationStatus.UNRESOLVED
    assert finding.related_table is None
    assert finding.related_id is None


def test_verification_flags_table_persists_and_reads_back(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(ScanRun(run_id="r1", started_at="2026-01-01T00:00:00Z", targets=["x.test"]))
    store.finish_run("r1", host_count=0, alive_count=0, warnings=[], errors=[])

    finding = VerificationFinding(
        claim="jenkins.api.fishbowlapp.com resolved",
        evidence='dnsx record has only "soa", no a/aaaa',
        raw_artifact="dnsx_records.jsonl",
        severity=ContradictionSeverity.INVALIDATES,
        detector="detect_dnsx_nodata_as_resolved",
        host="jenkins.api.fishbowlapp.com",
    )
    store.record_verification_findings("r1", [finding])

    rows = store.get_verification_flags("r1")
    assert len(rows) == 1
    assert rows[0]["detector"] == "detect_dnsx_nodata_as_resolved"
    assert rows[0]["severity"] == "INVALIDATES"
    assert rows[0]["status"] == "CONFIRMED"
    assert rows[0]["host"] == "jenkins.api.fishbowlapp.com"


def test_get_verification_flags_filters_by_status(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(ScanRun(run_id="r1", started_at="2026-01-01T00:00:00Z", targets=["x.test"]))
    store.finish_run("r1", host_count=0, alive_count=0, warnings=[], errors=[])

    store.record_verification_findings(
        "r1",
        [
            VerificationFinding(
                claim="a",
                evidence="b",
                raw_artifact=None,
                severity=ContradictionSeverity.INVALIDATES,
                detector="d1",
                status=VerificationStatus.CONFIRMED,
            ),
            VerificationFinding(
                claim="c",
                evidence="d",
                raw_artifact=None,
                severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
                detector="d2",
                status=VerificationStatus.UNRESOLVED,
            ),
        ],
    )

    confirmed = store.get_verification_flags("r1", status="CONFIRMED")
    unresolved = store.get_verification_flags("r1", status="UNRESOLVED")
    assert len(confirmed) == 1 and confirmed[0]["detector"] == "d1"
    assert len(unresolved) == 1 and unresolved[0]["detector"] == "d2"


def test_record_verification_findings_empty_list_is_a_noop(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(ScanRun(run_id="r1", started_at="2026-01-01T00:00:00Z", targets=["x.test"]))
    store.record_verification_findings("r1", [])
    assert store.get_verification_flags("r1") == []


def test_run_persists_scope_file_hash_and_attribution_fingerprint(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(
        ScanRun(
            run_id="r1",
            started_at="2026-01-01T00:00:00Z",
            targets=["x.test"],
            program_name="ProgA",
            scope_file_hash="sha256:abc",
            attribution_fingerprint="sha256:def",
        )
    )
    row = store.get_run("r1")
    assert row is not None
    assert row["scope_file_hash"] == "sha256:abc"
    assert row["attribution_fingerprint"] == "sha256:def"


def test_find_latest_finished_run_for_program(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(
        ScanRun(
            run_id="old",
            started_at="2026-01-01T00:00:00Z",
            targets=["a.test"],
            program_name="ProgA",
        )
    )
    store.finish_run("old", host_count=0, alive_count=0, warnings=[], errors=[])
    store.create_run(
        ScanRun(
            run_id="new",
            started_at="2026-02-01T00:00:00Z",
            targets=["b.test"],
            program_name="ProgA",
        )
    )
    store.finish_run("new", host_count=0, alive_count=0, warnings=[], errors=[])
    store.create_run(
        ScanRun(
            run_id="other-program",
            started_at="2026-03-01T00:00:00Z",
            targets=["c.test"],
            program_name="ProgB",
        )
    )
    store.finish_run("other-program", host_count=0, alive_count=0, warnings=[], errors=[])

    assert store.find_latest_finished_run_for_program("ProgA") == "new"
    assert store.find_latest_finished_run_for_program("ProgB") == "other-program"
    assert store.find_latest_finished_run_for_program("NoSuchProgram") is None
    assert store.find_latest_finished_run_for_program("") is None


def test_find_latest_finished_run_for_program_ignores_unfinished_runs(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(
        ScanRun(
            run_id="unfinished",
            started_at="2026-01-01T00:00:00Z",
            targets=["a.test"],
            program_name="ProgA",
        )
    )
    assert store.find_latest_finished_run_for_program("ProgA") is None

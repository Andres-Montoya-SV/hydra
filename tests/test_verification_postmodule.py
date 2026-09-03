"""core/verification/postmodule.py — wires the four B.2 detectors to the
real artifacts a run writes to `output_dir`. Every fixture here is the exact
real data already used to prove each detector correct in
tests/test_verification_detectors.py (fishbowlapp.com dnsx, creator.stripchat.com
headers, virusbarrier.xyz WHOIS and port_verify) — reused, not re-derived, so
this test proves the wiring, not the detection logic itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.assets import ScanRun
from core.verification.model import ContradictionSeverity
from core.verification.postmodule import (
    _check_dnsx,
    _check_port_verify,
    _check_security_headers,
    _check_whois,
    _extract_domain_whois_section,
    run_post_module_checks,
)

# Same real fixture as tests/test_verification_detectors.py::FISHBOWL_NODATA_RECORD
FISHBOWL_NODATA_RECORD = {
    "host": "jenkins.api.fishbowlapp.com",
    "soa": [{"name": "fishbowlapp.com", "ns": "irma.ns.cloudflare.com"}],
    "status_code": "NOERROR",
}
FISHBOWL_RESOLVED_RECORD = {
    "host": "api.fishbowlapp.com",
    "a": ["104.18.32.42"],
    "status_code": "NOERROR",
}

# Same real fixture as tests/test_verification_detectors.py::STRIPCHAT_REAL_HTTPX_HEADER
STRIPCHAT_REAL_HTTPX_HEADER = {
    "server": "cloudflare",
    "strict_transport_security": "max-age=31536000; includeSubDomains",
    "x_frame_options": "deny",
}

# Same real fixture as tests/test_verification_detectors.py::VIRUSBARRIER_WHOIS_RAW
VIRUSBARRIER_WHOIS_RAW = """% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.nic.xyz

domain:       XYZ

organisation: XYZ.COM LLC
address:      4425 Spring Mountain Rd., Suite 2
address:      Las Vegas NV 89102
address:      United States of America (the)

contact:      technical
name:         CTO
organisation: CentralNic
e-mail:       tld.ops@centralnic.com

nserver:      GENERATIONXYZ.NIC.XYZ 212.18.249.42
whois:        whois.nic.xyz

status:       ACTIVE
remarks:      Registration information: https://nic.xyz

created:      2014-02-06
changed:      2025-08-12
source:       IANA

# whois.nic.xyz

Domain Name: VIRUSBARRIER.XYZ
Registry Domain ID: D633493768-CNIC
Registrar WHOIS Server: whois.spaceship.com
Registrar URL: https://www.spaceship.com/
Updated Date: 2026-07-22T01:53:28.0Z
Creation Date: 2026-07-22T01:53:27.0Z
Registry Expiry Date: 2027-07-22T23:59:59.0Z
Registrar: Spaceship, Inc.
Registrar IANA ID: 3862
Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
Name Server: LAUNCH2.SPACESHIP.NET
Name Server: LAUNCH1.SPACESHIP.NET
DNSSEC: signedDelegation
Registrar Abuse Contact Email: abuse@spaceship.com
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2026-08-04T18:46:53.0Z <<<

# whois.spaceship.com
"""


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


class TestCheckDnsx:
    def test_fishbowlapp_nodata_wrongly_in_resolved_txt_is_flagged(self, tmp_path: Path) -> None:
        _write_jsonl(
            tmp_path / "dnsx_records.jsonl",
            [FISHBOWL_NODATA_RECORD, FISHBOWL_RESOLVED_RECORD],
        )
        (tmp_path / "resolved.txt").write_text(
            "jenkins.api.fishbowlapp.com\napi.fishbowlapp.com\n", encoding="utf-8"
        )

        findings = _check_dnsx(tmp_path)

        assert len(findings) == 1
        assert findings[0].host == "jenkins.api.fishbowlapp.com"
        assert findings[0].severity is ContradictionSeverity.INVALIDATES
        assert findings[0].raw_artifact == "dnsx_records.jsonl"

    def test_nodata_correctly_excluded_from_resolved_txt_is_not_flagged(
        self, tmp_path: Path
    ) -> None:
        """The fix already holds: NODATA host never made it into resolved.txt."""
        _write_jsonl(
            tmp_path / "dnsx_records.jsonl",
            [FISHBOWL_NODATA_RECORD, FISHBOWL_RESOLVED_RECORD],
        )
        (tmp_path / "resolved.txt").write_text("api.fishbowlapp.com\n", encoding="utf-8")

        assert _check_dnsx(tmp_path) == []

    def test_missing_dnsx_records_file_skips_cleanly(self, tmp_path: Path) -> None:
        assert _check_dnsx(tmp_path) == []

    def test_missing_resolved_txt_treats_nothing_as_resolved(self, tmp_path: Path) -> None:
        """No resolved.txt at all means no host was counted resolved —
        never a false flag purely because the file is absent."""
        _write_jsonl(tmp_path / "dnsx_records.jsonl", [FISHBOWL_NODATA_RECORD])
        assert _check_dnsx(tmp_path) == []


class TestCheckSecurityHeaders:
    def test_stripchat_headers_falsely_claimed_missing_are_flagged(self, tmp_path: Path) -> None:
        _write_jsonl(
            tmp_path / "httpx.json",
            [
                {
                    "host": "creator.stripchat.com",
                    "url": "https://creator.stripchat.com/",
                    "header": STRIPCHAT_REAL_HTTPX_HEADER,
                }
            ],
        )
        _write_jsonl(
            tmp_path / "security_headers.jsonl",
            [
                {
                    "host": "creator.stripchat.com",
                    "header_key": "strict-transport-security",
                    "missing": True,
                    "raw_artifact": "security_headers_raw/creator.stripchat.com.txt",
                },
                {
                    "host": "creator.stripchat.com",
                    "header_key": "content-security-policy",
                    "missing": True,
                    "raw_artifact": "security_headers_raw/creator.stripchat.com.txt",
                },
            ],
        )

        findings = _check_security_headers(tmp_path)

        assert len(findings) == 1
        assert findings[0].host == "creator.stripchat.com"
        assert findings[0].severity is ContradictionSeverity.INVALIDATES
        assert "strict-transport-security" in findings[0].claim
        assert "content-security-policy" not in findings[0].claim
        assert findings[0].raw_artifact == "security_headers_raw/creator.stripchat.com.txt"

    def test_genuinely_missing_headers_are_not_flagged(self, tmp_path: Path) -> None:
        _write_jsonl(
            tmp_path / "httpx.json",
            [{"host": "plain.example.com", "header": {"server": "nginx"}}],
        )
        _write_jsonl(
            tmp_path / "security_headers.jsonl",
            [
                {
                    "host": "plain.example.com",
                    "header_key": "strict-transport-security",
                    "missing": True,
                    "raw_artifact": "security_headers_raw/plain.example.com.txt",
                }
            ],
        )

        assert _check_security_headers(tmp_path) == []

    def test_missing_artifacts_skip_cleanly(self, tmp_path: Path) -> None:
        assert _check_security_headers(tmp_path) == []


class TestCheckWhois:
    def test_virusbarrier_tld_date_claimed_as_creation_is_flagged(self, tmp_path: Path) -> None:
        raw_text = f"===== virusbarrier.xyz =====\n{VIRUSBARRIER_WHOIS_RAW}\n"
        (tmp_path / "whois_raw.txt").write_text(raw_text, encoding="utf-8")
        _write_jsonl(
            tmp_path / "whois.jsonl",
            [
                {
                    "domain": "virusbarrier.xyz",
                    "created_at": "2014-02-06",
                    "raw_artifact": "whois_raw.txt",
                }
            ],
        )

        findings = _check_whois(tmp_path)

        assert len(findings) == 1
        assert findings[0].host == "virusbarrier.xyz"
        assert findings[0].severity is ContradictionSeverity.INVALIDATES
        assert "2014-02-06" in findings[0].claim

    def test_correct_registrar_date_is_not_flagged(self, tmp_path: Path) -> None:
        raw_text = f"===== virusbarrier.xyz =====\n{VIRUSBARRIER_WHOIS_RAW}\n"
        (tmp_path / "whois_raw.txt").write_text(raw_text, encoding="utf-8")
        _write_jsonl(
            tmp_path / "whois.jsonl",
            [
                {
                    "domain": "virusbarrier.xyz",
                    "created_at": "2026-07-22T01:53:27.0Z",
                    "raw_artifact": "whois_raw.txt",
                }
            ],
        )

        assert _check_whois(tmp_path) == []

    def test_multi_domain_shared_raw_file_does_not_cross_contaminate(self, tmp_path: Path) -> None:
        """whois_raw.txt is one shared file across every queried domain
        (modules/whois.py) — a second, clean domain's own section must not
        pick up virusbarrier.xyz's TLD-block date."""
        other_raw = (
            "Domain Name: EXAMPLE.COM\nRegistrar: NameCheap, Inc.\n" "Creation Date: 2020-01-01\n"
        )
        raw_text = (
            f"===== virusbarrier.xyz =====\n{VIRUSBARRIER_WHOIS_RAW}\n"
            f"===== example.com =====\n{other_raw}\n"
        )
        (tmp_path / "whois_raw.txt").write_text(raw_text, encoding="utf-8")
        _write_jsonl(
            tmp_path / "whois.jsonl",
            [
                {
                    "domain": "virusbarrier.xyz",
                    "created_at": "2014-02-06",
                    "raw_artifact": "whois_raw.txt",
                },
                {
                    "domain": "example.com",
                    "created_at": "2020-01-01",
                    "raw_artifact": "whois_raw.txt",
                },
            ],
        )

        findings = _check_whois(tmp_path)

        assert len(findings) == 1
        assert findings[0].host == "virusbarrier.xyz"

    def test_missing_artifacts_skip_cleanly(self, tmp_path: Path) -> None:
        assert _check_whois(tmp_path) == []


class TestCheckPortVerify:
    def test_virusbarrier_port_37_disagreement_is_flagged(self, tmp_path: Path) -> None:
        _write_jsonl(
            tmp_path / "port_verify.jsonl",
            [
                {
                    "host": "virusbarrier.xyz",
                    "port": 37,
                    "naabu_state": "open",
                    "nmap_state": "filtered",
                    "raw_artifact": "port_verify_raw/virusbarrier.xyz.txt",
                },
                {
                    "host": "virusbarrier.xyz",
                    "port": 4899,
                    "naabu_state": "open",
                    "nmap_state": "open",
                    "raw_artifact": "port_verify_raw/virusbarrier.xyz.txt",
                },
            ],
        )

        findings = _check_port_verify(tmp_path)

        assert len(findings) == 1
        assert findings[0].host == "virusbarrier.xyz"
        assert findings[0].severity is ContradictionSeverity.DOWNGRADES_CONFIDENCE
        assert findings[0].raw_artifact == "port_verify_raw/virusbarrier.xyz.txt"

    def test_missing_artifact_skips_cleanly(self, tmp_path: Path) -> None:
        assert _check_port_verify(tmp_path) == []


class TestExtractDomainWhoisSection:
    def test_unknown_marker_returns_full_text(self) -> None:
        assert _extract_domain_whois_section("no markers here", "example.com") == (
            "no markers here"
        )


class TestRunPostModuleChecks:
    def test_clean_run_produces_zero_findings(self, tmp_path: Path) -> None:
        """Every artifact present, every value internally consistent — the
        'Verificacion final' #2 requirement: no false positives."""
        _write_jsonl(tmp_path / "dnsx_records.jsonl", [FISHBOWL_RESOLVED_RECORD])
        (tmp_path / "resolved.txt").write_text("api.fishbowlapp.com\n", encoding="utf-8")

        _write_jsonl(
            tmp_path / "httpx.json",
            [{"host": "clean.example.com", "header": {"server": "nginx"}}],
        )
        _write_jsonl(
            tmp_path / "security_headers.jsonl",
            [
                {
                    "host": "clean.example.com",
                    "header_key": "strict-transport-security",
                    "missing": True,
                    "raw_artifact": "security_headers_raw/clean.example.com.txt",
                }
            ],
        )

        clean_whois_raw = (
            "Domain Name: EXAMPLE.COM\nRegistrar: NameCheap, Inc.\n" "Creation Date: 2020-01-01\n"
        )
        (tmp_path / "whois_raw.txt").write_text(
            f"===== example.com =====\n{clean_whois_raw}\n", encoding="utf-8"
        )
        _write_jsonl(
            tmp_path / "whois.jsonl",
            [
                {
                    "domain": "example.com",
                    "created_at": "2020-01-01",
                    "raw_artifact": "whois_raw.txt",
                }
            ],
        )

        _write_jsonl(
            tmp_path / "port_verify.jsonl",
            [
                {
                    "host": "clean.example.com",
                    "port": 443,
                    "naabu_state": "open",
                    "nmap_state": "open",
                    "raw_artifact": "port_verify_raw/clean.example.com.txt",
                }
            ],
        )

        assert run_post_module_checks(tmp_path) == []

    def test_empty_output_dir_produces_zero_findings(self, tmp_path: Path) -> None:
        assert run_post_module_checks(tmp_path) == []

    def test_aggregates_findings_from_every_detector_at_once(self, tmp_path: Path) -> None:
        """All four real-incident fixtures present at once in one run
        directory — proves the four checks compose without interfering."""
        _write_jsonl(
            tmp_path / "dnsx_records.jsonl",
            [FISHBOWL_NODATA_RECORD, FISHBOWL_RESOLVED_RECORD],
        )
        (tmp_path / "resolved.txt").write_text(
            "jenkins.api.fishbowlapp.com\napi.fishbowlapp.com\n", encoding="utf-8"
        )

        _write_jsonl(
            tmp_path / "httpx.json",
            [{"host": "creator.stripchat.com", "header": STRIPCHAT_REAL_HTTPX_HEADER}],
        )
        _write_jsonl(
            tmp_path / "security_headers.jsonl",
            [
                {
                    "host": "creator.stripchat.com",
                    "header_key": "strict-transport-security",
                    "missing": True,
                    "raw_artifact": "security_headers_raw/creator.stripchat.com.txt",
                }
            ],
        )

        (tmp_path / "whois_raw.txt").write_text(
            f"===== virusbarrier.xyz =====\n{VIRUSBARRIER_WHOIS_RAW}\n", encoding="utf-8"
        )
        _write_jsonl(
            tmp_path / "whois.jsonl",
            [
                {
                    "domain": "virusbarrier.xyz",
                    "created_at": "2014-02-06",
                    "raw_artifact": "whois_raw.txt",
                }
            ],
        )

        _write_jsonl(
            tmp_path / "port_verify.jsonl",
            [
                {
                    "host": "virusbarrier.xyz",
                    "port": 37,
                    "naabu_state": "open",
                    "nmap_state": "filtered",
                    "raw_artifact": "port_verify_raw/virusbarrier.xyz.txt",
                }
            ],
        )

        findings = run_post_module_checks(tmp_path)

        detectors = {f.detector for f in findings}
        assert detectors == {
            "detect_dnsx_nodata_as_resolved",
            "detect_security_headers_key_mismatch",
            "detect_whois_block_specificity",
            "detect_naabu_nmap_port_disagreement",
        }
        severities = {f.detector: f.severity for f in findings}
        assert severities["detect_naabu_nmap_port_disagreement"] is (
            ContradictionSeverity.DOWNGRADES_CONFIDENCE
        )
        assert severities["detect_dnsx_nodata_as_resolved"] is ContradictionSeverity.INVALIDATES


class TestRunPostModuleChecksWiredIntoFinalize:
    """core/runner.py::PipelineRunner._finalize_to_store actually calls
    run_post_module_checks and persists the result to verification_flags —
    not just that the function works in isolation. Drives the real
    finalize path directly (rather than the full PipelineRunner.run(),
    which needs real tool binaries) the same way
    tests/test_runner.py::test_live_network_state_plugins_never_replay_cached_results
    builds a minimal real PipelineContext to exercise runner internals
    hermetically.
    """

    @pytest.mark.asyncio
    async def test_real_fishbowlapp_nodata_bug_is_captured_in_verification_flags(
        self, settings: Settings, project_root: Path
    ) -> None:
        """'Verificacion final' #1: reproduce the real item-6 incident
        (a fishbowlapp.com NODATA record wrongly counted resolved) through
        the real _finalize_to_store path and confirm verification_flags
        captured it with INVALIDATES severity."""
        from core.intel.scope import CollectionScope
        from core.models import PipelineContext
        from core.runner import PipelineRunner
        from core.store import AssetStore

        db_path = project_root / "output" / "recon.db"
        store = AssetStore(db_path)
        store.create_run(ScanRun(run_id="run1", started_at="2026-01-01T00:00:00Z", targets=[]))

        output_dir = project_root / "output" / "run1"
        output_dir.mkdir(parents=True)
        _write_jsonl(
            output_dir / "dnsx_records.jsonl",
            [FISHBOWL_NODATA_RECORD, FISHBOWL_RESOLVED_RECORD],
        )
        (output_dir / "resolved.txt").write_text(
            "jenkins.api.fishbowlapp.com\napi.fishbowlapp.com\n", encoding="utf-8"
        )

        context = PipelineContext(
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["fishbowlapp.com"]),
        )
        context.run_id = "run1"

        runner = PipelineRunner(settings)
        runner._finalize_to_store(context, store)

        flags = store.get_verification_flags("run1")
        dnsx_flags = [f for f in flags if f["detector"] == "detect_dnsx_nodata_as_resolved"]
        assert len(dnsx_flags) == 1
        assert dnsx_flags[0]["severity"] == ContradictionSeverity.INVALIDATES.value
        assert dnsx_flags[0]["host"] == "jenkins.api.fishbowlapp.com"
        assert any("detect_dnsx_nodata_as_resolved" in w for w in context.warnings)

    @pytest.mark.asyncio
    async def test_clean_run_produces_zero_flags_end_to_end(
        self, settings: Settings, project_root: Path
    ) -> None:
        """'Verificacion final' #2: a run whose dnsx artifacts are already
        internally consistent produces zero verification_flags rows."""
        from core.intel.scope import CollectionScope
        from core.models import PipelineContext
        from core.runner import PipelineRunner
        from core.store import AssetStore

        db_path = project_root / "output" / "recon.db"
        store = AssetStore(db_path)
        store.create_run(ScanRun(run_id="run1", started_at="2026-01-01T00:00:00Z", targets=[]))

        output_dir = project_root / "output" / "run1"
        output_dir.mkdir(parents=True)
        _write_jsonl(output_dir / "dnsx_records.jsonl", [FISHBOWL_RESOLVED_RECORD])
        (output_dir / "resolved.txt").write_text("api.fishbowlapp.com\n", encoding="utf-8")

        context = PipelineContext(
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["fishbowlapp.com"]),
        )
        context.run_id = "run1"

        runner = PipelineRunner(settings)
        runner._finalize_to_store(context, store)

        assert store.get_verification_flags("run1") == []

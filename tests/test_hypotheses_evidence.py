"""core/hypotheses/evidence.py — gather_run_evidence (docs/
HYPOTHESIS_ENGINE_DESIGN.md Section A.1). Uses the correlation engine
directly (like tests/test_intel_virusbarrier.py) rather than hand-built
SQL rows, so this test exercises the real intel_relationships/
intel_entities shape gather_run_evidence actually reads.
"""

from __future__ import annotations

from pathlib import Path

from core.assets import Finding, Host, RiskLevel, ScanRun
from core.hypotheses.evidence import DEFAULT_MAX_RELATIONSHIPS, gather_run_evidence
from core.intel.engine import IntelEngine, IntelRunConfig
from core.store import AssetStore
from core.verification.model import ContradictionSeverity, VerificationFinding, VerificationStatus

RUN_ID = "evidence-run"
SEED = "example.test"


def _engine_with_one_relationship() -> IntelEngine:
    config = IntelRunConfig(
        run_id=RUN_ID,
        seed_domains=[SEED],
        scope_patterns=[SEED],
        collected_domains={SEED},
        observed_at="2026-08-21T00:00:00Z",
    )
    engine = IntelEngine(config)
    engine.ingest_passive_resolutions({SEED: "203.0.113.10", "sibling.test": "203.0.113.10"})
    engine.correlate()
    return engine


def _seed_store(tmp_path: Path, *, with_finding_host: str | None = None) -> AssetStore:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-08-21T00:00:00Z", targets=[SEED]))
    engine = _engine_with_one_relationship()
    hosts: dict[str, Host] = {}
    if with_finding_host:
        hosts[with_finding_host] = Host(
            domain=with_finding_host,
            hostname=with_finding_host,
            risk_level=RiskLevel.HIGH,
            risk_score=70,
            findings=[
                Finding(
                    host=with_finding_host,
                    template_id="exposed-admin-panel",
                    severity="high",
                    name="Exposed admin panel",
                    source="nuclei",
                )
            ],
        )
    store.persist_registry(RUN_ID, hosts, intel=engine.snapshot())
    return store


class TestGatherRunEvidence:
    def test_reads_relationships_and_entities_for_the_run(self, tmp_path: Path) -> None:
        store = _seed_store(tmp_path)
        evidence = gather_run_evidence(store, RUN_ID)
        assert evidence.relationships
        assert evidence.entities
        assert not evidence.is_empty

    def test_empty_run_returns_empty_evidence(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        store.create_run(
            ScanRun(run_id="empty-run", started_at="2026-08-21T00:00:00Z", targets=[SEED])
        )
        evidence = gather_run_evidence(store, "empty-run")
        assert evidence.is_empty
        assert evidence.relationships == []
        assert evidence.entities == []
        assert evidence.findings == []

    def test_relationship_by_id_finds_a_real_relationship(self, tmp_path: Path) -> None:
        store = _seed_store(tmp_path)
        evidence = gather_run_evidence(store, RUN_ID)
        real_id = evidence.relationships[0]["relationship_id"]
        assert evidence.relationship_by_id(real_id) is not None
        assert evidence.relationship_by_id("does-not-exist") is None

    def test_entity_by_id_finds_a_real_entity(self, tmp_path: Path) -> None:
        store = _seed_store(tmp_path)
        evidence = gather_run_evidence(store, RUN_ID)
        real_id = evidence.entities[0]["entity_id"]
        assert evidence.entity_by_id(real_id) is not None
        assert evidence.entity_by_id("does-not-exist") is None

    def test_max_relationships_caps_how_many_rows_are_read(self, tmp_path: Path) -> None:
        store = _seed_store(tmp_path)
        evidence = gather_run_evidence(store, RUN_ID, max_relationships=1)
        assert len(evidence.relationships) <= 1

    def test_default_max_relationships_constant_is_reasonable(self) -> None:
        assert DEFAULT_MAX_RELATIONSHIPS > 0

    def test_findings_are_included_when_present(self, tmp_path: Path) -> None:
        store = _seed_store(tmp_path, with_finding_host="admin.example.test")
        evidence = gather_run_evidence(store, RUN_ID)
        assert any(f["host"] == "admin.example.test" for f in evidence.findings)

    def test_finding_on_host_with_confirmed_invalidates_flag_is_excluded(
        self, tmp_path: Path
    ) -> None:
        """Design: 'an unverified or invalidated finding must never become
        hypothesis input.' The real verification_flags schema links via
        `host`, not a specific findings.id (see this module's own
        docstring) — this test proves the exclusion actually happens at
        that real granularity."""
        store = _seed_store(tmp_path, with_finding_host="admin.example.test")
        store.record_verification_findings(
            RUN_ID,
            [
                VerificationFinding(
                    claim="Finding is stale",
                    evidence="Host no longer resolves",
                    raw_artifact=None,
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="test-detector",
                    host="admin.example.test",
                    status=VerificationStatus.CONFIRMED,
                )
            ],
        )
        evidence = gather_run_evidence(store, RUN_ID)
        assert not any(f["host"] == "admin.example.test" for f in evidence.findings)

    def test_finding_on_host_with_unresolved_flag_is_not_excluded(self, tmp_path: Path) -> None:
        """Only a CONFIRMED + INVALIDATES flag excludes a finding — an
        UNRESOLVED or DISMISSED flag must not silently drop real input."""
        store = _seed_store(tmp_path, with_finding_host="admin.example.test")
        store.record_verification_findings(
            RUN_ID,
            [
                VerificationFinding(
                    claim="Possibly stale",
                    evidence="Unconfirmed",
                    raw_artifact=None,
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="test-detector",
                    host="admin.example.test",
                    status=VerificationStatus.UNRESOLVED,
                )
            ],
        )
        evidence = gather_run_evidence(store, RUN_ID)
        assert any(f["host"] == "admin.example.test" for f in evidence.findings)

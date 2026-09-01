"""Correlation-engine contract fixture (docs/CORRELATION_ENGINE_DESIGN.md).

This is the exact contract the 2026 Cursor architecture review asked for:
given `virusbarrier.xyz` as the only in-scope seed, and a certificate shared
with five off-root siblings (`virusinspector.top`, `cybermedic.buzz`,
`defendervault.shop`, `shieldvertex.mom`, `safesentinel.lol`), the engine
must retain all six names as observations, collect only the in-scope seed,
record the siblings without probing them, produce a HIGH-confidence
`shares_certificate` relationship and a MEDIUM (never HIGH) `shares_ipv4`
relationship, never use attribution language, and expose a non-empty graph
through the CLI query surface even when the CLI was given a single hostname.

Every assertion here restates one already covered — separately — by
`tests/test_intel_virusbarrier.py` (engine-level) and `tests/test_intel_cli.py`
/ `tests/test_cli_acceptance.py` (CLI-level). This file exists as the single
place that proves the *whole* contract together, using the real fixture, so
future changes that satisfy each half in isolation but break the seam
between them (engine snapshot -> SQLite -> CLI query) get caught. See
docs/CORRELATION_ENGINE_DESIGN.md Section 4 for why this passes today rather
than failing: the gap the original review described was already closed by
later work (SAN-as-observation in `core/intel/engine.py`, evidence-backed
relationships in `core/intel/correlate.py`, and the CLI query path in
`core/intel/cli.py` / `core/intel/query.py`).

`test_shared_ipv4_relationship_is_medium_not_high` calls
`ingest_passive_resolutions()` directly, same as `test_intel_virusbarrier.py`
— that is an engine-level shortcut, not something any collector plugin feeds
in a real run today. `tests/test_virusbarrier_e2e.py`
(`test_virusbarrier_pipeline_e2e_seed_only`) drives the *actual* production
finalize path with no such shortcut and correctly asserts `shared_ip == []`
for a real seed-only scan — no plugin populates `passive_dns.jsonl` yet, so
the `shares_ipv4` edge for off-root siblings is real in the model but does
not surface on a live scan without one. See CORRELATION_ENGINE_DESIGN.md
Section 3 for that as a proposed next increment.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.assets import ScanRun
from core.intel.cli import cmd_investigate, cmd_relationships
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.model import CollectionStatus, ConfidenceBand, RelationshipType, ScopeStatus
from core.store import AssetStore

FIXTURE = Path(__file__).parent / "fixtures" / "virusbarrier"
CASE = json.loads((FIXTURE / "case.json").read_text(encoding="utf-8"))
SANS = list(CASE["sans"])
SEED = CASE["seed"]
IP = CASE["ipv4"]
FINGERPRINT = CASE["fingerprint_sha256"]
SIBLINGS = [name for name in SANS if name != SEED]


def _run_engine(tmp_path: Path) -> IntelEngine:
    for name in ("ctlogs.jsonl", "httpx.json"):
        (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())
    config = IntelRunConfig(
        run_id="infra-correlation-contract",
        seed_domains=[SEED],
        scope_patterns=[SEED],
        collected_domains={SEED},
        observed_at="2026-08-21T00:00:00Z",
    )
    engine = IntelEngine(config)
    engine.ingest_artifacts(tmp_path)
    engine.ingest_passive_resolutions({name: IP for name in SANS}, collector="case_fixture")
    engine.correlate()
    return engine


def test_all_six_names_survive_as_observations(tmp_path: Path) -> None:
    engine = _run_engine(tmp_path)
    domains = {e.key for e in engine.entities.values() if e.entity_type.value == "DOMAIN"}
    assert set(SANS) <= domains


def test_in_scope_seed_is_collected(tmp_path: Path) -> None:
    engine = _run_engine(tmp_path)
    seed = engine.entities[f"domain:{SEED}"]
    assert seed.scope_status is ScopeStatus.IN_SCOPE
    assert seed.collection_status is CollectionStatus.COLLECTED


def test_out_of_scope_siblings_are_recorded_not_probed(tmp_path: Path) -> None:
    engine = _run_engine(tmp_path)
    for name in SIBLINGS:
        entity = engine.entities[f"domain:{name}"]
        assert entity.scope_status is ScopeStatus.OUT_OF_SCOPE
        assert entity.collection_status is CollectionStatus.NOT_ALLOWED


def test_shared_certificate_relationship_is_high_confidence_with_evidence(tmp_path: Path) -> None:
    engine = _run_engine(tmp_path)
    shared = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    assert shared
    for rel in shared:
        assert rel.confidence is ConfidenceBand.HIGH
        assert rel.data.get("fingerprint_sha256") == FINGERPRINT
        evidence = engine.evidence[rel.evidence_id]
        assert evidence.reason


def test_shared_ipv4_relationship_is_medium_not_high(tmp_path: Path) -> None:
    engine = _run_engine(tmp_path)
    shared = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared
    assert all(r.confidence is ConfidenceBand.MEDIUM for r in shared)
    assert not any(r.confidence is ConfidenceBand.HIGH for r in shared)


def test_output_never_contains_attribution_language(tmp_path: Path) -> None:
    engine = _run_engine(tmp_path)
    blob = json.dumps(engine.snapshot().to_dict() if hasattr(engine.snapshot(), "to_dict") else {})
    graph_blob = json.dumps(engine.to_infrastructure_graph().to_dict())
    combined = (blob + graph_blob).lower()
    for phrase in ("actor", "owner", "same threat"):
        assert phrase not in combined


def test_cluster_is_not_empty_for_a_single_hostname_cli_target(tmp_path: Path, capsys) -> None:
    """Query-side proof of the same contract: persist the engine snapshot to
    SQLite exactly as `core/registry.py::HostRegistry.finalize()` does for a
    real run, then drive it through the same `core/intel/cli.py` functions
    `app.py investigate` / `app.py relationships` call — with the seed as the
    *only* CLI target, matching `-d virusbarrier.xyz`."""
    engine = _run_engine(tmp_path)
    db_path = tmp_path / "recon.db"
    store = AssetStore(db_path)
    run_id = "infra-correlation-contract"
    store.create_run(ScanRun(run_id=run_id, started_at="2026-08-21T00:00:00Z", targets=[SEED]))
    store.persist_registry(run_id, {}, intel=engine.snapshot())
    store.finish_run(run_id, host_count=1, alive_count=1, warnings=[], errors=[])

    assert cmd_investigate(db_path, SEED, run_id, None) == 0
    investigate_payload = json.loads(capsys.readouterr().out)
    assert investigate_payload.get("relationships") or investigate_payload.get("observations")

    assert cmd_relationships(db_path, SEED, run_id) == 0
    relationships_payload = json.loads(capsys.readouterr().out)
    assert relationships_payload[
        "relationships"
    ], "graph must not be empty for a single-host CLI target"

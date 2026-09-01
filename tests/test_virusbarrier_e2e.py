"""True virusbarrier end-to-end: artifacts → parsers → finalize → SQLite → CLI.

These tests must not call ingest_passive_resolutions() or any intelligence
shortcut that injects the expected graph. They exercise the same finalize
path the runner uses after collectors write artifacts.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from config.settings import Settings
from core.assets import ScanRun
from core.intel.cli import cmd_investigate, cmd_relationships
from core.intel.model import CollectionStatus, EntityType, RelationshipType, ScopeStatus
from core.models import DomainTarget, PipelineContext
from core.registry import HostRegistry
from core.runner import intel_config_for_pipeline
from core.store import AssetStore
from utils.files import read_jsonl, read_lines

FIXTURE = Path(__file__).parent / "fixtures" / "virusbarrier"
CASE = json.loads((FIXTURE / "case.json").read_text(encoding="utf-8"))
SANS = list(CASE["sans"])
SEED = CASE["seed"]
SIBLINGS = [name for name in SANS if name != SEED]
FINGERPRINT = CASE["fingerprint_sha256"]
IP = CASE["ipv4"]
RUN_ID = "virusbarrier-e2e"

_PRODUCTION_ARTIFACTS = (
    "ctlogs.jsonl",
    "ctlogs_domains.txt",
    "httpx.json",
    "dnsx_records.jsonl",
    "resolved.txt",
    "scope.txt",
)


def _copy_seed_only_artifacts(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in _PRODUCTION_ARTIFACTS:
        shutil.copy2(FIXTURE / name, output_dir / name)
    shutil.copy2(FIXTURE / "resolved.txt", output_dir / "subdomains.txt")


def _run_production_finalize(
    tmp_path: Path,
    *,
    extra_files: dict[str, str] | None = None,
) -> tuple[HostRegistry, Path, PipelineContext]:
    output_dir = tmp_path / "output" / RUN_ID
    _copy_seed_only_artifacts(output_dir)
    if extra_files:
        for name, body in extra_files.items():
            (output_dir / name).write_text(body, encoding="utf-8")

    settings = Settings(project_root=tmp_path, scope_file=output_dir / "scope.txt")
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        subdomains=[SEED],
        resolved=[SEED],
        output_dir=output_dir,
        run_id=RUN_ID,
    )
    context.collection_scope = None
    config = intel_config_for_pipeline(context, settings)
    assert config.collected_domains == {SEED}

    registry = HostRegistry(RUN_ID, output_dir)
    registry.intel_config = config
    for tool in ("ctlogs", "dnsx", "httpx"):
        registry.ingest(tool)
    registry.finalize()
    assert registry.intel is not None

    db_path = tmp_path / "output" / "recon.db"
    store = AssetStore(db_path)
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-08-21T00:00:00Z", targets=[SEED]))
    store.persist_registry(
        RUN_ID,
        registry.to_dict(),
        clusters=registry.clusters,
        graph=registry.graph,
        intel=registry.intel,
    )
    store.finish_run(
        RUN_ID, host_count=len(registry.to_dict()), alive_count=1, warnings=[], errors=[]
    )
    return registry, db_path, context


def test_virusbarrier_pipeline_e2e_seed_only(tmp_path: Path, capsys) -> None:
    registry, db_path, _context = _run_production_finalize(tmp_path)
    snapshot = registry.intel
    assert snapshot is not None

    domains = {e.key: e for e in snapshot.entities.values() if e.entity_type is EntityType.DOMAIN}
    assert set(SANS) <= set(domains)

    seed = domains[SEED]
    assert seed.is_seed
    assert seed.scope_status is ScopeStatus.IN_SCOPE
    assert seed.collection_status is CollectionStatus.COLLECTED

    for name in SIBLINGS:
        entity = domains[name]
        assert entity.scope_status is ScopeStatus.OUT_OF_SCOPE
        assert entity.collection_status is CollectionStatus.NOT_ALLOWED
        assert any(
            obs.entity_id == entity.entity_id for obs in snapshot.observations
        ), f"{name} must remain an observation"

    hosts = registry.to_dict()
    assert SEED in hosts
    assert not (
        set(SIBLINGS) & set(hosts)
    ), "parsers must not materialize OOS siblings as collected hosts"

    dns_hosts = {
        str(rec.get("host") or "")
        for rec in read_jsonl(registry.output_dir / "dnsx_records.jsonl")
        if isinstance(rec, dict)
    }
    http_targets = {
        str(rec.get("input") or rec.get("host") or "")
        for rec in read_jsonl(registry.output_dir / "httpx.json")
        if isinstance(rec, dict)
    }
    resolved = set(read_lines(registry.output_dir / "resolved.txt"))
    assert dns_hosts == {SEED}
    assert http_targets == {SEED}
    assert resolved == {SEED}
    for name in SIBLINGS:
        assert name not in dns_hosts
        assert name not in http_targets
        assert name not in resolved

    certs = [e for e in snapshot.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    fingerprinted = [c for c in certs if c.data.get("fingerprint_sha256") == FINGERPRINT]
    assert fingerprinted
    assert any(c.entity_id == f"certificate:{FINGERPRINT}" for c in fingerprinted)

    shared_cert = [
        r
        for r in snapshot.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    assert shared_cert
    assert all(r.data.get("fingerprint_sha256") == FINGERPRINT for r in shared_cert)

    shared_ip = [
        r
        for r in snapshot.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared_ip == [], "seed-only DNS must not invent sibling IPs"

    blob = json.dumps(
        {
            "entities": [e.to_dict() for e in snapshot.entities.values()],
            "relationships": [r.to_dict() for r in snapshot.relationships.values()],
        }
    ).lower()
    assert "actor" not in blob
    assert "owner" not in blob

    store = AssetStore(db_path)
    conn = store.intel_connection()
    rows = conn.execute(
        "SELECT key, scope_status, collection_status FROM intel_entities WHERE run_id=? AND entity_type='DOMAIN'",
        (RUN_ID,),
    ).fetchall()
    by_key = {row["key"]: row for row in rows}
    assert set(SANS) <= set(by_key)
    assert by_key[SEED]["collection_status"] == CollectionStatus.COLLECTED.value
    for name in SIBLINGS:
        assert by_key[name]["scope_status"] == ScopeStatus.OUT_OF_SCOPE.value
        assert by_key[name]["collection_status"] == CollectionStatus.NOT_ALLOWED.value
    rel_types = {
        row["relationship_type"]
        for row in conn.execute(
            "SELECT relationship_type FROM intel_relationships WHERE run_id=?",
            (RUN_ID,),
        )
    }
    assert "SHARES_CERTIFICATE" in rel_types
    assert "SHARES_IPV4" not in rel_types
    conn.close()

    assert cmd_investigate(db_path, SEED, RUN_ID, None) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert SEED in out
    assert FINGERPRINT in out
    assert "SHARES_CERTIFICATE" in out or "certificate:" in out
    assert "explanations" in payload
    assert any("SHARES_CERTIFICATE" in (item.get("text") or "") for item in payload["explanations"])
    assert "actor" not in out.lower()
    assert "owner" not in out.lower()
    assert cmd_investigate(db_path, SIBLINGS[0], RUN_ID, None) == 0
    sibling_out = capsys.readouterr().out
    sibling_payload = json.loads(sibling_out)
    assert SIBLINGS[0] in sibling_out
    assert "NOT_ALLOWED" in sibling_out or "OUT_OF_SCOPE" in sibling_out
    assert any(
        "NOT_ALLOWED" in (item.get("text") or "")
        for item in sibling_payload.get("explanations") or []
    )
    assert cmd_relationships(db_path, SEED, RUN_ID) == 0
    capsys.readouterr()
    from core.intel.cli import cmd_evidence, cmd_graph

    assert cmd_graph(db_path, SEED, RUN_ID) == 0
    graph_out = capsys.readouterr().out
    assert "nodes" in graph_out
    assert "SHARES_IPV4" not in graph_out
    shares = [
        r
        for r in snapshot.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    assert shares
    assert cmd_evidence(db_path, shares[0].relationship_id, RUN_ID) == 0
    evidence_out = capsys.readouterr().out
    assert FINGERPRINT in evidence_out
    assert "explanation" in evidence_out


def test_virusbarrier_shared_ipv4_requires_resolution_evidence(tmp_path: Path) -> None:
    passive = (
        "\n".join(
            json.dumps(
                {"host": name, "ip": IP, "collector": "passive_dns", "source": "passive_dns"}
            )
            for name in SANS
        )
        + "\n"
    )
    registry, db_path, _context = _run_production_finalize(
        tmp_path,
        extra_files={"passive_dns.jsonl": passive},
    )
    snapshot = registry.intel
    assert snapshot is not None
    shared_ip = [
        r
        for r in snapshot.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared_ip
    assert all(
        r.data.get("ip") == IP or "34.75.127.116" in json.dumps(r.to_dict()) for r in shared_ip
    )

    store = AssetStore(db_path)
    conn = store.intel_connection()
    types = {
        row["relationship_type"]
        for row in conn.execute(
            "SELECT relationship_type FROM intel_relationships WHERE run_id=?",
            (RUN_ID,),
        )
    }
    assert "SHARES_IPV4" in types
    conn.close()


def test_virusbarrier_pipeline_e2e_passive_dns_closes_the_gap(tmp_path: Path) -> None:
    """The gap `test_virusbarrier_pipeline_e2e_seed_only` documents
    (`shared_ip == []` for a real seed-only scan) is closed once
    `modules/passive_dns.py` has produced `passive_dns.jsonl` — same
    production `finalize()` path, no `ingest_passive_resolutions()`
    shortcut, using the real fixture file a provider-shaped
    `passive_dns.jsonl` (Mnemonic-shaped: `host`/`ip`/`collector`/`source`/
    `providers`) would leave on disk, not synthesized inline."""
    passive_dns_body = (FIXTURE / "passive_dns.jsonl").read_text(encoding="utf-8")
    registry, db_path, _context = _run_production_finalize(
        tmp_path,
        extra_files={"passive_dns.jsonl": passive_dns_body},
    )
    snapshot = registry.intel
    assert snapshot is not None

    shared_ip = [
        r
        for r in snapshot.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared_ip, "passive_dns.jsonl must close the documented shares_ipv4 gap"
    assert all(r.confidence.value == "MEDIUM" for r in shared_ip)
    assert not any(r.confidence.value == "HIGH" for r in shared_ip)

    store = AssetStore(db_path)
    conn = store.intel_connection()
    types = {
        row["relationship_type"]
        for row in conn.execute(
            "SELECT relationship_type FROM intel_relationships WHERE run_id=?",
            (RUN_ID,),
        )
    }
    assert "SHARES_IPV4" in types
    conn.close()


def test_virusbarrier_passive_dns_empty_provider_response_adds_no_evidence(
    tmp_path: Path,
) -> None:
    """A sibling with no passive-DNS history (`query_status: empty`, `ip: []`)
    must not break anything and must not fabricate a relationship for it."""
    passive_dns_body = (
        json.dumps(
            {
                "host": SIBLINGS[0],
                "ip": [],
                "collector": "passive_dns",
                "source": "passive_dns",
                "providers": [],
                "query_status": "empty",
            }
        )
        + "\n"
    )
    registry, _db_path, _context = _run_production_finalize(
        tmp_path,
        extra_files={"passive_dns.jsonl": passive_dns_body},
    )
    snapshot = registry.intel
    assert snapshot is not None
    shared_ip = [
        r
        for r in snapshot.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared_ip == []
    domains = {e.key: e for e in snapshot.entities.values() if e.entity_type is EntityType.DOMAIN}
    assert domains[SIBLINGS[0]].collection_status is CollectionStatus.NOT_ALLOWED


def test_e2e_seed_only_does_not_call_injection_helpers() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    start = source.index("def test_virusbarrier_pipeline_e2e_seed_only")
    end = source.index("def test_virusbarrier_shared_ipv4_requires_resolution_evidence")
    body = source[start:end]
    assert "ingest_passive_resolutions" not in body
    assert "ingest_passive_dns_records" not in body

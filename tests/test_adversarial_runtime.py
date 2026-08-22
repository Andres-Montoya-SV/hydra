"""Adversarial tests that attack production runtime paths, not helpers alone."""

from __future__ import annotations

import json
from pathlib import Path

from config.settings import Settings
from core.assets import Host, HttpService, ScanRun, TlsCertificate, normalize_http_url
from core.collectors import (
    ACTIVE_COLLECTION_PLUGINS,
    RESOLVE_DNS_PLUGINS,
    STRICT_OPSEC_ALLOWED_PLUGINS,
    SUBDOMAIN_PLUGINS,
)
from core.intel.bounds import DiscoveryBounds
from core.intel.cli import cmd_diff_runs, cmd_investigate
from core.intel.engine import IntelEngine, IntelRunConfig, build_intel
from core.intel.model import (
    CollectionStatus,
    EntityType,
    IndicatorKind,
    RelationshipType,
    ScopeStatus,
)
from core.intel.plugin import StructuredEmission
from core.intel.scope import CollectionScope, authorize_plugin_input
from core.models import DomainTarget, PipelineContext
from core.parsers.crawlers import parse_crawler_output
from core.parsers.registry import parse_tool_output
from core.runner import PipelineRunner
from core.store import AssetStore
from tests.test_virusbarrier_e2e import (
    FINGERPRINT,
    SEED,
    SIBLINGS,
    _run_production_finalize,
)


def test_collectors_declare_capabilities_not_name_lists() -> None:
    assert "subfinder" in SUBDOMAIN_PLUGINS
    assert "ctlogs" in SUBDOMAIN_PLUGINS
    assert "dnsx" in RESOLVE_DNS_PLUGINS
    assert RESOLVE_DNS_PLUGINS == frozenset({"dnsx"})
    assert "dnsx" in ACTIVE_COLLECTION_PLUGINS
    assert "httpx" in ACTIVE_COLLECTION_PLUGINS
    assert "ctlogs" not in ACTIVE_COLLECTION_PLUGINS
    assert "subfinder" not in ACTIVE_COLLECTION_PLUGINS
    assert "jq" not in STRICT_OPSEC_ALLOWED_PLUGINS
    assert "dnsx" not in STRICT_OPSEC_ALLOWED_PLUGINS
    assert "httpx" in STRICT_OPSEC_ALLOWED_PLUGINS
    assert "ctlogs" in STRICT_OPSEC_ALLOWED_PLUGINS


def test_scope_escape_via_plugin_input_is_stripped(tmp_path: Path) -> None:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    poisoned = output_dir / "subdomains.txt"
    poisoned.write_text(
        f"{SEED}\n{SIBLINGS[0]}\nhttps://{SIBLINGS[1]}/login\n",
        encoding="utf-8",
    )
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([SEED], patterns=[SEED]),
    )
    for plugin in ("dnsx", "httpx", "naabu"):
        authorized = authorize_plugin_input(context, poisoned, plugin)
        body = authorized.read_text(encoding="utf-8")
        assert SEED in body.splitlines()
        for sibling in SIBLINGS:
            assert sibling not in body
            assert sibling not in body.lower()


def test_poisoned_ctlogs_txt_does_not_authorize_or_invent_ip(tmp_path: Path) -> None:
    registry, db_path, _ = _run_production_finalize(
        tmp_path,
        extra_files={"ctlogs_domains.txt": f"{SEED}\n{SIBLINGS[0]}\n"},
    )
    snapshot = registry.intel
    assert snapshot is not None
    hosts = registry.to_dict()
    sibling = next(e for e in snapshot.entities.values() if e.key == SIBLINGS[0])
    assert sibling.scope_status is ScopeStatus.OUT_OF_SCOPE
    assert sibling.collection_status is CollectionStatus.NOT_ALLOWED
    shared_ip = [
        r
        for r in snapshot.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared_ip == []
    if SIBLINGS[0] in hosts:
        assert not hosts[SIBLINGS[0]].dns_resolved
    store = AssetStore(db_path)
    conn = store.intel_connection()
    types = {
        row["relationship_type"]
        for row in conn.execute(
            "SELECT relationship_type FROM intel_relationships WHERE run_id=?",
            ("virusbarrier-e2e",),
        )
    }
    conn.close()
    assert "SHARES_CERTIFICATE" in types
    assert "SHARES_IPV4" not in types


def test_shared_cloud_ip_is_medium_not_ownership() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="cloud",
            seed_domains=["a.example.com", "b.example.com"],
            collected_domains={"a.example.com", "b.example.com"},
        )
    )
    engine.ingest_httpx_records(
        [
            {"input": "a.example.com", "ip": "34.75.127.116"},
            {"input": "b.example.com", "ip": "34.75.127.116"},
        ]
    )
    engine.correlate()
    shared = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared
    assert all(r.strength == "shared_cloud_tenancy" for r in shared)
    blob = json.dumps([r.to_dict() for r in shared]).lower()
    assert "owner" not in blob
    assert "actor" not in blob


def test_certificate_rotation_persists_two_entities(tmp_path: Path) -> None:
    first = (
        json.dumps(
            {
                "input": SEED,
                "host": SEED,
                "url": f"https://{SEED}/",
                "ip": "34.75.127.116",
                "tls": {
                    "subject_an": [SEED, SIBLINGS[0]],
                    "fingerprint_hash": {"sha256": "a" * 64},
                },
            }
        )
        + "\n"
    )
    registry, _db, _ = _run_production_finalize(tmp_path, extra_files={"httpx.json": first})
    snapshot = registry.intel
    assert snapshot is not None
    fps = {
        e.data.get("fingerprint_sha256")
        for e in snapshot.entities.values()
        if e.entity_type is EntityType.CERTIFICATE
    }
    assert FINGERPRINT in fps
    assert "a" * 64 in fps
    assert f"certificate:{FINGERPRINT}" in snapshot.entities
    assert f"certificate:{'a' * 64}" in snapshot.entities


def test_duplicate_entities_and_relationships_are_stable() -> None:
    engine = IntelEngine(
        IntelRunConfig(run_id="dup", seed_domains=[SEED], collected_domains={SEED})
    )
    record = {
        "input": SEED,
        "ip": "8.8.8.8",
        "tls": {
            "subject_an": [SEED, "www.virusbarrier.xyz"],
            "fingerprint_hash": {"sha256": "c" * 64},
        },
    }
    engine.ingest_httpx_records([record, record])
    engine.ingest_httpx_records([record])
    engine.correlate()
    engine.correlate()
    domains = [e.key for e in engine.entities.values() if e.entity_type is EntityType.DOMAIN]
    assert domains.count(SEED) == 1
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    assert len(certs) == 1
    presents = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.PRESENTS_CERTIFICATE
    ]
    assert len(presents) == 1


def test_malformed_plugin_output_is_ignored() -> None:
    engine = IntelEngine(IntelRunConfig(run_id="bad", seed_domains=[SEED]))
    engine.ingest_emissions(
        [
            {"not": "an emission"},
            StructuredEmission(
                domains=["not a domain!!!", SEED],
                relationships=[
                    {
                        "source_entity": "actor:evil",
                        "target_entity": f"domain:{SEED}",
                        "relationship_type": "SHARES_CERTIFICATE",
                        "confidence": "VERY_HIGH",
                    },
                    {
                        "source_entity": f"domain:{SEED}",
                        "target_entity": f"certificate:{'d' * 64}",
                        "relationship_type": "OWNED_BY",
                        "confidence": "HIGH",
                    },
                ],
                followups=[{"kind": "DOMAIN", "reason": "NOT_A_REASON", "value": SIBLINGS[0]}],
            ).to_dict(),
        ]
    )
    engine.correlate()
    assert "actor:evil" not in engine.entities
    assert not any(
        r.relationship_type.value == "OWNED_BY" for r in engine.relationships.values()
    )
    assert engine.queue.get(IndicatorKind.DOMAIN, SIBLINGS[0]) is None


def test_attribution_injection_rejected_and_not_in_cli(tmp_path, capsys) -> None:
    engine = IntelEngine(
        IntelRunConfig(run_id="attr", seed_domains=[SEED], collected_domains={SEED})
    )
    engine.ingest_emissions(
        [
            StructuredEmission(
                relationships=[
                    {
                        "source_entity": f"domain:{SEED}",
                        "target_entity": "threat_group:hydra",
                        "relationship_type": "SHARES_ASN",
                        "confidence": "HIGH",
                    }
                ]
            ).to_dict()
        ]
    )
    engine.correlate()
    db = tmp_path / "recon.db"
    store = AssetStore(db)
    store.create_run(ScanRun(run_id="attr", started_at="2026-01-01T00:00:00Z", targets=[SEED]))
    store.persist_registry("attr", {}, intel=engine.snapshot())
    store.finish_run("attr", host_count=0, alive_count=0, warnings=[], errors=[])
    assert cmd_investigate(db, SEED, "attr", None) == 0
    out = capsys.readouterr().out.lower()
    assert "threat_group" not in out
    assert "same owner" not in out
    assert "same actor" not in out


def test_entity_and_relationship_caps_fail_closed() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="cap",
            seed_domains=["example.com"],
            collected_domains={"example.com"},
            bounds=DiscoveryBounds(max_entities=5, max_relationships=2),
        )
    )
    sans = ["example.com"] + [f"h{i}.example.com" for i in range(20)]
    engine.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "tls": {"subject_an": sans, "fingerprint_hash": {"sha256": "e" * 64}},
            }
        ]
    )
    engine.correlate()
    snap = engine.snapshot()
    assert snap.truncated is True
    assert len(snap.entities) <= 5
    known = set(snap.entities)
    assert all(obs.entity_id in known for obs in snap.observations)
    assert all(
        rel.source_entity in known and rel.target_entity in known
        for rel in snap.relationships.values()
    )


def test_unfinished_run_is_not_selected_by_cli(tmp_path, capsys) -> None:
    store = AssetStore(tmp_path / "recon.db")
    engine = IntelEngine(
        IntelRunConfig(run_id="done", seed_domains=[SEED], collected_domains={SEED})
    )
    engine.ingest_httpx_records([{"input": SEED, "ip": "8.8.8.8"}])
    engine.correlate()
    store.create_run(ScanRun(run_id="done", started_at="2026-01-01T00:00:00Z", targets=[SEED]))
    store.persist_registry("done", {}, intel=engine.snapshot())
    store.finish_run("done", host_count=1, alive_count=1, warnings=[], errors=[])
    store.create_run(ScanRun(run_id="crash", started_at="2026-01-02T00:00:00Z", targets=[SEED]))
    assert store.find_latest_finished_run(domain=SEED) == "done"
    assert cmd_investigate(tmp_path / "recon.db", SEED, None, None) == 0
    out = capsys.readouterr().out
    assert "done" in out
    assert "crash" not in out


def test_queue_duplication_from_plugin_followups() -> None:
    engine = IntelEngine(
        IntelRunConfig(run_id="q", seed_domains=[SEED], collected_domains={SEED})
    )
    emission = StructuredEmission(
        domains=[SEED, "www.virusbarrier.xyz"],
        followups=[
            {"kind": "DOMAIN", "reason": "CERTIFICATE_SAN"},
            {"kind": "DOMAIN", "reason": "CERTIFICATE_SAN", "value": SEED},
            {"kind": "DOMAIN", "reason": "CERTIFICATE_SAN", "value": SEED},
        ],
    )
    engine.ingest_emissions([emission, emission.to_dict()])
    indicators = [i for i in engine.queue.values() if i.kind is IndicatorKind.DOMAIN and i.value == SEED]
    assert len(indicators) == 1


def test_url_normalization_collapses_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "gau.txt"
    path.write_text(
        "\n".join(
            [
                f"https://{SEED}/",
                f"https://{SEED}",
                f"https://{SEED}:443/",
                f"HTTPS://{SEED.upper()}/#frag",
                f"https://{SEED}/login",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    hosts, _ = parse_tool_output("gau", tmp_path)
    assert len(hosts) == 1
    urls = {item.url for item in hosts[0].urls}
    assert normalize_http_url(f"https://{SEED}/") in urls
    assert len(urls) == 2
    crawler = tmp_path / "katana.jsonl"
    crawler.write_text(
        json.dumps({"url": f"https://{SEED}/"})
        + "\n"
        + json.dumps({"url": f"https://{SEED}:443/#x"})
        + "\n",
        encoding="utf-8",
    )
    crawled, _ = parse_crawler_output(crawler, source="katana")
    assert len(crawled[0].urls) == 1


def test_http_service_entities_dedupe_equivalent_urls() -> None:
    engine = IntelEngine(
        IntelRunConfig(run_id="urls", seed_domains=["example.com"], collected_domains={"example.com"})
    )
    host = Host(domain="example.com", dns_resolved=True)

    host = Host(domain="example.com", dns_resolved=True)
    host.http_services.extend(
        [
            HttpService(url="https://example.com/", host="example.com"),
            HttpService(url="https://example.com:443", host="example.com"),
            HttpService(url="https://EXAMPLE.com/#x", host="example.com"),
        ]
    )
    engine.ingest_hosts({"example.com": host})
    services = [e for e in engine.entities.values() if e.entity_type is EntityType.HTTP_SERVICE]
    assert len(services) == 1


def test_recursive_explosion_stops_at_depth_and_followup_cap() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="boom",
            seed_domains=["example.com"],
            collected_domains={"example.com"},
            bounds=DiscoveryBounds(max_discovery_depth=1, max_followup_indicators=5, max_domains_per_source=8),
        )
    )
    sans = ["example.com"] + [f"h{i}.example.com" for i in range(40)]
    engine.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "tls": {"subject_an": sans, "fingerprint_hash": {"sha256": "f" * 64}},
            }
        ]
    )
    claimed = engine.eligible_followups(IndicatorKind.DOMAIN)
    assert len(claimed) <= 5
    assert all(item.depth <= 1 for item in claimed)
    assert engine.eligible_followups(IndicatorKind.DOMAIN) == []


def test_wildcard_blocks_followup_schedule(tmp_path: Path, settings: Settings) -> None:
    from core.intel.model import CollectReason

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "wildcard_check.jsonl").write_text(
        json.dumps({"root_domain": "example.com", "wildcard_dns_detected": True, "canary_resolved": ["a.example.com"]})
        + "\n",
        encoding="utf-8",
    )
    context = PipelineContext(
        targets=[DomainTarget(domain="example.com")],
        resolved=["example.com"],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(["example.com"]),
    )
    engine = IntelEngine(
        IntelRunConfig(run_id="w", seed_domains=["example.com"], collected_domains={"example.com"})
    )
    engine.queue.add(
        kind=IndicatorKind.DOMAIN,
        value="random-canary.example.com",
        depth=1,
        parent_id=None,
        reason=CollectReason.DNS_RESOLUTION,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="",
    )
    runner = PipelineRunner(settings)
    plan = runner.schedule_followup_collection(context, engine)
    assert "random-canary.example.com" not in plan.dns_targets
    assert "random-canary.example.com" not in plan.http_targets


def test_strict_opsec_blocks_unverified_active_plugins(tmp_path: Path) -> None:
    settings = Settings(
        project_root=tmp_path,
        strict_opsec=True,
        outbound_proxy_url="http://proxy.example:8080",
    )
    runner = PipelineRunner(settings)
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=tmp_path / "out",
        run_id="opsec",
    )
    context.output_dir.mkdir()
    dnsx = runner.tool_manager.get_plugin("dnsx")
    assert dnsx is not None
    assert dnsx.name not in STRICT_OPSEC_ALLOWED_PLUGINS

    async def _go():
        return await runner._run_single_plugin(context, dnsx, tmp_path / "out" / "subdomains.txt")

    import asyncio

    result = asyncio.run(_go())
    assert result is not None
    assert result.skipped is True
    assert "OPSEC" in (result.message or "")


def test_historical_diff_by_domain_reads_sqlite_only(tmp_path, capsys) -> None:
    db = tmp_path / "recon.db"
    store = AssetStore(db)

    def _persist(run_id: str, started: str, ip: str) -> None:
        engine = IntelEngine(
            IntelRunConfig(run_id=run_id, seed_domains=[SEED], collected_domains={SEED})
        )
        engine.ingest_httpx_records([{"input": SEED, "ip": ip}])
        engine.correlate()
        store.create_run(ScanRun(run_id=run_id, started_at=started, targets=[SEED]))
        store.persist_registry(
            run_id,
            {SEED: Host(domain=SEED, ips=[ip], dns_resolved=True)},
            intel=engine.snapshot(),
        )
        store.finish_run(run_id, host_count=1, alive_count=1, warnings=[], errors=[])

    _persist("old", "2026-01-01T00:00:00Z", "1.1.1.1")
    _persist("new", "2026-01-02T00:00:00Z", "8.8.8.8")
    assert cmd_diff_runs(db, SEED, None) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["previous_run_id"] == "old"
    assert payload["current_run_id"] == "new"
    fields = {c.get("field") for c in payload.get("field_changes") or []}
    assert "ip" in fields or "ipv4" in fields


def test_risk_is_not_increased_by_shared_certificate() -> None:
    host = Host(domain=SEED, dns_resolved=True, risk_score=10)
    other = Host(domain=SIBLINGS[0], dns_resolved=False, risk_score=10)
    host.tls = TlsCertificate(
        host=SEED,
        fingerprint_sha256=FINGERPRINT,
        sans=[SEED, *SIBLINGS],
        subject=SEED,
    )
    hosts = {SEED: host, SIBLINGS[0]: other}
    build_intel(
        IntelRunConfig(run_id="risk", seed_domains=[SEED], collected_domains={SEED}),
        hosts,
    )
    assert host.risk_score == 10
    assert "infrastructure correlation, not attribution" in " ".join(host.risk_reasons)

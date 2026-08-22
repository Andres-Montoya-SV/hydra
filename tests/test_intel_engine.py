"""Unit and adversarial tests for the intelligence engine."""

from __future__ import annotations

import json
from pathlib import Path

from core.assets import Host, HttpService, TlsCertificate
from core.intel.engine import IntelEngine, IntelRunConfig, build_intel
from core.intel.model import (
    CollectionStatus,
    ConfidenceBand,
    EntityType,
    IndicatorKind,
    RelationshipType,
    ScopeStatus,
    normalize_fingerprint,
)
from core.intel.plugin import StructuredEmission
from core.intel.scope import classify_scope
from core.intel.tls import extract_certificate_names, extract_tls_fingerprint
from core.store import AssetStore


def test_fingerprint_identity_not_sans() -> None:
    tls = {
        "subject_an": ["b.example", "a.example", "c.example"],
        "fingerprint_hash": {
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
    }
    assert extract_tls_fingerprint(tls) == "a" * 64
    assert normalize_fingerprint("AA:" * 32) == "a" * 64


def test_scope_unknown_and_oos_are_not_collectable() -> None:
    assert classify_scope(
        "virusinspector.top", seed_domains=["virusbarrier.xyz"], scope_patterns=None
    ) is (ScopeStatus.OUT_OF_SCOPE)
    assert (
        classify_scope("", seed_domains=["example.com"], scope_patterns=None) is ScopeStatus.UNKNOWN
    )
    assert (
        classify_scope("www.example.com", seed_domains=["example.com"], scope_patterns=None)
        is ScopeStatus.IN_SCOPE
    )
    assert (
        classify_scope(
            "api.example.com",
            seed_domains=["example.com"],
            scope_patterns=["example.com"],
        )
        is ScopeStatus.IN_SCOPE
    )
    assert (
        classify_scope(
            "evil.com",
            seed_domains=["example.com"],
            scope_patterns=["example.com"],
        )
        is ScopeStatus.OUT_OF_SCOPE
    )


def test_queue_bounds_and_dedup() -> None:
    from core.intel.bounds import DiscoveryBounds
    from core.intel.model import CollectReason
    from core.intel.queue import IndicatorQueue

    queue = IndicatorQueue(DiscoveryBounds(max_discovery_depth=1, max_followup_indicators=2))
    queue.add(
        kind=IndicatorKind.DOMAIN,
        value="a.example.com",
        depth=1,
        parent_id=None,
        reason=CollectReason.CERTIFICATE_SAN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="e1",
    )
    queue.add(
        kind=IndicatorKind.DOMAIN,
        value="a.example.com",
        depth=2,
        parent_id="p",
        reason=CollectReason.CERTIFICATE_SAN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="e2",
    )
    assert len(queue) == 1
    queue.add(
        kind=IndicatorKind.DOMAIN,
        value="b.example.com",
        depth=1,
        parent_id=None,
        reason=CollectReason.CERTIFICATE_SAN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="e3",
    )
    queue.add(
        kind=IndicatorKind.DOMAIN,
        value="c.example.com",
        depth=1,
        parent_id=None,
        reason=CollectReason.CERTIFICATE_SAN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="e4",
    )
    follow = queue.eligible_followups()
    assert len(follow) == 2
    assert all(item.collection_status.value == "IN_FLIGHT" for item in follow)
    assert queue.eligible_followups() == []


def test_malformed_ct_and_duplicate_sans(tmp_path: Path) -> None:
    (tmp_path / "ctlogs.jsonl").write_text(
        "not-json\n"
        + json.dumps({"name_value": "a.example.com\na.example.com\n*.a.example.com"})
        + "\n"
        + json.dumps(["unexpected-list"])
        + "\n",
        encoding="utf-8",
    )
    engine = IntelEngine(IntelRunConfig(run_id="t", seed_domains=["example.com"]))
    engine.ingest_artifacts(tmp_path)
    names = extract_certificate_names("a.example.com\na.example.com\n*.a.example.com")
    assert names == ["a.example.com"]


def test_hundred_sans_and_unrelated_orgs() -> None:
    sans = [f"host{i}.example.com" for i in range(100)] + ["unrelated-bank.example"]
    config = IntelRunConfig(
        run_id="t", seed_domains=["example.com"], collected_domains={"example.com"}
    )
    engine = IntelEngine(config)
    engine.ingest_ct_records(
        [
            {
                "id": 1,
                "name_value": "\n".join(sans),
                "fingerprint_sha256": "b" * 64,
                "common_name": "example.com",
                "query_domain": "example.com",
            }
        ]
    )
    engine.correlate()
    domains = [e for e in engine.entities.values() if e.entity_type is EntityType.DOMAIN]
    assert len(domains) >= 101
    oos = engine.entities["domain:unrelated-bank.example"]
    assert oos.scope_status is ScopeStatus.OUT_OF_SCOPE
    assert oos.collection_status is CollectionStatus.NOT_ALLOWED


def test_idn_punycode_and_expired_cert() -> None:
    engine = IntelEngine(IntelRunConfig(run_id="t", seed_domains=["xn--exmple-qta.com"]))
    engine.ingest_ct_records(
        [
            {
                "id": 9,
                "name_value": "exämple.com",
                "fingerprint_sha256": "c" * 64,
                "not_after": "2020-01-01T00:00:00Z",
                "query_domain": "xn--exmple-qta.com",
            }
        ]
    )
    puny = [e.key for e in engine.entities.values() if e.entity_type is EntityType.DOMAIN]
    assert any(k.startswith("xn--") or "example" in k or "exmple" in k for k in puny)
    cert = next(e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE)
    assert cert.data.get("not_after") == "2020-01-01T00:00:00Z"


def test_certificate_rotation_two_fingerprints() -> None:
    engine = IntelEngine(IntelRunConfig(run_id="t", seed_domains=["example.com"]))
    engine.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "ip": "1.2.3.4",
                "tls": {
                    "subject_an": ["example.com"],
                    "fingerprint_hash": {"sha256": "d" * 64},
                },
            },
            {
                "input": "example.com",
                "ip": "1.2.3.4",
                "tls": {
                    "subject_an": ["example.com", "www.example.com"],
                    "fingerprint_hash": {"sha256": "e" * 64},
                },
            },
        ]
    )
    fps = {
        e.data.get("fingerprint_sha256")
        for e in engine.entities.values()
        if e.entity_type is EntityType.CERTIFICATE
    }
    assert fps == {"d" * 64, "e" * 64}


def test_many_domains_one_cloud_ip_is_medium() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="t",
            seed_domains=["a.example.com", "b.example.com"],
            collected_domains={"a.example.com", "b.example.com"},
        )
    )
    engine.ingest_passive_resolutions(
        {"a.example.com": "34.75.127.116", "b.example.com": "34.75.127.116"}
    )
    engine.correlate()
    shared = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared
    assert shared[0].confidence is ConfidenceBand.MEDIUM
    assert shared[0].strength == "shared_cloud_tenancy"


def test_plugin_emission_contract() -> None:
    engine = IntelEngine(IntelRunConfig(run_id="t", seed_domains=["example.com"]))
    engine.ingest_emissions(
        [
            StructuredEmission(
                produces=["Domain", "Certificate"],
                domains=["extra.example.com"],
                certificates=[
                    {
                        "fingerprint_sha256": "f" * 64,
                        "sans": ["extra.example.com", "example.com"],
                        "collector": "my_tool",
                    }
                ],
                relationships=[
                    {
                        "source_entity": "domain:example.com",
                        "target_entity": f"certificate:{'f' * 64}",
                        "relationship_type": "PRESENTS_CERTIFICATE",
                        "confidence": "VERY_HIGH",
                        "reason": "plugin_tls",
                    }
                ],
            ).to_dict()
        ]
    )
    engine.correlate()
    assert "domain:extra.example.com" in engine.entities
    assert any(
        r.relationship_type is RelationshipType.PRESENTS_CERTIFICATE
        for r in engine.relationships.values()
    )


def test_host_view_survives_intel(tmp_path: Path) -> None:
    host = Host(domain="example.com", ips=["1.1.1.1"], dns_resolved=True)
    host.tls = TlsCertificate(
        host="example.com",
        fingerprint_sha256="1" * 64,
        sans=["example.com"],
        subject="example.com",
    )
    host.http_services.append(
        HttpService(url="https://example.com", host="example.com", status_code=200)
    )
    config = IntelRunConfig(
        run_id="t", seed_domains=["example.com"], collected_domains={"example.com"}
    )
    engine = build_intel(config, {"example.com": host})
    assert host.domain == "example.com"
    assert host.http_services
    assert engine.entities["domain:example.com"].is_seed


def test_persist_and_query(tmp_path: Path) -> None:
    from core.assets import ScanRun
    from core.intel.query import IntelQuery

    engine = IntelEngine(
        IntelRunConfig(
            run_id="runq", seed_domains=["example.com"], collected_domains={"example.com"}
        )
    )
    engine.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "ip": "8.8.8.8",
                "tls": {
                    "subject_an": ["example.com", "www.example.com"],
                    "fingerprint_hash": {"sha256": "2" * 64},
                },
            }
        ]
    )
    engine.correlate()
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(
        ScanRun(run_id="runq", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("runq", {}, intel=engine.snapshot())
    conn = store.intel_connection()
    query = IntelQuery(conn, "runq")
    payload = query.investigate("example.com")
    assert payload["entity"]
    assert payload["certificates"]
    assert payload["relationships"]
    conn.close()


def test_wildcard_scope_file(tmp_path: Path) -> None:
    from core.scope import load_scope_patterns

    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n*.corp.example.com\n", encoding="utf-8")
    patterns = load_scope_patterns(scope)
    assert (
        classify_scope(
            "api.corp.example.com", seed_domains=["example.com"], scope_patterns=patterns
        )
        is ScopeStatus.IN_SCOPE
    )
    assert (
        classify_scope("other.com", seed_domains=["example.com"], scope_patterns=patterns)
        is ScopeStatus.OUT_OF_SCOPE
    )

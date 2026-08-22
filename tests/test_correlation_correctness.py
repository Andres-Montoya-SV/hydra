"""Certificate identity, evidence, cardinality, tenancy, favicon, plugin validation."""

from __future__ import annotations

from pathlib import Path

from config.settings import Settings
from core.assets import Host, HttpService, ScanRun
from core.intel.correlate import band_score, shares_certificate_confidence
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.model import (
    ConfidenceBand,
    EntityType,
    RelationshipType,
)
from core.intel.plugin import StructuredEmission, validate_emitted_relationship
from core.intelligence.clustering import compute_clusters
from core.models import DomainTarget, PipelineContext
from core.reporter import ReportGenerator
from core.store import AssetStore


def _engine(seeds: list[str]) -> IntelEngine:
    return IntelEngine(
        IntelRunConfig(
            run_id="corr",
            seed_domains=seeds,
            collected_domains=set(seeds),
            observed_at="2026-08-21T00:00:00Z",
        )
    )


def test_certificate_rotation_same_sans_remain_two_entities() -> None:
    engine = _engine(["a.example", "b.example"])
    sans = ["a.example", "b.example"]
    engine.ingest_httpx_records(
        [
            {
                "input": "a.example",
                "tls": {
                    "subject_an": sans,
                    "fingerprint_hash": {"sha256": "a" * 64},
                },
            },
            {
                "input": "b.example",
                "tls": {
                    "subject_an": sans,
                    "fingerprint_hash": {"sha256": "b" * 64},
                },
            },
        ]
    )
    engine.correlate()
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    fps = {c.data.get("fingerprint_sha256") for c in certs}
    assert fps == {"a" * 64, "b" * 64}
    assert {c.entity_id for c in certs} == {f"certificate:{'a' * 64}", f"certificate:{'b' * 64}"}
    assert not hasattr(IntelEngine, "_merge_equivalent_certificates")


def test_unidentified_certificate_does_not_share_domains() -> None:
    engine = _engine(["example.com"])
    engine.ingest_ct_records(
        [
            {
                "name_value": "example.com\nwww.example.com",
                "common_name": "example.com",
                "query_domain": "example.com",
            }
        ]
    )
    engine.correlate()
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    assert certs
    assert all(c.data.get("identity_kind") == "unidentified" for c in certs)
    assert not any(
        r.relationship_type is RelationshipType.SHARES_CERTIFICATE
        for r in engine.relationships.values()
    )
    assert any(
        r.relationship_type is RelationshipType.SAN_CONTAINS for r in engine.relationships.values()
    )


def test_six_san_certificate_is_meaningful() -> None:
    sans = [
        "virusbarrier.xyz",
        "virusinspector.top",
        "cybermedic.buzz",
        "defendervault.shop",
        "shieldvertex.mom",
        "safesentinel.lol",
    ]
    band, reason = shares_certificate_confidence(sans, identity_kind="sha256")
    assert band is ConfidenceBand.HIGH
    engine = _engine(["virusbarrier.xyz"])
    engine.ingest_ct_records(
        [
            {
                "name_value": "\n".join(sans),
                "fingerprint_sha256": "c" * 64,
                "serial_number": "01ab",
                "issuer_name": "Let's Encrypt YE1",
                "query_domain": "virusbarrier.xyz",
            }
        ]
    )
    engine.correlate()
    shared = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    assert shared
    assert all(r.confidence is ConfidenceBand.HIGH for r in shared)
    assert all(r.data.get("san_cardinality") == 6 for r in shared)
    ev = engine.evidence[shared[0].evidence_id]
    assert ev.metadata.get("san_cardinality") == 6
    assert ev.metadata.get("certificate_fingerprint") == "c" * 64
    assert ev.metadata.get("certificate_serial") == "01ab"
    assert ev.metadata.get("source") == "correlation"
    assert ev.observed_at
    blob = str(shared[0].to_dict()).lower()
    assert "actor" not in blob
    assert "owner" not in blob


def test_hundred_unrelated_etld_is_not_high_clique() -> None:
    sans = [f"org{i}.example{i}.test" for i in range(100)]
    band, _reason = shares_certificate_confidence(sans, identity_kind="sha256")
    assert band is not ConfidenceBand.HIGH
    engine = _engine(["org0.example0.test"])
    engine.ingest_ct_records(
        [
            {
                "name_value": "\n".join(sans),
                "fingerprint_sha256": "d" * 64,
                "query_domain": "org0.example0.test",
            }
        ]
    )
    engine.correlate()
    shared = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    sans = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SAN_CONTAINS
    ]
    assert shared == []
    assert len(sans) == 100
    cert = next(e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE)
    assert len(cert.data.get("sans") or []) == 100


def test_shares_ipv4_evidence_marks_cloud_tenancy() -> None:
    engine = _engine(["a.example.com", "b.example.com"])
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
    assert all(r.confidence is ConfidenceBand.MEDIUM for r in shared)
    assert all(r.strength == "shared_cloud_tenancy" for r in shared)
    assert all(r.data.get("shared_cloud_tenancy") is True for r in shared)
    ev = engine.evidence[shared[0].evidence_id]
    assert ev.metadata.get("ip") == "34.75.127.116"
    assert ev.metadata.get("source") == "correlation"
    assert ev.metadata.get("shared_cloud_tenancy") is True
    assert ev.metadata.get("provider") == "GCP"


def test_favicon_alone_is_not_high() -> None:
    engine = _engine(["a.example.com", "b.example.com"])
    engine.ingest_hosts(
        {
            "a.example.com": Host(
                domain="a.example.com",
                dns_resolved=True,
                http_services=[
                    HttpService(
                        url="https://a.example.com",
                        host="a.example.com",
                        favicon_hash="deadbeef",
                    )
                ],
            ),
            "b.example.com": Host(
                domain="b.example.com",
                dns_resolved=True,
                http_services=[
                    HttpService(
                        url="https://b.example.com",
                        host="b.example.com",
                        favicon_hash="deadbeef",
                    )
                ],
            ),
        }
    )
    engine.correlate()
    fav = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_FAVICON
    ]
    assert fav
    assert all(r.confidence is ConfidenceBand.MEDIUM for r in fav)
    assert all(r.data.get("corroborated") is False for r in fav)


def test_favicon_plus_body_hash_is_high() -> None:
    engine = _engine(["a.example.com", "b.example.com"])
    engine.ingest_hosts(
        {
            "a.example.com": Host(
                domain="a.example.com",
                dns_resolved=True,
                http_services=[
                    HttpService(
                        url="https://a.example.com",
                        host="a.example.com",
                        favicon_hash="deadbeef",
                        body_hash="body111",
                    )
                ],
            ),
            "b.example.com": Host(
                domain="b.example.com",
                dns_resolved=True,
                http_services=[
                    HttpService(
                        url="https://b.example.com",
                        host="b.example.com",
                        favicon_hash="deadbeef",
                        body_hash="body111",
                    )
                ],
            ),
        }
    )
    engine.correlate()
    fav = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_FAVICON
    ]
    body = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_BODY_HASH
    ]
    assert fav and body
    assert all(r.confidence is ConfidenceBand.HIGH for r in fav)
    assert all(r.confidence is ConfidenceBand.HIGH for r in body)


def test_plugin_rejects_actor_and_unsubstantiated_cert_share() -> None:
    assert (
        validate_emitted_relationship(
            {
                "source_entity": "actor:apt-x",
                "target_entity": "domain:example.com",
                "relationship_type": "SHARES_CERTIFICATE",
                "confidence": "HIGH",
            }
        )
        is None
    )
    assert (
        validate_emitted_relationship(
            {
                "source_entity": "domain:a.example",
                "target_entity": "domain:b.example",
                "relationship_type": "SHARES_CERTIFICATE",
                "confidence": "VERY_HIGH",
            }
        )
        is None
    )
    accepted = validate_emitted_relationship(
        {
            "source_entity": "domain:a.example",
            "target_entity": "domain:b.example",
            "relationship_type": "SHARES_CERTIFICATE",
            "confidence": "VERY_HIGH",
            "metadata": {"fingerprint_sha256": "e" * 64},
        }
    )
    assert accepted is not None
    assert accepted["confidence"] is ConfidenceBand.HIGH

    engine = _engine(["example.com"])
    engine.ingest_emissions(
        [
            StructuredEmission(
                relationships=[
                    {
                        "source_entity": "owner:someone",
                        "target_entity": "domain:example.com",
                        "relationship_type": "SHARES_ASN",
                        "confidence": "HIGH",
                    },
                    {
                        "source_entity": "domain:example.com",
                        "target_entity": "domain:other.example",
                        "relationship_type": "SHARES_CERTIFICATE",
                        "confidence": "VERY_HIGH",
                    },
                ]
            ).to_dict()
        ]
    )
    assert not engine.relationships


def test_cluster_and_report_use_named_confidence(tmp_path: Path, settings: Settings) -> None:
    hosts = {
        "a.example.com": Host(domain="a.example.com", ips=["34.75.127.116"]),
        "b.example.com": Host(domain="b.example.com", ips=["34.75.127.116"]),
    }
    for host in hosts.values():
        host.http_services.append(
            HttpService(url=f"https://{host.domain}", host=host.domain, favicon_hash="abc")
        )
    clusters = compute_clusters(hosts)
    ip_cluster = next(c for c in clusters if c.cluster_type == "ip")
    fav_cluster = next(c for c in clusters if c.cluster_type == "favicon")
    assert ip_cluster.confidence == band_score(ConfidenceBand.MEDIUM)
    assert "shared_cloud_tenancy" in ip_cluster.description
    assert fav_cluster.confidence == band_score(ConfidenceBand.MEDIUM)
    assert ip_cluster.confidence != 90
    assert fav_cluster.confidence != 95

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain="a.example.com")],
        output_dir=output_dir,
        run_id="corr-html",
    )
    db = tmp_path / "recon.db"
    store = AssetStore(db)
    store.create_run(
        ScanRun(run_id="corr-html", started_at="2026-08-21T00:00:00Z", targets=["a.example.com"])
    )
    store.persist_registry("corr-html", hosts, clusters=clusters)
    store.finish_run("corr-html", host_count=2, alive_count=2, warnings=[], errors=[])
    ReportGenerator(settings).generate(context, store=store)
    html = (output_dir / "summary.html").read_text(encoding="utf-8")
    md = (settings.project_root / settings.reports_directory / "overview.md").read_text(
        encoding="utf-8"
    )
    combined = html + md
    assert "MEDIUM" in combined
    assert "shared cloud tenancy, not ownership" in combined
    assert "actor" not in combined.lower() or "not actor" in combined.lower()
    assert "ownership" in combined
    assert "not ownership" in combined

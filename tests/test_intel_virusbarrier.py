"""Mandatory six-domain virusbarrier regression fixture.

The current Host/CT pipeline discarded off-root SANs. This fixture requires
the intelligence engine to retain them as observations without probing them.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.model import (
    CollectionStatus,
    ConfidenceBand,
    EntityType,
    IndicatorKind,
    RelationshipType,
    ScopeStatus,
)

FIXTURE = Path(__file__).parent / "fixtures" / "virusbarrier"
CASE = json.loads((FIXTURE / "case.json").read_text(encoding="utf-8"))
SANS = list(CASE["sans"])
FINGERPRINT = CASE["fingerprint_sha256"]
SEED = CASE["seed"]
IP = CASE["ipv4"]


def _write_artifacts(tmp_path: Path) -> Path:
    names = "\n".join(SANS)
    (tmp_path / "ctlogs.jsonl").write_text(
        json.dumps(
            {
                "id": 424242,
                "common_name": CASE["subject"],
                "name_value": names,
                "issuer_name": CASE["issuer"],
                "not_before": CASE["not_before"],
                "not_after": CASE["not_after"],
                "fingerprint_sha256": FINGERPRINT,
                "query_domain": SEED,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "httpx.json").write_text(
        json.dumps(
            {
                "input": SEED,
                "host": SEED,
                "url": f"https://{SEED}/",
                "ip": IP,
                "a": [IP],
                "status_code": 200,
                "title": "VirusBarrier",
                "tls": {
                    "subject_cn": CASE["subject"],
                    "issuer_cn": CASE["issuer"],
                    "subject_an": SANS,
                    "not_before": CASE["not_before"],
                    "not_after": CASE["not_after"],
                    "fingerprint_hash": {"sha256": FINGERPRINT},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return tmp_path


def _engine(tmp_path: Path, *, with_sibling_resolutions: bool = False) -> IntelEngine:
    _write_artifacts(tmp_path)
    config = IntelRunConfig(
        run_id="virusbarrier-fixture",
        seed_domains=[SEED],
        scope_patterns=[SEED],
        collected_domains={SEED},
        observed_at="2026-08-21T00:00:00Z",
    )
    engine = IntelEngine(config)
    engine.ingest_artifacts(tmp_path)
    if with_sibling_resolutions:
        engine.ingest_passive_resolutions({name: IP for name in SANS}, collector="case_fixture")
    engine.correlate()
    return engine


def test_virusbarrier_retains_all_six_names(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    domains = {e.key for e in engine.entities.values() if e.entity_type is EntityType.DOMAIN}
    assert set(SANS) <= domains


def test_virusbarrier_seed_collected_siblings_not_probed(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    seed = engine.entities[f"domain:{SEED}"]
    assert seed.is_seed
    assert seed.collection_status is CollectionStatus.COLLECTED
    assert seed.scope_status is ScopeStatus.IN_SCOPE
    for name in SANS:
        if name == SEED:
            continue
        entity = engine.entities[f"domain:{name}"]
        assert entity.scope_status is ScopeStatus.OUT_OF_SCOPE
        assert entity.collection_status is CollectionStatus.NOT_ALLOWED
        indicator = engine.queue.get(IndicatorKind.DOMAIN, name)
        assert indicator is not None
        assert indicator.collection_status is CollectionStatus.NOT_ALLOWED
        assert indicator.reason.value == "CERTIFICATE_SAN"


def test_virusbarrier_single_fingerprint_certificate(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    fingerprinted = [c for c in certs if c.data.get("fingerprint_sha256") == FINGERPRINT]
    assert len(fingerprinted) == 1
    cert = fingerprinted[0]
    assert cert.entity_id == f"certificate:{FINGERPRINT}"
    assert set(cert.data.get("sans") or []) == set(SANS)


def test_virusbarrier_san_relationships_and_shared_cert(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    cert_id = f"certificate:{FINGERPRINT}"
    san_edges = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SAN_CONTAINS
    ]
    assert {r.target_entity for r in san_edges} == {f"domain:{n}" for n in SANS}
    assert all(r.source_entity == cert_id for r in san_edges)
    assert all(r.confidence is ConfidenceBand.VERY_HIGH for r in san_edges)

    shared = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    assert shared
    assert all(r.confidence is ConfidenceBand.HIGH for r in shared)
    assert all(r.data.get("fingerprint_sha256") == FINGERPRINT for r in shared)
    assert all("actor" not in json.dumps(r.to_dict()).lower() for r in shared)
    assert all("owner" not in json.dumps(r.to_dict()).lower() for r in shared)


def test_virusbarrier_shared_ipv4_is_medium_cloud_tenancy(tmp_path: Path) -> None:
    engine = _engine(tmp_path, with_sibling_resolutions=True)
    ipv4 = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert ipv4
    assert all(r.confidence is ConfidenceBand.MEDIUM for r in ipv4)
    assert all(r.strength == "shared_cloud_tenancy" for r in ipv4)
    ip_entity = engine.entities[f"ip_address:{IP}"]
    assert ip_entity.data.get("provider") == "GCP"
    assert ip_entity.data.get("cloud_tenancy") is True


def test_virusbarrier_graph_and_evidence(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    graph = engine.to_infrastructure_graph()
    domain_nodes = [n for n in graph.nodes if n.startswith("domain:")]
    assert {n.removeprefix("domain:") for n in domain_nodes} >= set(SANS)
    cert_nodes = [n for n in graph.nodes if n.startswith("certificate:")]
    assert cert_nodes == [f"certificate:{FINGERPRINT}"]
    blob = json.dumps(graph.to_dict())
    assert "actor" not in blob.lower()
    assert "owner" not in blob.lower()
    assert "threat actor" not in blob.lower()

    presents = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.PRESENTS_CERTIFICATE
    ]
    assert any(r.source_entity == f"domain:{SEED}" for r in presents)
    for rel in engine.relationships.values():
        ev = engine.evidence[rel.evidence_id]
        assert ev.reason
        assert ev.source


def test_virusbarrier_followups_do_not_include_oos(tmp_path: Path) -> None:
    engine = _engine(tmp_path, with_sibling_resolutions=False)
    followups = engine.eligible_followups()
    assert all(
        item.value == SEED or item.scope_status is ScopeStatus.IN_SCOPE for item in followups
    )
    assert not any(item.value in set(SANS) - {SEED} for item in followups)


def test_old_ct_filter_would_drop_siblings() -> None:
    """Document the historical bug the fixture exists to prevent."""
    from modules.ctlogs import _extract_names, extract_all_names

    raw = "\n".join(SANS)
    kept_old = _extract_names(raw, SEED)
    assert kept_old == {SEED}
    assert extract_all_names(raw) == set(SANS)

"""Certificate identity is fingerprint-first. SAN equality is not identity."""

from __future__ import annotations

from core.intel.bounds import DiscoveryBounds
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.model import EntityType, RelationshipType, ScopeStatus

FP_A = "a" * 64
FP_B = "b" * 64
SANS = ["x.example", "y.example", "z.example"]


def _engine(**kwargs) -> IntelEngine:
    bounds = kwargs.pop("bounds", DiscoveryBounds())
    return IntelEngine(
        IntelRunConfig(
            run_id="cert",
            seed_domains=["x.example"],
            collected_domains={"x.example"},
            bounds=bounds,
            **kwargs,
        )
    )


def test_duplicate_certificates_same_sans_different_fingerprints() -> None:
    engine = _engine()
    engine.ingest_ct_records(
        [
            {
                "id": 1,
                "name_value": "\n".join(SANS),
                "fingerprint_sha256": FP_A,
                "query_domain": "x.example",
            },
            {
                "id": 2,
                "name_value": "\n".join(SANS),
                "fingerprint_sha256": FP_B,
                "query_domain": "x.example",
            },
        ]
    )
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    fps = {c.data.get("fingerprint_sha256") for c in certs}
    assert FP_A in fps
    assert FP_B in fps
    assert len(certs) == 2
    assert (
        engine.entities[f"certificate:{FP_A}"].entity_id
        != engine.entities[f"certificate:{FP_B}"].entity_id
    )
    engine.correlate()
    shares = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    cert_ids = {r.data.get("certificate") or r.data.get("fingerprint_sha256") for r in shares}
    assert any(FP_A in str(item) for item in cert_ids) or any(
        "certificate:" + FP_A in str(r.data) for r in shares
    )


def test_certificate_rotation_preserves_history() -> None:
    engine = _engine()
    engine.ingest_httpx_records(
        [
            {
                "input": "x.example",
                "host": "x.example",
                "tls": {
                    "subject_an": SANS,
                    "fingerprint_hash": {"sha256": FP_A},
                },
            },
            {
                "input": "x.example",
                "host": "x.example",
                "tls": {
                    "subject_an": SANS,
                    "fingerprint_hash": {"sha256": FP_B},
                },
            },
        ]
    )
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    assert {c.data.get("fingerprint_sha256") for c in certs} == {FP_A, FP_B}


def test_crtsh_serial_issuer_without_fingerprint_does_not_invent_sha256() -> None:
    engine = _engine()
    engine.ingest_ct_records(
        [
            {
                "id": 4242,
                "name_value": "\n".join(SANS),
                "serial_number": "00aabbcc",
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
                "query_domain": "x.example",
            }
        ]
    )
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    assert certs
    cert = certs[0]
    assert cert.data.get("identity_kind") == "serial_issuer"
    assert not cert.data.get("fingerprint_sha256")
    assert "a" * 64 not in (cert.key or "")
    engine.correlate()
    shares = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    # serial+issuer is a weaker cryptographic identity, so correlation is allowed,
    # but Hydra must not claim a SHA-256 fingerprint it never observed.
    for rel in shares:
        assert not rel.data.get("fingerprint_sha256")
        assert rel.data.get("certificate_serial") == "00aabbcc"


def test_unidentified_ct_record_does_not_emit_shares_certificate() -> None:
    engine = _engine()
    engine.ingest_ct_records(
        [
            {
                "id": 7,
                "name_value": "\n".join(SANS),
                "query_domain": "x.example",
            }
        ]
    )
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    assert certs
    assert all(c.data.get("identity_kind") == "unidentified" for c in certs)
    engine.correlate()
    shares = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    assert shares == []
    assert any(
        r.relationship_type is RelationshipType.SAN_CONTAINS for r in engine.relationships.values()
    )


def test_100_san_certificate_stays_hub_not_clique() -> None:
    names = ["x.example"] + [f"n{i}.other.test" for i in range(99)]
    engine = _engine()
    engine.ingest_ct_records(
        [
            {
                "id": 100,
                "name_value": "\n".join(names),
                "fingerprint_sha256": FP_A,
                "query_domain": "x.example",
            }
        ]
    )
    engine.correlate()
    shares = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    sans = [
        r
        for r in engine.relationships.values()
        if r.relationship_type is RelationshipType.SAN_CONTAINS
    ]
    assert shares == []
    assert len(sans) >= 2
    cert = engine.entities[f"certificate:{FP_A}"]
    assert cert.data.get("san_cardinality") == 100


def test_10000_san_certificate_does_not_starve_seed() -> None:
    names = ["x.example"] + [f"n{i}.other.test" for i in range(10000)]
    engine = _engine(
        bounds=DiscoveryBounds(
            max_entities=80,
            max_ct_names_per_certificate=40,
            max_certificates=10,
            max_relationships=500,
        )
    )
    engine.ingest_ct_records(
        [
            {
                "id": 99,
                "name_value": "\n".join(names),
                "fingerprint_sha256": FP_A,
                "query_domain": "x.example",
            }
        ]
    )
    snapshot = engine.snapshot()
    assert snapshot.truncated
    assert snapshot.truncation_reason in {
        "ct_names_per_certificate",
        "entity_limit",
        "certificate_limit",
    }
    seed = engine.entities.get("domain:x.example")
    assert seed is not None
    assert seed.is_seed
    assert seed.scope_status is ScopeStatus.IN_SCOPE
    observed_others = [
        e.key
        for e in engine.entities.values()
        if e.entity_type is EntityType.DOMAIN and e.key != "x.example"
    ]
    assert len(observed_others) <= 40
    engine.correlate()
    for rel in engine.relationships.values():
        assert rel.source_entity in engine.entities
        assert rel.target_entity in engine.entities
        assert rel.evidence_id in engine.evidence

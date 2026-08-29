"""Field-level historical diff and previous-run selection."""

from __future__ import annotations

from core.assets import Host, HttpService, Port, ScanRun, TechnologyFinding, TlsCertificate
from core.diff import diff_runs
from core.store import AssetStore


def _host(domain: str, **kwargs) -> Host:
    host = Host(domain=domain, dns_resolved=True)
    for key, value in kwargs.items():
        setattr(host, key, value)
    return host


def test_previous_run_uses_target_overlap(tmp_path) -> None:
    store = AssetStore(tmp_path / "db.sqlite")
    store.create_run(
        ScanRun(run_id="unrelated", started_at="2026-01-01T00:00:00Z", targets=["other.com"])
    )
    store.finish_run("unrelated", host_count=1, alive_count=0, warnings=[], errors=[])
    store.create_run(
        ScanRun(run_id="old", started_at="2026-01-02T00:00:00Z", targets=["example.com"])
    )
    store.finish_run("old", host_count=1, alive_count=0, warnings=[], errors=[])
    store.create_run(
        ScanRun(run_id="new", started_at="2026-01-03T00:00:00Z", targets=["example.com"])
    )
    store.create_run(
        ScanRun(run_id="crash", started_at="2026-01-04T00:00:00Z", targets=["example.com"])
    )
    assert store.find_previous_run("new") == "old"
    store.create_run(
        ScanRun(run_id="newer", started_at="2026-01-05T00:00:00Z", targets=["example.com"])
    )
    assert store.find_previous_run("newer") == "old"


def test_field_level_certificate_and_ip_diff(tmp_path) -> None:
    store = AssetStore(tmp_path / "db.sqlite")
    store.create_run(
        ScanRun(run_id="a", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    old = _host("example.com", ips=["34.75.127.116"], asn="396982")
    old.tls = TlsCertificate(
        host="example.com",
        fingerprint_sha256="a" * 64,
        sans=["example.com"],
        not_after="2026-01-01",
    )
    old.ports.append(Port(host="example.com", port=443, protocol="tcp"))
    old.http_services.append(
        HttpService(
            url="https://example.com",
            host="example.com",
            status_code=200,
            title="Old",
            favicon_hash="111",
            body_hash="bbb",
            technologies=[TechnologyFinding(name="nginx", source="httpx", confidence=90)],
        )
    )
    store.persist_registry("a", {old.domain: old})
    store.finish_run("a", host_count=1, alive_count=1, warnings=[], errors=[])

    store.create_run(
        ScanRun(run_id="b", started_at="2026-01-02T00:00:00Z", targets=["example.com"])
    )
    new = _host("example.com", ips=["35.1.2.3"], asn="1")
    new.tls = TlsCertificate(
        host="example.com",
        fingerprint_sha256="b" * 64,
        sans=["example.com", "virusinspector.top"],
        not_after="2026-06-01",
    )
    new.ports.append(Port(host="example.com", port=80, protocol="tcp"))
    new.http_services.append(
        HttpService(
            url="https://example.com/login",
            host="example.com",
            status_code=401,
            title="New",
            favicon_hash="222",
            body_hash="ccc",
            technologies=[TechnologyFinding(name="apache", source="httpx", confidence=90)],
        )
    )
    www = _host("www.example.com", ips=["35.1.2.3"])
    store.persist_registry("b", {new.domain: new, www.domain: www})
    store.finish_run("b", host_count=2, alive_count=1, warnings=[], errors=[])

    diff = diff_runs(store, "b")
    assert diff is not None
    assert diff.previous_run_id == "a"
    assert diff.new_hosts == ["www.example.com"]
    assert diff.removed_hosts == []
    types = {c.change_type for c in diff.field_changes}
    assert "CERTIFICATE_CHANGED" in types
    assert "SAN_ADDED" in types
    assert "IP_CHANGED" in types
    assert "HTTP_STATUS_CHANGED" in types
    assert "PORTS_CHANGED" in types
    assert "TECHNOLOGIES_CHANGED" in types
    assert "FAVICON_CHANGED" in types
    assert "BODY_HASH_CHANGED" in types
    assert any(
        c.new == ["virusinspector.top"] for c in diff.field_changes if c.change_type == "SAN_ADDED"
    )
    assert diff.new_http == ["https://example.com/login"]
    assert diff.removed_http == ["https://example.com"]


def test_intel_relationship_history_tracks_certificate_rotation(tmp_path) -> None:
    from core.intel.engine import IntelEngine, IntelRunConfig
    from core.intel.model import RelationshipType

    store = AssetStore(tmp_path / "db.sqlite")
    sans = ["example.com", "www.example.com"]
    fp_a = "a" * 64
    fp_b = "b" * 64

    def _snap(run_id: str, fingerprint: str):
        engine = IntelEngine(
            IntelRunConfig(
                run_id=run_id,
                seed_domains=["example.com", "www.example.com"],
                collected_domains={"example.com", "www.example.com"},
                observed_at="2026-01-01T00:00:00Z",
            )
        )
        engine.ingest_ct_records(
            [
                {
                    "id": fingerprint[:4],
                    "name_value": "\n".join(sans),
                    "fingerprint_sha256": fingerprint,
                    "query_domain": "example.com",
                }
            ]
        )
        engine.correlate()
        return engine.snapshot()

    store.create_run(
        ScanRun(run_id="rel-a", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("rel-a", {}, intel=_snap("rel-a", fp_a))
    store.finish_run("rel-a", host_count=1, alive_count=0, warnings=[], errors=[])

    store.create_run(
        ScanRun(run_id="rel-b", started_at="2026-01-02T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("rel-b", {}, intel=_snap("rel-b", fp_b))
    store.finish_run("rel-b", host_count=1, alive_count=0, warnings=[], errors=[])

    diff = diff_runs(store, "rel-b", "rel-a")
    assert diff is not None
    appeared = [
        r for r in diff.new_relationships if r.get("relationship_type") == "SHARES_CERTIFICATE"
    ]
    disappeared = [
        r for r in diff.removed_relationships if r.get("relationship_type") == "SHARES_CERTIFICATE"
    ]
    assert appeared
    assert disappeared
    assert appeared[0]["relationship_id"] != disappeared[0]["relationship_id"]
    assert RelationshipType.SHARES_CERTIFICATE.value in {
        appeared[0]["relationship_type"],
        disappeared[0]["relationship_type"],
    }
    assert any(c["change_type"] == "CERTIFICATE_APPEARED" for c in diff.certificate_rotations)
    assert any(c["change_type"] == "CERTIFICATE_DISAPPEARED" for c in diff.certificate_rotations)
    assert diff.new_entities
    assert diff.new_evidence or diff.removed_evidence or diff.new_observations


def test_intel_relationship_confidence_change_is_reported(tmp_path) -> None:
    """Same relationship_id, HIGH -> MEDIUM confidence, must show up as a change,
    not be silently dropped because it's neither a new nor a removed relationship."""
    from core.intel.engine import IntelEngine, IntelRunConfig
    from core.intel.model import ConfidenceBand

    store = AssetStore(tmp_path / "db.sqlite")
    sans = ["example.com", "www.example.com"]
    fp = "c" * 64

    def _snap(run_id: str, *, confidence: ConfidenceBand):
        engine = IntelEngine(
            IntelRunConfig(
                run_id=run_id,
                seed_domains=["example.com", "www.example.com"],
                collected_domains={"example.com", "www.example.com"},
                observed_at="2026-01-01T00:00:00Z",
            )
        )
        engine.ingest_ct_records(
            [
                {
                    "id": "1",
                    "name_value": "\n".join(sans),
                    "fingerprint_sha256": fp,
                    "query_domain": "example.com",
                }
            ]
        )
        engine.correlate()
        # Confidence is under the diff's test, not the correlation heuristic
        # (already covered elsewhere) — force it so the scenario is exact.
        for rel in engine.relationships.values():
            rel.confidence = confidence
        return engine.snapshot()

    store.create_run(
        ScanRun(run_id="conf-a", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("conf-a", {}, intel=_snap("conf-a", confidence=ConfidenceBand.HIGH))
    store.finish_run("conf-a", host_count=1, alive_count=0, warnings=[], errors=[])

    store.create_run(
        ScanRun(run_id="conf-b", started_at="2026-01-02T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("conf-b", {}, intel=_snap("conf-b", confidence=ConfidenceBand.MEDIUM))
    store.finish_run("conf-b", host_count=1, alive_count=0, warnings=[], errors=[])

    diff = diff_runs(store, "conf-b", "conf-a")
    assert diff is not None
    assert not diff.new_relationships
    assert not diff.removed_relationships
    assert diff.changed_relationships
    change = diff.changed_relationships[0]
    assert change["change_type"] == "CONFIDENCE_DECREASED"
    assert change["old_confidence"] == "HIGH"
    assert change["new_confidence"] == "MEDIUM"


def test_intel_relationship_evidence_change_is_reported(tmp_path) -> None:
    """Same relationship_id, same confidence, genuinely different evidence content
    (a third domain joins the shared certificate) must be reported as a change.

    `evidence_id` itself is *not* usable as the change signal — it is derived
    from an observation_id namespaced by run_id (`core/intel/engine.py:
    _observe`), so it differs between any two runs even when nothing at all
    changed. `_intel_relationship_diff` must compare the relationship's
    content (`data`) instead, or every relationship would show as "changed"
    on every re-scan regardless of anything real changing — this test would
    fail against that naive implementation because the SHARES_CERTIFICATE
    relationship between example.com and www.example.com keeps the exact
    same relationship_id and confidence in both runs; only its
    `san_cardinality`/`members` content changes.
    """
    from core.intel.engine import IntelEngine, IntelRunConfig
    from core.intel.model import RelationshipType

    store = AssetStore(tmp_path / "db.sqlite")
    fp = "d" * 64

    def _snap(run_id: str, sans: list[str]):
        engine = IntelEngine(
            IntelRunConfig(
                run_id=run_id,
                seed_domains=["example.com", "www.example.com", "extra.example.com"],
                collected_domains=set(sans),
                observed_at="2026-01-01T00:00:00Z",
            )
        )
        engine.ingest_ct_records(
            [
                {
                    "id": "1",
                    "name_value": "\n".join(sans),
                    "fingerprint_sha256": fp,
                    "query_domain": "example.com",
                }
            ]
        )
        engine.correlate()
        return engine.snapshot()

    store.create_run(
        ScanRun(run_id="ev-a", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("ev-a", {}, intel=_snap("ev-a", ["example.com", "www.example.com"]))
    store.finish_run("ev-a", host_count=1, alive_count=0, warnings=[], errors=[])

    store.create_run(
        ScanRun(run_id="ev-b", started_at="2026-01-02T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry(
        "ev-b",
        {},
        intel=_snap("ev-b", ["example.com", "www.example.com", "extra.example.com"]),
    )
    store.finish_run("ev-b", host_count=1, alive_count=0, warnings=[], errors=[])

    diff = diff_runs(store, "ev-b", "ev-a")
    assert diff is not None
    shares_cert_changed = [
        c
        for c in diff.changed_relationships
        if c["relationship_type"] == RelationshipType.SHARES_CERTIFICATE.value
        and {c["source_entity"], c["target_entity"]}
        == {"domain:example.com", "domain:www.example.com"}
    ]
    assert shares_cert_changed, (
        "expected the example.com<->www.example.com SHARES_CERTIFICATE relationship "
        "(same relationship_id in both runs) to show up as changed"
    )
    change = shares_cert_changed[0]
    assert change["change_type"] == "EVIDENCE_CHANGED"
    assert change["old_confidence"] == change["new_confidence"]
    # evidence_id is still reported for reference but is not the change signal.
    assert change["old_evidence_id"] != change["new_evidence_id"]

    # And a scan producing byte-identical CT input must NOT report a spurious
    # change just because evidence_id is namespaced by run_id.
    store.create_run(
        ScanRun(run_id="ev-c", started_at="2026-01-03T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry(
        "ev-c",
        {},
        intel=_snap("ev-c", ["example.com", "www.example.com", "extra.example.com"]),
    )
    store.finish_run("ev-c", host_count=1, alive_count=0, warnings=[], errors=[])
    stable_diff = diff_runs(store, "ev-c", "ev-b")
    assert stable_diff is not None
    assert stable_diff.new_relationships == []
    assert stable_diff.removed_relationships == []
    assert stable_diff.changed_relationships == []

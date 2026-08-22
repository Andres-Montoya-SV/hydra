"""SQLite integrity, unfinished runs, entity/relationship caps, cert rotation."""

from __future__ import annotations

import time

from core.assets import ScanRun
from core.intel.bounds import DiscoveryBounds
from core.intel.cli import cmd_investigate
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.model import EntityType, RelationshipType
from core.store import AssetStore


def _persist(store: AssetStore, run_id: str, engine: IntelEngine, *, finish: bool) -> None:
    store.create_run(
        ScanRun(run_id=run_id, started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry(run_id, {}, intel=engine.snapshot())
    if finish:
        store.finish_run(run_id, host_count=1, alive_count=0, warnings=[], errors=[])


def _ct_record(names: list[str], fingerprint: str, query: str = "example.com") -> dict:
    return {
        "name_value": "\n".join(names),
        "fingerprint_sha256": fingerprint,
        "query_domain": query,
        "common_name": names[0],
    }


def test_investigate_skips_newer_unfinished_run(tmp_path, capsys) -> None:
    db = tmp_path / "recon.db"
    store = AssetStore(db)
    finished = IntelEngine(
        IntelRunConfig(
            run_id="run-a",
            seed_domains=["example.com"],
            collected_domains={"example.com"},
        )
    )
    finished.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "ip": "1.2.3.4",
                "tls": {
                    "subject_an": ["example.com"],
                    "fingerprint_hash": {"sha256": "a" * 64},
                },
            }
        ]
    )
    store.create_run(
        ScanRun(run_id="run-a", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("run-a", {}, intel=finished.snapshot())
    store.finish_run("run-a", host_count=1, alive_count=1, warnings=[], errors=[])

    crashed = IntelEngine(
        IntelRunConfig(run_id="run-b", seed_domains=["example.com"], collected_domains=set())
    )
    store.create_run(
        ScanRun(run_id="run-b", started_at="2026-01-02T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("run-b", {}, intel=crashed.snapshot())

    assert store.find_latest_finished_run(domain="example.com") == "run-a"
    assert cmd_investigate(db, "example.com", None, None) == 0
    out = capsys.readouterr().out
    assert "run-a" in out
    assert "run-b" not in out
    assert store.intel_integrity("run-a")["ok"] is True
    assert store.intel_integrity("run-b")["ok"] is True


def test_entity_cap_fail_closed_no_dummy_or_orphans(tmp_path) -> None:
    names = ["example.com"] + [f"h{i}.example.com" for i in range(40)]
    engine = IntelEngine(
        IntelRunConfig(
            run_id="cap-e",
            seed_domains=["example.com"],
            bounds=DiscoveryBounds(max_entities=5, max_relationships=200),
        )
    )
    engine.ingest_ct_records([_ct_record(names, "1" * 64)])
    snap = engine.snapshot()
    assert snap.truncated is True
    assert snap.truncation_reason == "entity_limit"
    assert len(snap.entities) <= 5
    known = set(snap.entities)
    assert all(obs.entity_id in known for obs in snap.observations)
    assert all(
        rel.source_entity in known and rel.target_entity in known
        for rel in snap.relationships.values()
    )

    store = AssetStore(tmp_path / "cap.db")
    _persist(store, "cap-e", engine, finish=True)
    report = store.intel_integrity("cap-e")
    assert report["ok"] is True
    assert report["foreign_keys"] == 1
    with store.intel_connection() as conn:
        row = conn.execute(
            "SELECT intel_truncated, intel_truncation_reason FROM runs WHERE run_id='cap-e'"
        ).fetchone()
    assert row["intel_truncated"] == 1
    assert row["intel_truncation_reason"] == "entity_limit"


def test_relationship_cap_keeps_strong_hub_edges(tmp_path) -> None:
    names = [f"h{i}.example.com" for i in range(200)]
    engine = IntelEngine(
        IntelRunConfig(
            run_id="cap-r",
            seed_domains=["example.com"],
            bounds=DiscoveryBounds(
                max_entities=5000,
                max_relationships=80,
                max_ct_names_per_certificate=500,
            ),
        )
    )
    engine.ingest_ct_records([_ct_record(["example.com", *names], "2" * 64)])
    engine.correlate()
    snap = engine.snapshot()
    shares = [
        rel
        for rel in snap.relationships.values()
        if rel.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    sans = [
        rel
        for rel in snap.relationships.values()
        if rel.relationship_type is RelationshipType.SAN_CONTAINS
    ]
    assert len(shares) == 0
    assert len(sans) >= 1
    assert len(snap.relationships) <= 80
    assert snap.truncated is True
    assert snap.truncation_reason == "relationship_limit"

    store = AssetStore(tmp_path / "rel.db")
    _persist(store, "cap-r", engine, finish=True)
    assert store.intel_integrity("cap-r")["ok"] is True


def test_large_certificate_does_not_emit_unbounded_clique() -> None:
    names = [f"h{i}.example.com" for i in range(200)]
    engine = IntelEngine(
        IntelRunConfig(
            run_id="clique",
            seed_domains=["example.com"],
            bounds=DiscoveryBounds(
                max_entities=5000,
                max_relationships=20000,
                max_ct_names_per_certificate=500,
            ),
        )
    )
    engine.ingest_ct_records([_ct_record(["example.com", *names], "3" * 64)])
    engine.correlate()
    shares = [
        rel
        for rel in engine.relationships.values()
        if rel.relationship_type is RelationshipType.SHARES_CERTIFICATE
    ]
    sans = [
        rel
        for rel in engine.relationships.values()
        if rel.relationship_type is RelationshipType.SAN_CONTAINS
    ]
    assert len(shares) == 0
    assert len(sans) == 201
    assert len(engine.relationships) < 500


def test_certificate_rotation_keeps_historical_and_current_observations() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="rotate",
            seed_domains=["example.com"],
            collected_domains={"example.com"},
        )
    )
    old_fp = "a" * 64
    new_fp = "b" * 64
    engine.ingest_ct_records([_ct_record(["example.com", "www.example.com"], old_fp)])
    engine.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "tls": {
                    "subject_an": ["example.com", "www.example.com"],
                    "fingerprint_hash": {"sha256": new_fp},
                },
            }
        ]
    )
    engine.correlate()
    certs = [e for e in engine.entities.values() if e.entity_type is EntityType.CERTIFICATE]
    fps = {c.data.get("fingerprint_sha256") for c in certs}
    assert fps == {old_fp, new_fp}
    cert_obs = [obs for obs in engine.observations if obs.entity_id.startswith("certificate:")]
    observed = {obs.entity_id for obs in cert_obs}
    assert f"certificate:{old_fp}" in observed
    assert f"certificate:{new_fp}" in observed
    assert not hasattr(IntelEngine, "_merge_equivalent_certificates")


def test_find_previous_run_bounded_with_hundreds_of_runs(tmp_path) -> None:
    store = AssetStore(tmp_path / "hist.db")
    for i in range(300):
        run_id = f"hist-{i:03d}"
        store.create_run(
            ScanRun(
                run_id=run_id,
                started_at=f"2026-01-01T{i // 60:02d}:{i % 60:02d}:00Z",
                targets=["example.com"],
            )
        )
        store.finish_run(run_id, host_count=1, alive_count=0, warnings=[], errors=[])
    store.create_run(
        ScanRun(run_id="crash", started_at="2026-06-01T00:00:00Z", targets=["example.com"])
    )
    store.create_run(
        ScanRun(run_id="current", started_at="2026-06-02T00:00:00Z", targets=["example.com"])
    )
    started = time.monotonic()
    previous = store.find_previous_run("current")
    elapsed = time.monotonic() - started
    assert previous == "hist-299"
    assert elapsed < 1.0
    assert store.find_latest_finished_run() == "hist-299"


def test_sqlite_foreign_keys_and_integrity_on_normal_run(tmp_path) -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="ok",
            seed_domains=["example.com"],
            collected_domains={"example.com"},
        )
    )
    engine.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "ip": "1.2.3.4",
                "tls": {
                    "subject_an": ["example.com", "www.example.com"],
                    "fingerprint_hash": {"sha256": "c" * 64},
                },
            }
        ]
    )
    engine.correlate()
    store = AssetStore(tmp_path / "ok.db")
    _persist(store, "ok", engine, finish=True)
    report = store.intel_integrity("ok")
    assert report["foreign_keys"] == 1
    assert report["integrity_check"] == "ok"
    assert report["foreign_key_violations"] == []
    assert report["orphans"] == {"observations": [], "relationships": [], "evidence": []}
    assert report["ok"] is True
    with store.intel_connection() as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    assert str(mode).lower() == "wal"
    assert int(fk) == 1

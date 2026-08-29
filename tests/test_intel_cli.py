"""CLI integration tests for query commands (no live scan)."""

from __future__ import annotations

import json

from core.assets import ScanRun
from core.intel.cli import cmd_certificates, cmd_investigate, cmd_relationships
from core.intel.engine import IntelEngine, IntelRunConfig
from core.store import AssetStore


def test_investigate_cli(tmp_path, capsys) -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="cli1", seed_domains=["example.com"], collected_domains={"example.com"}
        )
    )
    engine.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "ip": "1.2.3.4",
                "tls": {
                    "subject_an": ["example.com"],
                    "fingerprint_hash": {"sha256": "3" * 64},
                },
            }
        ]
    )
    engine.correlate()
    db = tmp_path / "recon.db"
    store = AssetStore(db)
    store.create_run(
        ScanRun(run_id="cli1", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("cli1", {}, intel=engine.snapshot())
    store.finish_run("cli1", host_count=0, alive_count=0, warnings=[], errors=[])

    assert cmd_investigate(db, "example.com", "cli1", None) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "example.com" in out
    assert "PRESENTS_CERTIFICATE" in out or "certificate:" in out
    assert "explanations" in payload
    assert cmd_certificates(db, "example.com", "cli1") == 0
    assert cmd_relationships(db, "example.com", "cli1") == 0


def test_investigate_and_relationships_agree_on_the_same_relationship(tmp_path, capsys) -> None:
    """`cmd_investigate` and `cmd_relationships` must report identical
    confidence/certificate fields for the same relationship — both derive
    from `core.intel.serialize.serialize_relationship`, not two independent
    formatters that could silently drift apart."""
    engine = IntelEngine(
        IntelRunConfig(
            run_id="cli2", seed_domains=["example.com"], collected_domains={"example.com"}
        )
    )
    engine.ingest_httpx_records(
        [
            {
                "input": "example.com",
                "ip": "1.2.3.4",
                "tls": {
                    "subject_an": ["example.com"],
                    "fingerprint_hash": {"sha256": "4" * 64},
                },
            }
        ]
    )
    engine.correlate()
    db = tmp_path / "recon.db"
    store = AssetStore(db)
    store.create_run(
        ScanRun(run_id="cli2", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    store.persist_registry("cli2", {}, intel=engine.snapshot())
    store.finish_run("cli2", host_count=0, alive_count=0, warnings=[], errors=[])

    assert cmd_investigate(db, "example.com", "cli2", None) == 0
    investigate_payload = json.loads(capsys.readouterr().out)
    assert cmd_relationships(db, "example.com", "cli2") == 0
    relationships_payload = json.loads(capsys.readouterr().out)

    by_id_investigate = {
        r["relationship_id"]: r
        for r in investigate_payload["relationships"]
        if r.get("evidence_id")
    }
    by_id_relationships = {r["relationship_id"]: r for r in relationships_payload["relationships"]}
    shared_ids = set(by_id_investigate) & set(by_id_relationships)
    assert shared_ids, "expected at least one relationship visible from both CLI commands"
    for rid in shared_ids:
        a = by_id_investigate[rid]
        b = by_id_relationships[rid]
        assert a["confidence_band"] == b["confidence_band"]
        assert a["certificate_fingerprint"] == b["certificate_fingerprint"]
        assert a["relationship_type"] == b["relationship_type"]

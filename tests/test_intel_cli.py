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

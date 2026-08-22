"""Basic performance guard for batched SQLite intelligence writes."""

from __future__ import annotations

import time

from core.assets import ScanRun
from core.intel.bounds import DiscoveryBounds
from core.intel.engine import IntelEngine, IntelRunConfig
from core.store import AssetStore


def test_thousands_of_entities_roundtrip(tmp_path) -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="perf",
            seed_domains=["seed.example.com"],
            bounds=DiscoveryBounds(max_entities=20000, max_relationships=50000),
        )
    )
    records = []
    for i in range(2000):
        records.append(
            {
                "input": f"h{i}.example.com",
                "ip": f"10.0.{i // 256}.{i % 256}",
                "tls": {
                    "subject_an": [f"h{i}.example.com"],
                    "fingerprint_hash": {"sha256": f"{i:064x}"[-64:]},
                },
            }
        )
    start = time.monotonic()
    engine.ingest_httpx_records(records)
    engine.correlate()
    store = AssetStore(tmp_path / "perf.db")
    store.create_run(
        ScanRun(run_id="perf", started_at="2026-01-01T00:00:00Z", targets=["seed.example.com"])
    )
    store.persist_registry("perf", {}, intel=engine.snapshot())
    elapsed = time.monotonic() - start
    assert elapsed < 15
    with store.intel_connection() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM intel_entities WHERE run_id='perf'"
        ).fetchone()["c"]
    assert count >= 2000

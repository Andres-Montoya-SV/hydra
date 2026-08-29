"""`explain-collection`: reconstructs, from real SQLite alone, why an
indicator was (or wasn't) collected — the causal chain the mission's
"why did Hydra collect this hostname?" requirement demands: indicator ->
hypothesis/authorization -> evidence -> collection attempt -> network
request, with no rescan.
"""

from __future__ import annotations

import json

from core.assets import ScanRun
from core.intel.cli import cmd_explain_collection
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.model import CollectionCapability
from core.store import AssetStore

SEED = "seed.explain-test.internal"
RELATED = "related.explain-test.internal"
OOS = "evil.explain-test.internal"


def _build_run(run_id: str) -> tuple[IntelEngine, dict]:
    engine = IntelEngine(
        IntelRunConfig(run_id=run_id, seed_domains=[SEED], collected_domains={SEED})
    )
    fp = "5" * 64
    engine.ingest_httpx_records(
        [
            {
                "input": SEED,
                "ip": "203.0.113.10",
                "tls": {
                    "subject_an": [SEED, RELATED],
                    "fingerprint_hash": {"sha256": fp},
                },
            }
        ]
    )
    engine.correlate()
    engine.authorize_hypothesis(RELATED)
    attempt = engine.claim_attempt(
        RELATED, capability=CollectionCapability.DNS_RESOLUTION, collector="dnsx"
    )
    engine.record_attempt(
        RELATED,
        capability=CollectionCapability.DNS_RESOLUTION,
        success=True,
        collector="dnsx",
        reason="resolved",
        artifact="dnsx_records_followup_1.jsonl",
    )
    network_requests = [
        {
            "request_id": "nr-related-1",
            "collector": "httpx",
            "capability": "http_probe",
            "method": "GET",
            "url": f"https://{RELATED}/",
            "normalized_hostname": RELATED,
            "port": 443,
            "redirect_hop": 0,
            "decision": "ALLOW",
            "reason": "in_scope",
            "network_attempted": True,
            "network_completed": True,
            "observed_at": "2026-01-01T00:00:00Z",
        },
        {
            "request_id": "nr-evil-1",
            "collector": "httpx",
            "capability": "http_probe",
            "method": "GET",
            "url": f"https://{OOS}/",
            "normalized_hostname": OOS,
            "port": 443,
            "redirect_hop": 1,
            "decision": "DENY",
            "reason": "out_of_scope",
            "network_attempted": False,
            "network_completed": False,
            "observed_at": "2026-01-01T00:00:01Z",
        },
    ]
    return engine, {"attempt_id": attempt.attempt_id, "network_requests": network_requests}


def test_explain_collection_reconstructs_authorized_chain(tmp_path, capsys) -> None:
    engine, extra = _build_run("explain1")
    db = tmp_path / "recon.db"
    store = AssetStore(db)
    store.create_run(ScanRun(run_id="explain1", started_at="2026-01-01T00:00:00Z", targets=[SEED]))
    store.persist_registry("explain1", {}, intel=engine.snapshot())
    store.record_network_requests("explain1", extra["network_requests"])
    store.finish_run("explain1", host_count=0, alive_count=0, warnings=[], errors=[])

    assert cmd_explain_collection(db, RELATED, "explain1") == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["resolved_value"] == RELATED
    assert payload["indicator"] is not None
    assert payload["hypothesis"]["status"] == "AUTHORIZED_FOR_COLLECTION"
    assert payload["evidence"] is not None
    assert len(payload["collection_attempts"]) == 2  # claimed (IN_FLIGHT) + completed (SUCCESS)
    statuses = {a["status"] for a in payload["collection_attempts"]}
    assert "SUCCESS" in statuses
    assert payload["network_requests"][0]["decision"] == "ALLOW"
    assert payload["network_requests"][0]["network_attempted"] == 1

    narrative_text = "\n".join(payload["narrative"])
    assert "AUTHORIZED_FOR_COLLECTION" in narrative_text
    assert "dnsx" in narrative_text
    assert "SUCCESS" in narrative_text


def test_explain_collection_shows_denied_out_of_scope_host(tmp_path, capsys) -> None:
    engine, extra = _build_run("explain2")
    db = tmp_path / "recon.db"
    store = AssetStore(db)
    store.create_run(ScanRun(run_id="explain2", started_at="2026-01-01T00:00:00Z", targets=[SEED]))
    store.persist_registry("explain2", {}, intel=engine.snapshot())
    store.record_network_requests("explain2", extra["network_requests"])
    store.finish_run("explain2", host_count=0, alive_count=0, warnings=[], errors=[])

    assert cmd_explain_collection(db, OOS, "explain2") == 0
    payload = json.loads(capsys.readouterr().out)

    # evil.explain-test.internal has no indicator/hypothesis/attempt at all —
    # only a DENY row in the network-request audit trail — proving the OOS
    # redirect target was recorded as denied, not silently dropped.
    assert payload["indicator"] is None
    assert payload["hypothesis"] is None
    assert payload["collection_attempts"] == []
    assert len(payload["network_requests"]) == 1
    assert payload["network_requests"][0]["decision"] == "DENY"
    assert payload["network_requests"][0]["network_attempted"] == 0

    narrative_text = "\n".join(payload["narrative"])
    assert "DENY" in narrative_text
    assert "attempted=False" in narrative_text


def test_explain_collection_resolves_by_attempt_id(tmp_path, capsys) -> None:
    engine, extra = _build_run("explain3")
    db = tmp_path / "recon.db"
    store = AssetStore(db)
    store.create_run(ScanRun(run_id="explain3", started_at="2026-01-01T00:00:00Z", targets=[SEED]))
    store.persist_registry("explain3", {}, intel=engine.snapshot())
    store.record_network_requests("explain3", extra["network_requests"])
    store.finish_run("explain3", host_count=0, alive_count=0, warnings=[], errors=[])

    assert cmd_explain_collection(db, extra["attempt_id"], "explain3") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["resolved_value"] == RELATED
    assert payload["indicator"] is not None

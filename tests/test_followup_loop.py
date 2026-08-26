"""Bounded indicator-driven follow-up: queue states, wildcard, scope, virusbarrier."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from config.settings import Settings
from core.assets import ScanRun
from core.intel.bounds import DiscoveryBounds
from core.intel.cli import cmd_investigate
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.followup import (
    load_wildcard_roots,
    plan_followup_collection,
    wildcard_blocks_active_collection,
)
from core.intel.model import (
    CollectionStatus,
    CollectReason,
    IndicatorKind,
    RelationshipType,
    ScopeStatus,
)
from core.intel.queue import IndicatorQueue
from core.intel.scope import CollectionScope, authorize_plugin_input
from core.models import DomainTarget, PipelineContext
from core.registry import HostRegistry
from core.runner import PipelineRunner, intel_config_for_pipeline
from core.store import AssetStore

FIXTURE = Path(__file__).parent / "fixtures" / "virusbarrier"
CASE = json.loads((FIXTURE / "case.json").read_text(encoding="utf-8"))
SEED = CASE["seed"]
SANS = list(CASE["sans"])
SIBLINGS = [name for name in SANS if name != SEED]
WWW = "www.virusbarrier.xyz"
FINGERPRINT = CASE["fingerprint_sha256"]


def _add(
    queue: IndicatorQueue,
    value: str,
    *,
    depth: int = 1,
    scope: ScopeStatus = ScopeStatus.IN_SCOPE,
    reason: CollectReason = CollectReason.CERTIFICATE_SAN,
    source: str = "certificate:test",
    collected: bool = False,
    is_seed: bool = False,
) -> None:
    queue.add(
        kind=IndicatorKind.DOMAIN,
        value=value,
        depth=depth,
        parent_id=None,
        reason=reason,
        scope_status=scope,
        evidence_id="e",
        discovered_from=source,
        collected=collected,
        is_seed=is_seed,
    )


def test_queue_claims_in_flight_and_does_not_repeat() -> None:
    queue = IndicatorQueue(DiscoveryBounds(max_discovery_depth=1, max_followup_indicators=2))
    _add(queue, "a.example.com")
    _add(queue, "b.example.com")
    _add(queue, "c.example.com")
    first = queue.eligible_followups()
    assert {item.value for item in first} == {"a.example.com", "b.example.com"}
    assert all(item.collection_status is CollectionStatus.IN_FLIGHT for item in first)
    assert queue.eligible_followups() == []
    assert queue.get(IndicatorKind.DOMAIN, "c.example.com").collection_status is (
        CollectionStatus.ELIGIBLE
    )
    queue.mark_collected(IndicatorKind.DOMAIN, "a.example.com")
    assert queue.get(IndicatorKind.DOMAIN, "a.example.com").collection_status is (
        CollectionStatus.COLLECTED
    )
    assert queue.eligible_followups() == []


def test_queue_terminal_states() -> None:
    queue = IndicatorQueue(DiscoveryBounds(max_discovery_depth=1))
    _add(queue, "seed.example.com", depth=0, collected=True, is_seed=True)
    _add(queue, "oos.example", scope=ScopeStatus.OUT_OF_SCOPE)
    _add(queue, "deep.example.com", depth=2)
    assert queue.get(IndicatorKind.DOMAIN, "seed.example.com").collection_status is (
        CollectionStatus.COLLECTED
    )
    assert queue.get(IndicatorKind.DOMAIN, "oos.example").collection_status is (
        CollectionStatus.NOT_ALLOWED
    )
    assert queue.get(IndicatorKind.DOMAIN, "deep.example.com").collection_status is (
        CollectionStatus.REJECTED
    )
    queue.mark_collected(IndicatorKind.DOMAIN, "oos.example")
    assert queue.get(IndicatorKind.DOMAIN, "oos.example").collection_status is (
        CollectionStatus.NOT_ALLOWED
    )
    _add(queue, "fly.example.com")
    claimed = queue.eligible_followups()
    assert claimed[0].collection_status is CollectionStatus.IN_FLIGHT
    queue.mark_failed(IndicatorKind.DOMAIN, "fly.example.com", reason="collector_error")
    assert queue.get(IndicatorKind.DOMAIN, "fly.example.com").collection_status is (
        CollectionStatus.FAILED
    )
    queue.mark_collected(IndicatorKind.DOMAIN, "fly.example.com")
    assert queue.get(IndicatorKind.DOMAIN, "fly.example.com").collection_status is (
        CollectionStatus.FAILED
    )


def test_queue_per_source_and_budget_stop_recursion() -> None:
    queue = IndicatorQueue(
        DiscoveryBounds(
            max_discovery_depth=1,
            max_followup_indicators=50,
            max_domains_per_source=2,
            max_collection_budget=1,
        )
    )
    source = "certificate:shared"
    _add(queue, "a.example.com", source=source)
    _add(queue, "b.example.com", source=source)
    _add(queue, "c.example.com", source=source)
    assert queue.get(IndicatorKind.DOMAIN, "c.example.com").collection_status is (
        CollectionStatus.REJECTED
    )
    claimed = queue.eligible_followups()
    assert len(claimed) == 1
    assert queue.eligible_followups() == []


def test_wildcard_does_not_authorize_dns_only_hosts() -> None:
    roots = {SEED}
    assert (
        wildcard_blocks_active_collection(
            "rand.virusbarrier.xyz",
            roots,
            CollectReason.DNS_RESOLUTION,
            evidence_ok=False,
        )
        is True
    )
    assert (
        wildcard_blocks_active_collection(
            WWW, roots, CollectReason.CERTIFICATE_SAN, evidence_ok=True
        )
        is False
    )
    assert (
        wildcard_blocks_active_collection(
            WWW, roots, CollectReason.CERTIFICATE_SAN, evidence_ok=False
        )
        is True
    )
    assert (
        wildcard_blocks_active_collection(
            "other.com", roots, CollectReason.DNS_RESOLUTION, evidence_ok=False
        )
        is False
    )


def test_followup_planner_never_trusts_queue() -> None:
    queue = IndicatorQueue(DiscoveryBounds())
    _add(queue, SIBLINGS[0], scope=ScopeStatus.IN_SCOPE)
    claimed = queue.eligible_followups()
    assert claimed
    plan = plan_followup_collection(
        candidates=claimed,
        scope=CollectionScope.from_seeds([SEED], patterns=[SEED]),
        wildcard_roots=set(),
        already_collected={SEED},
        dns_budget=10,
        http_budget=10,
    )
    assert plan.dns_targets == []
    assert plan.http_targets == []
    assert any(item.reason == "out_of_scope" for item in plan.rejected())


def test_followup_wildcard_skips_http_without_independent_evidence() -> None:
    queue = IndicatorQueue(DiscoveryBounds())
    _add(queue, "rand.virusbarrier.xyz", reason=CollectReason.DNS_RESOLUTION)
    _add(queue, WWW, reason=CollectReason.CERTIFICATE_SAN)
    claimed = queue.eligible_followups()
    plan = plan_followup_collection(
        candidates=claimed,
        scope=CollectionScope.from_seeds([SEED], patterns=[SEED]),
        wildcard_roots={SEED},
        already_collected={SEED},
        dns_budget=10,
        http_budget=10,
    )
    assert "rand.virusbarrier.xyz" not in plan.dns_targets
    assert "rand.virusbarrier.xyz" not in plan.http_targets
    assert any(item.reason == "wildcard_unconfirmed" for item in plan.rejected())
    assert WWW not in plan.dns_targets
    assert any(item.reason == "spoofed_or_missing_evidence" for item in plan.rejected())


def test_corrupted_followup_file_cannot_reach_collectors(tmp_path: Path) -> None:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    poisoned = output_dir / "followup_domains.txt"
    poisoned.write_text(f"{WWW}\n{SIBLINGS[0]}\n{SEED}\n", encoding="utf-8")
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([SEED], patterns=[SEED]),
    )
    for plugin in ("dnsx", "httpx", "naabu"):
        authorized = authorize_plugin_input(context, poisoned, plugin)
        body = authorized.read_text(encoding="utf-8")
        assert SIBLINGS[0] not in body
        assert WWW in body.splitlines()
        assert SEED in body.splitlines()


def _write_integration_artifacts(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "ctlogs_domains.txt",
        "httpx.json",
        "dnsx_records.jsonl",
        "resolved.txt",
        "scope.txt",
    ):
        shutil.copy2(FIXTURE / name, output_dir / name)
    names = list(dict.fromkeys([*SANS, WWW]))
    (output_dir / "ctlogs.jsonl").write_text(
        json.dumps(
            {
                "id": 424242,
                "common_name": CASE["subject"],
                "name_value": "\n".join(names),
                "issuer_name": CASE["issuer"],
                "not_before": CASE["not_before"],
                "not_after": CASE["not_after"],
                "fingerprint_sha256": FINGERPRINT,
                "serial_number": "aa11",
                "query_domain": SEED,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (output_dir / "wildcard_check.jsonl").write_text(
        json.dumps(
            {
                "root_domain": SEED,
                "wildcard_dns_detected": False,
                "canary_hosts": ["zqxvwtest1." + SEED],
                "canary_resolved": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    shutil.copy2(FIXTURE / "resolved.txt", output_dir / "subdomains.txt")


def test_virusbarrier_followup_loop_integration(tmp_path: Path, capsys) -> None:
    output_dir = tmp_path / "output" / "vb-follow"
    _write_integration_artifacts(output_dir)
    settings = Settings(
        project_root=tmp_path,
        scope_file=output_dir / "scope.txt",
        max_discovery_depth=1,
        max_followup_indicators=10,
        max_domains_per_source=20,
        max_collection_budget=50,
    )
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        subdomains=[SEED],
        resolved=[SEED],
        output_dir=output_dir,
        run_id="vb-follow",
        metadata={"dns_probes": 1, "http_probes": 1},
    )
    config = intel_config_for_pipeline(context, settings)
    registry = HostRegistry("vb-follow", output_dir)
    registry.intel_config = config
    for tool in ("ctlogs", "wildcard_check", "dnsx", "httpx"):
        registry.ingest(tool)
    registry.finalize()

    engine = IntelEngine(config)
    engine.queue.mark_collected(IndicatorKind.DOMAIN, SEED)
    engine.ingest_artifacts(output_dir)
    engine.correlate()

    runner = PipelineRunner(settings)
    plan = runner.schedule_followup_collection(context, engine)

    for name in SIBLINGS:
        assert name not in plan.dns_targets
        assert name not in plan.http_targets
        entity = engine.entities[f"domain:{name}"]
        assert entity.scope_status is ScopeStatus.OUT_OF_SCOPE
        assert entity.collection_status is CollectionStatus.NOT_ALLOWED
        assert any(obs.entity_id == entity.entity_id for obs in engine.observations)

    assert WWW in plan.dns_targets
    assert WWW in plan.http_targets
    assert engine.queue.get(IndicatorKind.DOMAIN, WWW).collection_status is (
        CollectionStatus.IN_FLIGHT
    )
    assert engine.eligible_followups() == []

    for filename, plugin in (
        ("followup_domains.txt", "dnsx"),
        ("followup_http_targets.txt", "httpx"),
        ("followup_naabu_targets.txt", "naabu"),
    ):
        lines = (output_dir / filename).read_text(encoding="utf-8").splitlines()
        for name in SIBLINGS:
            assert name not in lines
        assert WWW in lines
        assert SEED not in lines
        authorized = authorize_plugin_input(context, output_dir / filename, plugin)
        assert SIBLINGS[0] not in authorized.read_text(encoding="utf-8")
        assert WWW in authorized.read_text(encoding="utf-8").splitlines()

    assert load_wildcard_roots(output_dir, context.metadata) == set()
    assert not any(
        rel.relationship_type is RelationshipType.SHARES_IPV4
        for rel in engine.relationships.values()
    )
    assert any(
        rel.relationship_type is RelationshipType.SAN_CONTAINS
        and rel.target_entity == f"domain:{SIBLINGS[0]}"
        for rel in engine.relationships.values()
    )

    db = tmp_path / "output" / "recon.db"
    store = AssetStore(db)
    store.create_run(ScanRun(run_id="vb-follow", started_at="2026-08-21T00:00:00Z", targets=[SEED]))
    store.persist_registry(
        "vb-follow",
        registry.to_dict(),
        clusters=registry.clusters,
        graph=registry.graph,
        intel=engine.snapshot(),
    )
    store.finish_run("vb-follow", host_count=1, alive_count=1, warnings=[], errors=[])
    assert cmd_investigate(db, SIBLINGS[0], "vb-follow", None) == 0
    out = capsys.readouterr().out
    assert SIBLINGS[0] in out
    assert "NOT_ALLOWED" in out
    assert "OUT_OF_SCOPE" in out
    assert FINGERPRINT in out or "SAN_CONTAINS" in out
    assert "actor" not in out.lower()

    by_value = {item.value: item for item in engine.queue.values()}
    assert by_value[SEED].collection_status is CollectionStatus.COLLECTED
    assert by_value[WWW].collection_status is CollectionStatus.IN_FLIGHT
    for name in SIBLINGS:
        assert by_value[name].collection_status is CollectionStatus.NOT_ALLOWED
    transitions = [(item.value, item.previous, item.current) for item in engine.queue.trace]
    assert (SEED, "", CollectionStatus.COLLECTED.value) in transitions
    assert (WWW, "", CollectionStatus.DISCOVERED.value) in transitions
    assert (
        WWW,
        CollectionStatus.DISCOVERED.value,
        CollectionStatus.ELIGIBLE.value,
    ) in transitions
    assert (WWW, CollectionStatus.ELIGIBLE.value, CollectionStatus.IN_FLIGHT.value) in transitions
    assert (SIBLINGS[0], "", CollectionStatus.NOT_ALLOWED.value) in transitions


@pytest.mark.asyncio
async def test_followup_dns_crash_leaves_durable_in_flight_attempt(tmp_path: Path) -> None:
    """A crash between claiming a follow-up indicator and dnsx completing must
    leave a durable IN_FLIGHT CollectionAttempt row, not silence.

    Before this fix, `record_attempt()` only ran after the subprocess plugin
    finished and its output was parsed — a crash in between left the
    indicator lifecycle crash-safe (overlay_status turns a restored IN_FLIGHT
    into FAILED) but `intel_collection_attempts` got no row at all for that
    specific attempt. `engine.claim_attempt()` + a persist call now happen
    immediately after the claim and before `_run_plugin_chain` runs.
    """
    output_dir = tmp_path / "output" / "vb-crash"
    _write_integration_artifacts(output_dir)
    settings = Settings(
        project_root=tmp_path,
        scope_file=output_dir / "scope.txt",
        max_discovery_depth=1,
        max_followup_indicators=10,
        max_domains_per_source=20,
        max_collection_budget=50,
    )
    run_id = "vb-crash"
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        subdomains=[SEED],
        resolved=[SEED],
        output_dir=output_dir,
        run_id=run_id,
        metadata={"dns_probes": 1, "http_probes": 1},
    )

    db = tmp_path / "output" / "recon-crash.db"
    store = AssetStore(db)
    store.create_run(ScanRun(run_id=run_id, started_at="2026-08-24T00:00:00Z", targets=[SEED]))

    runner = PipelineRunner(settings)
    runner._store = store

    async def crash(*args, **kwargs):
        raise RuntimeError("simulated crash mid-subprocess")

    runner._run_plugin_chain = crash  # type: ignore[method-assign]
    runner.tool_manager.is_runnable = lambda name: True  # type: ignore[method-assign]

    resolved_path = output_dir / "resolved.txt"
    await runner._maybe_collect_followups(context, resolved_path)

    assert "Follow-up DNS crashed; seed DNS artifacts preserved" in context.warnings

    attempts = context.metadata.get("collection_attempts") or []
    claimed = [row for row in attempts if row.get("value") == WWW]
    assert claimed, "expected a persisted attempt row for the claimed host before the crash"
    assert claimed[0]["status"] == "IN_FLIGHT"
    assert claimed[0]["capability"] == "DNS_RESOLUTION"
    assert claimed[0]["collector"] == "dnsx"

    # The row is durable in SQLite too, not just in the in-memory context.
    with store._connect() as conn:
        stored = conn.execute(
            "SELECT status, capability FROM intel_collection_attempts WHERE run_id=? AND value=?",
            (run_id, WWW),
        ).fetchall()
    assert any(row[0] == "IN_FLIGHT" and row[1] == "DNS_RESOLUTION" for row in stored)


def test_schedule_blocks_wildcard_dns_only_name(tmp_path: Path) -> None:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    (output_dir / "wildcard_check.jsonl").write_text(
        json.dumps(
            {
                "root_domain": SEED,
                "wildcard_dns_detected": True,
                "canary_hosts": ["zqxvwcanary." + SEED],
                "canary_resolved": ["zqxvwcanary." + SEED],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    settings = Settings(project_root=tmp_path, scope_file=FIXTURE / "scope.txt")
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        resolved=[SEED],
        output_dir=output_dir,
        run_id="wild",
        metadata={"dns_probes": 0, "http_probes": 0},
    )
    context.collection_scope = CollectionScope.from_seeds([SEED], patterns=[SEED])
    engine = IntelEngine(
        IntelRunConfig(
            run_id="wild",
            seed_domains=[SEED],
            scope_patterns=[SEED],
            collected_domains={SEED},
        )
    )
    engine.ingest_ct_records(
        [
            {
                "id": 1,
                "name_value": f"{SEED}\n{WWW}",
                "fingerprint_sha256": "ab" * 32,
                "query_domain": SEED,
            }
        ]
    )
    engine.queue.add(
        kind=IndicatorKind.DOMAIN,
        value="rand.virusbarrier.xyz",
        depth=1,
        parent_id=None,
        reason=CollectReason.DNS_RESOLUTION,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="dns",
        discovered_from="dnsx",
    )
    plan = PipelineRunner(settings).schedule_followup_collection(context, engine)
    assert "rand.virusbarrier.xyz" not in plan.dns_targets
    assert "rand.virusbarrier.xyz" not in plan.http_targets
    assert WWW in plan.dns_targets
    assert engine.queue.get(IndicatorKind.DOMAIN, "rand.virusbarrier.xyz").collection_status is (
        CollectionStatus.REJECTED
    )


def test_bounds_stop_recursive_explosion() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="bound",
            seed_domains=[SEED],
            scope_patterns=[SEED],
            bounds=DiscoveryBounds(max_discovery_depth=1, max_followup_indicators=1),
            collected_domains={SEED},
        )
    )
    engine.ingest_ct_records(
        [
            {
                "name_value": "\n".join(
                    [SEED, WWW, "api.virusbarrier.xyz", "dev.virusbarrier.xyz"]
                ),
                "fingerprint_sha256": "1" * 64,
                "query_domain": SEED,
            }
        ]
    )
    engine.queue.add(
        kind=IndicatorKind.DOMAIN,
        value="nested.api.virusbarrier.xyz",
        depth=2,
        parent_id=None,
        reason=CollectReason.CERTIFICATE_SAN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="deep",
        discovered_from="certificate:nested",
    )
    first = engine.eligible_followups()
    assert len(first) == 1
    assert engine.eligible_followups() == []
    nested = engine.queue.get(IndicatorKind.DOMAIN, "nested.api.virusbarrier.xyz")
    assert nested is not None
    assert nested.collection_status is CollectionStatus.REJECTED

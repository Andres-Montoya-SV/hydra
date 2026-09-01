"""Adversarial matrix for authorization, follow-up artifacts, evidence, and bounds."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from config.settings import Settings
from core.intel.authorize import AuthorizationDecision, authorize_active_indicator
from core.intel.bounds import DiscoveryBounds
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.followup import plan_followup_collection
from core.intel.model import (
    CollectionStatus,
    CollectReason,
    ConfidenceBand,
    IndicatorKind,
    RelationshipType,
    ScopeStatus,
)
from core.intel.queue import IndicatorQueue
from core.intel.scope import CollectionScope, authorize_plugin_input
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from core.runner import PipelineRunner
from utils.files import read_lines, write_jsonl, write_lines

SEED = "seed.example.com"
WWW = "www.seed.example.com"
OOS = "evil.example.net"


def test_authorize_unknown_fails_closed() -> None:
    result = authorize_active_indicator("not a host", None, "dnsx", "test")
    assert result.decision is AuthorizationDecision.UNKNOWN
    assert not result.allowed
    scope = CollectionScope.from_seeds([SEED])
    malformed = authorize_active_indicator("http://", scope, "httpx", "test")
    assert malformed.decision is AuthorizationDecision.UNKNOWN
    oos = authorize_active_indicator(OOS, scope, "httpx", "test")
    assert oos.decision is AuthorizationDecision.DENY
    allow = authorize_active_indicator(SEED, scope, "httpx", "seed")
    assert allow.decision is AuthorizationDecision.ALLOW


def test_cloud_endpoint_requires_explicit_policy() -> None:
    scope = CollectionScope.from_seeds([SEED], cloud_collection_allowed=False)
    result = authorize_active_indicator("brand.s3.amazonaws.com", scope, "httpx", "derived")
    assert result.decision is AuthorizationDecision.DENY

    denied_op = authorize_active_indicator(
        "brand.s3.amazonaws.com", scope, "cloud_bucket_enum", "policy"
    )
    assert denied_op.decision is AuthorizationDecision.DENY

    allowed_scope = CollectionScope.from_seeds([SEED], cloud_collection_allowed=True)
    cloud = authorize_active_indicator(
        "brand.s3.amazonaws.com", allowed_scope, "cloud_bucket_enum", "policy"
    )
    # A generated bucket hostname never shares a registrable domain with the
    # seed by construction — explicit cloud_collection_allowed opt-in must
    # still result in ALLOW for the cloud_bucket_enum operation specifically,
    # not fall through to the normal seed-root scope check and get denied
    # anyway (that would make the opt-in flag a no-op).
    assert cloud.decision is AuthorizationDecision.ALLOW

    # Opting in to cloud_bucket_enum must not blanket-authorize other
    # capabilities to treat cloud infrastructure as an active target.
    other_op = authorize_active_indicator(
        "brand.s3.amazonaws.com", allowed_scope, "httpx", "derived"
    )
    assert other_op.decision is AuthorizationDecision.DENY


def test_spoofed_certificate_san_reason_is_rejected() -> None:
    engine = IntelEngine(IntelRunConfig(run_id="spoof", seed_domains=[SEED]))
    engine.queue.add(
        kind=IndicatorKind.DOMAIN,
        value=WWW,
        depth=1,
        parent_id=None,
        reason=CollectReason.CERTIFICATE_SAN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="forged",
    )
    claimed = engine.eligible_followups(IndicatorKind.DOMAIN)
    plan = plan_followup_collection(
        candidates=claimed,
        scope=CollectionScope.from_seeds([SEED]),
        wildcard_roots=set(),
        already_collected={SEED},
        dns_budget=10,
        http_budget=10,
        engine=engine,
    )
    assert WWW not in plan.dns_targets
    assert any(item.reason == "spoofed_or_missing_evidence" for item in plan.rejected())


def test_plugin_cannot_emit_certificate_san_reason() -> None:
    engine = IntelEngine(
        IntelRunConfig(run_id="plugin", seed_domains=[SEED], collected_domains={SEED})
    )
    engine.ingest_emissions(
        [
            {
                "domains": [WWW],
                "followups": [{"value": WWW, "reason": "CERTIFICATE_SAN"}],
            }
        ]
    )
    item = engine.queue.get(IndicatorKind.DOMAIN, WWW)
    assert item is not None
    assert item.reason is CollectReason.PLUGIN


def test_ten_thousand_san_certificate_is_truncated() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="sans",
            seed_domains=[SEED],
            collected_domains={SEED},
            bounds=DiscoveryBounds(max_ct_names_per_certificate=50, max_entities=200),
        )
    )
    names = [SEED] + [f"n{i}.{SEED}" for i in range(10000)]
    engine.ingest_ct_records(
        [
            {
                "id": 1,
                "name_value": "\n".join(names),
                "fingerprint_sha256": "aa" * 32,
                "query_domain": SEED,
            }
        ]
    )
    snap = engine.snapshot()
    assert snap.truncated
    certs = snap.certificates()
    assert certs
    assert certs[0].data.get("sans_truncated") is True
    assert len(certs[0].data.get("sans") or []) <= 50


def test_same_sans_different_fingerprints_are_distinct() -> None:
    engine = IntelEngine(
        IntelRunConfig(run_id="rot", seed_domains=[SEED], collected_domains={SEED})
    )
    sans = [SEED, WWW]
    engine.ingest_httpx_records(
        [
            {
                "input": SEED,
                "tls": {
                    "subject_an": sans,
                    "fingerprint_hash": {"sha256": "11" * 32},
                },
            },
            {
                "input": SEED,
                "tls": {
                    "subject_an": sans,
                    "fingerprint_hash": {"sha256": "22" * 32},
                },
            },
        ]
    )
    certs = engine.snapshot().certificates()
    fps = {c.data.get("fingerprint_sha256") for c in certs}
    assert "11" * 32 in fps
    assert "22" * 32 in fps


def test_shared_cdn_asn_favicon_are_not_high() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="weak",
            seed_domains=["a.example.com", "b.example.com"],
            collected_domains={"a.example.com", "b.example.com"},
        )
    )
    engine.ingest_hosts(
        {
            "a.example.com": _host("a.example.com", asn="AS1", cdn="cloudflare", fav="abc"),
            "b.example.com": _host("b.example.com", asn="AS1", cdn="cloudflare", fav="abc"),
        }
    )
    engine.correlate()
    high_share = [
        rel
        for rel in engine.relationships.values()
        if rel.confidence is ConfidenceBand.HIGH
        and rel.relationship_type
        in {
            RelationshipType.SHARES_ASN,
            RelationshipType.SHARES_FAVICON,
            RelationshipType.SHARES_BODY_HASH,
        }
    ]
    assert high_share == []


def _host(domain: str, *, asn: str, cdn: str, fav: str):
    from core.assets import Host, HttpService

    host = Host(domain=domain, asn=asn, cdn_provider=cdn, dns_resolved=True)
    host.http_services = [HttpService(host=domain, url=f"https://{domain}/", favicon_hash=fav)]
    return host


def test_poisoned_alive_and_subdomains_are_gated(tmp_path: Path) -> None:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    write_lines(
        output_dir / "alive.txt", [f"https://{SEED}/", f"https://{OOS}/"], base_dir=output_dir
    )
    write_lines(output_dir / "subdomains.txt", [SEED, OOS], base_dir=output_dir)
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([SEED]),
    )
    for plugin, source in (
        ("httpx", "alive.txt"),
        ("dnsx", "subdomains.txt"),
        ("katana", "alive.txt"),
    ):
        authorized = authorize_plugin_input(context, output_dir / source, plugin)
        body = authorized.read_text(encoding="utf-8")
        assert OOS not in body
        assert SEED in body


def test_missing_collection_scope_fails_closed(tmp_path: Path) -> None:
    from core.exceptions import ConfigurationError

    context = PipelineContext(output_dir=tmp_path, targets=[DomainTarget(domain=SEED)])
    with pytest.raises(ConfigurationError):
        authorize_plugin_input(context, tmp_path / "alive.txt", "httpx")


@pytest.mark.asyncio
async def test_followup_empty_and_crash_preserve_seed(tmp_path: Path, settings: Settings) -> None:
    settings.enable_followup_collection = True
    settings.max_discovery_depth = 1
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    write_lines(output_dir / "resolved.txt", [SEED], base_dir=output_dir)
    write_jsonl(
        output_dir / "dnsx_records.jsonl",
        [{"host": SEED, "a": ["203.0.113.10"]}],
        base_dir=output_dir,
    )
    write_lines(output_dir / "alive.txt", [f"https://{SEED}/"], base_dir=output_dir)
    write_jsonl(
        output_dir / "httpx.json",
        [{"input": SEED, "url": f"https://{SEED}/"}],
        base_dir=output_dir,
    )
    write_jsonl(
        output_dir / "ctlogs.jsonl",
        [
            {
                "id": 1,
                "name_value": f"{SEED}\n{WWW}",
                "fingerprint_sha256": "ab" * 32,
                "query_domain": SEED,
            }
        ],
        base_dir=output_dir,
    )
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        resolved=[SEED],
        alive_urls=[f"https://{SEED}/"],
        output_dir=output_dir,
        run_id="empty-follow",
        collection_scope=CollectionScope.from_seeds([SEED]),
        metadata={"dns_probes": 1, "http_probes": 1},
    )
    runner = PipelineRunner(settings)
    dnsx = runner.tool_manager.get_plugin("dnsx")
    httpx = runner.tool_manager.get_plugin("httpx")
    assert dnsx and httpx

    async def empty_dnsx(ctx, input_path):
        suffix = str(ctx.metadata.get("dnsx_output_suffix") or "")
        write_lines(ctx.output_dir / f"resolved{suffix}.txt", [], base_dir=ctx.output_dir)
        write_jsonl(ctx.output_dir / f"dnsx_records{suffix}.jsonl", [], base_dir=ctx.output_dir)
        return PluginResult(success=True, output_path=ctx.output_dir / f"resolved{suffix}.txt")

    async def empty_httpx(ctx, input_path):
        suffix = str(ctx.metadata.get("httpx_output_suffix") or "")
        write_jsonl(ctx.output_dir / f"httpx{suffix}.json", [], base_dir=ctx.output_dir)
        write_lines(ctx.output_dir / f"alive{suffix}.txt", [], base_dir=ctx.output_dir)
        ctx.alive_urls = []
        return PluginResult(success=True, output_path=ctx.output_dir / f"httpx{suffix}.json")

    dnsx.run = empty_dnsx  # type: ignore[method-assign]
    httpx.run = empty_httpx  # type: ignore[method-assign]
    runner.tool_manager.is_runnable = lambda name: name in {"dnsx", "httpx"}  # type: ignore[method-assign]
    runner.tool_manager.ensure_mandatory_tools = AsyncMock()

    await runner._maybe_collect_followups(context, output_dir / "resolved.txt")
    assert SEED in read_lines(output_dir / "resolved.txt")
    assert f"https://{SEED}/" in read_lines(output_dir / "alive.txt")
    assert (output_dir / "resolved_seed.txt").exists()
    assert (output_dir / "alive_seed.txt").exists()

    async def crash_dnsx(ctx, input_path):
        raise RuntimeError("timeout")

    dnsx.run = crash_dnsx  # type: ignore[method-assign]
    context.metadata["followup_pass"] = 1
    await runner._maybe_collect_followups(context, output_dir / "resolved.txt")
    assert SEED in read_lines(output_dir / "resolved.txt")
    assert f"https://{SEED}/" in read_lines(output_dir / "alive.txt")
    assert (output_dir / "resolved_seed.txt").exists()


def test_indicator_queue_discovered_to_eligible() -> None:
    queue = IndicatorQueue(DiscoveryBounds())
    item = queue.add(
        kind=IndicatorKind.DOMAIN,
        value=WWW,
        depth=1,
        parent_id=None,
        reason=CollectReason.CERTIFICATE_SAN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="ev1",
    )
    assert any(t.current == CollectionStatus.DISCOVERED.value for t in queue.trace)
    assert item.collection_status is CollectionStatus.ELIGIBLE


def test_spoofed_shared_certificate_reason_is_rejected() -> None:
    engine = IntelEngine(IntelRunConfig(run_id="spoof-share", seed_domains=[SEED]))
    engine.queue.add(
        kind=IndicatorKind.DOMAIN,
        value=WWW,
        depth=1,
        parent_id=None,
        reason=CollectReason.SHARED_CERTIFICATE,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="forged-share",
    )
    claimed = engine.eligible_followups(IndicatorKind.DOMAIN)
    plan = plan_followup_collection(
        candidates=claimed,
        scope=CollectionScope.from_seeds([SEED]),
        wildcard_roots=set(),
        already_collected={SEED},
        dns_budget=10,
        http_budget=10,
        engine=engine,
    )
    assert WWW not in plan.dns_targets
    assert any(item.reason == "spoofed_or_missing_evidence" for item in plan.rejected())


def test_dedicated_shared_ip_is_not_high() -> None:
    engine = IntelEngine(
        IntelRunConfig(
            run_id="ip",
            seed_domains=["a.example.com", "b.example.com"],
            collected_domains={"a.example.com", "b.example.com"},
        )
    )
    engine.ingest_passive_resolutions(
        {"a.example.com": "203.0.113.10", "b.example.com": "203.0.113.10"}
    )
    engine.correlate()
    shared = [
        rel
        for rel in engine.relationships.values()
        if rel.relationship_type is RelationshipType.SHARES_IPV4
    ]
    assert shared
    assert all(rel.confidence is not ConfidenceBand.HIGH for rel in shared)
    assert all(rel.confidence is not ConfidenceBand.VERY_HIGH for rel in shared)


def test_interrupted_in_flight_becomes_failed(tmp_path: Path) -> None:
    from core.assets import ScanRun
    from core.store import AssetStore, _apply_prior_indicator_lifecycle

    engine = IntelEngine(IntelRunConfig(run_id="crash", seed_domains=[SEED]))
    engine.queue.add(
        kind=IndicatorKind.DOMAIN,
        value=WWW,
        depth=1,
        parent_id=None,
        reason=CollectReason.PLUGIN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="ev",
    )
    claimed = engine.queue.eligible_followups(IndicatorKind.DOMAIN)
    assert claimed
    assert claimed[0].collection_status is CollectionStatus.IN_FLIGHT
    prior = [claimed[0].to_dict()]
    later = IntelEngine(IntelRunConfig(run_id="crash", seed_domains=[SEED]))
    later.queue.add(
        kind=IndicatorKind.DOMAIN,
        value=WWW,
        depth=1,
        parent_id=None,
        reason=CollectReason.PLUGIN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="ev",
    )
    snap = later.snapshot()
    _apply_prior_indicator_lifecycle(snap, prior)
    item = next(i for i in snap.indicators if i.value == WWW)
    assert item.collection_status is CollectionStatus.FAILED
    assert "interrupted" in (item.failure_reason or "")

    store = AssetStore(tmp_path / "db.sqlite")
    store.create_run(ScanRun(run_id="crash", started_at="2026-01-01T00:00:00Z", targets=[SEED]))
    first = IntelEngine(IntelRunConfig(run_id="crash", seed_domains=[SEED]))
    first.queue.add(
        kind=IndicatorKind.DOMAIN,
        value=WWW,
        depth=1,
        parent_id=None,
        reason=CollectReason.PLUGIN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="ev",
    )
    first.queue.eligible_followups(IndicatorKind.DOMAIN)
    store.persist_registry("crash", {}, intel=first.snapshot())
    second = IntelEngine(IntelRunConfig(run_id="crash", seed_domains=[SEED]))
    second.queue.add(
        kind=IndicatorKind.DOMAIN,
        value=WWW,
        depth=1,
        parent_id=None,
        reason=CollectReason.PLUGIN,
        scope_status=ScopeStatus.IN_SCOPE,
        evidence_id="ev",
    )
    store.persist_registry("crash", {}, intel=second.snapshot())
    rows = store.get_intel_indicators("crash")
    www = next(r for r in rows if r["value"] == WWW)
    assert www["collection_status"] == CollectionStatus.FAILED.value


def test_plugin_scope_object_does_not_authorize_oos() -> None:
    scope = CollectionScope.from_seeds([SEED])
    result = authorize_active_indicator(OOS, scope, "httpx", "has_scope_object")
    assert result.decision is AuthorizationDecision.DENY
    assert not result.allowed


def test_missing_scope_is_deny_not_allow() -> None:
    from core.intel.authorize import authorize_collection
    from modules.browser_probe import _httpx_targets, allow_browser_navigation
    from modules.threat_intel import _alive_hosts
    from modules.vuln_match import _collect_techs

    context = PipelineContext(output_dir=Path("/tmp"), targets=[DomainTarget(domain=SEED)])
    context.httpx_results = [
        {
            "input": SEED,
            "url": f"https://{SEED}/",
            "host": SEED,
            "tech": ["nginx:1.25.0"],
        }
    ]
    assert allow_browser_navigation(f"https://{SEED}/", context) is False
    assert _httpx_targets(context) == []
    assert _alive_hosts(context) == []
    assert _collect_techs(context) == []
    blocked = authorize_collection(
        SEED,
        CollectionScope.from_seeds([SEED]),
        capability="DNS_RESOLUTION",
        strict_opsec=True,
        opsec_allowed=False,
    )
    assert blocked.decision is AuthorizationDecision.DENY
    assert blocked.reason == "opsec_blocked"

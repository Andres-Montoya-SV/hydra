"""P0-2/P0-3: single authorization gate and collection-status invariants."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from config.settings import Settings
from core.assets import Host, HttpService
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.model import CollectionStatus, IndicatorKind, RelationshipType, ScopeStatus
from core.intel.scope import (
    CollectionScope,
    allows_active_collection,
    authorize_plugin_input,
    filter_authorized_indicators,
)
from core.models import DomainTarget, PipelineContext
from core.runner import ACTIVE_COLLECTION_PLUGINS, PipelineRunner
from modules.dnsx import DnsxPlugin
from modules.httpx import HttpxPlugin
from modules.naabu import NaabuPlugin

SEED = "virusbarrier.xyz"
WWW = "www.virusbarrier.xyz"
OOS = "virusinspector.top"


def _scope() -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=[SEED])


def test_allows_active_collection_is_the_hard_gate() -> None:
    scope = _scope()
    assert allows_active_collection(SEED, scope) is True
    assert allows_active_collection(WWW, scope) is True
    assert allows_active_collection(OOS, scope) is False
    assert allows_active_collection(f"https://{OOS}/login", scope) is False
    assert allows_active_collection(f"{OOS}:443", scope) is False
    assert allows_active_collection("", scope) is False


def test_subdomains_list_does_not_authorize_oos_collectors(tmp_path: Path) -> None:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    source = output_dir / "subdomains.txt"
    source.write_text(f"{SEED}\n{WWW}\n{OOS}\n", encoding="utf-8")

    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        subdomains=[SEED, WWW, OOS],
        output_dir=output_dir,
        collection_scope=_scope(),
    )

    for plugin in ("dnsx", "httpx", "naabu"):
        authorized = authorize_plugin_input(context, source, plugin)
        lines = authorized.read_text(encoding="utf-8").splitlines()
        assert SEED in lines
        assert WWW in lines
        assert OOS not in lines
        assert OOS not in authorized.read_text(encoding="utf-8")

    assert source.read_text(encoding="utf-8").splitlines() == [SEED, WWW, OOS]
    assert OOS in context.metadata.get("authorization_denied", [])

    engine = IntelEngine(IntelRunConfig(run_id="obs", seed_domains=[SEED], scope_patterns=[SEED]))
    engine.ingest_ct_records(
        [
            {
                "id": 1,
                "name_value": f"{SEED}\n{OOS}",
                "fingerprint_sha256": "b" * 64,
                "query_domain": SEED,
            }
        ]
    )
    assert f"domain:{OOS}" in engine.entities
    assert engine.entities[f"domain:{OOS}"].collection_status is CollectionStatus.NOT_ALLOWED
    assert any(obs.entity_id == f"domain:{OOS}" for obs in engine.observations)


@pytest.mark.asyncio
async def test_active_plugins_never_receive_oos_input(tmp_path: Path, settings: Settings) -> None:
    settings.naabu_tarpit_check = False
    settings.naabu_confirm_open_ports = False
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    source = output_dir / "subdomains.txt"
    source.write_text(f"{SEED}\n{WWW}\n{OOS}\n", encoding="utf-8")
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=_scope(),
    )

    async def _capture(_ctx: PipelineContext, args: list[str], *a, **kw):
        for path in args:
            candidate = Path(path)
            if candidate.exists() and candidate.is_file():
                assert OOS not in candidate.read_text(encoding="utf-8")
        from core.plugin_base import PluginResult

        return PluginResult(success=True, skipped=True, message="gated")

    for plugin in (DnsxPlugin(settings), HttpxPlugin(settings), NaabuPlugin(settings)):
        plugin._execute_self_output = AsyncMock(side_effect=_capture)  # type: ignore[method-assign]
        plugin._execute = AsyncMock(side_effect=_capture)  # type: ignore[method-assign]
        plugin._run_tool = AsyncMock(return_value=(0, "", ""))  # type: ignore[method-assign]
        context.current_tool = plugin.name
        await plugin.run(context, source)
        gated = output_dir / f"authorized_{plugin.name}_subdomains.txt"
        assert gated.exists()
        body = gated.read_text(encoding="utf-8")
        assert OOS not in body
        assert SEED in body
        assert WWW in body

    assert source.read_text(encoding="utf-8").splitlines() == [SEED, WWW, OOS]


def test_runner_gates_before_plugin_invocation(tmp_path: Path, settings: Settings) -> None:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    source = output_dir / "resolved.txt"
    source.write_text(f"{SEED}\n{OOS}\n", encoding="utf-8")
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=_scope(),
    )
    runner = PipelineRunner(settings)
    for name in ("dnsx", "httpx", "naabu"):
        plugin = type("P", (), {"name": name, "capability": name})()
        gated = runner._gate_active_input(context, plugin, source)
        assert OOS not in gated.read_text(encoding="utf-8")
        assert SEED in gated.read_text(encoding="utf-8")

    assert source.read_text(encoding="utf-8").splitlines() == [SEED, OOS]
    assert "dnsx" in ACTIVE_COLLECTION_PLUGINS
    assert "httpx" in ACTIVE_COLLECTION_PLUGINS
    assert "naabu" in ACTIVE_COLLECTION_PLUGINS


def test_gate_active_input_composes_opsec_not_just_scope(
    tmp_path: Path, settings: Settings
) -> None:
    """`_gate_active_input` must route through `authorize_collection` (scope
    AND OPSEC), not the scope-only `allows_active_collection` — so an
    in-scope indicator is still denied for a plugin STRICT_OPSEC does not
    allow, even calling the gate directly and bypassing the separate
    plugin-level STRICT_OPSEC skip in `_run_single_plugin`. That other check
    already keeps a disallowed plugin from reaching this point in the real
    pipeline; this proves the per-indicator gate is independently correct,
    not merely correct by relying on that other check running first.
    """
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    source = output_dir / "resolved.txt"
    source.write_text(f"{SEED}\n", encoding="utf-8")
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=_scope(),
    )
    settings.strict_opsec = True
    settings.outbound_proxy_url = "http://proxy.example:8080"
    runner = PipelineRunner(settings)

    # naabu has no strict_opsec_allowed = True — not in STRICT_OPSEC_ALLOWED_PLUGINS.
    naabu_plugin = type("P", (), {"name": "naabu", "capability": "port_scan"})()
    denied = runner._gate_active_input(context, naabu_plugin, source)
    assert denied.read_text(encoding="utf-8").strip() == ""

    # httpx declares strict_opsec_allowed = True — scope alone still governs.
    httpx_plugin = type("P", (), {"name": "httpx", "capability": "http_probe"})()
    allowed = runner._gate_active_input(context, httpx_plugin, source)
    assert SEED in allowed.read_text(encoding="utf-8")
    assert "ctlogs" not in ACTIVE_COLLECTION_PLUGINS
    assert "subfinder" not in ACTIVE_COLLECTION_PLUGINS


def test_oos_httpx_artifact_is_observed_not_collected() -> None:
    engine = IntelEngine(IntelRunConfig(run_id="p03", seed_domains=[SEED], scope_patterns=[SEED]))
    engine.ingest_httpx_records(
        [
            {
                "input": OOS,
                "host": OOS,
                "url": f"https://{OOS}/",
                "ip": "203.0.113.10",
                "a": ["203.0.113.10"],
                "status_code": 200,
                "tls": {
                    "subject_an": [OOS],
                    "fingerprint_hash": {"sha256": "a" * 64},
                },
            }
        ]
    )
    entity = engine.entities[f"domain:{OOS}"]
    assert entity.scope_status is ScopeStatus.OUT_OF_SCOPE
    assert entity.collection_status is CollectionStatus.NOT_ALLOWED
    indicator = engine.queue.get(IndicatorKind.DOMAIN, OOS)
    assert indicator is not None
    assert indicator.collection_status is CollectionStatus.NOT_ALLOWED
    engine.queue.mark_collected(IndicatorKind.DOMAIN, OOS)
    assert indicator.collection_status is CollectionStatus.NOT_ALLOWED
    assert not any(
        r.relationship_type is RelationshipType.RESOLVES_TO for r in engine.relationships.values()
    )


def test_oos_host_object_cannot_overwrite_authorization() -> None:
    host = Host(domain=OOS, ips=["203.0.113.10"], dns_resolved=True)
    host.http_services.append(HttpService(url=f"https://{OOS}/", host=OOS, status_code=200))
    engine = IntelEngine(
        IntelRunConfig(
            run_id="p03-host",
            seed_domains=[SEED],
            scope_patterns=[SEED],
            collected_domains={OOS},
        )
    )
    engine.ingest_hosts({OOS: host})
    entity = engine.entities[f"domain:{OOS}"]
    assert entity.scope_status is ScopeStatus.OUT_OF_SCOPE
    assert entity.collection_status is CollectionStatus.NOT_ALLOWED
    indicator = engine.queue.get(IndicatorKind.DOMAIN, OOS)
    if indicator is not None:
        assert indicator.collection_status is CollectionStatus.NOT_ALLOWED
    assert not any(
        r.relationship_type is RelationshipType.RESOLVES_TO for r in engine.relationships.values()
    )


def test_only_authorized_active_collection_is_collected() -> None:
    seed_host = Host(domain=SEED, ips=["34.75.127.116"], dns_resolved=True)
    ct_only = Host(domain=WWW)
    engine = IntelEngine(
        IntelRunConfig(
            run_id="p03-auth",
            seed_domains=[SEED],
            scope_patterns=[SEED],
            collected_domains={SEED},
        )
    )
    engine.ingest_hosts({SEED: seed_host, WWW: ct_only, OOS: Host(domain=OOS)})
    assert engine.entities[f"domain:{SEED}"].collection_status is CollectionStatus.COLLECTED
    assert engine.entities[f"domain:{WWW}"].collection_status is CollectionStatus.NOT_COLLECTED
    assert engine.entities[f"domain:{OOS}"].collection_status is CollectionStatus.NOT_ALLOWED


def test_filter_authorized_indicators_preserves_order() -> None:
    kept = filter_authorized_indicators([WWW, OOS, SEED, WWW], _scope())
    assert kept == [WWW, SEED]

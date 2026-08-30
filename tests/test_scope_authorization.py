"""Scope is a global authorization boundary. Discovery is not authorization."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from config.settings import Settings
from core.exceptions import ConfigurationError
from core.intel.engine import IntelEngine, IntelRunConfig
from core.intel.model import CollectionStatus, ScopeStatus
from core.intel.scope import (
    CollectionScope,
    allows_active_collection,
    authorize_plugin_input,
    classify_scope,
)
from core.models import DomainTarget, PipelineContext
from modules.cloud_bucket_enum import CloudBucketEnumPlugin
from modules.dnsx import DnsxPlugin
from modules.httpx import HttpxPlugin
from utils.files import write_lines

SEED = "virusbarrier.xyz"
OOS = "virusinspector.top"


def _scope() -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=[SEED])


def test_missing_collection_scope_fails_closed(tmp_path: Path, settings: Settings) -> None:
    source = tmp_path / "subdomains.txt"
    source.write_text(f"{SEED}\n", encoding="utf-8")
    context = PipelineContext(output_dir=tmp_path)
    with pytest.raises(ConfigurationError, match="CollectionScope is missing"):
        authorize_plugin_input(context, source, "dnsx")


@pytest.mark.asyncio
async def test_dnsx_without_scope_fails_closed(tmp_path: Path, settings: Settings) -> None:
    plugin = DnsxPlugin(settings)
    source = tmp_path / "hosts.txt"
    source.write_text(f"{SEED}\n", encoding="utf-8")
    context = PipelineContext(output_dir=tmp_path)
    with pytest.raises(ConfigurationError, match="fail closed"):
        await plugin.run(context, source)


@pytest.mark.asyncio
async def test_httpx_without_scope_fails_closed(tmp_path: Path, settings: Settings) -> None:
    plugin = HttpxPlugin(settings)
    source = tmp_path / "hosts.txt"
    source.write_text(f"{SEED}\n", encoding="utf-8")
    context = PipelineContext(output_dir=tmp_path)
    with pytest.raises(ConfigurationError, match="fail closed"):
        await plugin.run(context, source)


@pytest.mark.parametrize(
    "filename,oos",
    [
        ("subfinder.txt", "evil-subfinder.top"),
        ("amass.txt", "evil-amass.buzz"),
        ("assetfinder.txt", "evil-assetfinder.shop"),
        ("followup_domains.txt", OOS),
        ("ctlogs_domains.txt", OOS),
    ],
)
def test_oos_enumerator_results_never_reach_active_collectors(
    tmp_path: Path, filename: str, oos: str
) -> None:
    source = tmp_path / filename
    write_lines(source, [SEED, oos], base_dir=tmp_path)
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=tmp_path,
        collection_scope=_scope(),
    )
    for plugin in ("dnsx", "httpx", "naabu"):
        authorized = authorize_plugin_input(context, source, plugin)
        body = authorized.read_text(encoding="utf-8")
        assert SEED in body
        assert oos not in body


def test_wildcard_and_malformed_hostnames_are_not_collectable() -> None:
    scope = _scope()
    assert allows_active_collection(f"*.{SEED}", scope) is False
    assert classify_scope(f"*.{SEED}", seed_domains=[SEED], scope_patterns=[SEED]) is (
        ScopeStatus.UNKNOWN
    )
    assert allows_active_collection("not a host", scope) is False
    assert allows_active_collection("http://", scope) is False
    assert allows_active_collection("http://[::not-a-host", scope) is False
    assert allows_active_collection("", scope) is False
    assert allows_active_collection(f"www.{SEED}", scope) is True


def test_oos_ct_san_is_observed_not_collected() -> None:
    engine = IntelEngine(
        IntelRunConfig(run_id="oos-ct", seed_domains=[SEED], scope_patterns=[SEED])
    )
    engine.ingest_ct_records(
        [
            {
                "id": 9,
                "name_value": f"{SEED}\n{OOS}",
                "serial_number": "abc",
                "issuer_name": "Let's Encrypt",
                "query_domain": SEED,
            }
        ]
    )
    assert engine.entities[f"domain:{OOS}"].collection_status is CollectionStatus.NOT_ALLOWED
    assert engine.entities[f"domain:{OOS}"].scope_status is ScopeStatus.OUT_OF_SCOPE
    assert any(obs.entity_id == f"domain:{OOS}" for obs in engine.observations)


@pytest.mark.asyncio
async def test_cloud_derived_endpoints_require_explicit_opt_in(
    tmp_path: Path, settings: Settings
) -> None:
    settings.enable_cloud_bucket_enum = True
    settings.cloud_bucket_enum_authorize_derived = False
    settings.cloud_bucket_enum_delay_ms = 0
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(
        output_dir=output_dir,
        targets=[DomainTarget(domain="metaversejustice.com")],
        collection_scope=CollectionScope.from_seeds(["metaversejustice.com"]),
    )
    plugin = CloudBucketEnumPlugin(settings)
    with patch("core.collection.gateway._http_get") as http_get:
        result = await plugin.run(context, output_dir / "targets.txt")
    assert result.skipped
    http_get.assert_not_called()


@pytest.mark.asyncio
async def test_cloud_enum_scope_object_governs_even_if_settings_flag_is_stale(
    tmp_path: Path, settings: Settings
) -> None:
    """Per-host authorization must check the CollectionScope object itself, not
    just the Settings flag checked once at plugin entry.

    Production always keeps ``settings.cloud_bucket_enum_authorize_derived``
    and ``CollectionScope.cloud_collection_allowed`` in sync
    (`core/runner.py:_collection_scope_for`), but nothing enforces that for a
    scope object built any other way. This proves that if they ever drift —
    the settings flag says yes, the actual scope object says no — the scope
    object wins and no request is ever made, not just that the settings-only
    entry check happens to catch the common case.
    """
    settings.enable_cloud_bucket_enum = True
    settings.cloud_bucket_enum_authorize_derived = True
    settings.cloud_bucket_enum_delay_ms = 0
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(
        output_dir=output_dir,
        targets=[DomainTarget(domain="metaversejustice.com")],
        # Deliberately NOT threading cloud_collection_allowed through, unlike
        # the production wiring — this is the drift scenario.
        collection_scope=CollectionScope.from_seeds(["metaversejustice.com"]),
    )
    plugin = CloudBucketEnumPlugin(settings)
    with patch("core.collection.gateway._http_get") as http_get:
        result = await plugin.run(context, output_dir / "targets.txt")
    http_get.assert_not_called()
    assert result.success
    assert context.metadata.get("cloud_bucket_enum_denied_probes", 0) > 0
    assert any("not authorized by CollectionScope" in w for w in context.warnings)


@pytest.mark.asyncio
async def test_cloud_enum_missing_scope_fails_closed(tmp_path: Path, settings: Settings) -> None:
    settings.enable_cloud_bucket_enum = True
    settings.cloud_bucket_enum_authorize_derived = True
    context = PipelineContext(output_dir=tmp_path)
    plugin = CloudBucketEnumPlugin(settings)
    with patch("core.collection.gateway._http_get") as http_get:
        with pytest.raises(ConfigurationError, match="fail closed"):
            await plugin.run(context, tmp_path / "targets.txt")
    http_get.assert_not_called()


def test_oos_followup_hostname_is_not_authorized() -> None:
    scope = _scope()
    assert allows_active_collection(OOS, scope) is False
    assert allows_active_collection(f"https://{OOS}/login", scope) is False
    assert allows_active_collection("brand.s3.amazonaws.com", scope) is False
    assert allows_active_collection("storage.googleapis.com", scope) is False

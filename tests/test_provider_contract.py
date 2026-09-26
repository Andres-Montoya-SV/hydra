"""Fase 09 — minimal provider-contract tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.dependencies.registry import known_incompatible_version
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from core.provider_contract import (
    AuthorizationRequirement,
    ConfinementLevel,
    execution_status_for_result,
    provider_inventory,
)
from core.runner import PipelineRunner
from modules.httpx import HttpxPlugin
from modules.whatweb import WhatWebPlugin


def test_inventory_reuses_plugin_and_dependency_registries() -> None:
    rows = {row.provider: row for row in provider_inventory()}
    assert "httpx" in rows
    httpx = rows["httpx"]
    assert httpx.product_capability == HttpxPlugin.capability
    assert "http_probing" in httpx.dependency_capabilities
    assert httpx.authorization_requirement is AuthorizationRequirement.SCOPE_REQUIRED
    assert httpx.confinement is ConfinementLevel.PROXY_VERIFIED
    assert httpx.provenance_source == "httpx"


def test_optional_enrichment_provider_is_described_without_becoming_authority() -> None:
    rows = {row.provider: row for row in provider_inventory()}
    whatweb = rows["whatweb"]
    assert whatweb.optional is True
    assert whatweb.active_collection is True
    assert whatweb.product_capability == "technology_intelligence"
    assert whatweb.authorization_requirement is AuthorizationRequirement.SCOPE_REQUIRED
    assert whatweb.provenance_source == WhatWebPlugin.name


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (PluginResult(success=True, lines_produced=2), ToolStatus.SUCCESS_WITH_RESULTS),
        (PluginResult(success=True, lines_produced=0), ToolStatus.SUCCESS_NO_RESULTS),
        (PluginResult(success=False, partial=True), ToolStatus.PARTIAL),
        (PluginResult(success=False, skipped=True), ToolStatus.SKIPPED),
        (
            PluginResult(success=False, skipped=True, blocked_by_scope=True),
            ToolStatus.BLOCKED_BY_SCOPE,
        ),
        (PluginResult(success=False), ToolStatus.FAILED),
    ],
)
def test_execution_outcome_is_unambiguous(result: PluginResult, expected: ToolStatus) -> None:
    assert execution_status_for_result(result) is expected


def test_known_incompatible_provider_version_remains_dependency_registry_policy() -> None:
    message = known_incompatible_version("amass", "v5.1.1")
    assert message is not None
    assert "v5" in message


@pytest.mark.asyncio
async def test_runner_marks_full_scope_denial_blocked_by_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    runner = PipelineRunner(settings)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    raw = output_dir / "alive.txt"
    raw.write_text("https://outside.invalid/\n", encoding="utf-8")
    context = PipelineContext(
        targets=[DomainTarget(domain="example.com")],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(["example.com"], patterns=["example.com"]),
    )
    plugin = HttpxPlugin(settings)
    context.tool_states[plugin.name] = plugin.build_tool_info()

    monkeypatch.setattr(runner.tool_manager, "is_runnable", lambda name: True)

    result = await runner._run_single_plugin(context, plugin, raw)

    assert result is not None
    assert result.blocked_by_scope is True
    assert context.tool_states["httpx"].status is ToolStatus.BLOCKED_BY_SCOPE


def test_provider_inventory_is_machine_readable() -> None:
    rows = [row.to_dict() for row in provider_inventory()]
    assert rows
    required = {
        "provider",
        "provider_kind",
        "product_capability",
        "active_collection",
        "authorization_requirement",
        "confinement",
        "produces",
        "dependency_capabilities",
        "provenance_source",
    }
    assert required <= set(rows[0])

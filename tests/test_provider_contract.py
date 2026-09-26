"""Fase 09 — minimal provider-contract tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.dependencies.models import ToolDefinition, ToolHealth
from core.dependencies.registry import known_incompatible_version
from core.dependencies.service import DependencyService
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from core.provenance import record_observation
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


@pytest.mark.asyncio
async def test_missing_external_dependency_is_explicitly_missing(tmp_path: Path) -> None:
    service = DependencyService(
        {"hydra-provider-does-not-exist": tmp_path / "definitely-not-installed"}
    )
    report = await service.analyze_tool(
        ToolDefinition(
            name="hydra-provider-does-not-exist",
            display_name="Missing fixture provider",
            health_commands=(("--help",),),
        ),
        tmp_path / "definitely-not-installed",
        required=False,
    )
    assert report.health is ToolHealth.MISSING
    assert report.is_runnable is False


class _FakeProvider:
    name = "fake_provider"
    display_name = "Fake Provider"
    active_collection = False
    external_dependency = False
    capability = "fixture"
    strict_opsec_allowed = True
    cacheable = False

    def build_tool_info(self):
        from core.models import ToolInfo

        return ToolInfo(
            name=self.name,
            display_name=self.display_name,
            required=False,
            enabled=True,
        )

    def update_status(self, context, status, **kwargs):  # noqa: ANN001
        info = context.tool_states.setdefault(self.name, self.build_tool_info())
        info.status = status
        for key, value in kwargs.items():
            if hasattr(info, key):
                setattr(info, key, value)

    async def run(self, context, input_path):  # noqa: ANN001
        raise RuntimeError("provider exploded")


class _PartialProvider(_FakeProvider):
    name = "partial_provider"
    display_name = "Partial Provider"

    async def run(self, context, input_path):  # noqa: ANN001
        return PluginResult(
            success=False,
            partial=True,
            output_path=input_path,
            lines_produced=1,
            message="one target succeeded, one failed",
        )


@pytest.mark.asyncio
async def test_provider_exception_propagates_failed_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    runner = PipelineRunner(settings)
    output_dir = tmp_path / "output" / "run-exception"
    output_dir.mkdir(parents=True)
    source = output_dir / "input.txt"
    source.write_text("example.com\n", encoding="utf-8")
    context = PipelineContext(output_dir=output_dir)
    provider = _FakeProvider()
    context.tool_states[provider.name] = provider.build_tool_info()
    monkeypatch.setattr(runner.tool_manager, "is_runnable", lambda name: True)

    result = await runner._run_single_plugin(context, provider, source)

    assert result is None
    assert context.tool_states[provider.name].status is ToolStatus.FAILED
    assert context.errors


@pytest.mark.asyncio
async def test_partial_result_propagates_partial_not_failed_or_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    runner = PipelineRunner(settings)
    output_dir = tmp_path / "output" / "run-partial"
    output_dir.mkdir(parents=True)
    source = output_dir / "input.txt"
    source.write_text("example.com\n", encoding="utf-8")
    context = PipelineContext(output_dir=output_dir)
    provider = _PartialProvider()
    context.tool_states[provider.name] = provider.build_tool_info()
    monkeypatch.setattr(runner.tool_manager, "is_runnable", lambda name: True)

    result = await runner._run_single_plugin(context, provider, source)

    assert result is not None and result.partial is True
    assert context.tool_states[provider.name].status is ToolStatus.PARTIAL


def test_raw_artifact_stays_provenance_not_normalized_fact(tmp_path: Path) -> None:
    artifact = tmp_path / "provider_raw.json"
    artifact.write_text('{"raw": true}\n', encoding="utf-8")
    observation = record_observation(
        tool="fixture_provider",
        field="technology",
        value="nginx",
        confidence=80,
        artifact_path=str(artifact),
    )

    assert observation.value == "nginx"
    assert observation.artifact_path == "provider_raw.json"
    assert str(tmp_path) not in observation.artifact_path

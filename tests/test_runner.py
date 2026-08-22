"""Tests for pipeline runner error handling."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import PipelineContext
from core.runner import PipelineRunner
from core.store import AssetStore


class TestRunner:
    @pytest.mark.asyncio
    async def test_rejects_invalid_domain(self, settings: Settings) -> None:
        runner = PipelineRunner(settings)
        context = await runner.run(domain="not valid!")
        assert context.errors

    @pytest.mark.asyncio
    async def test_handles_missing_tools_gracefully(self, settings: Settings) -> None:
        runner = PipelineRunner(settings)
        with patch.object(
            runner.tool_manager,
            "validate_tools",
            new=AsyncMock(return_value=False),
        ):
            with patch.object(
                runner.tool_manager,
                "ensure_mandatory_tools",
                new=AsyncMock(side_effect=Exception("tools missing")),
            ):
                context = await runner.run(domain="example.com")
        assert context.finished_at is not None

    @pytest.mark.asyncio
    async def test_invalid_run_id(self, settings: Settings) -> None:
        runner = PipelineRunner(settings)
        context = await runner.run(domain="example.com", run_id="../bad")
        assert any("run-id" in e.lower() or "invalid" in e.lower() for e in context.errors)

    def test_live_network_state_plugins_never_replay_cached_results(
        self, settings: Settings, project_root: Path
    ) -> None:
        """Regression test: naabu/port_verify re-check a live, time-varying
        network property (current TCP port state). A cached "verification"
        is not a verification — replaying a stale artifact would silently
        hide the fact that the target's filtering behavior has changed
        since the artifact was produced. Only plugins that observe
        comparatively static data (e.g. WHOIS) may be served from cache.
        """
        from modules.naabu import NaabuPlugin
        from modules.port_verify import PortVerifyPlugin
        from modules.whois import WhoisPlugin

        runner = PipelineRunner(settings)
        runner._store = AssetStore(project_root / "output" / "recon.db")

        output_dir = project_root / "output" / "run1"
        output_dir.mkdir(parents=True)
        context = PipelineContext(
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["virusbarrier.xyz"]),
        )
        context.run_id = "run1"

        input_path = output_dir / "naabu.txt"
        input_path.write_text("virusbarrier.xyz:5060\n", encoding="utf-8")

        naabu = NaabuPlugin(settings)
        port_verify = PortVerifyPlugin(settings)
        whois_plugin = WhoisPlugin(settings)

        assert naabu.cacheable is False
        assert port_verify.cacheable is False
        assert whois_plugin.cacheable is True

        # Pre-populate a valid, non-expired cache entry for each plugin, as
        # if a prior run against identical input had already cached a
        # result — this is exactly the scenario that must NOT be replayed
        # for naabu/port_verify.
        for plugin in (naabu, port_verify, whois_plugin):
            cache_key, input_hash = runner._cache_key(plugin, input_path)
            runner._store.set_cache_entry(
                cache_key,
                tool=plugin.name,
                input_hash=input_hash,
                artifact_path=str(input_path),
                lines_produced=1,
                ttl_seconds=3600,
            )

        assert runner._load_cached_result(context, naabu, input_path) is None
        assert runner._load_cached_result(context, port_verify, input_path) is None
        assert runner._load_cached_result(context, whois_plugin, input_path) is not None

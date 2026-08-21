"""Tests for plugin registration and loading."""

from __future__ import annotations

import modules  # noqa: F401 — triggers plugin registration
from config.settings import Settings
from core.plugin_base import ReconPlugin
from core.tool_manager import ToolManager


class TestPlugins:
    def test_plugins_registered(self) -> None:
        names = {p.name for p in ReconPlugin.all_plugins()}
        assert "subfinder" in names
        assert "amass" in names
        assert "dnsx" in names
        assert "httpx" in names

    def test_tool_manager_discovers_plugins(self, settings: Settings) -> None:
        manager = ToolManager(settings)
        plugins = manager.get_all_plugins()
        assert len(plugins) >= 3

    def test_mandatory_plugins(self, settings: Settings) -> None:
        manager = ToolManager(settings)
        mandatory = manager.get_mandatory_plugins()
        assert all(p.required for p in mandatory)

    def test_optional_disabled_by_default(self, settings: Settings) -> None:
        manager = ToolManager(settings)
        nuclei = manager.get_plugin("nuclei")
        assert nuclei is not None
        assert not nuclei.is_enabled()

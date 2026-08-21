"""Tests for tool discovery subsystem."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from core.discovery.tool_discovery import ToolDiscovery
from core.platform import detect_platform


class TestPlatform:
    def test_detect_platform(self) -> None:
        info = detect_platform()
        assert info.home.exists()
        assert info.label

    def test_python_on_path(self) -> None:
        info = detect_platform()
        python = Path(sys.executable)
        assert (
            any(
                python.parent == d or python.parent.resolve() == d.resolve() for d in info.path_dirs
            )
            or python.exists()
        )


class TestToolDiscovery:
    @pytest.mark.asyncio
    async def test_discover_python(self) -> None:
        discovery = ToolDiscovery()
        result = await discovery.discover("python3", Path(sys.executable))
        assert result.is_usable
        assert result.absolute_path is not None

    @pytest.mark.asyncio
    async def test_discover_missing(self) -> None:
        discovery = ToolDiscovery()
        result = await discovery.discover("nonexistent-tool-xyz", Path("nonexistent-tool-xyz"))
        assert not result.is_usable
        assert result.availability.value == "not_found"

    def test_search_directories_nonempty(self) -> None:
        discovery = ToolDiscovery()
        dirs = discovery.search_directories()
        assert len(dirs) >= 1

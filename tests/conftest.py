"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# conftest.py is imported by pytest's own bootstrap, before it necessarily
# puts this directory on sys.path the way it does for collected test
# modules — insert it explicitly so a plain sibling-module import below
# works regardless of how pytest was invoked.
sys.path.insert(0, str(Path(__file__).parent))

from _httpx_verification import verified_tool_path_or_skip  # noqa: E402

from config.settings import Settings  # noqa: E402

# See docs/PAID_API_DESIGN.md's "Round 1 implemented" section for the
# full incident writeup: the Python `httpx` PyPI package (a test-only
# dependency, requirements-dev.txt, needed for fastapi.testclient) always
# installs a console-script entry point also named `httpx`, unconditionally
# — not gated behind any pip extra — which can outrank the real
# ProjectDiscovery `httpx` recon binary on PATH once a venv is active.
# `core/dependencies/service.py` already defends against exactly this for
# any REAL pipeline run (multi-candidate discovery + identity-marker
# validation — see its own "handles httpx vs python-httpx" comment); this
# fixture gives tests that construct a plugin/Settings directly, bypassing
# that layer on purpose, the same protection.


@pytest.fixture
async def verified_httpx_path() -> Path:
    """The real ProjectDiscovery `httpx` binary's resolved,
    identity-verified path (never the bare `Path("httpx")` `Settings`
    defaults to, which a subprocess call resolves via raw OS PATH search
    with no identity check at all). Skips the test, rather than failing
    it, when no genuine binary can be found/verified in this environment
    — a missing/misidentified tool is an environment fact, not a bug in
    the test itself."""
    return await verified_tool_path_or_skip("httpx")


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    """Temporary project root directory."""
    (tmp_path / "output").mkdir()
    (tmp_path / "logs").mkdir()
    (tmp_path / "reports").mkdir()
    return tmp_path


@pytest.fixture
def settings(project_root: Path) -> Settings:
    """Minimal valid settings for tests."""
    return Settings(project_root=project_root)


@pytest.fixture
def targets_file(project_root: Path) -> Path:
    """Sample targets file."""
    path = project_root / "targets.txt"
    path.write_text("example.com\nexample.org\n", encoding="utf-8")
    return path

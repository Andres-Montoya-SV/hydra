"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

# conftest.py is imported by pytest's own bootstrap, before it necessarily
# puts this directory on sys.path the way it does for collected test
# modules — insert it explicitly so a plain sibling-module import below
# works regardless of how pytest was invoked.
sys.path.insert(0, str(Path(__file__).parent))

from _httpx_verification import verified_tool_path_or_skip  # noqa: E402
from _optional_deps import install_strict_importorskip  # noqa: E402

from config.settings import Settings  # noqa: E402

# HYDRA_REQUIRE_OPTIONAL_DEPS=1 (the Docker CI job): a missing optional
# package fails instead of skipping. See tests/_optional_deps.py.
install_strict_importorskip()

# Productization Phase 10: HYDRA_TEST_DATABASE_URL (a disposable local
# Postgres, never a real deployment) runs every ControlDB in the suite on
# Postgres, each in its own schema; tests that reach into the SQLite file
# directly are marked `sqlite_only` and skipped. See tests/_pg_mode.py.
from _pg_mode import install_postgres_mode  # noqa: E402

install_postgres_mode()

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


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "sqlite_only: reads/writes the SQLite control-db file directly"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    from _pg_mode import POSTGRES_URL

    if not POSTGRES_URL:
        return
    skip = pytest.mark.skip(reason="reads the SQLite control-db file directly")
    for item in items:
        if item.get_closest_marker("sqlite_only"):
            item.add_marker(skip)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    del session, exitstatus
    from _pg_mode import drop_test_schemas

    drop_test_schemas()


@pytest.fixture(autouse=True)
def _restore_environment() -> Iterator[None]:
    """Every test starts and ends with the same process environment.
    `load_dotenv` (the CLI's Settings.from_env, the API's settings loader)
    writes a test's temporary .env into os.environ for good; without this,
    one test's ENABLE_*=false silently switched tools off in later tests
    (Phase 11f made API scans honour operator ENABLE_* switches)."""
    saved = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)

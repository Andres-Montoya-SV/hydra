"""Pytest configuration and shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings


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

"""Tests for Hydra CLI identity (banner, heads, version)."""

from __future__ import annotations

from pathlib import Path

from config.settings import Settings
from core.heads import HEAD_BLURBS, HYDRA_BANNER, HYDRA_TAGLINE
from core.tool_manager import ToolManager


def test_banner_contains_hydra() -> None:
    assert "HYDRA" in HYDRA_BANNER
    assert "recon" in HYDRA_TAGLINE.lower()


def test_heads_covers_registered_plugins(project_root: Path) -> None:
    from app import cmd_heads

    settings = Settings(project_root=project_root)
    assert cmd_heads(settings) == 0
    manager = ToolManager(settings)
    names = {p.name for p in manager.get_all_plugins()}
    assert "whois" in names
    assert "whois" in HEAD_BLURBS
    assert "param_fuzz" in HEAD_BLURBS

"""Tests for Hydra CLI identity (banner, heads, version)."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console

from config.settings import Settings
from core.heads import (
    HEAD_BLURBS,
    HYDRA_BANNER,
    HYDRA_TAGLINE,
    print_banner,
    should_print_banner,
)
from core.tool_manager import ToolManager


def test_banner_contains_wordmark_and_tagline() -> None:
    assert "██╗" in HYDRA_BANNER
    assert HYDRA_TAGLINE == "many heads. one hunt."
    assert "many heads. one hunt." in HYDRA_BANNER


def test_banner_only_for_run_and_help() -> None:
    assert should_print_banner(["--help"]) is True
    assert should_print_banner(["-h"]) is True
    assert should_print_banner([]) is True
    assert should_print_banner(["run", "-d", "example.com"]) is True
    assert should_print_banner(["heads"]) is False
    assert should_print_banner(["check-opsec"]) is False
    assert should_print_banner(["heads", "--help"]) is False


def test_no_banner_flag_and_env_suppress(monkeypatch) -> None:
    assert should_print_banner(["run", "--no-banner"]) is False
    assert should_print_banner(["--no-banner", "--help"]) is False
    monkeypatch.setenv("HYDRA_NO_BANNER", "1")
    assert should_print_banner(["run", "-d", "example.com"]) is False


def test_print_banner_suppressed_by_flag() -> None:
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, color_system=None)
    print_banner(["run", "--no-banner"], console=console)
    assert buf.getvalue() == ""


def test_print_banner_omitted_when_not_a_terminal() -> None:
    buf = StringIO()
    console = Console(file=buf, force_terminal=False)
    print_banner(["run"], console=console)
    assert buf.getvalue() == ""
    assert console.is_terminal is False


def test_print_banner_renders_tagline_on_tty() -> None:
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, color_system=None)
    print_banner(["run"], console=console)
    text = buf.getvalue()
    assert "many heads. one hunt." in text
    assert "██╗" in text


def test_parser_exposes_intel_and_skip_network() -> None:
    from app import build_parser

    parser = build_parser()
    opsec = parser.parse_args(["check-opsec", "--skip-network"])
    assert opsec.skip_network is True
    inv = parser.parse_args(["investigate", "example.com"])
    assert inv.command == "investigate"
    assert inv.domain == "example.com"
    diff = parser.parse_args(["diff", "run_a", "run_b"])
    assert diff.run_a == "run_a"
    assert diff.run_b == "run_b"
    diff_domain = parser.parse_args(["diff", "virusbarrier.xyz"])
    assert diff_domain.run_a == "virusbarrier.xyz"
    assert diff_domain.run_b is None
    ev_rel = parser.parse_args(["evidence", "abcd" * 8])
    assert ev_rel.domain == "abcd" * 8


def test_heads_covers_registered_plugins(project_root: Path) -> None:
    from app import cmd_heads

    settings = Settings(project_root=project_root)
    assert cmd_heads(settings) == 0
    manager = ToolManager(settings)
    names = {p.name for p in manager.get_all_plugins()}
    assert "whois" in names
    assert "whois" in HEAD_BLURBS
    assert "param_fuzz" in HEAD_BLURBS

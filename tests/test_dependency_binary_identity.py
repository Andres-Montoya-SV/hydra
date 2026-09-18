"""core/dependencies/{discovery,validation,service}.py — the defense
against a same-named impostor binary shadowing a real recon tool on
PATH (the exact "Python httpx package vs ProjectDiscovery httpx binary"
collision documented in docs/PAID_API_DESIGN.md's "Round 1 implemented"
section, and in tests/conftest.py's `verified_httpx_path` fixture).

This mechanism already existed before that incident —
`core/dependencies/registry.py`'s own httpx `ToolDefinition` already
declares `identity_markers` and a `path_denylist` covering `.venv`/
`site-packages`/`Python.framework`, and `service.py`'s own
`analyze_tool` comment says "handles httpx vs python-httpx" — but it had
zero test coverage. These tests confirm it actually does what its own
comments claim, with a real impostor script, not just by reading the
code and trusting it.
"""

from __future__ import annotations

import os
import stat
import textwrap
from pathlib import Path

import pytest

from core.dependencies.models import ToolDefinition
from core.dependencies.registry import get_tool_definition
from core.dependencies.service import DependencyService
from core.dependencies.validation import HealthValidator


def _write_impostor_script(path: Path, *, output: str, exit_code: int = 0) -> None:
    """A fake `httpx` that behaves like a real, runnable CLI tool (exits
    cleanly, prints something to -h/--version) but is obviously NOT the
    ProjectDiscovery binary — the same shape the real Python `httpx`
    package's own console script has: it runs fine, it's just a
    different tool entirely."""
    path.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            echo {output!r}
            exit {exit_code}
            """
        ),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


IMPOSTOR_OUTPUT = "usage: httpx [OPTIONS] URL\n\nA next generation HTTP client for Python.\n"


class TestIdentityMarkersRejectAnImpostor:
    """The exact mechanism the task asked to confirm: a same-named binary
    that runs successfully but isn't the real tool must be rejected with
    a clear reason, never silently accepted because "something called
    httpx responded to -h"."""

    @pytest.mark.asyncio
    async def test_validate_at_path_rejects_an_impostor_with_a_clear_reason(
        self, tmp_path: Path
    ) -> None:
        impostor = tmp_path / "httpx"
        _write_impostor_script(impostor, output=IMPOSTOR_OUTPUT)

        defn = get_tool_definition("httpx")
        validator = HealthValidator()
        result = await validator.validate_at_path(impostor, defn)

        assert result.can_execute is False
        assert any("identity check failed" in note.lower() for note in result.notes)

    @pytest.mark.asyncio
    async def test_validate_at_path_accepts_a_script_that_actually_claims_identity(
        self, tmp_path: Path
    ) -> None:
        """Sanity check on the test helper itself: the rejection above is
        because of the CONTENT mismatch, not because any script fails —
        a fake script whose output happens to contain a real identity
        marker passes, confirming the assertion above is testing the
        right thing."""
        genuine_looking = tmp_path / "httpx"
        _write_impostor_script(
            genuine_looking,
            output="projectdiscovery httpx — multi-purpose HTTP toolkit v9.9.9",
        )

        defn = get_tool_definition("httpx")
        validator = HealthValidator()
        result = await validator.validate_at_path(genuine_looking, defn)

        assert result.can_execute is True

    @pytest.mark.asyncio
    async def test_a_tool_definition_with_no_identity_markers_is_unaffected(
        self, tmp_path: Path
    ) -> None:
        """The identity check only applies to tools that declare
        `identity_markers` — confirms this is opt-in per tool, not a
        blanket behavior change that could break tools that never needed
        it (most of the registry has no identity_markers at all)."""
        script = tmp_path / "some-tool"
        _write_impostor_script(script, output="anything at all")

        defn = ToolDefinition(name="some-tool", display_name="Some Tool", binary_name="some-tool")
        assert defn.identity_markers == ()
        validator = HealthValidator()
        result = await validator.validate_at_path(script, defn)

        assert result.can_execute is True


class TestDependencyServiceSkipsTheImpostorForTheRealBinary:
    """The actual production shape of the incident: an impostor scores
    highly enough to be discovery's FIRST candidate (it's what
    `shutil.which` resolves once a venv with the Python `httpx` package
    installed is active), but a genuine binary is also reachable —
    `analyze_tool`'s "try candidates until one passes" loop must keep
    going past the impostor rather than stopping at the first thing that
    merely runs."""

    @pytest.mark.asyncio
    async def test_real_projectdiscovery_httpx_is_selected_over_an_earlier_impostor(
        self, tmp_path: Path, verified_httpx_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        impostor_dir = tmp_path / "fake_bin"
        impostor_dir.mkdir()
        impostor = impostor_dir / "httpx"
        _write_impostor_script(impostor, output=IMPOSTOR_OUTPUT)

        # Put the impostor's directory first on PATH — exactly the real
        # incident's shape (a venv's bin/ prepended ahead of the real
        # tool's directory) — while the real binary stays reachable via
        # its own already-installed location (Homebrew, GOPATH, etc.).
        monkeypatch.setenv("PATH", f"{impostor_dir}:{os.environ['PATH']}")

        service = DependencyService({"httpx": Path("httpx")})
        report = await service.analyze_tool(
            get_tool_definition("httpx"), Path("httpx"), required=True
        )

        assert report.resolved_path is not None
        assert report.resolved_path != impostor
        assert report.resolved_path == verified_httpx_path
        assert report.health.value == "healthy"

    @pytest.mark.asyncio
    async def test_impostor_only_reachable_via_path_never_wins_even_when_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With PATH pointing *only* at the impostor's directory (the
        real incident's shape — a venv's bin/ prepended, nothing else
        reachable via bare PATH search), discovery still finds Homebrew's
        installation independently (a fixed, known filesystem location,
        not a PATH lookup — confirmed directly: `detect_platform()`
        resolves `homebrew_bin` regardless of PATH). The invariant that
        actually matters, and that holds either way: the resolved binary
        is never the impostor, and the tool is never reported HEALTHY
        while pointing at it."""
        impostor_dir = tmp_path / "fake_bin"
        impostor_dir.mkdir()
        impostor = impostor_dir / "httpx"
        _write_impostor_script(impostor, output=IMPOSTOR_OUTPUT)

        monkeypatch.setenv("PATH", str(impostor_dir))

        service = DependencyService({"httpx": Path("httpx")})
        report = await service.analyze_tool(
            get_tool_definition("httpx"), Path("httpx"), required=True
        )

        assert report.resolved_path != impostor
        if report.health.value == "healthy":
            assert report.resolved_path is not None
            assert report.resolved_path != impostor

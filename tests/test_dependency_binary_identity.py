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
from core.platform import MacArch, OSType, PlatformInfo


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

_SYSTEM_BIN_DIRS = (Path("/usr/local/bin"), Path("/usr/bin"), Path("/bin"))


def _hide_real_system_bin_dirs(monkeypatch: pytest.MonkeyPatch) -> None:
    """`core/dependencies/discovery.py::BinaryDiscovery._build_candidates`
    unconditionally ALSO checks `/usr/local/bin`, `/usr/bin`, `/bin` as a
    fallback — hardcoded, independent of any `PlatformInfo` field a test
    can override. A synthetic `PlatformInfo`/restricted `PATH` alone
    (both already done by the tests calling this) is not enough to
    simulate "no real tool reachable anywhere" on a machine that
    genuinely has one installed at one of these three paths — and this
    project's OWN Dockerfile does exactly that
    (`COPY --from=go-builder /out/bin/ /usr/local/bin/`): the real,
    Go-compiled `httpx` binary genuinely lives at `/usr/local/bin/httpx`
    inside the CI Docker image (`docker` job,
    `.github/workflows/ci.yml`), which is exactly the environment these
    tests need to rule out to mean what their own docstrings claim. A
    real CI failure inside that container — `health=degraded` instead
    of the expected `missing`, and a skip that never fired — is what
    caught this gap; it was never visible on a bare `hostedtoolcache/
    Python` runner (the `check` job) or a normal dev machine without
    these tools installed system-wide. Patches `Path.is_dir` narrowly,
    only for these three exact paths, so the test is deterministic
    regardless of what the machine actually running it has installed —
    the production fallback itself is correct and untouched, only this
    test's isolation was incomplete."""
    real_is_dir = Path.is_dir

    def fake_is_dir(self: Path) -> bool:
        if self in _SYSTEM_BIN_DIRS:
            return False
        return real_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", fake_is_dir)


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
    async def test_real_binary_elsewhere_beats_an_impostor_first_on_path(
        self, tmp_path: Path, verified_httpx_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With PATH pointing at the impostor's directory FIRST (the real
        incident's shape — a venv's bin/ prepended ahead of the real
        tool's directory), a genuine binary reachable elsewhere (this
        machine's real Homebrew install) must still be selected — never
        the impostor, regardless of PATH order."""
        impostor_dir = tmp_path / "fake_bin"
        impostor_dir.mkdir()
        impostor = impostor_dir / "httpx"
        _write_impostor_script(impostor, output=IMPOSTOR_OUTPUT)

        monkeypatch.setenv("PATH", f"{impostor_dir}:{os.environ['PATH']}")

        service = DependencyService({"httpx": Path("httpx")})
        report = await service.analyze_tool(
            get_tool_definition("httpx"), Path("httpx"), required=True
        )

        assert report.resolved_path == verified_httpx_path
        assert report.resolved_path != impostor
        assert report.health.value == "healthy"

    @pytest.mark.asyncio
    async def test_impostor_only_anywhere_is_missing_with_resolved_path_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The exact CI failure shape: a synthetic platform with NO
        Homebrew, NO Go install locations, and PATH pointing only at the
        impostor — matching a bare `hostedtoolcache/Python` runner that
        never installed any real Go-based recon tool. Bug 1's fix:
        `resolved_path` must be `None`, never the impostor, whenever
        health isn't HEALTHY — a caller must never be able to observe
        `health=MISSING` and a `resolved_path` that points at the exact
        binary that caused that result."""
        impostor_dir = tmp_path / "fake_bin"
        impostor_dir.mkdir()
        impostor = impostor_dir / "httpx"
        _write_impostor_script(impostor, output=IMPOSTOR_OUTPUT)

        # BinaryDiscovery also calls shutil.which() directly, which reads
        # the real os.environ["PATH"] independent of PlatformInfo.path_dirs
        # below — both must be restricted for this to genuinely simulate
        # "nothing real reachable anywhere," not just "not in this one list."
        monkeypatch.setenv("PATH", str(impostor_dir))
        # Also independent of PlatformInfo entirely — see this helper's
        # own docstring for why (a real httpx binary genuinely lives at
        # /usr/local/bin inside this project's own Docker CI image).
        _hide_real_system_bin_dirs(monkeypatch)

        fake_platform = PlatformInfo(
            os_type=OSType.LINUX,
            mac_arch=MacArch.UNKNOWN,
            is_macos=False,
            is_linux=True,
            home=tmp_path,
            path_dirs=(impostor_dir,),
            gobin=None,
            gopath_bin=tmp_path / "go" / "bin",  # deliberately does not exist
            homebrew_bin=None,
            homebrew_prefix=None,
        )
        service = DependencyService({"httpx": Path("httpx")}, platform=fake_platform)
        report = await service.analyze_tool(
            get_tool_definition("httpx"), Path("httpx"), required=True
        )

        assert report.health.value == "missing"
        assert report.resolved_path is None
        assert "identity verification" in (report.status_reason or "").lower()
        # The rejected location is still surfaced for diagnostics, just
        # never as `resolved_path` — see ui/dependency_report.py.
        assert report.discovery is not None
        assert report.discovery.path == impostor


class TestLiveConfinementTestsSkipCleanlyRatherThanFailOnAnImpostor:
    """Bug 2: `shutil.which("httpx") is None` used to be the skip
    condition on the three live-network confinement test files — that
    finds an impostor just fine (it exists, it's executable), so the
    skip stopped firing the moment requirements-dev.txt put one on PATH,
    and the tests ran against the wrong binary and failed instead of
    skipping. Those files no longer have that module-level skipif at
    all; every test in them now takes `verified_httpx_path`
    (tests/conftest.py), whose own `pytest.skip()` call is exercised
    directly here — proving the actual mechanism a real impostor-only
    environment (a bare `hostedtoolcache/Python` CI runner, matching the
    real GitHub Actions failure this responds to) hits."""

    @pytest.mark.asyncio
    async def test_skip_fires_with_a_clear_message_when_only_an_impostor_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from _httpx_verification import verified_tool_path_or_skip

        impostor_dir = tmp_path / "fake_bin"
        impostor_dir.mkdir()
        _write_impostor_script(impostor_dir / "httpx", output=IMPOSTOR_OUTPUT)
        monkeypatch.setenv("PATH", str(impostor_dir))
        _hide_real_system_bin_dirs(monkeypatch)
        # core/dependencies/service.py does `from core.platform import
        # ... detect_platform` — that's its own local binding, so the
        # patch target is the importing module's name, not the origin.
        monkeypatch.setattr(
            "core.dependencies.service.detect_platform",
            lambda: PlatformInfo(
                os_type=OSType.LINUX,
                mac_arch=MacArch.UNKNOWN,
                is_macos=False,
                is_linux=True,
                home=tmp_path,
                path_dirs=(impostor_dir,),
                gobin=None,
                gopath_bin=tmp_path / "go" / "bin",
                homebrew_bin=None,
                homebrew_prefix=None,
            ),
        )

        with pytest.raises(pytest.skip.Exception) as exc_info:
            await verified_tool_path_or_skip("httpx")

        assert "no genuine httpx binary" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_does_not_skip_when_a_genuine_binary_is_reachable(
        self, verified_httpx_path: Path
    ) -> None:
        """Sanity check on the test above: the fixture only skips when
        genuinely warranted — on a normal dev machine with the real tool
        installed, it returns a real path instead, exactly like every
        other passing test in the three live-confinement files relies on."""
        assert verified_httpx_path.is_file()

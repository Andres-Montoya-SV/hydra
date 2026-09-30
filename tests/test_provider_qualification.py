"""Productization Phase 09: provider qualification.

Layers, from cheapest to most real:
1. `qualify()` rules.
2. Each plugin's flag literals (read from its source) match its binaries'
   profiles exactly: no flag used without a profile entry, no stale entry.
3. Every version the Dockerfile pins is a qualified version — so bumping a
   pin without re-qualifying fails even the lightweight CI matrix.
4. In the Docker image, the real pinned binaries qualify: detected version
   and help output. HYDRA_REQUIRE_IMAGE_TOOLS=1 (set on the Docker CI job)
   makes a missing binary a failure there instead of a skip.
Plus the preflight: ToolManager marks a binary that lost a flag UNAVAILABLE.
"""

from __future__ import annotations

import ast
import asyncio
import os
import re
from pathlib import Path

import pytest

from config.settings import Settings
from core.dependencies.models import ToolHealth, ToolReport, ValidationResult
from core.dependencies.service import DependencyService
from core.models import PipelineContext, ToolInfo, ToolStatus
from core.provider_qualification import PROFILES, qualify, qualify_report
from core.tool_manager import ToolManager

REPO = Path(__file__).resolve().parent.parent
FLAG = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9-]*$")
REQUIRE_IMAGE_TOOLS = os.environ.get("HYDRA_REQUIRE_IMAGE_TOOLS") == "1"


def _help_with(tool: str, *, drop: str | None = None) -> str:
    return "\n".join(token for flag, token in PROFILES[tool].flags.items() if flag != drop)


class TestQualifyRules:
    def test_a_pinned_version_with_every_flag_qualifies(self) -> None:
        result = qualify("httpx", installed=True, version="v1.12.0", help_text=_help_with("httpx"))
        assert (result.status, result.version) == ("qualified", "1.12.0")

    def test_another_version_runs_but_is_unverified(self) -> None:
        result = qualify("httpx", installed=True, version="1.13.0", help_text=_help_with("httpx"))
        assert result.status == "unverified_version"
        assert "1.12.0" in result.reasons[0]

    def test_a_removed_flag_is_reported_by_name(self) -> None:
        result = qualify(
            "httpx",
            installed=True,
            version="1.12.0",
            help_text=_help_with("httpx", drop="-tls-grab"),
        )
        assert result.status == "missing_flags"
        assert "-tls-grab" in result.reasons[0]

    def test_parametrized_help_tokens(self) -> None:
        help_text = _help_with("port_verify")
        assert "-T<0-5>" in help_text and "\n-T1\n" not in f"\n{help_text}\n"
        assert (
            qualify("port_verify", installed=True, version="7.95", help_text=help_text).status
            == "qualified"
        )

    def test_no_version_flag_is_qualified_on_flag_surface_alone(self) -> None:
        result = qualify(
            "hakrawler", installed=True, version=None, help_text=_help_with("hakrawler")
        )
        assert result.status == "qualified"
        assert "doesn't report a version" in result.reasons[0]

    def test_undetectable_version_and_absence(self) -> None:
        assert (
            qualify("nuclei", installed=True, version=None, help_text=_help_with("nuclei")).status
            == "version_unknown"
        )
        assert (
            qualify("nuclei", installed=False, version=None, help_text="").status == "not_installed"
        )


def _module_flags(module: str) -> set[str]:
    tree = ast.parse((REPO / "modules" / f"{module}.py").read_text())
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and FLAG.match(node.value)
    }


class TestPluginSourceContract:
    @pytest.mark.parametrize("module", sorted({m for p in PROFILES.values() for m in p.modules}))
    def test_every_flag_a_plugin_passes_is_profiled(self, module: str) -> None:
        profiled = {f for p in PROFILES.values() if module in p.modules for f in p.flags}
        assert _module_flags(module) - profiled == set()

    @pytest.mark.parametrize("tool", sorted(PROFILES))
    def test_no_profiled_flag_is_stale(self, tool: str) -> None:
        used = set().union(*(_module_flags(m) for m in PROFILES[tool].modules))
        assert set(PROFILES[tool].flags) - used == set()


def _dockerfile_pins() -> dict[str, str]:
    pins = {}
    for line in (REPO / "Dockerfile").read_text().splitlines():
        match = re.search(r"go install -v \S*/([a-z0-9]+)(?:/cmd/[a-z0-9]+)?@v?([0-9][\w.]*)", line)
        if match:
            pins[match.group(1)] = match.group(2)
    return pins


class TestDockerfilePins:
    def test_every_pinned_tool_is_profiled_at_its_pinned_version(self) -> None:
        pins = _dockerfile_pins()

        assert set(pins) == {p.binary for p in PROFILES.values() if p.binary != "nmap"}
        for binary, version in pins.items():
            profile = next(p for p in PROFILES.values() if p.binary == binary)
            assert version in profile.qualified_versions, (
                f"Dockerfile pins {binary} {version} but its profile qualifies "
                f"{sorted(profile.qualified_versions)}: re-qualify before bumping"
            )


def _resolved(tool: str) -> ToolReport:
    """The dependency report for the identity-verified binary, resolved the
    way production does (DependencyService), never a bare PATH lookup: in
    the image, PATH's `httpx` is the Python httpx package's console script,
    not ProjectDiscovery's (see requirements-dev.txt).

    The pinned image is the environment the profiles describe, so this
    layer runs there (HYDRA_REQUIRE_IMAGE_TOOLS=1, where a missing binary
    fails). A developer machine legitimately has other versions; the
    preflight reports those as unverified at scan time instead."""
    if not REQUIRE_IMAGE_TOOLS:
        pytest.skip("asserted against the Docker image's pinned binaries")
    configured = Path(PROFILES[tool].binary)
    report = asyncio.run(DependencyService({tool: configured}).analyze_all())[tool]
    if report.resolved_path is None or not report.is_runnable:
        pytest.fail(f"HYDRA_REQUIRE_IMAGE_TOOLS=1 but {configured} is not runnable")
    return report


class TestInstalledBinariesQualify:
    @pytest.mark.parametrize("tool", sorted(PROFILES))
    def test_the_installed_binary_qualifies(self, tool: str) -> None:
        result = qualify_report(tool, _resolved(tool))

        assert result.status == "qualified", result.reasons


def _report(tool: str, version: str, help_text: str) -> ToolReport:
    """What DependencyService would report: runnable, with the help output
    its health probe captured."""
    return ToolReport(
        name=tool,
        display_name=tool,
        required=False,
        health=ToolHealth.HEALTHY,
        configured_path=tool,
        resolved_path=Path(f"/usr/local/bin/{tool}"),
        version=version,
        can_execute=True,
        validation=ValidationResult(can_execute=True, version=version, probe_output=help_text),
    )


def _preflight(tmp_path: Path, tool: str, version: str, help_text: str) -> PipelineContext:
    manager = ToolManager(Settings(project_root=tmp_path))
    manager._reports[tool] = _report(tool, version, help_text)
    context = PipelineContext(output_dir=tmp_path)
    context.tool_states[tool] = ToolInfo(
        name=tool, display_name=tool, required=False, enabled=True, status=ToolStatus.READY
    )
    manager._qualify_providers(context)
    return context


class TestPreflight:
    def test_a_binary_that_lost_a_flag_is_made_unavailable(self, tmp_path: Path) -> None:
        context = _preflight(tmp_path, "katana", "1.7.0", _help_with("katana", drop="-jsonl"))

        assert context.tool_states["katana"].status is ToolStatus.UNAVAILABLE
        assert context.metadata["provider_qualification"]["katana"]["status"] == "missing_flags"
        assert any("-jsonl" in w for w in context.warnings)

    def test_an_unverified_version_runs_with_a_warning(self, tmp_path: Path) -> None:
        context = _preflight(tmp_path, "katana", "1.8.0", _help_with("katana"))

        assert context.tool_states["katana"].status is ToolStatus.READY
        assert context.metadata["provider_qualification"]["katana"]["status"] == (
            "unverified_version"
        )
        assert any("not a qualified version" in w for w in context.warnings)

    def test_a_qualified_binary_is_untouched(self, tmp_path: Path) -> None:
        context = _preflight(tmp_path, "katana", "1.7.0", _help_with("katana"))

        assert context.tool_states["katana"].status is ToolStatus.READY
        assert context.warnings == []

    def test_no_report_means_not_installed_never_qualified(self) -> None:
        assert qualify_report("katana", None).status == "not_installed"

"""Hardening round 2, Task 1 (dependency reproducibility): version
detection must extract a real version number, not silently return ASCII
banner art as if it were one.

Real bug found this round: `core/dependencies/validation.py::_extract_version`
only scanned the first 5 lines of a tool's version/help output, and its
fallback accepted *any* line containing a digit under 80 characters. Several
of Hydra's primary tools (httpx, naabu, katana, dnsx, amass) print a
multi-line ASCII banner before their real "Current Version: vX.Y.Z" line —
confirmed live against the real installed binaries on this machine, not
assumed:

    subfinder  -> '2.14.0' (correct, no fix needed)
    dnsx       -> '_             __  __'   (WRONG — banner line)
    httpx      -> '__    __  __       _  __'  (WRONG — banner line)
    naabu      -> '__'  (WRONG — banner line)
    katana     -> '__        __                ' (WRONG — banner line)
    amass      -> '+W@@@@@@8   &+W@#...'  (WRONG — banner line)

The fixture strings below are the exact real captured output from these
binaries (`amass -h`/`version`, `httpx -version`, etc. on this machine,
2026-09-14) — not synthesized banners that might not match real tool
behavior.
"""

from __future__ import annotations

import pytest

from core.dependencies.registry import KNOWN_INCOMPATIBLE_VERSIONS, known_incompatible_version
from core.dependencies.validation import _extract_version

# Real captured `amass version` output (banner + real version buried past
# line 5) — the exact case that silently produced a garbage "version".
_AMASS_VERSION_BANNER = (
    ".+++:.            :                             .+++.\n"
    "      +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+\n"
    "     &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&\n"
    "    +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8\n"
    "    8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:\n"
    "    WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:\n"
    "    #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8\n"
    "    o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.\n"
    "     WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o\n"
    "     :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+\n"
    "      :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&\n"
    "        +o&&&&+.                                                    +oooo.\n"
    "\n"
    "                                                                      v5.1.1\n"
    "                                           OWASP Amass Project - @owaspamass\n"
)

# Real captured `httpx -version` output.
_HTTPX_VERSION_BANNER = (
    "__    __  __       _  __\n"
    "   / /_  / /_/ /_____ | |/ /\n"
    "  / __ \\/ __/ __/ __ \\|   /\n"
    " / / / / /_/ /_/ /_/ /   |\n"
    "/_/ /_/\\__/\\__/ .___/_/|_|\n"
    "             /_/\n"
    "\n"
    "\t\tprojectdiscovery.io\n"
    "\n"
    "[\x1b[34mINF\x1b[0m] Current Version: v1.9.0"
)

# Real captured `dnsx -version` output.
_DNSX_VERSION_BANNER = (
    "      _             __  __\n"
    "   __| | _ __   ___ \\ \\/ /\n"
    "  / _' || '_ \\ / __| \\  / \n"
    " | (_| || | | |\\__ \\ /  \\ \n"
    "  \\__,_||_| |_||___//_/\\_\\\n"
    "\n"
    "\t\tprojectdiscovery.io\n"
    "\n"
    "[\x1b[34mINF\x1b[0m] Current Version: 1.2.3"
)

# Real captured `naabu -version` output.
_NAABU_VERSION_BANNER = (
    "\n"
    "                  __\n"
    "  ___  ___  ___ _/ /  __ __\n"
    " / _ \\/ _ \\/ _ \\/ _ \\/ // /\n"
    "/_//_/\\_,_/\\_,_/_.__/\\_,_/\n"
    "\n"
    "\t\tprojectdiscovery.io\n"
    "\n"
    "[\x1b[34mINF\x1b[0m] Current Version: 2.6.1"
)

# Real captured `katana -version` output.
_KATANA_VERSION_BANNER = (
    "   __        __                \n"
    "  / /_____ _/ /____ ____  ___ _\n"
    " /  '_/ _  / __/ _  / _ \\/ _  /\n"
    "/_/\\_\\\\_,_/\\__/\\_,_/_//_/\\_,_/\t\t\t\t\t\t\t \n"
    "\n"
    "\t\tprojectdiscovery.io\n"
    "\n"
    "[\x1b[34mINF\x1b[0m] Current version: v1.6.1"
)

# Real captured `amass -version` output (the clean alternative command).
_AMASS_DASH_VERSION = "v5.1.1"

# Real captured `jq --version` output.
_JQ_VERSION = "jq-1.7.1-apple"

# Real captured `nmap --version` (port_verify) first line.
_NMAP_VERSION_LINE = "Nmap version 7.97 ( https://nmap.org )"


class TestExtractVersionAgainstRealBannerOutput:
    def test_amass_multiline_banner_finds_the_real_version_not_ascii_art(self) -> None:
        assert _extract_version(_AMASS_VERSION_BANNER) == "5.1.1"

    def test_amass_clean_dash_version_flag(self) -> None:
        assert _extract_version(_AMASS_DASH_VERSION) == "5.1.1"

    def test_httpx_banner_finds_current_version_line(self) -> None:
        assert _extract_version(_HTTPX_VERSION_BANNER) == "1.9.0"

    def test_dnsx_banner_finds_current_version_line(self) -> None:
        assert _extract_version(_DNSX_VERSION_BANNER) == "1.2.3"

    def test_naabu_banner_finds_current_version_line(self) -> None:
        assert _extract_version(_NAABU_VERSION_BANNER) == "2.6.1"

    def test_katana_banner_finds_current_version_line(self) -> None:
        assert _extract_version(_KATANA_VERSION_BANNER) == "1.6.1"

    def test_jq_bare_version_with_word_prefix(self) -> None:
        assert _extract_version(_JQ_VERSION) == "jq-1.7.1-apple"

    def test_nmap_version_line(self) -> None:
        assert _extract_version(_NMAP_VERSION_LINE) == "7.97"

    def test_pure_ascii_art_with_no_real_version_returns_none_not_garbage(self) -> None:
        """The regression this whole file guards against: no real version
        anywhere in the input must return None, never a banner fragment
        that merely happens to contain a digit."""
        pure_banner = "\n".join(
            _AMASS_VERSION_BANNER.splitlines()[:11]
        )  # banner only, no "v5.1.1" line
        assert _extract_version(pure_banner) is None


class TestKnownIncompatibleVersions:
    def test_amass_v5_is_flagged(self) -> None:
        message = known_incompatible_version("amass", "5.1.1")
        assert message is not None
        assert "-o" in message
        assert "v4" in message

    def test_amass_v4_is_not_flagged(self) -> None:
        assert known_incompatible_version("amass", "4.2.0") is None

    def test_unversioned_tool_fails_open_not_closed(self) -> None:
        """No version string at all (detection failed) must never be
        treated as "known bad" — that would block a tool this table has
        no actual evidence about, the opposite of what a targeted
        allowlist of confirmed breakage should do."""
        assert known_incompatible_version("amass", None) is None

    def test_tool_with_no_registry_entry_is_never_flagged(self) -> None:
        assert known_incompatible_version("httpx", "99.0.0") is None

    def test_unparseable_version_string_fails_open(self) -> None:
        assert known_incompatible_version("amass", "not-a-version") is None

    def test_registry_entries_have_real_evidence_documented(self) -> None:
        """Guards against a future entry being added as a guess — every
        row must at least point at a real doc with the reproduction."""
        for _tool, (_major, message) in KNOWN_INCOMPATIBLE_VERSIONS.items():
            assert "docs/" in message, "every entry must cite where the incompatibility was proven"


class TestDependencyServiceSurfacesTheIncompatibilityBeforeAnyRun:
    """End-to-end: a known-incompatible version must make the tool
    not-runnable with a clear reason — not merely detectable in isolation."""

    @pytest.mark.asyncio
    async def test_amass_v5_marks_the_tool_not_runnable_with_a_clear_reason(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from core.dependencies.service import DependencyService
        from core.dependencies.validation import HealthValidator, _ProbeOutcome

        fake_amass = tmp_path / "amass"
        fake_amass.write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
        fake_amass.chmod(0o755)

        async def fake_run_probe(self, path, args):  # noqa: ANN001
            if args == ("-version",):
                return _ProbeOutcome(
                    success=True, label="amass -version", exit_code=0, output=_AMASS_DASH_VERSION
                )
            if args == ("--help",):
                return _ProbeOutcome(
                    success=True, label="amass --help", exit_code=0, output="usage: amass ..."
                )
            return _ProbeOutcome(success=False)

        monkeypatch.setattr(HealthValidator, "_run_probe", fake_run_probe)

        svc = DependencyService({"amass": fake_amass})
        reports = await svc.analyze_all()
        report = reports["amass"]

        assert report.version == "5.1.1"
        assert report.is_runnable is False
        assert "-o" in report.status_reason

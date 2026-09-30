"""Productization Phase 09: provider qualification — the explicit contract
between each external tool Hydra drives and the code that drives it.

The EASM final audit's open risk #11 was that a provider upgrade could
silently change behavior under Hydra's parsers. Every tool the container
image pins (Dockerfile) now has a profile stating:

- `qualified_versions`: the exact versions whose output format Hydra's
  parser was verified against (the Dockerfile pins). Anything else is
  `unverified_version`: allowed to run, but reported, never silently
  trusted as equivalent.
- `flags`: every command-line flag Hydra's plugin passes to the binary,
  each with the token that must appear in the binary's own help output.
  A test extracts the flag literals from the plugin source and requires
  them to match the profiles exactly, so a plugin can't start using a flag
  (or stop using one) without the profile changing too.
- `success_exit_codes`, and whether the tool reports its version at all.

`qualify()` turns an installed binary's detected version and `-h` output
into a status with concrete reasons. It runs in the Docker CI job against
the real pinned binaries (tests/test_provider_qualification.py): bumping a
pin in the Dockerfile without re-qualifying the profile fails CI there,
and a removed or renamed flag fails CI even when the version is qualified.
Confirmed-incompatible majors (core/dependencies/registry.py
KNOWN_INCOMPATIBLE_VERSIONS, e.g. amass v5) take precedence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from core.dependencies.models import ToolReport
from core.dependencies.registry import known_incompatible_version

QualificationStatus = Literal[
    "qualified",
    "unverified_version",
    "version_unknown",
    "missing_flags",
    "known_incompatible",
    "not_installed",
]


@dataclass(frozen=True)
class QualificationProfile:
    tool: str  # core/dependencies/registry.py name
    binary: str
    # Plugin modules (modules/<name>.py) that pass flags to this binary.
    modules: tuple[str, ...]
    qualified_versions: frozenset[str]
    # flag -> the token that must appear in the binary's help output.
    flags: dict[str, str]
    reports_version: bool = True
    success_exit_codes: frozenset[int] = field(default_factory=lambda: frozenset({0}))


def _same(*flags: str) -> dict[str, str]:
    return {flag: flag for flag in flags}


PROFILES: dict[str, QualificationProfile] = {
    profile.tool: profile
    for profile in (
        QualificationProfile(
            tool="subfinder",
            binary="subfinder",
            modules=("subfinder",),
            qualified_versions=frozenset({"2.16.0"}),
            flags=_same("-d", "-rate-limit", "-silent", "-t", "-timeout"),
        ),
        QualificationProfile(
            tool="dnsx",
            binary="dnsx",
            modules=("dnsx",),
            qualified_versions=frozenset({"1.3.1"}),
            flags=_same(
                "-a",
                "-aaaa",
                "-caa",
                "-cname",
                "-json",
                "-l",
                "-mx",
                "-ns",
                "-o",
                "-ptr",
                "-r",
                "-resp",
                "-retry",
                "-silent",
                "-soa",
                "-srv",
                "-t",
                "-txt",
            ),
        ),
        QualificationProfile(
            tool="httpx",
            binary="httpx",
            modules=("httpx",),
            qualified_versions=frozenset({"1.12.0"}),
            flags=_same(
                "-H",
                "-cname",
                "-content-length",
                "-disable-update-check",
                "-favicon",
                "-hash",
                "-include-response-header",
                "-ip",
                "-json",
                "-l",
                "-location",
                "-no-stdin",
                "-o",
                "-proxy",
                "-silent",
                "-status-code",
                "-t",
                "-tech-detect",
                "-timeout",
                "-title",
                "-tls-grab",
                "-tls-probe",
                "-u",
                "-web-server",
            ),
        ),
        QualificationProfile(
            tool="naabu",
            binary="naabu",
            modules=("naabu",),
            qualified_versions=frozenset({"2.6.1"}),
            flags=_same("-c", "-l", "-p", "-rate", "-silent"),
        ),
        QualificationProfile(
            tool="katana",
            binary="katana",
            modules=("katana",),
            qualified_versions=frozenset({"1.7.0"}),
            flags=_same("-H", "-c", "-jc", "-jsonl", "-list", "-o", "-proxy", "-silent"),
        ),
        QualificationProfile(
            tool="nuclei",
            binary="nuclei",
            modules=("nuclei",),
            qualified_versions=frozenset({"3.11.1"}),
            flags=_same(
                "-H", "-c", "-jsonl", "-l", "-ni", "-o", "-proxy", "-rate-limit", "-silent"
            ),
        ),
        QualificationProfile(
            tool="hakrawler",
            binary="hakrawler",
            modules=("hakrawler",),
            # hakrawler 2.1 has no version flag: its flag surface is what's verified.
            qualified_versions=frozenset({"2.1"}),
            reports_version=False,
            flags=_same("-d", "-h", "-insecure", "-proxy"),
        ),
        QualificationProfile(
            tool="port_verify",
            binary="nmap",
            modules=("port_verify", "naabu"),
            qualified_versions=frozenset({"7.95"}),
            flags={
                **_same("--host-timeout", "--max-retries", "--version-light", "-Pn", "-p", "-sV"),
                "-T1": "-T<0-5>",
            },
        ),
    )
}


@dataclass(frozen=True)
class Qualification:
    tool: str
    status: QualificationStatus
    version: str | None
    reasons: tuple[str, ...]


def normalize_version(version: str | None) -> str | None:
    return version.strip().lstrip("vV") if version else None


def lists_flag(help_text: str, token: str) -> bool:
    """Whether the help output lists `token` as a flag of its own — not as
    part of a longer one: `-d` must not match inside `--domain`, `-domain`
    or `-d2`. The token may not touch a letter, digit, `_` or `-` on either
    side; punctuation such as `,` `:` `=` `[` or a space may follow it."""
    return re.search(rf"(?<![\w-]){re.escape(token)}(?![\w-])", help_text) is not None


def qualify(tool: str, *, installed: bool, version: str | None, help_text: str) -> Qualification:
    """The qualification of one installed tool, from what the binary itself
    reports. Deterministic; every non-qualified status says why."""
    profile = PROFILES[tool]
    version = normalize_version(version)
    if not installed:
        return Qualification(tool, "not_installed", None, (f"{profile.binary} not found",))
    incompatible = known_incompatible_version(tool, version)
    if incompatible:
        return Qualification(tool, "known_incompatible", version, (incompatible,))
    missing = sorted(f for f, token in profile.flags.items() if not lists_flag(help_text, token))
    if missing:
        return Qualification(
            tool,
            "missing_flags",
            version,
            (f"{profile.binary} help no longer lists flag(s) Hydra passes: {', '.join(missing)}",),
        )
    if not profile.reports_version:
        return Qualification(
            tool,
            "qualified",
            version,
            (f"{profile.binary} doesn't report a version; its flag surface matches",),
        )
    if version is None:
        return Qualification(
            tool, "version_unknown", None, (f"{profile.binary} version could not be detected",)
        )
    if version not in profile.qualified_versions:
        return Qualification(
            tool,
            "unverified_version",
            version,
            (
                f"{profile.binary} {version} is not a qualified version "
                f"(qualified: {', '.join(sorted(profile.qualified_versions))}); parser output "
                "may differ",
            ),
        )
    return Qualification(tool, "qualified", version, (f"{profile.binary} {version} qualified",))


def qualify_report(tool: str, report: ToolReport | None) -> Qualification:
    """`qualify()` from the dependency report the service already built:
    its identity-verified binary, detected version, and the help output
    its health probe captured (`ValidationResult.probe_output`). No
    process of its own is started here."""
    runnable = report is not None and report.resolved_path is not None and report.is_runnable
    if report is None or not runnable:
        return qualify(tool, installed=False, version=None, help_text="")
    help_text = report.validation.probe_output if report.validation else ""
    return qualify(tool, installed=True, version=report.version, help_text=help_text)

"""Hydra CLI identity: ASCII banner and one-line plugin ("head") blurbs."""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console

HYDRA_WORDMARK = """\
    ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
    ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
    ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"""

HYDRA_ART = """\
              ╭─◉       ◉─╮
          ╭──┤            ├──╮
       ╭─◉    ╰─╮      ╭──╯    ◉─╮
      ╱          ╰────╯          ╲
     ◉                            ◉
      ╲__      ______________   __╱
         ╲____╱              ╲_╱"""

HYDRA_TAGLINE = "many heads. one hunt."

HYDRA_BANNER = f"{HYDRA_WORDMARK}\n\n{HYDRA_ART}\n              {HYDRA_TAGLINE}"

_COMMANDS = frozenset(
    {
        "run",
        "check-tools",
        "list-plugins",
        "heads",
        "validate-config",
        "check-opsec",
    }
)
_VALUE_FLAGS = frozenset({"-e", "--env"})

HEAD_BLURBS: dict[str, str] = {
    "whois": "domain attribution head",
    "asn_lookup": "network ownership (ASN) head",
    "ctlogs": "certificate-transparency discovery head",
    "subfinder": "passive subdomain enumeration head",
    "assetfinder": "related-hostname discovery head",
    "amass": "deep OSINT enumeration head",
    "anew": "new-entry tracking head",
    "wildcard_check": "wildcard-DNS canary head",
    "dnsx": "DNS resolution head",
    "naabu": "port-scan / tarpit-canary head",
    "port_verify": "service-verification (nmap) head",
    "httpx": "live HTTP probing head",
    "soft404_check": "soft-404 / catch-all detection head",
    "param_fuzz": "hidden-parameter discovery head",
    "cloud_bucket_enum": "cloud-bucket existence head",
    "threat_intel": "host-reputation (URLhaus) head",
    "gau": "archived-URL harvest head",
    "waybackurls": "Wayback Machine URL head",
    "katana": "active crawler head",
    "hakrawler": "lightweight crawler head",
    "unfurl": "URL-component extraction head",
    "nuclei": "template-based vuln scan head",
    "browser_probe": "browser cloaking-detection head",
    "vuln_match": "CVE correlation head",
    "security_headers": "HTTP security-header audit head",
}


def _argv(argv: list[str] | None) -> list[str]:
    return list(sys.argv[1:] if argv is None else argv)


def banner_suppressed(argv: list[str] | None = None) -> bool:
    """True when the operator asked to hide the startup banner."""
    env = os.environ.get("HYDRA_NO_BANNER", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        return True
    return "--no-banner" in _argv(argv)


def _first_command(argv: list[str]) -> str | None:
    i = 0
    while i < len(argv):
        token = argv[i]
        if token in _VALUE_FLAGS:
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        return token if token in _COMMANDS else None
    return None


def should_print_banner(argv: list[str] | None = None) -> bool:
    """Banner only for ``run``, top-level ``--help``, or no arguments."""
    args = _argv(argv)
    if banner_suppressed(args):
        return False
    if not args:
        return True
    command = _first_command(args)
    if "-h" in args or "--help" in args:
        return command is None or command == "run"
    return command == "run"


def print_banner(
    argv: list[str] | None = None,
    *,
    console: Console | None = None,
) -> None:
    """Print the colored Hydra banner, or nothing if suppressed / non-TTY."""
    if not should_print_banner(argv):
        return
    from rich.console import Console as RichConsole

    con = console or RichConsole()
    if not con.is_terminal:
        return
    con.print(HYDRA_WORDMARK, style="bold cyan", highlight=False)
    con.print()
    con.print(HYDRA_ART, style="magenta", highlight=False)
    con.print(f"              {HYDRA_TAGLINE}", style="dim", highlight=False)

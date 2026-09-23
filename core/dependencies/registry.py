"""Per-tool dependency registry — version probes, health checks, install methods, capabilities."""

from __future__ import annotations

from core.dependencies.models import ToolDefinition

TOOL_REGISTRY: dict[str, ToolDefinition] = {}


def _register(defn: ToolDefinition) -> ToolDefinition:
    TOOL_REGISTRY[defn.name] = defn
    return defn


# --- Mandatory ---
_register(
    ToolDefinition(
        name="subfinder",
        display_name="Subfinder",
        required=True,
        version_commands=(("-version",), ("--version",)),
        health_commands=(("-h",),),
        capabilities=frozenset({"subdomain_enumeration", "passive_dns"}),
        install_homebrew="subfinder",
        install_go="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    )
)

_register(
    ToolDefinition(
        name="dnsx",
        display_name="dnsx",
        required=True,
        version_commands=(("-version",), ("--version",)),
        health_commands=(("-h",),),
        capabilities=frozenset({"dns_resolution", "dns_records"}),
        install_homebrew="dnsx",
        install_go="github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    )
)

_register(
    ToolDefinition(
        name="httpx",
        display_name="httpx",
        required=True,
        version_commands=(("-version",), ("--version",)),
        health_commands=(("-h",),),
        capabilities=frozenset({"http_probing", "technology_detection", "tls_fingerprint"}),
        install_homebrew="httpx",
        install_go="github.com/projectdiscovery/httpx/cmd/httpx@latest",
        path_denylist=("Python.framework", "site-packages", "/venv/", "/.venv/"),
        identity_markers=("projectdiscovery", "__    __  __", "multi-purpose HTTP"),
    )
)

# --- Optional recon tools ---
_register(
    ToolDefinition(
        name="assetfinder",
        display_name="Assetfinder",
        health_commands=(("-h",), ("--help",)),
        capabilities=frozenset({"subdomain_enumeration"}),
        install_go="github.com/tomnomnom/assetfinder@latest",
        allow_smoke_test=True,
    )
)

_register(
    ToolDefinition(
        name="amass",
        display_name="amass",
        # `-version` first: confirmed live it prints a single clean
        # "v5.1.1" line, while the `version` subcommand prints a
        # multi-line ASCII banner with no parseable version in it at all
        # (hardening round 2, Task 1) — trying the noisy command first
        # used to make version detection silently report banner art.
        version_commands=(("-version",), ("version",)),
        health_commands=(("--help",), ("-h",)),
        capabilities=frozenset({"subdomain_enumeration", "passive_dns", "active_enumeration"}),
        install_homebrew="amass",
        # No versioned "amass@4" Homebrew formula exists (confirmed via
        # `brew search amass`) — Homebrew's one "amass" formula tracks
        # upstream latest (v5.x as of this writing), so `install_homebrew`
        # above is only ever a starting point; `go install` pinned to this
        # exact tag is the only reliable way to get v4. v4 is a deliberate,
        # investigated choice, not a stopgap waiting on a v5 rewrite: v5
        # replaced the single-process `enum -o <file>` model this plugin
        # depends on with a client/server architecture (`amass engine` +
        # `amass enum` as a client + a separate `amass subs` query step
        # against a graph database) — confirmed by direct testing,
        # including a real run that returned zero results even with a
        # 2-minute timeout. See docs/FINAL_PROJECT_AUDIT.md /
        # docs/HARDENING_ROUND2_P1.md (the detection gate) and
        # modules/amass.py's own docstring (the v4 pin + real output-format
        # parser fix) for the full history.
        install_go="github.com/owasp-amass/amass/v4/...@v4.2.0",
    )
)

_register(
    ToolDefinition(
        name="naabu",
        display_name="naabu",
        version_commands=(("-version",), ("--version",)),
        health_commands=(("-h",),),
        capabilities=frozenset({"port_scanning"}),
        install_homebrew="naabu",
        install_go="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    )
)

_register(
    ToolDefinition(
        name="katana",
        display_name="katana",
        version_commands=(("-version",), ("--version",)),
        health_commands=(("-h",),),
        capabilities=frozenset({"web_crawling", "javascript_crawling"}),
        install_homebrew="katana",
        install_go="github.com/projectdiscovery/katana/cmd/katana@latest",
    )
)

_register(
    ToolDefinition(
        name="nuclei",
        display_name="nuclei",
        version_commands=(("-version",), ("--version",)),
        health_commands=(("-h",),),
        capabilities=frozenset({"vulnerability_scanning", "template_scanning"}),
        install_homebrew="nuclei",
        install_go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    )
)

_register(
    ToolDefinition(
        name="gau",
        display_name="gau",
        health_commands=(("--help",), ("-h",)),
        capabilities=frozenset({"url_discovery", "archive_search"}),
        install_homebrew="gau",
        install_go="github.com/lc/gau/v2/cmd/gau@latest",
    )
)

_register(
    ToolDefinition(
        name="waybackurls",
        display_name="waybackurls",
        health_commands=(),  # no flags — smoke test only
        capabilities=frozenset({"url_discovery", "wayback_archive"}),
        install_go="github.com/tomnomnom/waybackurls@latest",
        allow_smoke_test=True,
    )
)

_register(
    ToolDefinition(
        name="hakrawler",
        display_name="hakrawler",
        health_commands=(("-h",),),
        capabilities=frozenset({"web_crawling"}),
        install_go="github.com/hakluke/hakrawler@latest",
        allow_smoke_test=True,
    )
)

_register(
    ToolDefinition(
        name="anew",
        display_name="anew",
        health_commands=(),
        capabilities=frozenset({"deduplication"}),
        install_go="github.com/tomnomnom/anew@latest",
        allow_smoke_test=True,
    )
)

_register(
    ToolDefinition(
        name="unfurl",
        display_name="unfurl",
        health_commands=(("-h",),),
        capabilities=frozenset({"url_parsing"}),
        install_go="github.com/tomnomnom/unfurl@latest",
        allow_smoke_test=True,
    )
)

_register(
    ToolDefinition(
        name="jq",
        display_name="jq",
        version_commands=(("--version",),),
        health_commands=(("--help",),),
        capabilities=frozenset({"json_processing"}),
        install_homebrew="jq",
        install_apt="jq",
    )
)

_register(
    ToolDefinition(
        name="whois",
        display_name="WHOIS",
        health_commands=(("-h",), ("--help",)),
        capabilities=frozenset({"domain_registration", "registrar_lookup"}),
        install_homebrew="whois",
        install_apt="whois",
        allow_smoke_test=True,
    )
)

_register(
    ToolDefinition(
        name="port_verify",
        display_name="Port Verification (nmap)",
        binary_name="nmap",
        version_commands=(("--version",),),
        health_commands=(("--help",), ("-h",)),
        capabilities=frozenset({"port_verification", "service_detection", "banner_grabbing"}),
        install_homebrew="nmap",
        install_apt="nmap",
    )
)

_register(
    ToolDefinition(
        name="sslyze",
        display_name="sslyze",
        version_commands=(("--version",),),
        health_commands=(("--help",),),
        capabilities=frozenset({"tls_posture", "certificate_analysis"}),
        install_pip="sslyze",
    )
)

_register(
    ToolDefinition(
        name="wafw00f",
        display_name="wafw00f",
        version_commands=(("-V",), ("--version",)),
        health_commands=(("--help",),),
        capabilities=frozenset({"waf_detection"}),
        install_pip="wafw00f",
    )
)

_register(
    ToolDefinition(
        name="theharvester",
        display_name="theHarvester",
        health_commands=(("--help",), ("-h",)),
        capabilities=frozenset({"email_personnel_osint"}),
        # Genuinely none of HOMEBREW/APT/GO/PIP fit — theHarvester
        # requires Python >=3.14, managed by `uv`, cloned from source
        # (confirmed directly, not assumed: it is NOT published on
        # PyPI). See modules/theharvester.py's own docstring and
        # docs/DOCKER.md for the real, tested setup.
        install_manual=(
            "git clone https://github.com/laramies/theHarvester.git && "
            "cd theHarvester && uv sync  (requires Python 3.14, managed by uv — "
            "see docs/DOCKER.md)"
        ),
        allow_smoke_test=True,
    )
)

_register(
    ToolDefinition(
        name="dnstwist",
        display_name="dnstwist",
        version_commands=(("--version",),),
        health_commands=(("--help",),),
        capabilities=frozenset({"typosquat_detection"}),
        install_homebrew="dnstwist",
        install_pip="dnstwist",
    )
)


def get_tool_definition(name: str) -> ToolDefinition:
    """Return registry entry or synthesize a minimal definition."""
    if name in TOOL_REGISTRY:
        return TOOL_REGISTRY[name]
    return ToolDefinition(name=name, display_name=name)


def _major_version(version: str) -> int | None:
    """Parse a leading major version number out of a detected version
    string ("5.1.1" / "v5.1.1" -> 5). Returns None if unparseable — never
    guessed, since a known-incompatible check must fail open (treat as
    unknown/compatible) rather than closed on a string it can't read, or
    every tool with a version format this doesn't recognize would be
    wrongly flagged."""
    stripped = version.lstrip("vV")
    head = stripped.split(".", 1)[0]
    return int(head) if head.isdigit() else None


# Hardening round 2, Task 1: known, *confirmed* hard incompatibilities
# between a specific tool's major version and the plugin code that drives
# it — not a general "minimum version" table (most tools here have no
# such constraint; newer is normally fine). Each entry is
# {tool_name: (min_incompatible_major, message)}. Checked once real
# version detection succeeds (core/dependencies/service.py); deliberately
# small and explicit rather than a generic semver-range system, since
# amass is the only entry with real, reproduced evidence behind it today
# (docs/FINAL_PROJECT_AUDIT.md, docs/HARDENING_ROUND1_P0.md) — add another
# row only with the same kind of direct reproduction, not a guess.
KNOWN_INCOMPATIBLE_VERSIONS: dict[str, tuple[int, str]] = {
    "amass": (
        5,
        "amass v5 replaced the single-process enum model modules/amass.py "
        "depends on with a client/server architecture (every invocation "
        'fails: "flag provided but not defined: -o"), and this is not a '
        "planned future rewrite — investigated and rejected as a "
        "disproportionate integration for this plugin (see "
        "modules/amass.py's docstring). Install v4 instead (go install "
        "github.com/owasp-amass/amass/v4/...@v4.2.0; there is no "
        "versioned amass@4 Homebrew formula), or leave ENABLE_AMASS=false. "
        "See docs/FINAL_PROJECT_AUDIT.md.",
    ),
}


def known_incompatible_version(name: str, version: str | None) -> str | None:
    """Return a clear, actionable message if `version` is a confirmed-bad
    major version for tool `name`, else None. Fails open on anything it
    can't confidently classify (no entry, no version string, unparseable
    version) — this is a targeted allowlist of confirmed breakage, not a
    general gate that could wrongly block a tool this table has no
    evidence about."""
    entry = KNOWN_INCOMPATIBLE_VERSIONS.get(name)
    if not entry or not version:
        return None
    min_bad_major, message = entry
    major = _major_version(version)
    if major is not None and major >= min_bad_major:
        return message
    return None


def install_hint_for(defn: ToolDefinition, *, is_macos: bool, is_linux: bool) -> str:
    """Build platform-appropriate install hint."""
    if is_macos and defn.install_homebrew:
        return f"brew install {defn.install_homebrew}"
    if is_linux and defn.install_apt:
        return f"sudo apt install {defn.install_apt}"
    if defn.install_go:
        return f"go install -v {defn.install_go}"
    if defn.install_homebrew:
        return f"brew install {defn.install_homebrew}"
    if defn.install_apt:
        return f"sudo apt install {defn.install_apt}"
    if defn.install_pip:
        return f"pip install {defn.install_pip}"
    if defn.install_manual:
        return defn.install_manual
    return "See tool documentation for installation"

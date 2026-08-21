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
        version_commands=(("version",), ("-version",)),
        health_commands=(("--help",), ("-h",)),
        capabilities=frozenset({"subdomain_enumeration", "passive_dns", "active_enumeration"}),
        install_homebrew="amass",
        install_go="github.com/owasp-amass/amass/v4/...@master",
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


def get_tool_definition(name: str) -> ToolDefinition:
    """Return registry entry or synthesize a minimal definition."""
    if name in TOOL_REGISTRY:
        return TOOL_REGISTRY[name]
    return ToolDefinition(name=name, display_name=name)


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
    return "See tool documentation for installation"

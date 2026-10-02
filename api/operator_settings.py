"""Productization Phase 11f: which of the operator's pipeline settings API
scans use.

Until now, `api/tenancy.py::account_settings` built every API scan's
`Settings` from defaults alone, never the operator's `.env`. That kept
tenants isolated, but it also dropped the operator's safety and
infrastructure settings: a lowered `RATE_LIMIT`, an `OUTBOUND_PROXY_URL`,
a tool installed at a custom path.

Every `Settings` field is classified below (a test fails on an
unclassified one):

- `INHERITED`: operator infrastructure and safety. Tool binary paths,
  shared data files, egress, and every timeout, rate limit, concurrency
  and size cap. API scans use the operator's values.
- `ACCOUNT_ONLY`: never taken from the operator:
  - the account's own directories;
  - scope (`SCOPE_FILE`, `OWNED_DOMAINS`, exclusions: an API scan's scope
    is its verified domains);
  - modes for targets the operator doesn't own;
  - CLI-only output and notification settings;
  - the operator's **personal bug-bounty identity** (researcher headers,
    program names), which must never reach a customer's targets;
  - **third-party credentials and LLM settings** (decision 2026-10-01: the
    operator's data-source keys are never shared with tenants; LLM keys
    are handled separately, with per-account spend limits).
- `TOGGLES` (`ENABLE_*`, `NUCLEI_ENABLE_INTERACTSH`): **the operator can
  only switch a tool off** (decision 2026-10-01). An `ENABLE_X` explicitly
  set to false in the operator environment turns X off for every API
  scan. Nothing the operator sets turns on a tool the scan's profile and
  tier didn't select.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

from config.settings import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
# The operator's .env (the same file the CLI reads); tests point it at an
# empty file so a developer's own .env never leaks in.
_ENV_FILE = _PROJECT_ROOT / ".env"

INHERITED: frozenset[str] = frozenset(
    {
        # Tool binaries.
        "subfinder_path",
        "dnsx_path",
        "httpx_path",
        "naabu_path",
        "katana_path",
        "hakrawler_path",
        "gau_path",
        "waybackurls_path",
        "nuclei_path",
        "assetfinder_path",
        "unfurl_path",
        "amass_path",
        "anew_path",
        "jq_path",
        "nmap_path",
        "theharvester_path",
        "sslyze_path",
        "wafw00f_path",
        "whatweb_path",
        "ffuf_path",
        "dnstwist_path",
        "gitleaks_path",
        # Shared data files and egress.
        "resolvers_file",
        "wordlist",
        "ffuf_wordlist_path",
        "geoip_db_path",
        "outbound_proxy_url",
        "user_agent",
        "strict_opsec",
        # Global rate, concurrency and timeouts.
        "timeout",
        "threads",
        "rate_limit",
        "httpx_threads",
        "httpx_max_redirect_hops",
        "cache_ttl_seconds",
        "asn_lookup_timeout",
        "ctlogs_timeout",
        "ctlogs_delay_seconds",
        "port_verify_timeout",
        "port_verify_max_hosts",
        "port_verify_max_ports_per_host",
        "port_verify_concurrency",
        "naabu_confirm_open_ports",
        "naabu_confirm_delay_seconds",
        "naabu_tarpit_check",
        "naabu_tarpit_canary_count",
        "naabu_tarpit_open_threshold",
        "naabu_tarpit_timeout",
        "whois_timeout",
        "whois_retries",
        "whois_retry_delay_seconds",
        "threat_intel_timeout",
        "threat_intel_concurrency",
        "passive_dns_timeout",
        "passive_dns_delay_seconds",
        "passive_dns_max_candidates",
        "browser_probe_timeout",
        "browser_probe_max_hosts",
        "wildcard_canary_count",
        "soft404_timeout",
        "soft404_max_hosts",
        "soft404_concurrency",
        "param_fuzz_timeout",
        "param_fuzz_max_urls_per_host",
        "param_fuzz_delay_ms",
        "param_fuzz_body_delta_pct",
        "cloud_bucket_enum_timeout",
        "cloud_bucket_enum_delay_ms",
        "sub_takeover_timeout",
        "whatweb_timeout",
        "whatweb_threads",
        "whatweb_max_urls",
        "theharvester_timeout",
        "sslyze_timeout",
        "wafw00f_timeout",
        "ffuf_timeout",
        "ffuf_extensions",
        "ffuf_rate_limit",
        "ffuf_threads",
        "ffuf_max_time_per_host",
        "ffuf_max_hosts",
        "dnstwist_timeout",
        "dnstwist_threads",
        "dnstwist_fresh_registration_days",
        "gitleaks_timeout",
        "github_secrets_clone_depth",
        "github_secrets_max_repos",
        "github_secrets_include_forks",
        "vuln_match_timeout",
        # Size and budget caps.
        "max_discovery_depth",
        "max_followup_indicators",
        "max_domains_per_source",
        "max_collection_budget",
        "max_http_probes",
        "max_dns_probes",
        "max_runtime_seconds",
        "max_entities",
        "max_relationships",
        "max_ct_names_per_certificate",
        "max_certificates",
        "max_ips",
        "max_url_entities",
        "max_technology_entities",
        "max_followups_per_relationship",
        "max_relationships_per_signal",
    }
)

ACCOUNT_ONLY: frozenset[str] = frozenset(
    {
        # The account's own directories and CLI presentation.
        "project_root",
        "output_directory",
        "logs_directory",
        "reports_directory",
        "log_level",
        "default_output_format",
        "webhook_url",
        # Scope: an API scan's scope is its verified domains and exclusions.
        "scope_file",
        "scope_exclusions",
        "owned_domains",
        "external_target_mode",
        "cloud_bucket_enum_authorize_derived",
        "github_org",
        # The operator's personal bug-bounty identity.
        "custom_http_headers",
        "x_hackerone_researcher",
        "researcher_attribution_header",
        "attribution_user_agent",
        "program_name",
        "program_platform",
        # Third-party credentials and LLM configuration.
        "github_token",
        "wpscan_api_token",
        "urlhaus_api_key",
        "securitytrails_api_key",
        "anthropic_api_key",
        "anthropic_model",
        "openai_api_key",
        "openai_model",
        "reportability_provider",
        "reportability_adversarial_provider",
        "reportability_max_findings_per_batch",
        "hypothesis_provider",
        "hypothesis_adversarial_provider",
        "hypothesis_max_relationships_per_batch",
    }
)

# Switches the operator may only turn off: `enable_*` plus interactsh.
TOGGLES: frozenset[str] = frozenset(
    {f.name for f in dataclasses.fields(Settings) if f.name.startswith("enable_")}
    | {"nuclei_enable_interactsh"}
)


def operator_settings() -> Settings:
    """The operator's pipeline settings: the repo `.env` and the process
    environment, parsed and validated the way the CLI does."""
    return Settings.from_env(env_file=_ENV_FILE, project_root=_PROJECT_ROOT)


def _explicitly_off(toggle: str) -> bool:
    raw = os.getenv(toggle.upper())
    return raw is not None and raw.strip().lower() in {"0", "false", "no", "off"}


def operator_disabled_toggles() -> frozenset[str]:
    """Toggles the operator environment explicitly sets to false."""
    return frozenset(toggle for toggle in TOGGLES if _explicitly_off(toggle))


def inherit_operator_settings(settings: Settings, operator: Settings) -> None:
    """Copies the operator's infrastructure and safety values (INHERITED)."""
    for name in INHERITED:
        setattr(settings, name, getattr(operator, name))


def apply_operator_disables(settings: Settings) -> frozenset[str]:
    """Switches off what the operator switched off; returns those toggles.
    Applied last, after the scan's own profile and tier selection."""
    disabled = operator_disabled_toggles()
    for toggle in disabled:
        setattr(settings, toggle, False)
    return disabled

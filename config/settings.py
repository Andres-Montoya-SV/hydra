"""Application configuration loaded from environment variables."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv

from core.exceptions import ConfigurationError
from utils.security import (
    validate_binary_path,
    validate_header_name,
    validate_header_value,
    validate_log_level,
    validate_positive_int,
    validate_readable_file,
)

_VALID_OUTPUT_FORMATS = frozenset({"json", "csv", "txt"})
_BOOL_TRUE = frozenset({"1", "true", "yes", "on"})
_BOOL_FALSE = frozenset({"0", "false", "no", "off", ""})


def _bool(value: str | None, default: bool = False) -> bool:
    """Parse a boolean environment variable.

    Raises:
        ConfigurationError: If value is not a recognized boolean.
    """
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _BOOL_TRUE:
        return True
    if normalized in _BOOL_FALSE:
        return False
    raise ConfigurationError(
        f"Invalid boolean value: {value!r}. Use true/false, yes/no, 1/0, on/off."
    )


def _int(value: str | None, default: int, name: str, *, maximum: int = 10_000) -> int:
    """Parse a bounded positive integer environment variable.

    Raises:
        ConfigurationError: If value is not a valid integer.
    """
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value.strip())
    except ValueError as exc:
        raise ConfigurationError(f"Invalid integer for {name}: {value!r}") from exc
    return validate_positive_int(parsed, name, maximum=maximum)


def _parse_headers(raw: str | None) -> dict[str, str]:
    """Parse custom HTTP headers from env string.

    Supports JSON object or comma-separated 'Header: value' pairs.

    Raises:
        ConfigurationError: On malformed JSON or invalid header names/values.
    """
    if not raw or not raw.strip():
        return {}

    raw = raw.strip()
    headers: dict[str, str] = {}

    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"Invalid JSON in HTTP_CUSTOM_HEADERS: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ConfigurationError("HTTP_CUSTOM_HEADERS JSON must be an object")
        for key, value in parsed.items():
            name = validate_header_name(str(key))
            headers[name] = validate_header_value(str(value))
        return headers

    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ConfigurationError(f"Invalid header format (expected 'Name: value'): {part!r}")
        key, _, value = part.partition(":")
        name = validate_header_name(key)
        headers[name] = validate_header_value(value)

    return headers


def _safe_path(value: str, default: str) -> Path:
    """Parse a path env var, rejecting null bytes."""
    raw = value.strip() if value else default
    if "\x00" in raw:
        raise ConfigurationError("Path values must not contain null bytes")
    return Path(raw)


@dataclass
class Settings:
    """Central configuration for the reconnaissance framework."""

    project_root: Path = field(default_factory=Path.cwd)

    # Paths
    output_directory: Path = field(default_factory=lambda: Path("output"))
    logs_directory: Path = field(default_factory=lambda: Path("logs"))
    reports_directory: Path = field(default_factory=lambda: Path("reports"))
    resolvers_file: Path | None = None
    wordlist: Path | None = None

    # Tool binaries
    subfinder_path: Path = field(default_factory=lambda: Path("subfinder"))
    dnsx_path: Path = field(default_factory=lambda: Path("dnsx"))
    httpx_path: Path = field(default_factory=lambda: Path("httpx"))
    naabu_path: Path = field(default_factory=lambda: Path("naabu"))
    katana_path: Path = field(default_factory=lambda: Path("katana"))
    hakrawler_path: Path = field(default_factory=lambda: Path("hakrawler"))
    gau_path: Path = field(default_factory=lambda: Path("gau"))
    waybackurls_path: Path = field(default_factory=lambda: Path("waybackurls"))
    nuclei_path: Path = field(default_factory=lambda: Path("nuclei"))
    assetfinder_path: Path = field(default_factory=lambda: Path("assetfinder"))
    unfurl_path: Path = field(default_factory=lambda: Path("unfurl"))
    amass_path: Path = field(default_factory=lambda: Path("amass"))
    anew_path: Path = field(default_factory=lambda: Path("anew"))
    jq_path: Path = field(default_factory=lambda: Path("jq"))
    whois_path: Path = field(default_factory=lambda: Path("whois"))
    nmap_path: Path = field(default_factory=lambda: Path("nmap"))

    # Execution
    timeout: int = 300
    threads: int = 50
    rate_limit: int = 150
    httpx_threads: int = 50
    user_agent: str = "hydra/1.0"
    log_level: str = "INFO"
    default_output_format: str = "json"
    enable_cache: bool = True
    cache_ttl_seconds: int = 86400
    # Covers TCP WHOIS attempt (may idle ~5s on broken :43 paths) + DNS fallback.
    asn_lookup_timeout: int = 20
    ctlogs_timeout: int = 15
    ctlogs_delay_seconds: int = 2
    port_verify_timeout: int = 120
    port_verify_max_hosts: int = 50
    port_verify_max_ports_per_host: int = 100
    port_verify_concurrency: int = 4
    # Some shared-hosting/anti-scan middleboxes complete TCP handshakes for
    # an essentially random sample of probed ports on any single scan pass,
    # producing a different noisy "open" set every run against the SAME,
    # unchanged target. Re-probing just the ports naabu found open a second
    # time (after a short delay) and keeping only the intersection filters
    # this out before it ever reaches nmap/port_verify.
    naabu_confirm_open_ports: bool = True
    naabu_confirm_delay_seconds: int = 5
    # Some shared-hosting anti-recon defenses (tarpit/portspoof) fabricate
    # "open" TCP handshakes for EVERY port, not just a noisy subset — the
    # confirmation pass above cannot catch this since the same fake ports
    # reproduce consistently. Before trusting any naabu result for a host,
    # probe a handful of high, arbitrary ports with no standard/real-world
    # service association; if enough of them come back "open", nothing that
    # tool reports about that host's ports can be trusted.
    naabu_tarpit_check: bool = True
    naabu_tarpit_canary_count: int = 4
    naabu_tarpit_open_threshold: int = 2
    # Canary probes use nmap -sV (same technique that confirmed the DreamHost
    # tarpit manually). Shared-hosting tarpits respond slowly — the user's
    # manual 4-port -sV pass took ~165s — so the patient pass must be allowed
    # to run that long (host-timeout 5m + -T1 retries). A fast first pass
    # avoids paying this cost on ordinary hosts.
    naabu_tarpit_timeout: int = 360
    # WHOIS is a single registry query — do not inherit the global 300s tool
    # timeout. Short per-attempt timeout + a couple of backoff retries handles
    # temporary throttling without hanging the pipeline for five minutes.
    whois_timeout: int = 25
    whois_retries: int = 2
    whois_retry_delay_seconds: int = 5
    threat_intel_timeout: int = 15
    threat_intel_concurrency: int = 4
    browser_probe_timeout: int = 15
    browser_probe_max_hosts: int = 20
    # Before trusting passively enumerated subdomains, resolve 2-3 random
    # improbable canary names under each root. If any resolve, the zone has
    # wildcard DNS and passive discoveries need independent confirmation.
    wildcard_canary_count: int = 3
    # Before trusting HTTP 200 as "URL exists", probe a random nonexistent
    # path and compare body hash/size against the site root.
    soft404_timeout: int = 10
    soft404_max_hosts: int = 50
    soft404_concurrency: int = 8
    # Active parameter discovery (opt-in). Conservative defaults.
    param_fuzz_timeout: int = 10
    param_fuzz_max_urls_per_host: int = 5
    param_fuzz_delay_ms: int = 200
    param_fuzz_body_delta_pct: int = 5
    # Active cloud bucket enumeration (opt-in).
    cloud_bucket_enum_timeout: int = 10
    cloud_bucket_enum_delay_ms: int = 150
    strict_opsec: bool = False
    outbound_proxy_url: str | None = None

    # Feature flags
    enable_amass: bool = False
    enable_naabu: bool = False
    enable_katana: bool = False
    enable_hakrawler: bool = False
    enable_gau: bool = False
    enable_waybackurls: bool = False
    enable_nuclei: bool = False
    enable_assetfinder: bool = False
    enable_unfurl: bool = False
    enable_anew: bool = False
    enable_jq: bool = False
    enable_whois: bool = True
    enable_asn_lookup: bool = True
    enable_ctlogs: bool = True
    enable_port_verify: bool = True
    enable_threat_intel: bool = False
    enable_browser_probe: bool = False
    enable_wildcard_check: bool = True
    enable_soft404_check: bool = True
    enable_param_fuzz: bool = False
    enable_cloud_bucket_enum: bool = False
    enable_vuln_match: bool = True
    enable_security_headers: bool = True
    vuln_match_timeout: int = 15
    wpscan_api_token: str | None = None
    scope_file: Path | None = None
    webhook_url: str | None = None

    # Optional API credentials (never included in to_safe_dict)
    urlhaus_api_key: str | None = None

    # Bug bounty headers (stored separately; never logged)
    custom_http_headers: dict[str, str] = field(default_factory=dict)
    x_hackerone_researcher: str | None = None

    # Program metadata (optional, for reports only)
    program_name: str = ""
    program_platform: str = ""

    @classmethod
    def from_env(cls, env_file: Path | None = None, project_root: Path | None = None) -> Settings:
        """Load settings from .env file and environment variables.

        Args:
            env_file: Explicit .env path.
            project_root: Project root for relative path resolution.

        Returns:
            Parsed Settings instance (call validate() before use).
        """
        root = project_root or Path.cwd()

        if env_file and env_file.exists():
            load_dotenv(env_file, override=False)
        else:
            for candidate in (root / ".env", root / "config" / ".env"):
                if candidate.exists():
                    load_dotenv(candidate, override=False)
                    break

        resolvers = os.getenv("RESOLVERS_FILE", "").strip()
        wordlist = os.getenv("WORDLIST", "").strip()

        settings = cls(
            project_root=root,
            output_directory=_safe_path(os.getenv("OUTPUT_DIRECTORY", ""), "output"),
            logs_directory=_safe_path(os.getenv("LOGS_DIRECTORY", ""), "logs"),
            reports_directory=_safe_path(os.getenv("REPORTS_DIRECTORY", ""), "reports"),
            resolvers_file=Path(resolvers) if resolvers else None,
            wordlist=Path(wordlist) if wordlist else None,
            subfinder_path=_safe_path(os.getenv("SUBFINDER_PATH", ""), "subfinder"),
            dnsx_path=_safe_path(os.getenv("DNSX_PATH", ""), "dnsx"),
            httpx_path=_safe_path(os.getenv("HTTPX_PATH", ""), "httpx"),
            naabu_path=_safe_path(os.getenv("NAABU_PATH", ""), "naabu"),
            katana_path=_safe_path(os.getenv("KATANA_PATH", ""), "katana"),
            hakrawler_path=_safe_path(os.getenv("HAKRAWLER_PATH", ""), "hakrawler"),
            gau_path=_safe_path(os.getenv("GAU_PATH", ""), "gau"),
            waybackurls_path=_safe_path(os.getenv("WAYBACKURLS_PATH", ""), "waybackurls"),
            nuclei_path=_safe_path(os.getenv("NUCLEI_PATH", ""), "nuclei"),
            assetfinder_path=_safe_path(os.getenv("ASSETFINDER_PATH", ""), "assetfinder"),
            unfurl_path=_safe_path(os.getenv("UNFURL_PATH", ""), "unfurl"),
            amass_path=_safe_path(os.getenv("AMASS_PATH", ""), "amass"),
            anew_path=_safe_path(os.getenv("ANEW_PATH", ""), "anew"),
            jq_path=_safe_path(os.getenv("JQ_PATH", ""), "jq"),
            whois_path=_safe_path(os.getenv("WHOIS_PATH", ""), "whois"),
            nmap_path=_safe_path(os.getenv("NMAP_PATH", ""), "nmap"),
            timeout=_int(os.getenv("TIMEOUT"), 300, "TIMEOUT"),
            threads=_int(os.getenv("THREADS"), 50, "THREADS"),
            rate_limit=_int(os.getenv("RATE_LIMIT"), 150, "RATE_LIMIT"),
            httpx_threads=_int(os.getenv("HTTPX_THREADS"), 50, "HTTPX_THREADS"),
            user_agent=_validate_user_agent(os.getenv("USER_AGENT", "hydra/1.0")),
            log_level=validate_log_level(os.getenv("LOG_LEVEL", "INFO")),
            default_output_format=os.getenv("DEFAULT_OUTPUT_FORMAT", "json").strip().lower(),
            enable_cache=_bool(os.getenv("ENABLE_CACHE"), True),
            cache_ttl_seconds=_int(
                os.getenv("CACHE_TTL_SECONDS"), 86400, "CACHE_TTL_SECONDS", maximum=604_800
            ),
            asn_lookup_timeout=_int(os.getenv("ASN_LOOKUP_TIMEOUT"), 20, "ASN_LOOKUP_TIMEOUT"),
            ctlogs_timeout=_int(os.getenv("CTLOGS_TIMEOUT"), 15, "CTLOGS_TIMEOUT"),
            ctlogs_delay_seconds=_int(os.getenv("CTLOGS_DELAY_SECONDS"), 2, "CTLOGS_DELAY_SECONDS"),
            port_verify_timeout=_int(os.getenv("PORT_VERIFY_TIMEOUT"), 120, "PORT_VERIFY_TIMEOUT"),
            port_verify_max_hosts=_int(
                os.getenv("PORT_VERIFY_MAX_HOSTS"), 50, "PORT_VERIFY_MAX_HOSTS"
            ),
            port_verify_max_ports_per_host=_int(
                os.getenv("PORT_VERIFY_MAX_PORTS_PER_HOST"),
                100,
                "PORT_VERIFY_MAX_PORTS_PER_HOST",
            ),
            port_verify_concurrency=_int(
                os.getenv("PORT_VERIFY_CONCURRENCY"), 4, "PORT_VERIFY_CONCURRENCY"
            ),
            naabu_confirm_open_ports=_bool(os.getenv("NAABU_CONFIRM_OPEN_PORTS"), True),
            naabu_confirm_delay_seconds=_int(
                os.getenv("NAABU_CONFIRM_DELAY_SECONDS"),
                5,
                "NAABU_CONFIRM_DELAY_SECONDS",
                maximum=300,
            ),
            naabu_tarpit_check=_bool(os.getenv("NAABU_TARPIT_CHECK"), True),
            naabu_tarpit_canary_count=_int(
                os.getenv("NAABU_TARPIT_CANARY_COUNT"), 4, "NAABU_TARPIT_CANARY_COUNT", maximum=20
            ),
            naabu_tarpit_open_threshold=_int(
                os.getenv("NAABU_TARPIT_OPEN_THRESHOLD"),
                2,
                "NAABU_TARPIT_OPEN_THRESHOLD",
                maximum=20,
            ),
            naabu_tarpit_timeout=_int(
                os.getenv("NAABU_TARPIT_TIMEOUT"), 360, "NAABU_TARPIT_TIMEOUT", maximum=900
            ),
            whois_timeout=_int(os.getenv("WHOIS_TIMEOUT"), 25, "WHOIS_TIMEOUT", maximum=120),
            whois_retries=_int(os.getenv("WHOIS_RETRIES"), 2, "WHOIS_RETRIES", maximum=5),
            whois_retry_delay_seconds=_int(
                os.getenv("WHOIS_RETRY_DELAY_SECONDS"),
                5,
                "WHOIS_RETRY_DELAY_SECONDS",
                maximum=60,
            ),
            threat_intel_timeout=_int(
                os.getenv("THREAT_INTEL_TIMEOUT"), 15, "THREAT_INTEL_TIMEOUT"
            ),
            threat_intel_concurrency=_int(
                os.getenv("THREAT_INTEL_CONCURRENCY"), 4, "THREAT_INTEL_CONCURRENCY"
            ),
            browser_probe_timeout=_int(
                os.getenv("BROWSER_PROBE_TIMEOUT"), 15, "BROWSER_PROBE_TIMEOUT"
            ),
            browser_probe_max_hosts=_int(
                os.getenv("BROWSER_PROBE_MAX_HOSTS"), 20, "BROWSER_PROBE_MAX_HOSTS"
            ),
            wildcard_canary_count=_int(
                os.getenv("WILDCARD_CANARY_COUNT"), 3, "WILDCARD_CANARY_COUNT", maximum=10
            ),
            soft404_timeout=_int(os.getenv("SOFT404_TIMEOUT"), 10, "SOFT404_TIMEOUT"),
            soft404_max_hosts=_int(os.getenv("SOFT404_MAX_HOSTS"), 50, "SOFT404_MAX_HOSTS"),
            soft404_concurrency=_int(os.getenv("SOFT404_CONCURRENCY"), 8, "SOFT404_CONCURRENCY"),
            param_fuzz_timeout=_int(os.getenv("PARAM_FUZZ_TIMEOUT"), 10, "PARAM_FUZZ_TIMEOUT"),
            param_fuzz_max_urls_per_host=_int(
                os.getenv("PARAM_FUZZ_MAX_URLS_PER_HOST"),
                5,
                "PARAM_FUZZ_MAX_URLS_PER_HOST",
                maximum=20,
            ),
            param_fuzz_delay_ms=_int(
                os.getenv("PARAM_FUZZ_DELAY_MS"), 200, "PARAM_FUZZ_DELAY_MS", maximum=5000
            ),
            param_fuzz_body_delta_pct=_int(
                os.getenv("PARAM_FUZZ_BODY_DELTA_PCT"),
                5,
                "PARAM_FUZZ_BODY_DELTA_PCT",
                maximum=50,
            ),
            cloud_bucket_enum_timeout=_int(
                os.getenv("CLOUD_BUCKET_ENUM_TIMEOUT"),
                10,
                "CLOUD_BUCKET_ENUM_TIMEOUT",
            ),
            cloud_bucket_enum_delay_ms=_int(
                os.getenv("CLOUD_BUCKET_ENUM_DELAY_MS"),
                150,
                "CLOUD_BUCKET_ENUM_DELAY_MS",
                maximum=5000,
            ),
            strict_opsec=_bool(os.getenv("STRICT_OPSEC")),
            outbound_proxy_url=_optional_proxy_url(os.getenv("OUTBOUND_PROXY_URL", "").strip()),
            enable_amass=_bool(os.getenv("ENABLE_AMASS")),
            enable_naabu=_bool(os.getenv("ENABLE_NAABU")),
            enable_katana=_bool(os.getenv("ENABLE_KATANA")),
            enable_hakrawler=_bool(os.getenv("ENABLE_HAKRAWLER")),
            enable_gau=_bool(os.getenv("ENABLE_GAU")),
            enable_waybackurls=_bool(os.getenv("ENABLE_WAYBACKURLS")),
            enable_nuclei=_bool(os.getenv("ENABLE_NUCLEI")),
            enable_assetfinder=_bool(os.getenv("ENABLE_ASSETFINDER")),
            enable_unfurl=_bool(os.getenv("ENABLE_UNFURL")),
            enable_anew=_bool(os.getenv("ENABLE_ANEW")),
            enable_jq=_bool(os.getenv("ENABLE_JQ")),
            enable_whois=_bool(os.getenv("ENABLE_WHOIS"), True),
            enable_asn_lookup=_bool(os.getenv("ENABLE_ASN_LOOKUP"), True),
            enable_ctlogs=_bool(os.getenv("ENABLE_CTLOGS"), True),
            enable_port_verify=_bool(os.getenv("ENABLE_PORT_VERIFY"), True),
            enable_threat_intel=_bool(os.getenv("ENABLE_THREAT_INTEL")),
            enable_browser_probe=_bool(os.getenv("ENABLE_BROWSER_PROBE")),
            enable_wildcard_check=_bool(os.getenv("ENABLE_WILDCARD_CHECK"), True),
            enable_soft404_check=_bool(os.getenv("ENABLE_SOFT404_CHECK"), True),
            enable_param_fuzz=_bool(os.getenv("ENABLE_PARAM_FUZZ")),
            enable_cloud_bucket_enum=_bool(os.getenv("ENABLE_CLOUD_BUCKET_ENUM")),
            enable_vuln_match=_bool(os.getenv("ENABLE_VULN_MATCH"), True),
            enable_security_headers=_bool(os.getenv("ENABLE_SECURITY_HEADERS"), True),
            vuln_match_timeout=_int(os.getenv("VULN_MATCH_TIMEOUT"), 15, "VULN_MATCH_TIMEOUT"),
            wpscan_api_token=os.getenv("WPSCAN_API_TOKEN", "").strip() or None,
            scope_file=_optional_scope_file(os.getenv("SCOPE_FILE", "").strip()),
            webhook_url=os.getenv("WEBHOOK_URL", "").strip() or None,
            urlhaus_api_key=os.getenv("URLHAUS_API_KEY", "").strip() or None,
            custom_http_headers=_parse_headers(os.getenv("HTTP_CUSTOM_HEADERS")),
            x_hackerone_researcher=_optional_researcher(
                os.getenv("X_HACKERONE_RESEARCHER", "").strip()
            ),
            program_name=_sanitize_metadata(os.getenv("PROGRAM_NAME", "")),
            program_platform=_sanitize_metadata(os.getenv("PROGRAM_PLATFORM", "")),
        )

        return settings

    def validate(self) -> list[str]:
        """Validate all configuration values.

        Returns:
            List of validation error messages (empty if valid).

        Raises:
            ConfigurationError: If configuration is invalid and strict mode desired.
        """
        errors: list[str] = []

        try:
            self.log_level = validate_log_level(self.log_level)
        except ConfigurationError as exc:
            errors.append(str(exc))

        if self.default_output_format not in _VALID_OUTPUT_FORMATS:
            errors.append(f"DEFAULT_OUTPUT_FORMAT must be one of {sorted(_VALID_OUTPUT_FORMATS)}")

        if self.strict_opsec and not self.outbound_proxy_url:
            errors.append(
                "STRICT_OPSEC requires OUTBOUND_PROXY_URL; refusing direct network probes"
            )

        for directory in (self.output_directory, self.logs_directory, self.reports_directory):
            try:
                resolved = (self.project_root / directory).resolve()
                if resolved.exists() and not resolved.is_dir():
                    errors.append(f"Path is not a directory: {directory}")
            except OSError as exc:
                errors.append(f"Invalid directory path {directory}: {exc}")

        if self.resolvers_file:
            try:
                validate_readable_file(self.resolvers_file)
            except Exception as exc:
                errors.append(f"RESOLVERS_FILE: {exc}")

        if self.wordlist:
            try:
                validate_readable_file(self.wordlist)
            except Exception as exc:
                errors.append(f"WORDLIST: {exc}")

        if self.scope_file:
            try:
                validate_readable_file(self.scope_file)
            except Exception as exc:
                errors.append(f"SCOPE_FILE: {exc}")

        for path in self.all_tool_paths().values():
            if path.name != str(path):
                try:
                    validate_binary_path(path)
                except ConfigurationError as exc:
                    errors.append(str(exc))

        return errors

    def validate_or_raise(self) -> None:
        """Validate configuration, raising on first batch of errors."""
        errors = self.validate()
        if errors:
            raise ConfigurationError("Configuration validation failed:\n- " + "\n- ".join(errors))

    def ensure_directories(self) -> None:
        """Create output, logs, and reports directories under project root."""
        for directory in (self.output_directory, self.logs_directory, self.reports_directory):
            (self.project_root / directory).mkdir(parents=True, exist_ok=True)
            try:
                (self.project_root / directory).chmod(0o700)
            except OSError:
                pass

    def get_run_output_dir(self, run_id: str) -> Path:
        """Return per-run output subdirectory.

        Args:
            run_id: Validated run identifier.

        Returns:
            Absolute path to run output directory.
        """
        run_dir = (self.project_root / self.output_directory / run_id).resolve()
        base = (self.project_root / self.output_directory).resolve()
        try:
            run_dir.relative_to(base)
        except ValueError as exc:
            raise ConfigurationError(f"Invalid run output path for run_id: {run_id}") from exc
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            run_dir.chmod(0o700)
        except OSError:
            pass
        return run_dir

    def merged_headers(self) -> dict[str, str]:
        """Return HTTP headers for tool invocations, including any program-mandated
        researcher identification header.

        Strict OPSEC mode suppresses all identifying headers, since sending them
        would defeat the purpose of proxy-routed, non-attributable probing.
        """
        if self.strict_opsec:
            return {}
        headers = dict(self.custom_http_headers)
        if self.x_hackerone_researcher and "X-HackerOne-Researcher" not in headers:
            headers["X-HackerOne-Researcher"] = self.x_hackerone_researcher
        return headers

    def effective_user_agent(self) -> str:
        """Return a non-identifying User-Agent when strict OPSEC is active."""
        if self.strict_opsec:
            return (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            )
        return self.user_agent

    def all_tool_paths(self) -> dict[str, Path]:
        """Return mapping of tool name to configured binary path."""
        return {
            "subfinder": self.subfinder_path,
            "amass": self.amass_path,
            "dnsx": self.dnsx_path,
            "httpx": self.httpx_path,
            "naabu": self.naabu_path,
            "katana": self.katana_path,
            "hakrawler": self.hakrawler_path,
            "gau": self.gau_path,
            "waybackurls": self.waybackurls_path,
            "nuclei": self.nuclei_path,
            "assetfinder": self.assetfinder_path,
            "unfurl": self.unfurl_path,
            "anew": self.anew_path,
            "jq": self.jq_path,
            "whois": self.whois_path,
            "port_verify": self.nmap_path,
        }

    def to_safe_dict(self) -> dict[str, Any]:
        """Return settings safe for logging (no secrets or header values)."""
        return {
            "output_directory": str(self.output_directory),
            "timeout": self.timeout,
            "threads": self.threads,
            "rate_limit": self.rate_limit,
            "httpx_threads": self.httpx_threads,
            "log_level": self.log_level,
            "default_output_format": self.default_output_format,
            "enable_cache": self.enable_cache,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "enabled_optional": [
                name
                for name, enabled in [
                    ("amass", self.enable_amass),
                    ("naabu", self.enable_naabu),
                    ("katana", self.enable_katana),
                    ("hakrawler", self.enable_hakrawler),
                    ("gau", self.enable_gau),
                    ("waybackurls", self.enable_waybackurls),
                    ("nuclei", self.enable_nuclei),
                    ("assetfinder", self.enable_assetfinder),
                    ("unfurl", self.enable_unfurl),
                    ("anew", self.enable_anew),
                    ("whois", self.enable_whois),
                    ("asn_lookup", self.enable_asn_lookup),
                    ("ctlogs", self.enable_ctlogs),
                    (
                        "port_verify",
                        self.enable_naabu and self.enable_port_verify,
                    ),
                    ("threat_intel", self.enable_threat_intel),
                    ("browser_probe", self.enable_browser_probe),
                    ("wildcard_check", self.enable_wildcard_check),
                    ("soft404_check", self.enable_soft404_check),
                    ("param_fuzz", self.enable_param_fuzz),
                    ("cloud_bucket_enum", self.enable_cloud_bucket_enum),
                    ("vuln_match", self.enable_vuln_match),
                    ("security_headers", self.enable_security_headers),
                ]
                if enabled
            ],
            "custom_headers_count": len(self.custom_http_headers),
            "has_researcher_header": self.x_hackerone_researcher is not None,
            "strict_opsec": self.strict_opsec,
            "has_outbound_proxy": self.outbound_proxy_url is not None,
            "has_webhook": self.webhook_url is not None,
            "has_scope_file": self.scope_file is not None,
            "has_wpscan_token": self.wpscan_api_token is not None,
        }


def _validate_user_agent(value: str) -> str:
    """Validate User-Agent string."""
    if not value or "\r" in value or "\n" in value or "\x00" in value:
        raise ConfigurationError("USER_AGENT must be a non-empty string without control characters")
    if len(value) > 512:
        raise ConfigurationError("USER_AGENT exceeds maximum length (512)")
    return value


def _optional_researcher(value: str) -> str | None:
    """Validate optional researcher username."""
    if not value:
        return None
    if not re.match(r"^[a-zA-Z0-9._-]{1,64}$", value):
        raise ConfigurationError(
            "X_HACKERONE_RESEARCHER must be 1-64 alphanumeric chars, dots, underscores, or hyphens"
        )
    return value


def _optional_proxy_url(value: str) -> str | None:
    """Validate an HTTP(S) proxy without exposing its credentials."""
    if not value:
        return None
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ConfigurationError("OUTBOUND_PROXY_URL contains control characters")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("OUTBOUND_PROXY_URL must be an http:// or https:// proxy URL")
    return value


def _optional_scope_file(value: str) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if "\x00" in str(path):
        raise ConfigurationError("SCOPE_FILE must not contain null bytes")
    return path


def _sanitize_metadata(value: str) -> str:
    """Sanitize optional metadata fields."""
    cleaned = value.strip()
    if "\r" in cleaned or "\n" in cleaned or "\x00" in cleaned:
        raise ConfigurationError("Metadata fields must not contain control characters")
    return cleaned[:256]

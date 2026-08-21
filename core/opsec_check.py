"""Pre-flight diagnostics for STRICT_OPSEC proxy-routed scanning.

This module answers one question before a real scan starts: "if I turn on
STRICT_OPSEC, will Hydra actually behave the way the documentation claims?"
It never runs during the normal pipeline — only from the `check-opsec` CLI
command — and every network probe it performs is against a neutral IP-echo
service or the configured proxy itself, never a bug bounty target.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request

from core.models import PipelineContext
from utils.network import open_url

_IP_ECHO_URL = "https://api.ipify.org?format=text"
_DEFAULT_CONNECT_TIMEOUT = 5.0
_DEFAULT_REQUEST_TIMEOUT = 10.0

Level = str  # "pass" | "warn" | "fail" | "info"


@dataclass
class OpsecCheck:
    """A single diagnostic result."""

    name: str
    level: Level
    message: str
    remediation: str | None = None


def check_configuration(settings) -> list[OpsecCheck]:
    """Validate STRICT_OPSEC / OUTBOUND_PROXY_URL coherence without raising."""
    if not settings.strict_opsec:
        return [
            OpsecCheck(
                name="Strict OPSEC mode",
                level="warn",
                message=(
                    "STRICT_OPSEC is disabled. Hydra will connect to targets and "
                    "third parties (crt.sh, URLhaus, Team Cymru, DNS resolvers) "
                    "directly from this machine's IP address."
                ),
                remediation="Set STRICT_OPSEC=true and OUTBOUND_PROXY_URL in .env to reduce exposure.",
            )
        ]

    checks = [OpsecCheck(name="Strict OPSEC mode", level="pass", message="Enabled")]

    if not settings.outbound_proxy_url:
        checks.append(
            OpsecCheck(
                name="Outbound proxy configuration",
                level="fail",
                message=(
                    "OUTBOUND_PROXY_URL is not set. Hydra will refuse to start a "
                    "scan in this state (fails closed)."
                ),
                remediation="Set OUTBOUND_PROXY_URL=http://user:pass@proxy-host:port in .env.",
            )
        )
        return checks

    parsed = urlparse(settings.outbound_proxy_url)
    checks.append(
        OpsecCheck(
            name="Outbound proxy configuration",
            level="pass",
            message=f"{parsed.scheme}://{parsed.hostname}:{parsed.port or 'default'}",
        )
    )
    return checks


def check_proxy_reachability(
    proxy_url: str,
    *,
    timeout: float = _DEFAULT_CONNECT_TIMEOUT,
) -> OpsecCheck:
    """Attempt a raw TCP connect to the configured proxy."""
    parsed = urlparse(proxy_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return OpsecCheck(
            name="Proxy TCP reachability",
            level="fail",
            message=f"Could not parse a host from OUTBOUND_PROXY_URL: {proxy_url!r}",
        )
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = (time.monotonic() - start) * 1000
            return OpsecCheck(
                name="Proxy TCP reachability",
                level="pass",
                message=f"Connected to {host}:{port} in {elapsed_ms:.0f}ms",
            )
    except OSError as exc:
        return OpsecCheck(
            name="Proxy TCP reachability",
            level="fail",
            message=f"Could not connect to {host}:{port}: {exc}",
            remediation="Verify the proxy is running and reachable from this host/network.",
        )


def check_proxy_functional(
    proxy_url: str,
    user_agent: str,
    *,
    timeout: float = _DEFAULT_REQUEST_TIMEOUT,
    echo_url: str = _IP_ECHO_URL,
) -> OpsecCheck:
    """Issue one real HTTP request *through* the proxy to confirm it forwards traffic."""
    request = Request(echo_url, headers={"User-Agent": user_agent})
    try:
        with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
            body = response.read(256).decode("utf-8", errors="replace").strip()
    except Exception as exc:
        return OpsecCheck(
            name="Proxy functional test",
            level="fail",
            message=f"Request through the proxy failed: {exc}",
            remediation="Confirm the proxy accepts CONNECT requests to HTTPS destinations.",
        )
    if not body:
        return OpsecCheck(
            name="Proxy functional test",
            level="warn",
            message="Proxy request succeeded but returned an empty body",
        )
    return OpsecCheck(
        name="Proxy functional test",
        level="pass",
        message=f"Request through proxy succeeded — observed egress IP: {body}",
    )


def check_direct_ip(
    user_agent: str,
    *,
    timeout: float = _DEFAULT_REQUEST_TIMEOUT,
    echo_url: str = _IP_ECHO_URL,
) -> OpsecCheck:
    """Reveal this machine's real public IP by connecting WITHOUT the proxy.

    Only invoke this when the analyst has explicitly opted in via
    --reveal-direct-ip — it exists solely to let them confirm the proxied
    egress IP differs from their real one, and itself sends one request to a
    third-party IP-echo service from the analyst's real address.
    """
    request = Request(echo_url, headers={"User-Agent": user_agent})
    try:
        with open_url(request, timeout=timeout, proxy_url=None) as response:
            body = response.read(256).decode("utf-8", errors="replace").strip()
    except Exception as exc:
        return OpsecCheck(
            name="Direct (non-proxied) egress IP",
            level="warn",
            message=f"Direct connection failed: {exc}",
        )
    return OpsecCheck(
        name="Direct (non-proxied) egress IP",
        level="info",
        message=f"Direct connection egress IP: {body or 'unknown'} (compare against the proxied IP above)",
    )


def check_httpx_strict_args(settings) -> OpsecCheck:
    """Build httpx's real argv and confirm it matches strict-mode promises.

    The side-probe flags (-ip, -cname, -tls-probe, -tls-grab) are intentional
    and harmless in normal mode — they only represent a promise-breaking leak
    when STRICT_OPSEC is actually enabled, so this check is a no-op otherwise.
    """
    from modules.httpx import HttpxPlugin

    if not settings.strict_opsec:
        return OpsecCheck(
            name="httpx proxy routing",
            level="info",
            message="Not applicable — STRICT_OPSEC is disabled, httpx uses normal probing",
        )

    plugin = HttpxPlugin(settings)
    context = PipelineContext(output_dir=settings.project_root / settings.output_directory)
    args = plugin._build_args(context, Path("hosts.txt"), Path("httpx.json"))

    leaky = [flag for flag in ("-ip", "-cname", "-tls-probe", "-tls-grab") if flag in args]
    if leaky:
        return OpsecCheck(
            name="httpx direct side-probes",
            level="fail",
            message=f"httpx would still send: {', '.join(leaky)}",
        )
    if settings.outbound_proxy_url and "-proxy" not in args:
        return OpsecCheck(
            name="httpx proxy routing",
            level="fail",
            message="httpx would not be invoked with -proxy despite strict mode being enabled",
        )
    return OpsecCheck(
        name="httpx proxy routing",
        level="pass",
        message="httpx will route through the configured proxy without direct TLS/IP/CNAME side-probes",
    )


def check_blocked_plugins(settings, manager) -> OpsecCheck:
    """Report which enabled plugins would be skipped by strict mode."""
    from core.runner import STRICT_OPSEC_ALLOWED_PLUGINS

    direct_enabled = sorted(
        p.name
        for p in manager.get_all_plugins()
        if p.is_enabled() and p.name not in STRICT_OPSEC_ALLOWED_PLUGINS
    )
    if not direct_enabled:
        return OpsecCheck(
            name="Direct-network plugin blocking",
            level="pass",
            message="No enabled plugins require direct-network blocking",
        )
    return OpsecCheck(
        name="Direct-network plugin blocking",
        level="pass" if settings.strict_opsec else "info",
        message=(
            f"{len(direct_enabled)} enabled plugin(s) "
            f"{'will be skipped in strict mode' if settings.strict_opsec else 'would run with direct network access'}: "
            + ", ".join(direct_enabled)
        ),
    )


def check_identity_headers(settings) -> OpsecCheck:
    """Report whether identifying HTTP headers would be sent."""
    headers = settings.merged_headers()
    if headers:
        return OpsecCheck(
            name="Identity headers",
            level="fail" if settings.strict_opsec else "info",
            message=f"{len(headers)} header(s) will be sent: {', '.join(sorted(headers))}",
        )
    return OpsecCheck(
        name="Identity headers",
        level="pass",
        message="No identifying headers will be sent",
    )


async def run_diagnostics(
    settings,
    manager,
    *,
    reveal_direct_ip: bool = False,
    skip_network: bool = False,
) -> list[OpsecCheck]:
    """Run the full STRICT_OPSEC diagnostic suite.

    Args:
        settings: Loaded application settings.
        manager: ToolManager instance for plugin enumeration.
        reveal_direct_ip: If True, also make one non-proxied request to reveal
            this machine's real public IP for comparison. Opt-in only.
        skip_network: If True, skip live network probes (proxy reachability /
            functional test) and only run static/config checks.

    Returns:
        Ordered list of OpsecCheck results.
    """
    checks: list[OpsecCheck] = []
    checks.extend(check_configuration(settings))

    proxy_configured = settings.strict_opsec and settings.outbound_proxy_url
    if proxy_configured and not skip_network:
        reachability = await asyncio.to_thread(
            check_proxy_reachability, settings.outbound_proxy_url
        )
        checks.append(reachability)
        if reachability.level == "pass":
            checks.append(
                await asyncio.to_thread(
                    check_proxy_functional,
                    settings.outbound_proxy_url,
                    settings.effective_user_agent(),
                )
            )
        if reveal_direct_ip:
            checks.append(await asyncio.to_thread(check_direct_ip, settings.effective_user_agent()))
    elif proxy_configured and skip_network:
        checks.append(
            OpsecCheck(
                name="Proxy network probes",
                level="info",
                message="Skipped (--skip-network)",
            )
        )

    checks.append(check_httpx_strict_args(settings))
    checks.append(check_blocked_plugins(settings, manager))
    checks.append(check_identity_headers(settings))
    checks.append(check_dns_leak(settings))
    return checks


def check_dns_leak(settings) -> OpsecCheck:
    """Informational check: does this host resolve names via the OS resolver?

    STRICT_OPSEC routes HTTP through a proxy, but Python ``getaddrinfo`` and
    tools like dnsx still use the local stub resolver unless the OS itself
    is forced through the proxy. A successful local lookup of a public name
    therefore means DNS *can* leave the analyst network directly.

    This check is **informational, not conclusive**: NXDOMAIN or a timeout
    does not prove DNS is proxied — only that this particular lookup failed.
    """
    probe_name = "example.com"
    try:
        socket.getaddrinfo(probe_name, 443)
        leaked = True
    except OSError:
        leaked = False
    if settings.strict_opsec and leaked:
        return OpsecCheck(
            name="DNS leak (local resolver)",
            level="warn",
            message=(
                f"This host resolved {probe_name} via the OS resolver. Under "
                "STRICT_OPSEC, HTTP is proxied but DNS for non-proxied tools "
                "may still egress directly. Informational — not proof of a leak "
                "on every lookup."
            ),
            remediation=(
                "Force system DNS through the proxy or a trusted resolver; "
                "do not treat this as a conclusive fail."
            ),
        )
    if leaked:
        return OpsecCheck(
            name="DNS leak (local resolver)",
            level="info",
            message=(
                f"Local resolver answered {probe_name}. Informational only — "
                "STRICT_OPSEC is off so direct DNS is expected."
            ),
        )
    return OpsecCheck(
        name="DNS leak (local resolver)",
        level="info",
        message=(
            f"Could not resolve {probe_name} locally. Inconclusive — this does "
            "not prove DNS is proxied."
        ),
    )


def summarize_checks(checks: list[OpsecCheck]) -> str:
    """Return 'N pass, N warn, N fail — safe to proceed|do not proceed'."""
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for check in checks:
        counts[check.level] = counts.get(check.level, 0) + 1
    verdict = "do not proceed" if counts["fail"] else "safe to proceed"
    return f"{counts['pass']} pass, {counts['warn']} warn, {counts['fail']} fail " f"— {verdict}"


def enforce_opsec_gate(settings, manager) -> None:
    """Run static OPSEC checks and refuse to start on any fail."""
    import asyncio

    from core.exceptions import ConfigurationError

    async def _run() -> list[OpsecCheck]:
        return await run_diagnostics(settings, manager, skip_network=True)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # Already inside the pipeline event loop — run the static subset inline.
        checks = []
        checks.extend(check_configuration(settings))
        checks.append(check_httpx_strict_args(settings))
        checks.append(check_blocked_plugins(settings, manager))
        checks.append(check_identity_headers(settings))
        checks.append(check_dns_leak(settings))
    else:
        checks = asyncio.run(_run())
    fails = [c for c in checks if c.level == "fail"]
    if fails:
        detail = "; ".join(f"{c.name}: {c.message}" for c in fails)
        raise ConfigurationError(f"STRICT_OPSEC gate failed ({summarize_checks(checks)}): {detail}")

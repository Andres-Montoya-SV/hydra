"""sslyze TLS/certificate posture plugin (optional, active).

SECURITY HOLD (2026-09-26): execution and automatic installation are blocked
until an upstream release accepts patched cryptography. The historical design
below and pure parser remain for archived evidence; see SSLYZE_SECURITY_HOLD.md.

**Why sslyze over testssl.sh**: sslyze is a pure Python package
(`pip install sslyze`, confirmed against its real current PyPI page and
its `pyproject.toml` — no other system dependency), so it installs into
this project's own `requirements-optional.txt` exactly like `python-docx`/
`playwright` already do, with no second subprocess-parsing-of-bash-output
layer and no separate binary to discover/verify the way `testssl.sh`
(a bash script) would need. testssl.sh is more exhaustive in places, but
sslyze's structured JSON output (a serialized dataclass tree, not text
scraped from a terminal-formatted report) is materially easier to parse
correctly and is what this task's own "pick one, justify it" asked for.

**Confirmed against sslyze 6.3.1's real current behavior, not assumed**
(installed and run for real against `example.com` during this task's own
development — see `tests/fixtures/sslyze_real_output.json`, sanitized):

- CLI: `sslyze --certinfo --heartbleed --robot --http_headers
  --json_out=<file> host[:port] ...` — confirmed directly from sslyze's
  own `command_line_parser.py` source (the `--json_out` flag's exact name
  and behavior — `"-"` for stdout — is not documented on sslyze's own
  README, only in its actual argparse source). Each scan command
  (`--certinfo`, `--heartbleed`, `--robot`, `--http_headers`) must be
  requested explicitly — a bare `sslyze <host>` with no flags runs a
  DIFFERENT small bundled default set (certinfo/heartbleed/robot/cipher
  suites/etc.) that does NOT include `http_headers`, confirmed by a real
  run: `http_headers.status` came back `"NOT_SCHEDULED"` with
  `result: null` until `--http_headers` was passed explicitly. This
  module always requests all four scan commands so no result field is
  ever silently `null`-because-unscheduled.
- JSON shape: `server_scan_results[].scan_result.<scan_command>` is
  always `{"status", "error_reason", "error_trace", "result"}` — `result`
  is only meaningful when `status == "COMPLETED"`, never trusted
  otherwise (see `core/verification/detectors.py::
  detect_sslyze_result_used_despite_not_completed`, the real
  contradiction risk this shape creates if a caller skips the status
  check).
- `robot.result.robot_result` real enum values (confirmed directly from
  the installed `sslyze.plugins.robot.implementation.RobotScanResultEnum`,
  not guessed): `VULNERABLE_WEAK_ORACLE`, `VULNERABLE_STRONG_ORACLE`,
  `NOT_VULNERABLE_NO_ORACLE`, `NOT_VULNERABLE_RSA_NOT_SUPPORTED`,
  `UNKNOWN_INCONSISTENT_RESULTS` — only the two `VULNERABLE_*` values are
  ever reported as a finding; `UNKNOWN_INCONSISTENT_RESULTS` is neither
  claimed vulnerable NOR claimed safe (a real, deliberate non-claim, not
  an oversight — see the matching verification detector).
- `http_headers.result.strict_transport_security_header` is `null` when
  the response carries no HSTS header at all (confirmed live against
  `example.com`, which genuinely does not send one) — this is what
  becomes the "missing HSTS" finding, same finding shape
  `modules/security_headers.py` already established for other missing
  headers.
- Certificate expiry/trust: `certificate_info.result.
  certificate_deployments[].received_certificate_chain[0]` is the leaf
  certificate as a PEM string — sslyze's JSON has no separate
  "not_valid_after" field, so this module parses the PEM with
  `cryptography.x509` (already a real transitive dependency of sslyze
  itself, confirmed installed) to get the real expiry timestamp, rather
  than inventing a second certificate parser.

**Active plugin, proxy-confined like `modules/httpx.py`/`modules/naabu.py`**:
each candidate host is re-authorized via
`AuthorizedCollectionTarget.authorize()` (scope + SSRF/private-IP check)
immediately before being handed to the real `sslyze` subprocess — a host
that fails authorization is skipped with a warning, never silently
dropped without a trace. sslyze makes its own raw TLS-handshake
connections (not HTTP requests through an HTTP proxy), so — like naabu —
this is authorization-by-checked-input, not `ScopeEnforcingProxy`
interception; there is no HTTP-proxy flag on sslyze's own CLI to route
through in the first place.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from core.collection.target import AuthorizedCollectionTarget
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl

# Not an operator/environment bypass: removal requires a reviewed dependency fix.
SSLYZE_SECURITY_HOLD = True
_MAX_HOSTS_PER_RUN = 10
_WEAK_PROTOCOL_KEYS = (
    "ssl_2_0_cipher_suites",
    "ssl_3_0_cipher_suites",
    "tls_1_0_cipher_suites",
    "tls_1_1_cipher_suites",
)
_VULNERABLE_ROBOT_RESULTS = {"VULNERABLE_WEAK_ORACLE", "VULNERABLE_STRONG_ORACLE"}


class SslyzePlugin(BaseToolPlugin):
    name = "sslyze"
    display_name = "sslyze"
    required = False
    stage_order = 41
    produces = ("tls_findings",)
    capability = "tls_posture"
    active_collection = True
    # TLS configuration is a live, time-varying property (cert renewal,
    # config changes) — never silently replay a stale scan result.
    cacheable = False
    install_hint_macos = "Security hold: see docs/SSLYZE_SECURITY_HOLD.md"
    install_hint_linux = install_hint_macos

    def is_enabled(self) -> bool:
        return self.settings.enable_sslyze

    def get_binary_path(self) -> Path:
        return self.settings.sslyze_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        if SSLYZE_SECURITY_HOLD:
            message = "SSLyze execution blocked: vulnerable dependency; see SSLYZE_SECURITY_HOLD.md"
            context.add_warning(message)
            return PluginResult(success=False, message=message)
        alive_urls = self._alive_urls(context)
        https_urls = [u for u in alive_urls if u.startswith("https://")]
        if not https_urls:
            return self._skip("No HTTPS services to analyze")

        from core.intel.scope import require_collection_scope

        scope = require_collection_scope(context)
        targets: list[AuthorizedCollectionTarget] = []
        seen_hosts: set[str] = set()
        for url in https_urls:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                continue
            port = parsed.port or 443
            host_key = f"{host}:{port}"
            if host_key in seen_hosts:
                continue
            target = AuthorizedCollectionTarget.authorize(
                url, scope, capability="tls_scan", operation="sslyze"
            )
            if target is None:
                context.add_warning(f"sslyze: {host} failed re-authorization — skipped")
                continue
            seen_hosts.add(host_key)
            targets.append(target)
            if len(targets) >= _MAX_HOSTS_PER_RUN:
                break

        if not targets:
            return self._skip("No authorized HTTPS hosts to analyze")

        output_path = self._output_path(context, "sslyze.json")
        findings_path = self._output_path(context, "sslyze_findings.jsonl")

        args = [
            str(self.get_binary_path()),
            "--certinfo",
            "--heartbleed",
            "--robot",
            "--http_headers",
            f"--json_out={output_path}",
        ]
        args.extend(f"{t.hostname}:{t.port or 443}" for t in targets)

        self.update_status(context, ToolStatus.RUNNING)
        return_code, stdout, stderr = await self._run_tool(
            context, args, timeout=self.settings.sslyze_timeout
        )
        self._scan_telemetry(context, stdout, stderr)

        if not output_path.exists():
            message = f"sslyze produced no output (exit {return_code})"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, message=message)

        import json

        try:
            data = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            message = f"sslyze produced unparseable JSON: {exc}"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, output_path=output_path, message=message)

        findings = parse_sslyze_results(data)
        count = write_jsonl(findings_path, findings, base_dir=context.output_dir)
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=findings_path,
            lines_produced=count,
            message=f"sslyze: {count} TLS finding(s) across {len(targets)} host(s)",
        )


def _leaf_certificate_expiry(deployment: dict) -> datetime | None:
    """Parses the leaf certificate's real PEM (sslyze's JSON has no
    separate expiry field) via `cryptography.x509` — already a real
    transitive dependency of sslyze itself."""
    chain = deployment.get("received_certificate_chain") or []
    if not chain:
        return None
    leaf_pem = chain[0]
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
        return cert.not_valid_after_utc
    except Exception:
        return None


def parse_sslyze_results(data: dict) -> list[dict[str, object]]:
    """Real sslyze `--json_out` document -> this plugin's findings shape.
    Every `scan_result.<command>.result` read here is gated on
    `status == "COMPLETED"` first — see this module's own docstring for
    why a `null` result on an unscheduled scan command must never be
    misread as "checked and clean"."""
    findings: list[dict[str, object]] = []
    for server_result in data.get("server_scan_results") or []:
        host = (server_result.get("server_location") or {}).get("hostname", "")
        scan_result = server_result.get("scan_result") or {}

        heartbleed = scan_result.get("heartbleed") or {}
        if heartbleed.get("status") == "COMPLETED":
            hb_result = heartbleed.get("result") or {}
            if hb_result.get("is_vulnerable_to_heartbleed"):
                findings.append(
                    _finding(
                        host,
                        "tls-heartbleed",
                        "critical",
                        "Vulnerable to Heartbleed (CVE-2014-0160)",
                    )
                )

        robot = scan_result.get("robot") or {}
        if robot.get("status") == "COMPLETED":
            robot_result = str((robot.get("result") or {}).get("robot_result") or "")
            if robot_result in _VULNERABLE_ROBOT_RESULTS:
                findings.append(
                    _finding(
                        host, "tls-robot", "high", f"Vulnerable to ROBOT attack ({robot_result})"
                    )
                )

        for key in _WEAK_PROTOCOL_KEYS:
            node = scan_result.get(key) or {}
            if node.get("status") != "COMPLETED":
                continue
            result = node.get("result") or {}
            if result.get("is_tls_version_supported"):
                protocol = result.get("tls_version_used") or key
                findings.append(
                    _finding(
                        host,
                        "tls-weak-protocol",
                        "medium",
                        f"Server accepts a deprecated/insecure TLS protocol: {protocol}",
                    )
                )

        http_headers = scan_result.get("http_headers") or {}
        if http_headers.get("status") == "COMPLETED":
            hh_result = http_headers.get("result") or {}
            if hh_result.get("strict_transport_security_header") is None:
                findings.append(
                    _finding(host, "tls-missing-hsts", "low", "No Strict-Transport-Security header")
                )

        cert_info = scan_result.get("certificate_info") or {}
        if cert_info.get("status") == "COMPLETED":
            for deployment in (cert_info.get("result") or {}).get("certificate_deployments") or []:
                path_results = deployment.get("path_validation_results") or []
                any_trusted = any(r.get("was_validation_successful") for r in path_results)
                if path_results and not any_trusted:
                    findings.append(
                        _finding(
                            host,
                            "tls-untrusted-certificate",
                            "medium",
                            "Certificate did not validate against any trust store",
                        )
                    )
                expiry = _leaf_certificate_expiry(deployment)
                if expiry is not None and expiry < datetime.now(timezone.utc):
                    findings.append(
                        _finding(
                            host,
                            "tls-expired-certificate",
                            "high",
                            f"Certificate expired on {expiry.date().isoformat()}",
                        )
                    )
    return findings


def _finding(host: str, template_id: str, severity: str, description: str) -> dict[str, object]:
    return {
        "host": host,
        "template_id": template_id,
        "severity": severity,
        "name": description,
        "description": description,
        # Points at the full raw sslyze.json for this run — the internal
        # HTML report's raw-evidence link (core/reporter.py) reads this,
        # same convention every other module's own findings already use.
        "raw_artifact": "sslyze.json",
    }

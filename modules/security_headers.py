"""Audit HTTP security headers on live httpx services.

Never makes its own request — confirmed by reading this file: `_httpx_services`
reads `context.httpx_results` (i.e. `httpx.json`, already captured by
`modules/httpx.py`'s real subprocess run with `-include-response-header`).
`security_headers` is a pure re-check of data httpx already collected, not a
second network round-trip.

That distinction is exactly what mattered for a real false-negative found
against `creator.stripchat.com`: a live scan reported `x-frame-options` and
`strict-transport-security` as MISSING, while a manual `curl -sI` against the
same host consistently showed both present. Investigated (not assumed) by
reading the real archived `httpx.json` from that run and reproducing live:

- httpx's OWN capture already had `"x_frame_options": "deny"` and
  `"strict_transport_security": "max-age=..."` in its `header` JSON object —
  the real response httpx received DID carry both headers.
- 3 fresh live `curl -sI` runs and 3 fresh live `httpx` runs (identical flags
  to `modules/httpx.py`) against the same host, across different Cloudflare
  edge nodes (different `cf-ray` values each time), all consistently showed
  both headers present. No intermittency — Cloudflare backend/pod rotation is
  not the cause.
- The actual bug: `normalize_header_map` only lowercased keys. httpx's JSON
  encoder renames every hyphenated header name to use underscores instead
  (`X-Frame-Options` -> `x_frame_options`, `Strict-Transport-Security` ->
  `strict_transport_security`) — an artifact of httpx's own Go JSON
  serialization, not the real wire format (HTTP header names use hyphens,
  RFC 7230). Every entry in `CHECKED_HEADERS` below is hyphenated, so the
  lookup against an underscored key silently always failed — for every one
  of the 6 checked headers, on every host, in every run, since this
  comparison never converted underscores back to hyphens. This was not an
  occasional false positive; it was a 100%-reproducible, systemic one: any
  of these 6 headers being genuinely present was unreportable.

Fixed by having `normalize_header_map` fold `_` to `-` as well as
lowercasing. See `tests/test_security_headers.py` for the regression case
using the real `creator.stripchat.com` header dict.
"""

from __future__ import annotations

from pathlib import Path

from core.exceptions import ValidationError
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.security import (
    atomic_write_text,
    relative_output_path,
    validate_output_path,
    validate_safe_filename,
)

CHECKED_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)

_HEADER_LABELS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def normalize_header_map(headers: dict) -> dict[str, str]:
    """Lowercase header keys and fold underscores to hyphens.

    httpx's JSON output renames every hyphenated header name to use
    underscores (`Content-Type` -> `content_type`) — its own encoding
    artifact, not the real wire format. Without this fold, every lookup
    against `CHECKED_HEADERS` (all hyphenated) silently never matched a
    genuinely present header. See this module's docstring for the real
    creator.stripchat.com case this was confirmed against.
    """
    return {str(k).lower().replace("_", "-"): str(v) for k, v in (headers or {}).items()}


def missing_security_headers(headers: dict[str, str]) -> list[str]:
    """Return canonical missing header names.

    CSP ``frame-ancestors`` satisfies clickjacking protection even without
    ``X-Frame-Options``.
    """
    missing: list[str] = []
    lower = {k.lower(): v for k, v in headers.items()}
    for name in CHECKED_HEADERS:
        if name == "x-frame-options":
            csp = lower.get("content-security-policy", "")
            if "frame-ancestors" in csp.lower() or lower.get("x-frame-options"):
                continue
            missing.append(name)
            continue
        if not lower.get(name):
            missing.append(name)
    return missing


def score_from_missing(missing: list[str]) -> int:
    present = len(CHECKED_HEADERS) - len(missing)
    return int(round(100 * present / len(CHECKED_HEADERS)))


class SecurityHeadersPlugin(BaseToolPlugin):
    """Flag absent security headers on each httpx service."""

    name = "security_headers"
    display_name = "Security Headers"
    required = False
    external_dependency = False
    stage_order = 58
    cacheable = False
    produces = ("findings",)
    capability = "http_headers"
    active_collection = True
    strict_opsec_allowed = True

    def is_enabled(self) -> bool:
        return self.settings.enable_security_headers

    def get_binary_path(self) -> Path:
        return Path("built-in")

    def get_install_hint(self) -> str:
        return "Built-in (uses httpx response headers)"

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        services = _httpx_services(context)
        if not services:
            return self._skip("No HTTP services with headers to audit")

        self.update_status(context, ToolStatus.RUNNING)
        rows: list[dict[str, object]] = []

        for svc in services:
            headers = normalize_header_map(svc["headers"])
            missing = missing_security_headers(headers)
            score = score_from_missing(missing)
            raw_artifact = self._write_raw_artifact(
                context,
                svc["host"],
                url=svc["url"],
                method=svc["method"],
                status_code=svc["status_code"],
                timestamp=svc["timestamp"],
                headers=headers,
                missing=missing,
            )
            for name in missing:
                rows.append(
                    {
                        "host": svc["host"],
                        "url": svc["url"],
                        "header": _HEADER_LABELS[name],
                        "header_key": name,
                        "missing": True,
                        "security_headers_score": score,
                        "raw_artifact": raw_artifact,
                    }
                )
            if not missing:
                rows.append(
                    {
                        "host": svc["host"],
                        "url": svc["url"],
                        "header": None,
                        "header_key": None,
                        "missing": False,
                        "security_headers_score": score,
                        "raw_artifact": raw_artifact,
                    }
                )

        output_path = self._output_path(context, "security_headers.jsonl")
        count = write_jsonl(output_path, rows, base_dir=context.output_dir)
        context.metadata["security_headers_rows"] = count
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=f"Security headers: {count} observation(s) across {len(services)} service(s)",
        )

    def _write_raw_artifact(
        self,
        context: PipelineContext,
        host: str,
        *,
        url: str,
        method: str,
        status_code: object,
        timestamp: str,
        headers: dict[str, str],
        missing: list[str],
    ) -> str | None:
        """One raw file per host — same convention as
        `soft404_check_raw/<host>.txt`/`port_verify_raw/<host>.txt` — not a
        single concatenated file that is hard to reference per host.

        Records every header httpx captured for this host, not just the 6
        this module evaluates — real evidence for a report, not a repeat of
        the already-interpreted missing=[...] summary.
        """
        try:
            filename = validate_safe_filename(f"{host}.txt")
        except ValidationError:
            filename = validate_safe_filename(f"host-{abs(hash(host))}.txt")
        raw_path = validate_output_path(
            context.output_dir / "security_headers_raw" / filename, context.output_dir
        )
        lines = [
            f"HOST {host}",
            f"REQUEST {method or 'GET'} {url} HTTP/1.1",
            f"TIMESTAMP {timestamp or 'unknown'}",
            f"RESPONSE STATUS {status_code if status_code is not None else 'unknown'}",
            "RESPONSE HEADERS (as captured by httpx — every header, not just the "
            "6 evaluated below; httpx's own JSON encoding renames hyphens to "
            "underscores, folded back here):",
        ]
        for key in sorted(headers):
            lines.append(f"  {key}: {headers[key]}")
        lines.append(f"EVALUATED ({len(CHECKED_HEADERS)} checked): missing={missing}")
        try:
            atomic_write_text(raw_path, "\n".join(lines) + "\n")
        except OSError as exc:
            self.logger.warning(
                "Failed to write security_headers raw artifact for %s: %s", host, exc
            )
            return None
        return relative_output_path(raw_path, context.output_dir)


def _httpx_services(context: PipelineContext) -> list[dict]:
    services: list[dict] = []
    for record in context.httpx_results:
        url = str(record.get("url") or "")
        host = str(record.get("host") or record.get("input") or "")
        headers = record.get("header") or record.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        if not url and not host:
            continue
        services.append(
            {
                "host": host,
                "url": url,
                "headers": headers,
                "method": str(record.get("method") or ""),
                "status_code": record.get("status_code"),
                "timestamp": str(record.get("timestamp") or ""),
            }
        )
    return services

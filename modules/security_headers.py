"""Audit HTTP security headers on live httpx services."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.security import atomic_write_text, relative_output_path, validate_output_path

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
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


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
        raw_lines: list[str] = []

        for svc in services:
            headers = normalize_header_map(svc["headers"])
            missing = missing_security_headers(headers)
            score = score_from_missing(missing)
            raw_lines.append(f"HOST {svc['host']} url={svc['url']} score={score} missing={missing}")
            for name in missing:
                rows.append(
                    {
                        "host": svc["host"],
                        "url": svc["url"],
                        "header": _HEADER_LABELS[name],
                        "header_key": name,
                        "missing": True,
                        "security_headers_score": score,
                        "raw_artifact": None,
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
                        "raw_artifact": None,
                    }
                )

        raw_rel = self._write_raw(context, "\n".join(raw_lines) + "\n")
        for row in rows:
            row["raw_artifact"] = raw_rel

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

    def _write_raw(self, context: PipelineContext, content: str) -> str | None:
        raw_path = validate_output_path(
            context.output_dir / "security_headers_raw.txt", context.output_dir
        )
        try:
            atomic_write_text(raw_path, content)
        except OSError:
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
        services.append({"host": host, "url": url, "headers": headers})
    return services

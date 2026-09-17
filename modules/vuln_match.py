"""Correlate detected technologies with public vulnerability databases."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.network import open_url
from utils.security import atomic_write_text, relative_output_path, validate_output_path

_OSV_QUERY = "https://api.osv.dev/v1/query"
_WPSCAN_PLUGIN = "https://wpscan.com/api/v3/plugins/{slug}"


def parse_tech_name_version(raw: str) -> tuple[str, str | None]:
    """Split httpx-style 'Name:1.2.3' into (name, version)."""
    text = str(raw).strip()
    if ":" in text:
        name, ver = text.split(":", 1)
        ver = ver.strip()
        if ver and re.match(r"^\d", ver):
            return name.strip(), ver
    return text, None


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class VulnMatchPlugin(BaseToolPlugin):
    """Match httpx technologies against OSV.dev (and optional WPScan)."""

    name = "vuln_match"
    display_name = "CVE Correlation"
    required = False
    external_dependency = False
    stage_order = 57
    cacheable = False
    produces = ("findings", "technologies")
    capability = "vuln_match"
    active_collection = True
    strict_opsec_allowed = True

    def is_enabled(self) -> bool:
        return self.settings.enable_vuln_match

    def get_binary_path(self) -> Path:
        return Path("built-in")

    def get_install_hint(self) -> str:
        return "Built-in (OSV.dev; optional WPSCAN_API_TOKEN)"

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        techs = _collect_techs(context)
        if not techs:
            return self._skip("No technologies with versions to correlate")

        self.update_status(context, ToolStatus.RUNNING)
        cache: dict[tuple[str, str], tuple[list[dict[str, object]], list[dict[str, str]]]] = {}
        rows: list[dict[str, object]] = []
        raw_chunks: list[str] = []
        check_failures: list[dict[str, object]] = []

        for item in techs:
            key = (item["name"].lower(), item["version"])
            if key not in cache:
                vulns, raw, failures = _query_sources(
                    item["name"],
                    item["version"],
                    token=self.settings.wpscan_api_token,
                    timeout=self.settings.vuln_match_timeout,
                    proxy_url=self.settings.outbound_proxy_url,
                    user_agent=self.settings.effective_user_agent(),
                )
                cache[key] = (vulns, failures)
                raw_chunks.append(raw)
            cached_vulns, cached_failures = cache[key]
            for vuln in cached_vulns:
                row = {
                    "host": item["host"],
                    "url": item.get("url"),
                    "technology": item["name"],
                    "version": item["version"],
                    "check_status": "checked_vulnerable",
                    "identifier": vuln["identifier"],
                    "severity": vuln["severity"],
                    "source": vuln["source"],
                    "source_url": vuln.get("source_url"),
                    "summary": vuln.get("summary") or "",
                    "raw_artifact": None,
                }
                rows.append(row)
            # Never collapsed into "checked, nothing found": a source that
            # could not be queried at all (network error, invalid/expired
            # token, rate limit, malformed response) must never be
            # indistinguishable from one that was queried and came back
            # clean — same fail-visible discipline as
            # modules/param_fuzz.py's baseline_invalid rows. This is the
            # ONLY thing this hardening round changes: a technology this
            # run genuinely verified clean across every applicable source
            # still produces zero rows, exactly as before.
            for failure in cached_failures:
                row = {
                    "host": item["host"],
                    "url": item.get("url"),
                    "technology": item["name"],
                    "version": item["version"],
                    "check_status": "check_failed",
                    "identifier": None,
                    "severity": None,
                    "source": failure["source"],
                    "source_url": None,
                    "summary": failure["reason"],
                    "raw_artifact": None,
                }
                rows.append(row)
                check_failures.append(row)

        raw_rel = self._write_raw(context, "\n".join(raw_chunks) + "\n")
        for row in rows:
            row["raw_artifact"] = raw_rel

        output_path = self._output_path(context, "vuln_match.jsonl")
        count = write_jsonl(output_path, rows, base_dir=context.output_dir)
        hit_count = sum(1 for row in rows if row["check_status"] == "checked_vulnerable")
        context.metadata["vuln_match_hits"] = hit_count
        context.metadata["vuln_match_check_failed"] = [
            {
                "host": row["host"],
                "technology": row["technology"],
                "version": row["version"],
                "source": row["source"],
                "reason": row["summary"],
            }
            for row in check_failures
        ]
        for row in check_failures:
            context.add_warning(
                f"⚠ No se pudo verificar {row['technology']}:{row['version']} contra "
                f"{row['source']} ({row['summary']}) — tecnología detectada, "
                "vulnerabilidad no descartada."
            )

        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        message = f"CVE correlation: {hit_count} matching advisory/ies"
        if check_failures:
            message += (
                f"; {len(check_failures)} check(s) could not be completed "
                "(see warnings — not the same as 'no vulnerabilities')"
            )
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=message,
        )

    def _write_raw(self, context: PipelineContext, content: str) -> str | None:
        raw_path = validate_output_path(
            context.output_dir / "vuln_match_raw.txt", context.output_dir
        )
        try:
            atomic_write_text(raw_path, content)
        except OSError:
            return None
        return relative_output_path(raw_path, context.output_dir)


def _collect_techs(context: PipelineContext) -> list[dict[str, str]]:
    from core.intel.scope import allows_active_collection

    scope = getattr(context, "collection_scope", None)
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for record in context.httpx_results:
        host = str(record.get("host") or record.get("input") or "")
        url = str(record.get("url") or "")
        landing = url or host
        if scope is None or (landing and not allows_active_collection(landing, scope)):
            continue
        techs = record.get("tech") or []
        if not isinstance(techs, list):
            continue
        for raw in techs:
            name, version = parse_tech_name_version(str(raw))
            if not version:
                continue
            key = (host, name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            found.append({"host": host, "url": url, "name": name, "version": version})
    return found


def _query_sources(
    name: str,
    version: str,
    *,
    token: str | None,
    timeout: int,
    proxy_url: str | None,
    user_agent: str,
) -> tuple[list[dict[str, object]], str, list[dict[str, str]]]:
    """Returns (vulns, raw_log, check_failures). `check_failures` lists,
    per source, why that source's query could not be completed — a source
    that fails is NEVER folded into `vulns` as "queried, nothing found";
    the caller must surface each failure distinctly (design: `check_failed`
    is a third state, not a degenerate case of `checked_clean`)."""
    vulns: list[dict[str, object]] = []
    raw_parts: list[str] = []
    failures: list[dict[str, str]] = []

    osv, osv_raw, osv_error = _osv_query(
        name, version, timeout=timeout, proxy_url=proxy_url, user_agent=user_agent
    )
    raw_parts.append(osv_raw)
    if osv_error:
        failures.append({"source": "osv.dev", "reason": osv_error})
    else:
        vulns.extend(osv)

    slug = name.lower().replace(" ", "-")
    is_wp_family = "wordpress" in slug or slug in {"bookly", "woocommerce", "elementor"}
    if is_wp_family:
        if not token:
            # A WPSCAN_API_TOKEN is optional to CONFIGURE, but once a
            # WordPress-family plugin is detected, WPScan is the
            # authoritative source for it — OSV rarely carries
            # WordPress-plugin advisories. Not having a token means this
            # technology's real vulnerability status was never verified
            # against the source that matters most for it; that gap must
            # be visible, not silently absorbed into "OSV said clean."
            failures.append({"source": "wpscan", "reason": "no WPSCAN_API_TOKEN configured"})
        else:
            wp, wp_raw, wp_error = _wpscan_query(
                slug,
                version,
                token=token,
                timeout=timeout,
                proxy_url=proxy_url,
                user_agent=user_agent,
            )
            raw_parts.append(wp_raw)
            if wp_error:
                failures.append({"source": "wpscan", "reason": wp_error})
            else:
                vulns.extend(wp)

    # Dedupe by identifier
    unique: dict[str, dict[str, object]] = {}
    for vuln in vulns:
        ident = str(vuln.get("identifier") or "")
        if ident and ident not in unique:
            unique[ident] = vuln
    return list(unique.values()), "\n".join(raw_parts), failures


def _osv_query(
    name: str,
    version: str,
    *,
    timeout: int,
    proxy_url: str | None,
    user_agent: str,
) -> tuple[list[dict[str, object]], str, str | None]:
    """Returns (vulns, raw_log, error). `error` is None only when the
    query genuinely completed — an empty `vulns` with `error is None` is
    a real "checked, nothing found" answer. Any exception (network error,
    timeout, non-2xx HTTP status raised by urllib) or unparseable body
    means the query did NOT complete, so it must never be reported as
    equivalent to a clean result."""
    payload = json.dumps({"version": version, "package": {"name": name}}).encode("utf-8")
    request = Request(
        _OSV_QUERY,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": user_agent},
        method="POST",
    )
    try:
        with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
            body = response.read(2_000_000).decode("utf-8", errors="replace")
    except Exception as exc:
        return [], f"OSV {name}@{version} error: {exc}\n", f"query failed: {exc}"
    vulns = []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return [], f"OSV {name}@{version} invalid JSON\n", "invalid JSON response"
    for vuln in data.get("vulns") or []:
        ident = ""
        aliases = vuln.get("aliases") or []
        for alias in aliases:
            if str(alias).startswith("CVE-"):
                ident = str(alias)
                break
        ident = ident or str(vuln.get("id") or "")
        score = _osv_score(vuln)
        vulns.append(
            {
                "identifier": ident,
                "severity": severity_from_score(score),
                "source": "osv.dev",
                "source_url": f"https://osv.dev/vulnerability/{vuln.get('id')}",
                "summary": str(vuln.get("summary") or "")[:500],
            }
        )
    return vulns, f"OSV {name}@{version}\n{body[:4000]}\n", None


def _osv_score(vuln: dict) -> float | None:
    for item in vuln.get("severity") or []:
        try:
            return float(item.get("score"))
        except (TypeError, ValueError):
            continue
    return None


def _wpscan_query(
    slug: str,
    version: str,
    *,
    token: str,
    timeout: int,
    proxy_url: str | None,
    user_agent: str,
) -> tuple[list[dict[str, object]], str, str | None]:
    """Returns (vulns, raw_log, error). `error` is None only when the
    query genuinely completed — an empty `vulns` with `error is None` is
    a real "checked, nothing found" answer. Any exception — including an
    HTTP error status urllib raises for a 401/404/429/5xx (invalid or
    expired token, unknown slug, rate limit, outage) — means the query
    did NOT complete. Deliberately conservative: this never tries to
    distinguish "token rejected" from "plugin not in WPScan's database"
    by status code alone, since the real production case this was fixed
    from (an invalid WPSCAN_API_TOKEN) surfaced as a plain 404 — treating
    ANY failed call as `check_failed` is the safe default; a genuinely
    covered plugin with no advisories only ever reaches the empty-vulns,
    no-error return below.
    """
    url = _WPSCAN_PLUGIN.format(slug=quote(slug, safe=""))
    request = Request(
        url,
        headers={"Authorization": f"Token token={token}", "User-Agent": user_agent},
    )
    try:
        with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
            body = response.read(2_000_000).decode("utf-8", errors="replace")
    except Exception as extra:
        return [], f"WPScan {slug} error: {extra}\n", f"query failed: {extra}"
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return [], f"WPScan {slug} invalid JSON\n", "invalid JSON response"
    vulns = []
    for _title, entry in (
        (data.get("vulnerabilities") or {}).items()
        if isinstance(data.get("vulnerabilities"), dict)
        else []
    ):
        ident = ""
        for ref in entry.get("references", {}).get("cve", []) if isinstance(entry, dict) else []:
            ident = f"CVE-{ref}" if not str(ref).startswith("CVE-") else str(ref)
            break
        ident = ident or str(entry.get("id") or "")
        vulns.append(
            {
                "identifier": ident,
                "severity": "medium",
                "source": "wpscan",
                "source_url": url,
                "summary": str(_title)[:500],
            }
        )
    return vulns, f"WPScan {slug}@{version}\n{body[:4000]}\n", None

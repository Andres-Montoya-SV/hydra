"""Hidden HTTP parameter discovery (opt-in active probe).

SECURITY / AUTHORIZATION
------------------------
This plugin sends active GET requests with crafted query parameters against
the target. It is disabled by default. Only enable it when you own the
domain or have explicit written authorization (e.g. a bug-bounty program).

It detects whether a parameter *influences* the response (and whether a
canary value is reflected). It does **not** inject SQL, XSS, path traversal,
or any other exploit payload — the canary value is a fixed inert token.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.assets import normalize_domain
from core.exceptions import ValidationError
from core.http_probe import http_get
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from core.response_diff import (
    ResponseSnapshot,
    reflected_context,
    significant_response_change,
)
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.security import (
    atomic_write_text,
    relative_output_path,
    validate_output_path,
    validate_safe_filename,
)

# Inert canary — recognizable if reflected, never an exploit payload.
CANARY_VALUE = "reconprobe123"

# Curated high-signal parameter names for recon (not an exhaustive dump).
PARAM_WORDLIST: tuple[str, ...] = (
    "id",
    "page",
    "p",
    "q",
    "query",
    "search",
    "s",
    "keyword",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "returnUrl",
    "return_url",
    "returnTo",
    "next",
    "url",
    "uri",
    "dest",
    "destination",
    "continue",
    "callback",
    "cb",
    "jsonp",
    "ref",
    "referer",
    "referrer",
    "source",
    "src",
    "from",
    "target",
    "out",
    "view",
    "action",
    "cmd",
    "command",
    "exec",
    "do",
    "op",
    "option",
    "mode",
    "type",
    "format",
    "output",
    "lang",
    "language",
    "locale",
    "file",
    "filename",
    "path",
    "filepath",
    "dir",
    "folder",
    "template",
    "tpl",
    "include",
    "doc",
    "document",
    "page_id",
    "post",
    "post_id",
    "article",
    "cat",
    "category",
    "tag",
    "sort",
    "order",
    "orderby",
    "filter",
    "limit",
    "offset",
    "start",
    "size",
    "count",
    "per_page",
    "token",
    "access_token",
    "auth",
    "key",
    "api_key",
    "apikey",
    "secret",
    "session",
    "sid",
    "user",
    "username",
    "email",
    "account",
    "admin",
    "debug",
    "test",
    "testing",
    "dev",
    "develop",
    "trace",
    "verbose",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_debug",
    "gclid",
    "fbclid",
    "preview",
    "draft",
    "version",
    "v",
    "api",
    "method",
    "endpoint",
    "resource",
    "data",
    "json",
    "xml",
    "callback_url",
    "webhook",
    "image",
    "img",
    "avatar",
    "download",
    "export",
    "import",
    "config",
    "setting",
    "settings",
    "env",
    "host",
    "domain",
    "port",
    "proxy",
)


class ParamFuzzPlugin(BaseToolPlugin):
    """Probe common parameter names for behavioral influence on live URLs."""

    name = "param_fuzz"
    display_name = "Parameter Discovery"
    required = False
    external_dependency = False
    stage_order = 55
    cacheable = False
    produces = ("urls",)
    capability = "param_fuzz"
    active_collection = True
    strict_opsec_allowed = True

    def is_enabled(self) -> bool:
        return self.settings.enable_param_fuzz

    def get_binary_path(self) -> Path:
        return Path("built-in")

    def get_install_hint(self) -> str:
        return "Built-in (stdlib urllib) — opt-in active probe"

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        urls = _select_urls(context, self.settings.param_fuzz_max_urls_per_host)
        if not urls:
            return self._skip("No live HTTP URLs to fuzz for parameters")

        context.add_warning(
            "Parameter Discovery sends active GET requests with crafted query "
            "parameters against the target. Enable only with ownership or explicit "
            "authorization (bug-bounty scope). No exploit payloads are used — "
            "existence/reflection only."
        )
        self.update_status(context, ToolStatus.RUNNING)

        positives: list[dict[str, object]] = []
        invalid_baselines: list[dict[str, object]] = []
        hosts_with_invalid_baseline: set[str] = set()
        probed_urls = 0
        total_probes = 0
        delay = max(0, self.settings.param_fuzz_delay_ms) / 1000.0
        timeout = self.settings.param_fuzz_timeout
        rel_delta = self.settings.param_fuzz_body_delta_pct / 100.0

        for url in urls:
            host = normalize_domain(urlparse(url).hostname or "") or "unknown"
            # Once a host's baseline is blocked, further URLs on that host are
            # almost certainly the same wall — don't burn the wordlist again.
            if host in hosts_with_invalid_baseline:
                continue

            record_lines: list[str] = []
            baseline = await asyncio.to_thread(
                http_get,
                url,
                timeout=timeout,
                proxy_url=self.settings.outbound_proxy_url,
            )
            total_probes += 1
            record_lines.append(
                f"BASELINE {url}\n"
                f"  status={baseline.status_code} len={baseline.body_length} "
                f"hash={baseline.body_hash} err={baseline.error}"
            )

            invalid_reason = _baseline_invalid_reason(baseline)
            if invalid_reason:
                hosts_with_invalid_baseline.add(host)
                skip_row: dict[str, object] = {
                    "host": host,
                    "url": url,
                    "baseline_status": baseline.status_code,
                    "baseline_body_hash": baseline.body_hash,
                    "baseline_body_length": baseline.body_length,
                    "baseline_error": baseline.error,
                    "baseline_invalid": True,
                    "reason": invalid_reason,
                    "parameters_probed": 0,
                    "raw_artifact": None,
                }
                invalid_baselines.append(skip_row)
                record_lines.append(
                    f"BASELINE_INVALID skipped_param_probes=True\n" f"  reason={invalid_reason}"
                )
                raw_path = self._write_raw_artifact(context, host, url, "\n".join(record_lines))
                skip_row["raw_artifact"] = raw_path
                continue

            probed_urls += 1
            if delay:
                await asyncio.sleep(delay)

            for param in PARAM_WORDLIST:
                probe_url = _with_param(url, param, CANARY_VALUE)
                candidate = await asyncio.to_thread(
                    http_get,
                    probe_url,
                    timeout=timeout,
                    proxy_url=self.settings.outbound_proxy_url,
                )
                total_probes += 1
                influences = significant_response_change(
                    baseline,
                    candidate,
                    max_rel_delta=rel_delta,
                )
                context_excerpt = reflected_context(candidate.body, CANARY_VALUE)
                reflected = context_excerpt is not None
                line = (
                    f"PARAM {param}={CANARY_VALUE}\n"
                    f"  url={probe_url}\n"
                    f"  status={candidate.status_code} len={candidate.body_length} "
                    f"hash={candidate.body_hash} influences={influences} "
                    f"reflected={reflected} err={candidate.error}"
                )
                if reflected and context_excerpt:
                    line += f"\n  reflected_context: {context_excerpt}"
                record_lines.append(line)
                if influences or reflected:
                    row: dict[str, object] = {
                        "host": host,
                        "url": url,
                        "probe_url": probe_url,
                        "parameter": param,
                        "canary_value": CANARY_VALUE,
                        "baseline_status": baseline.status_code,
                        "probe_status": candidate.status_code,
                        "baseline_body_hash": baseline.body_hash,
                        "probe_body_hash": candidate.body_hash,
                        "baseline_body_length": baseline.body_length,
                        "probe_body_length": candidate.body_length,
                        "parameter_influences_response": influences,
                        "reflected": reflected,
                        "raw_artifact": None,
                    }
                    if reflected and context_excerpt:
                        row["reflected_context"] = context_excerpt
                    positives.append(row)
                if delay:
                    await asyncio.sleep(delay)

            raw_path = self._write_raw_artifact(context, host, url, "\n".join(record_lines))
            for row in positives:
                if row.get("host") == host and row.get("url") == url:
                    row["raw_artifact"] = raw_path

        output_path = self._output_path(context, "param_fuzz.jsonl")
        # Hits first, then skip markers — parser ignores baseline_invalid rows.
        write_jsonl(
            output_path,
            positives + invalid_baselines,
            base_dir=context.output_dir,
        )
        hit_count = len(positives)
        context.metadata["param_fuzz_probes"] = total_probes
        context.metadata["param_fuzz_hits"] = hit_count
        context.metadata["param_fuzz_urls"] = len(urls)
        context.metadata["param_fuzz_urls_probed"] = probed_urls
        context.metadata["param_fuzz_wordlist_size"] = len(PARAM_WORDLIST)
        context.metadata["param_fuzz_baseline_invalid_hosts"] = [
            {
                "host": row["host"],
                "url": row["url"],
                "baseline_status": row.get("baseline_status"),
                "reason": row["reason"],
                "baseline_invalid": True,
            }
            for row in invalid_baselines
        ]

        if invalid_baselines:
            hosts_list = ", ".join(sorted(hosts_with_invalid_baseline))
            context.add_warning(
                "Parameter discovery skipped for host(s) with an invalid baseline "
                f"({hosts_list}) — baseline request was blocked/rate-limited; "
                "results would be unreliable. Not the same as '0 parameter hits'."
            )

        self.update_status(context, ToolStatus.COMPLETED, output_lines=hit_count)
        if invalid_baselines:
            message = (
                f"Parameter discovery: {hit_count} hit(s) across {probed_urls} probed "
                f"URL(s); skipped {len(invalid_baselines)} URL(s) on "
                f"{len(hosts_with_invalid_baseline)} host(s) — baseline "
                f"blocked/rate-limited ({total_probes} total requests)"
            )
        else:
            message = (
                f"Parameter discovery: {hit_count} hit(s) across {len(urls)} URL(s) "
                f"({total_probes} total requests)"
            )
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=hit_count,
            message=message,
        )

    def _write_raw_artifact(
        self,
        context: PipelineContext,
        host: str,
        url: str,
        content: str,
    ) -> str | None:
        try:
            filename = validate_safe_filename(f"{host}.txt")
        except ValidationError:
            filename = validate_safe_filename(f"host-{abs(hash(host))}.txt")
        raw_path = validate_output_path(
            context.output_dir / "param_fuzz_raw" / filename, context.output_dir
        )
        # Append if multiple URLs share a host.
        header = f"===== {url} =====\n"
        existing = ""
        if raw_path.exists():
            try:
                existing = raw_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                existing = ""
        try:
            atomic_write_text(raw_path, existing + header + content + "\n\n")
        except OSError as exc:
            self.logger.warning("Failed to write param_fuzz raw artifact for %s: %s", host, exc)
            return None
        return relative_output_path(raw_path, context.output_dir)


def _baseline_invalid_reason(baseline: ResponseSnapshot) -> str | None:
    """Return a human reason when the baseline is unsafe to diff against.

    A usable baseline must be an observed success/redirect (HTTP 200–399).
    Block/WAF/rate-limit statuses (403/429/503), other 4xx/5xx, and transport
    failures all make parameter comparisons meaningless — every probe would
    look identical to the block page and report a false clean "0 hits".
    """
    status = baseline.status_code
    if status is None:
        err = baseline.error or "no response"
        return (
            f"baseline request failed ({err}) — cannot establish a valid "
            "reference response for parameter comparison"
        )
    if 200 <= status <= 399:
        return None
    if status == 429:
        return "baseline returned HTTP 429 — target is rate-limiting or blocking " "requests"
    if status == 503:
        return "baseline returned HTTP 503 — target unavailable or actively " "shedding traffic"
    if status == 403:
        return "baseline returned HTTP 403 — target/WAF is blocking requests"
    return (
        f"baseline returned HTTP {status} (expected 200–399) — reference "
        "response is not usable for parameter comparison"
    )


def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    query.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(query)))


def _select_urls(context: PipelineContext, max_per_host: int) -> list[str]:
    """Prefer root-ish live URLs; cap per host to keep traffic bounded."""
    by_host: dict[str, list[str]] = {}
    candidates: list[str] = []
    for record in context.httpx_results:
        url = str(record.get("url") or record.get("input") or "")
        if url:
            candidates.append(url)
    if not candidates:
        candidates.extend(context.alive_urls)
    if not candidates:
        alive_path = context.output_dir / "alive.txt"
        if alive_path.exists():
            from utils.files import read_lines

            candidates.extend(read_lines(alive_path))

    for url in candidates:
        if "://" not in url:
            url = f"https://{url}"
        host = normalize_domain(urlparse(url).hostname or "")
        if not host:
            continue
        by_host.setdefault(host, [])
        if url not in by_host[host]:
            by_host[host].append(url)

    selected: list[str] = []
    for host in sorted(by_host):
        urls = sorted(by_host[host], key=_url_priority)
        selected.extend(urls[: max(1, max_per_host)])
    return selected


def _url_priority(url: str) -> tuple[int, int, str]:
    """Lower is better: prefer shorter paths / root URLs."""
    path = urlparse(url).path or "/"
    depth = path.strip("/").count("/") + (0 if path in ("", "/") else 1)
    return (depth, len(path), url)

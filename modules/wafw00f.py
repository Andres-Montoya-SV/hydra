"""wafw00f WAF/CDN fingerprinting plugin (optional, active).

Confirmed against wafw00f 2.4.2's real current behavior, not assumed —
installed and run for real against `https://example.com` during this
task's own development (`tests/fixtures/wafw00f_real_output.json`,
unmodified real output):

    [
      {"detected": true, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc.",
       "trigger_url": "https://example.com/?nvtdsrce=...", "url": "https://example.com"},
      {"detected": false, "firewall": "None", "manufacturer": "None",
       "trigger_url": null, "url": "https://example.com"}
    ]

CLI, confirmed via `wafw00f --help`: `-a/--findall` (keep testing every
signature instead of stopping at the first match — used here, since
"which WAFs, plural" is more useful evidence than "the first one
matched"), `-f json`/`-o -` for JSON to stdout, `-p PROXY` (a real,
supported proxy flag — HTTP or SOCKS5), `-r/--noredirect` (never follow
a 3xx response).

**Scope discipline, and why this is authorized-input gating (like
`modules/naabu.py`/`modules/sslyze.py`), not the full
`ScopeEnforcingProxy` `modules/katana.py`/`modules/hakrawler.py` use**:
wafw00f's own "how it works" is sending crafted requests (including the
canary payloads visible in `trigger_url` above) to the SAME target URL
it was given — it does not discover or pivot to a DIFFERENT external
host on its own the way a crawler does. `-r` (always passed here)
removes the one way it could otherwise leave the authorized target (a
3xx redirect to somewhere else), and each target URL is independently
re-authorized via `AuthorizedCollectionTarget.authorize()` immediately
before wafw00f is invoked against it — the same two-part guarantee
(bounded input, no self-directed pivot) naabu's port list and sslyze's
host list already rely on, applied here because it is the correct model
for how this specific tool actually behaves, confirmed by reading its
real detection method, not assumed by analogy alone.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.collection.target import AuthorizedCollectionTarget
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl

_MAX_URLS_PER_RUN = 10


class Wafw00fPlugin(BaseToolPlugin):
    name = "wafw00f"
    display_name = "wafw00f"
    required = False
    stage_order = 43
    produces = ("waf_findings",)
    capability = "waf_detection"
    active_collection = True
    # A WAF/CDN can be added, removed, or reconfigured between runs —
    # never silently replay a stale detection.
    cacheable = False
    install_hint_macos = "pip install wafw00f  (requirements-optional.txt)"
    install_hint_linux = install_hint_macos

    def is_enabled(self) -> bool:
        return self.settings.enable_wafw00f

    def get_binary_path(self) -> Path:
        return self.settings.wafw00f_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        alive_urls = self._alive_urls(context)
        if not alive_urls:
            return self._skip("No alive HTTP(S) services to fingerprint")

        from core.intel.scope import require_collection_scope

        scope = require_collection_scope(context)
        targets: list[AuthorizedCollectionTarget] = []
        seen: set[str] = set()
        for url in alive_urls:
            target = AuthorizedCollectionTarget.authorize(
                url, scope, capability="waf_detection", operation="wafw00f"
            )
            if target is None:
                context.add_warning(f"wafw00f: {url} failed re-authorization — skipped")
                continue
            if target.raw in seen:
                continue
            seen.add(target.raw)
            targets.append(target)
            if len(targets) >= _MAX_URLS_PER_RUN:
                break

        if not targets:
            return self._skip("No authorized services to fingerprint")

        output_path = self._output_path(context, "wafw00f.json")
        findings_path = self._output_path(context, "wafw00f_findings.jsonl")

        args = [
            str(self.get_binary_path()),
            "-a",
            "-r",
            "-f",
            "json",
            "-o",
            str(output_path),
        ]
        args.extend(t.raw for t in targets)

        self.update_status(context, ToolStatus.RUNNING)
        return_code, stdout, stderr = await self._run_tool(
            context, args, timeout=self.settings.wafw00f_timeout
        )
        self._scan_telemetry(context, stdout, stderr)

        if not output_path.exists():
            message = f"wafw00f produced no output (exit {return_code})"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, message=message)

        try:
            data = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            message = f"wafw00f produced unparseable JSON: {exc}"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, output_path=output_path, message=message)

        findings = parse_wafw00f_results(data)
        count = write_jsonl(findings_path, findings, base_dir=context.output_dir)
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=findings_path,
            lines_produced=count,
            message=f"wafw00f: {count} WAF/CDN observation(s) across {len(targets)} target(s)",
        )


def parse_wafw00f_results(data: object) -> list[dict[str, object]]:
    """Real wafw00f `-f json` output -> this plugin's own records —
    genuinely useful METADATA (per this task's own framing: "affects how
    a finding should be interpreted"), never a standalone Finding/
    vulnerability in its own right. `core/parsers/registry.py::
    Wafw00fParser` feeds these into `core.assets.Host.is_waf`/
    `.waf_provider` and `HttpService.waf` — the EXISTING fields
    `core.validation.engine.detect_cdn_waf`'s passive header-heuristic
    already populates, never a new parallel data shape. wafw00f's real,
    active detection is authoritative over that passive heuristic for
    any host it actually confirms.

    `-a` (findall) makes wafw00f emit one entry per matched signature PLUS
    a trailing generic-detection entry that is `detected: false` whenever
    nothing NEW was found by the generic method — that entry is NOT "no
    WAF was detected overall" (a real, confirmed shape: the captured
    output above has exactly this — a real Cloudflare detection followed
    by a `detected: false` generic-method entry for the SAME url). Only
    `detected: true` entries are ever kept here; a naive "read the last
    entry" parser would wrongly conclude "no WAF" — see
    `core/verification/detectors.py::
    detect_wafw00f_generic_negative_overwrites_earlier_detection` for the
    contradiction check this shape motivated.
    """
    if not isinstance(data, list):
        return []
    records: list[dict[str, object]] = []
    for entry in data:
        if not isinstance(entry, dict) or not entry.get("detected"):
            continue
        url = str(entry.get("url") or "")
        firewall = str(entry.get("firewall") or "Unknown")
        manufacturer = str(entry.get("manufacturer") or "")
        records.append({"url": url, "firewall": firewall, "manufacturer": manufacturer})
    return records

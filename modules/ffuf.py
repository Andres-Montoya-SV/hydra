"""Hidden endpoint/content discovery via `ffuf` (opt-in, active).

WHAT THIS ADDS BEYOND `katana`/`gau`
-----------------------------------------
`modules/katana.py` crawls links a real page actually contains;
`modules/gau.py` pulls URLs from historical web archives (Wayback
Machine, etc.). Both are powerful but fundamentally passive/discovery-
of-the-already-linked: a path that was never linked from anywhere and
never appeared in a crawl or in any historical archive — an old admin
panel nobody removed, a `.git/` directory left behind by a sloppy
deploy, a backup file dropped next to the real one — is, by definition,
invisible to every existing collector in this codebase. This module
closes that specific gap with wordlist-based brute force against each
known host, wrapping `ffuf` rather than reimplementing request-fuzzing.

AUTHORIZATION — ADAPTING `param_fuzz.py`'s PATTERN TO AN EXTERNAL TOOL
--------------------------------------------------------------------------
`modules/param_fuzz.py`'s own pattern (a BUILT-IN Python collector that
constructs every candidate URL itself) re-authorizes each individual
candidate URL as its own `AuthorizedCollectionTarget` before Hydra's own
code makes the request. `ffuf` is a different shape of tool: it is a
separate EXTERNAL BINARY that generates and requests its own candidate
URLs internally from a wordlist — Hydra's Python code never enumerates
each of the (here) ~900 per-host candidate paths to build/authorize a
target object for each one, the same way `modules/katana.py` never
does that for the links a crawl discovers on its own. The correct
adaptation, used by every other external-binary active plugin in this
codebase, is layered:

1. The base host itself is authorized as an `AuthorizedCollectionTarget`
   (`AuthorizedCollectionTarget.authorize()`, same call sslyze.py uses)
   BEFORE `ffuf` is ever invoked against it — a host that fails this
   check is skipped with a warning, never silently dropped.
2. Every actual request `ffuf` makes (all ~900 of them, since only the
   *path* varies — the host is fixed once authorized) is routed through
   `self._crawler_confinement(context)`, the same `ScopeEnforcingProxy`
   confinement `katana`/`hakrawler`/`nuclei` already use, via ffuf's own
   `-x` flag. **Confirmed by real testing, not assumed**: ffuf's real,
   current flag for this is `-x` (`-proxy` does not exist in ffuf —
   confirmed against its real `-h` output; that name is specific to
   katana/hakrawler/nuclei, not a codebase-wide convention). A live test
   during this module's own development ran real `ffuf` traffic through
   a real `ScopeEnforcingProxy`: every request to an in-scope target
   showed up in the proxy's own audit log (ALLOW/in_scope), and every
   request to an out-of-scope target never reached the real target at
   all — the target's own access log recorded nothing, and ffuf reported
   connection errors for all of them. `ffuf` is listed in
   `core/collection/crawler_proxy.py::PROXY_VERIFIED_TOOLS` on the
   strength of that real, direct verification.

Together, these give the same real guarantee `param_fuzz.py`'s per-
candidate re-authorization gives (no request ever reaches an
unauthorized destination) via the mechanism that actually fits an
external, self-driving fuzzing engine — not by bending
`AuthorizedCollectionTarget` to pretend Hydra built each candidate URL
itself.

WORDLIST — CURATED AND SMALL BY DEFAULT, NOT SecLists' raft-large
------------------------------------------------------------------------
`modules/data/ffuf_wordlist_quick.txt` is a hand-curated, real-world
list of ~180 entries (common admin/management paths, version-control
and environment-file leaks, backup/config file names, well-known
info-disclosure endpoints) — not an enormous generic wordlist like
SecLists' `raft-large-directories.txt` (tens of thousands of entries).
Combined with `-e .bak,.old,.zip,.sql` (ffuf's own extension-expansion
flag — tries `<word>` and `<word><ext>` for each entry without
duplicating every line by hand), this is ~900 real requests per host —
confirmed by an actual timed run against a local test server: ~18
seconds at `ffuf_rate_limit=50` req/s, comfortably inside the per-host
time budget below. `FFUF_WORDLIST_PATH` opts into a larger, slower,
operator-supplied wordlist (e.g. a full SecLists list) when that
tradeoff is wanted for a specific engagement — this module's own
default is deliberately conservative, not "the biggest list available."

RATE LIMITING AND PER-HOST TIME BUDGET — REAL, ENFORCED CEILINGS
------------------------------------------------------------------------
This is the most request-heavy active plugin in this codebase. Real
ceilings, not just configured and hoped for:

- `-rate 50` (`Settings.ffuf_rate_limit`) — ffuf's own real, native
  rate limiter (confirmed present in its current `-h` output), a
  moderate default matching the target-politeness posture the rest of
  this project already uses (`Settings.rate_limit` for the pipeline
  generally; `soft404_check`/`param_fuzz` use their own smaller,
  dedicated per-module knobs the same way this one does).
- `-t 20` (`Settings.ffuf_threads`) concurrent connections.
- `-maxtime-job 120` (`Settings.ffuf_max_time_per_host`) — confirmed by
  a real, live test (a 2000-entry wordlist against a fast local target
  with `-maxtime-job 2`) that ffuf genuinely stops early
  (`[WARN] Maximum running time for this job reached...`) rather than
  merely accepting the flag; this is a real per-host ceiling, not a
  hopeful one.
- `Settings.ffuf_max_hosts` (default 10) caps how many hosts get fuzzed
  at all in one run — the primary defense against turning a 25-minute
  scan into a multi-hour one against a target with many discovered
  hosts, since 10 hosts x 120s worst case is a bounded 20 minutes, not
  unbounded.
- `Settings.ffuf_timeout` (default 180s, Hydra's own subprocess-level
  wrapper via `_run_tool`) is a coarser outer safety net in case ffuf's
  own `-maxtime-job` were ever bypassed by a bug in ffuf itself.

FALSE-POSITIVE HANDLING — WIRED AGAINST `modules/soft404_check.py`,
NOT REIMPLEMENTED
------------------------------------------------------------------------
Two independent, complementary layers, since neither alone is
sufficient — confirmed by real testing:

1. **ffuf's own `-ac` (auto-calibration)**, always enabled. Confirmed by
   two real tests: against a genuine catch-all server (every path
   returns an identical 200 body), `-ac` correctly suppressed ALL hits
   from a 6-entry wordlist down to zero; against a normal server (real
   404s plus one genuine file), `-ac` correctly kept the one real hit.
   This is ffuf's own existing capability, used as intended — not a
   reimplementation of soft-404 detection.
2. **`modules/soft404_check.py`'s own signal**, consulted before ffuf
   ever runs against a host: `context.metadata["soft_404_detected_hosts"]`
   (populated earlier in the pipeline by that module's own canary-based
   detection) is checked first, and any host already flagged there is
   skipped entirely for `ffuf`, with a warning explaining why — that
   module already proved, with an independent method (a single random
   canary path vs. the site root), that status-code-based existence is
   unreliable on that specific host; spending ~900 more requests to
   rediscover the same fact would be wasted budget, and `-ac`'s own
   per-run calibration sample might not catch every case a dedicated
   canary-vs-root comparison already did. `soft404_check.py`'s own
   logic was extended-by-consultation here, not duplicated — this
   module adds no new soft-404 detection algorithm of its own.

SEVERITY — NOT EVERY DISCOVERED PATH IS A FINDING
------------------------------------------------------
A bare `200` on an arbitrary path is not inherently interesting.
`_categorize_path` below:

- Silently excludes a short allowlist of universally-expected files
  (`robots.txt`, `sitemap.xml`, `favicon.ico`, `humans.txt`,
  `security.txt`) — the task's own example (`/robots.txt` responding is
  not interesting) made explicit and structural, not a raw list of
  everything ffuf touched.
- `critical`: version-control/environment/credential leaks (`.git`,
  `.svn`, `.env`, `.htpasswd`, `.aws/`, `.ssh/`, `id_rsa`) and backup-
  looking hits (`.bak`, `.old`, `.zip`, `.sql` on an otherwise-sensitive
  base name) — a `.git/config` or `.env` responding is a real,
  actionable leak, not a curiosity.
- `high`: admin/management panels (`admin`, `wp-admin`, `phpmyadmin`,
  `manager`, `console`, `dashboard`, `cpanel`, `actuator`, `debug`).
- `low`: everything else ffuf genuinely confirmed (still worth
  recording — a hidden path that exists is real recon value — but not
  urgent the way the categories above are).

NON-GOALS
------------
Recursive discovery (fuzzing further into a directory this module
found) — one level of brute force per host this pass; ffuf's own
`-recursion`/`-recursion-depth` flags are a real, cheap follow-up once
this base capability is proven. Authenticated/session-aware fuzzing —
this product holds no target credentials, so anything behind a login is
out of scope by construction, not by choice made here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from core.collection.target import AuthorizedCollectionTarget
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl

_DEFAULT_WORDLIST = Path(__file__).resolve().parent / "data" / "ffuf_wordlist_quick.txt"

# The task's own example, made structural: universally-expected files that
# every real site has and that responding 200 says nothing interesting.
_UNINTERESTING_PATHS = frozenset(
    {
        "robots.txt",
        "sitemap.xml",
        "favicon.ico",
        "humans.txt",
        "security.txt",
        ".well-known/security.txt",
    }
)

_CRITICAL_PATTERNS = (
    re.compile(r"\.git(/|$)"),
    re.compile(r"\.svn(/|$)"),
    re.compile(r"\.hg(/|$)"),
    re.compile(r"(^|/)\.env"),
    re.compile(r"\.htpasswd$"),
    re.compile(r"(^|/)\.aws/"),
    re.compile(r"(^|/)\.ssh/"),
    re.compile(r"id_rsa"),
    re.compile(r"credentials\.json$"),
    re.compile(r"service-account\.json$"),
    re.compile(r"\.(bak|old|zip|sql|tar\.gz)$"),
)
_HIGH_PATTERNS = (
    re.compile(r"(^|/)(admin|administrator|wp-admin|phpmyadmin|pma|adminer\.php)(/|$)"),
    re.compile(r"(^|/)(manager|management|console|dashboard|cpanel|webmail|portal)(/|$)"),
    re.compile(r"(^|/)actuator"),
    re.compile(r"(^|/)debug(\.php)?$"),
    re.compile(r"(^|/)(server-status|server-info)$"),
)


def _categorize_path(path: str) -> tuple[str, int] | None:
    """Returns (severity, confidence_score), or None to exclude the hit
    entirely (the `_UNINTERESTING_PATHS` allowlist)."""
    normalized = path.strip("/").lower()
    if normalized in _UNINTERESTING_PATHS:
        return None
    for pattern in _CRITICAL_PATTERNS:
        if pattern.search(normalized):
            return "critical", 90
    for pattern in _HIGH_PATTERNS:
        if pattern.search(normalized):
            return "high", 75
    return "low", 50


class FfufPlugin(BaseToolPlugin):
    """Hidden endpoint/content discovery via ffuf. See module docstring."""

    name = "ffuf"
    display_name = "ffuf (Content Discovery)"
    required = False
    stage_order = 54
    produces = ("hidden_endpoints",)
    capability = "content_discovery"
    active_collection = True
    cacheable = False
    install_hint_macos = "brew install ffuf"
    install_hint_linux = "go install github.com/ffuf/ffuf/v2@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_ffuf

    def get_binary_path(self) -> Path:
        return self.settings.ffuf_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        from core.intel.scope import require_collection_scope

        scope = require_collection_scope(context)
        soft_404_hosts = set(context.metadata.get("soft_404_detected_hosts") or [])
        alive_urls = self._alive_urls(context)

        by_host: dict[str, str] = {}
        for url in alive_urls:
            host = urlparse(url).hostname
            if host:
                by_host.setdefault(host.lower(), url)

        skipped_soft_404 = [h for h in by_host if h in soft_404_hosts]
        candidates = [h for h in by_host if h not in soft_404_hosts]
        if skipped_soft_404:
            context.add_warning(
                "ffuf: skipped "
                f"{len(skipped_soft_404)} host(s) already flagged by soft404_check "
                f"as returning HTTP 200 for nonexistent paths — "
                f"{', '.join(sorted(skipped_soft_404)[:10])}"
            )
        if not candidates:
            return self._skip("No eligible hosts to fuzz (none alive, or all soft-404-affected)")

        max_hosts = max(1, self.settings.ffuf_max_hosts)
        candidates = sorted(candidates)[:max_hosts]

        wordlist = self.settings.ffuf_wordlist_path or _DEFAULT_WORDLIST
        if not wordlist.exists():
            message = f"ffuf wordlist not found: {wordlist}"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, message=message)

        context.add_warning(
            "Content Discovery (ffuf) sends a curated wordlist of read-only GET "
            "requests against each known host. Enable only with ownership or "
            "explicit authorization (bug-bounty scope)."
        )
        self.update_status(context, ToolStatus.RUNNING)

        targets: list[AuthorizedCollectionTarget] = []
        for host in candidates:
            target = AuthorizedCollectionTarget.authorize(
                by_host[host], scope, capability=self.capability, operation="ffuf"
            )
            if target is None:
                context.add_warning(f"ffuf: {host} failed re-authorization — skipped")
                continue
            targets.append(target)

        if not targets:
            return self._skip("No authorized hosts to fuzz")

        all_findings: list[dict[str, object]] = []
        scanned = 0

        async with self._crawler_confinement(context) as proxy:
            for target in targets:
                findings = await self._fuzz_host(context, proxy.proxy_url, target, wordlist)
                if findings is not None:
                    scanned += 1
                    all_findings.extend(findings)

        output_path = self._output_path(context, "ffuf_findings.jsonl")
        count = write_jsonl(output_path, all_findings, base_dir=context.output_dir)
        critical = sum(1 for f in all_findings if f["severity"] == "critical")

        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=(
                f"ffuf: {count} hidden endpoint(s) found across {scanned}/{len(targets)} "
                f"host(s) ({critical} critical)"
            ),
        )

    async def _fuzz_host(
        self,
        context: PipelineContext,
        proxy_url: str,
        target: AuthorizedCollectionTarget,
        wordlist: Path,
    ) -> list[dict[str, object]] | None:
        host = target.hostname
        scheme = target.scheme or "https"
        port_part = f":{target.port}" if target.port else ""
        base_url = f"{scheme}://{host}{port_part}"
        output_path = self._output_path(context, f"ffuf_{_safe_stem(host)}.json")

        args = [
            str(self.get_binary_path()),
            "-w",
            str(wordlist),
            "-u",
            f"{base_url}/FUZZ",
            "-e",
            self.settings.ffuf_extensions,
            "-ac",
            "-rate",
            str(self.settings.ffuf_rate_limit),
            "-t",
            str(self.settings.ffuf_threads),
            "-maxtime-job",
            str(self.settings.ffuf_max_time_per_host),
            "-x",
            proxy_url,
            "-json",
            "-o",
            str(output_path),
            "-of",
            "json",
            "-noninteractive",
            "-mc",
            "all",
        ]
        headers = self.settings.merged_headers()
        for key, value in headers.items():
            args.extend(["-H", f"{key}: {value}"])
        user_agent = self.settings.effective_user_agent()
        if user_agent:
            args.extend(["-H", f"User-Agent: {user_agent}"])

        return_code, stdout, stderr = await self._run_tool(
            context, args, timeout=self.settings.ffuf_timeout
        )
        self._scan_telemetry(context, stdout, stderr)
        if not output_path.exists():
            context.add_warning(
                f"ffuf: {host} produced no output (exit {return_code}) — "
                f"{(stderr or stdout).strip()[:200] or 'no output'}"
            )
            return None

        rows = _read_ffuf_json(output_path)
        findings: list[dict[str, object]] = []
        for row in rows:
            finding = _row_to_finding(row, host)
            if finding is not None:
                findings.append(finding)
        return findings


def _safe_stem(host: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)


def _read_ffuf_json(path: Path) -> list[dict[str, object]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    results = data.get("results") if isinstance(data, dict) else None
    return results if isinstance(results, list) else []


def _row_to_finding(row: dict[str, object], host: str) -> dict[str, object] | None:
    """Real ffuf `-of json` result row -> this module's own finding shape."""
    url = str(row.get("url") or "")
    if not url:
        return None
    path = urlparse(url).path
    category = _categorize_path(path)
    if category is None:
        return None
    severity, confidence = category
    status = row.get("status")
    length = row.get("length")
    words = row.get("words")

    return {
        "host": host,
        "url": url,
        "path": path,
        "status": status,
        "length": length,
        "words": words,
        "severity": severity,
        "confidence_score": confidence,
        "template_id": "hidden-endpoint-discovered",
        "name": f"Hidden endpoint discovered: {path}",
        "description": (
            f"ffuf found an unlinked, brute-forced endpoint at {url} "
            f"(HTTP {status}, {length} bytes) — never surfaced by crawling "
            "(katana) or historical archives (gau/waybackurls)."
        ),
        "raw_artifact": "ffuf_findings.jsonl",
    }

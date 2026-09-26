"""WhatWeb technology-intelligence provider (optional, active).

Hydra treats this as an enrichment provider for the existing Technology
Intelligence capability, not as a parallel asset model. WhatWeb's JSON is
normalized into the same `TechnologyFinding` shape httpx already feeds,
which means Fase 04's cross-run observations/evidence model automatically
persists the facts without another technology table.

Safety posture:
- only already-alive, currently-authorized URLs are handed to WhatWeb;
- redirects are disabled at the WhatWeb layer;
- traffic is routed through Hydra's ScopeEnforcingProxy using WhatWeb's
  documented --proxy option. Until a dedicated real-binary confinement test
  proves this exact WhatWeb build honors the proxy for every request, Hydra's
  existing _crawler_confinement helper intentionally emits the
  UNTRUSTED_NETWORK_TOOL warning and STRICT_OPSEC does not allow this plugin.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from core.collection.target import AuthorizedCollectionTarget
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl

_MAX_URLS_PER_RUN = 20

# WhatWeb plugins that describe response/document metadata rather than a
# technology/product. Keeping them would turn Technology Intelligence into
# noisy "Title/IP/Country" observations instead of a software inventory.
_NON_TECHNOLOGY_PLUGINS = frozenset(
    {
        "Country",
        "Email",
        "IP",
        "Meta-Author",
        "Meta-Description",
        "PasswordField",
        "Title",
        "UncommonHeaders",
    }
)


class WhatWebPlugin(BaseToolPlugin):
    name = "whatweb"
    display_name = "WhatWeb"
    required = False
    stage_order = 42
    produces = ("technology_observations",)
    capability = "technology_intelligence"
    active_collection = True
    cacheable = False
    install_hint_macos = (
        "install WhatWeb from https://github.com/urbanadventurer/WhatWeb "
        "(no Homebrew/core formula is currently documented)"
    )
    install_hint_linux = "sudo apt install whatweb"

    def is_enabled(self) -> bool:
        return self.settings.enable_whatweb

    def get_binary_path(self) -> Path:
        return self.settings.whatweb_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        alive_urls = self._alive_urls(context)
        if not alive_urls:
            return self._skip("No alive HTTP(S) services for Technology Intelligence")

        from core.intel.scope import require_collection_scope

        scope = require_collection_scope(context)
        targets: list[AuthorizedCollectionTarget] = []
        seen: set[str] = set()
        for url in alive_urls:
            target = AuthorizedCollectionTarget.authorize(
                url,
                scope,
                capability="technology_intelligence",
                operation="whatweb",
            )
            if target is None:
                context.add_warning(f"WhatWeb: {url} failed re-authorization — skipped")
                continue
            if target.raw in seen:
                continue
            seen.add(target.raw)
            targets.append(target)
            if len(targets) >= min(self.settings.whatweb_max_urls, _MAX_URLS_PER_RUN):
                break

        if not targets:
            return self._skip("No authorized HTTP(S) services for Technology Intelligence")

        raw_path = self._output_path(context, "whatweb.json")
        normalized_path = self._output_path(context, "whatweb_technologies.jsonl")

        # WhatWeb can follow redirects by default. Never let a response choose
        # the next destination: every target is separately authorized above,
        # and --follow-redirect=never makes that authorization stable for the
        # lifetime of this invocation.
        args = [
            str(self.get_binary_path()),
            "--quiet",
            "--no-errors",
            "--colour=never",
            "--follow-redirect=never",
            f"--max-threads={self.settings.whatweb_threads}",
            f"--open-timeout={self.settings.whatweb_timeout}",
            f"--read-timeout={self.settings.whatweb_timeout}",
            f"--log-json={raw_path}",
        ]
        args.extend(t.raw for t in targets)

        self.update_status(context, ToolStatus.RUNNING)
        async with self._crawler_confinement(context) as proxy:
            proxy_netloc = urlparse(proxy.proxy_url).netloc
            args.extend(["--proxy", proxy_netloc])
            return_code, stdout, stderr = await self._run_tool(
                context, args, timeout=self.settings.whatweb_timeout
            )

        self._scan_telemetry(context, stdout, stderr)
        if return_code != 0:
            message = f"WhatWeb exited with code {return_code}"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, output_path=raw_path, message=message)

        if not raw_path.exists():
            message = "WhatWeb completed without producing its JSON log"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, message=message)

        try:
            data = json.loads(raw_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            message = f"WhatWeb produced unparseable JSON: {exc}"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, output_path=raw_path, message=message)

        records = parse_whatweb_results(data)
        count = write_jsonl(normalized_path, records, base_dir=context.output_dir)
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=normalized_path,
            lines_produced=count,
            message=f"WhatWeb: {count} normalized technology observation(s)",
        )


def _first_string(value: object) -> str | None:
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, list):
        for item in value:
            cleaned = str(item).strip()
            if cleaned:
                return cleaned
    return None


def parse_whatweb_results(data: object) -> list[dict[str, object]]:
    """Normalize WhatWeb --log-json output into Hydra technology records.

    Current WhatWeb JSON records are shaped as:
      {"target": "...", "plugins": {"Apache": {"version": ["2.4"]}, ...}}

    Plugin names are the technology identity. Version is intentionally
    optional because most WhatWeb detections are product-presence signals,
    not exact-version proofs.
    """
    if not isinstance(data, list):
        return []

    records: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        target = str(row.get("target") or "").strip()
        parsed = urlparse(target if "://" in target else f"//{target}")
        host = (parsed.hostname or "").lower().rstrip(".")
        plugins = row.get("plugins")
        if not host or not isinstance(plugins, dict):
            continue

        for plugin_name, details in plugins.items():
            technology = str(plugin_name).strip()
            if not technology or technology in _NON_TECHNOLOGY_PLUGINS:
                continue
            version: str | None = None
            if isinstance(details, dict):
                version = _first_string(details.get("version"))
            key = (host, technology.casefold(), version or "")
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "host": host,
                    "url": target,
                    "technology": technology,
                    "version": version,
                    "source": "whatweb",
                    "confidence_score": 80,
                }
            )
    return records

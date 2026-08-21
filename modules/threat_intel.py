"""URLhaus reputation enrichment for live hosts."""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from core.assets import normalize_domain
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.network import open_url

_URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


class ThreatIntelPlugin(BaseToolPlugin):
    """Check live hosts against URLhaus community intelligence."""

    name = "threat_intel"
    display_name = "URLhaus Threat Intelligence"
    required = False
    external_dependency = False
    stage_order = 45

    def is_enabled(self) -> bool:
        return self.settings.enable_threat_intel

    def get_binary_path(self) -> Path:
        return Path("built-in")

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        api_key = self.settings.urlhaus_api_key
        if not api_key:
            return self._skip("URLhaus Auth-Key not configured")

        hosts = _alive_hosts(context)
        if not hosts:
            return self._skip("No live hosts to query")

        self.update_status(context, ToolStatus.RUNNING)
        semaphore = asyncio.Semaphore(self.settings.threat_intel_concurrency)

        async def query(host: str) -> dict[str, object]:
            async with semaphore:
                try:
                    response = await asyncio.to_thread(
                        _query_urlhaus,
                        host,
                        api_key,
                        self.settings.threat_intel_timeout,
                        self.settings.effective_user_agent(),
                        self.settings.outbound_proxy_url,
                    )
                    response["query_host"] = host
                    return response
                except Exception as exc:
                    return {
                        "query_host": host,
                        "query_status": "error",
                        "error": str(exc)[:240],
                    }

        records = await asyncio.gather(*(query(host) for host in hosts))
        output_path = self._output_path(context, "threat_intel.jsonl")
        count = write_jsonl(output_path, records, base_dir=context.output_dir)
        errors = sum(1 for record in records if record.get("query_status") == "error")
        malicious = sum(1 for record in records if _has_online_url(record))
        if errors:
            context.add_warning(f"URLhaus: {errors} host lookup(s) failed")
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=f"URLhaus confirmed {malicious} host(s) with online malicious URLs",
        )


def _query_urlhaus(
    host: str,
    api_key: str,
    timeout: int,
    user_agent: str,
    proxy_url: str | None = None,
) -> dict[str, object]:
    body = urllib.parse.urlencode({"host": host}).encode("ascii")
    request = urllib.request.Request(
        _URLHAUS_HOST_ENDPOINT,
        data=body,
        method="POST",
        headers={
            "Auth-Key": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": user_agent or "hydra/1.0",
        },
    )
    with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
        payload = response.read(5 * 1024 * 1024)
    parsed = json.loads(payload.decode("utf-8", errors="replace"))
    if not isinstance(parsed, dict):
        raise ValueError("URLhaus returned a non-object response")
    return parsed


def _alive_hosts(context: PipelineContext) -> list[str]:
    hosts: set[str] = set()
    for record in context.httpx_results:
        raw = str(record.get("input") or record.get("url") or "")
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        host = normalize_domain(parsed.hostname or raw.split(":")[0])
        if host:
            hosts.add(host)
    return sorted(hosts)


def _has_online_url(record: dict[str, object]) -> bool:
    urls = record.get("urls")
    return (
        record.get("query_status") == "ok"
        and isinstance(urls, list)
        and any(isinstance(item, dict) and item.get("url_status") == "online" for item in urls)
    )

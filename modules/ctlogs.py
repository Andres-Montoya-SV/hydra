"""Certificate Transparency discovery through crt.sh."""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from pathlib import Path

from core.assets import normalize_domain
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_jsonl, write_lines
from utils.network import open_url


class CtlogsPlugin(BaseToolPlugin):
    """Discover current and historical hostnames from certificate logs."""

    name = "ctlogs"
    display_name = "Certificate Transparency"
    required = False
    external_dependency = False
    stage_order = 12

    def is_enabled(self) -> bool:
        return self.settings.enable_ctlogs

    def get_binary_path(self) -> Path:
        return Path("built-in")

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        certs_path = self._output_path(context, "ctlogs.jsonl")
        domains_path = self._output_path(context, "ctlogs_domains.txt")
        all_certs: dict[str, dict] = {}
        discovered: set[str] = set()
        warnings: list[str] = []

        self.update_status(context, ToolStatus.RUNNING)
        targets = [target.domain for target in context.targets]
        for index, domain in enumerate(targets):
            context.current_target = domain
            try:
                records = await asyncio.to_thread(
                    _fetch_crtsh,
                    domain,
                    self.settings.ctlogs_timeout,
                    self.settings.effective_user_agent(),
                    self.settings.outbound_proxy_url,
                )
            except Exception as exc:
                warnings.append(f"{domain}: {exc}")
                records = []

            for record in records:
                cert_id = str(record.get("id", ""))
                dedupe_key = cert_id or json.dumps(record, sort_keys=True, default=str)
                record["query_domain"] = domain
                all_certs[dedupe_key] = record
                discovered.update(_extract_names(record.get("name_value"), domain))

            if index < len(targets) - 1:
                await asyncio.sleep(self.settings.ctlogs_delay_seconds)

        write_jsonl(certs_path, list(all_certs.values()), base_dir=context.output_dir)
        domain_count = write_lines(domains_path, sorted(discovered), base_dir=context.output_dir)

        merged = read_lines(context.output_dir / "subdomains.txt")
        merged.extend(sorted(discovered))
        write_lines(context.output_dir / "subdomains.txt", merged, base_dir=context.output_dir)
        context.subdomains = read_lines(context.output_dir / "subdomains.txt")
        context.current_target = None

        if warnings:
            context.add_warning("Certificate Transparency: " + "; ".join(warnings[:3]))
        self.update_status(context, ToolStatus.COMPLETED, output_lines=domain_count)
        return PluginResult(
            success=True,
            output_path=domains_path,
            lines_produced=domain_count,
            message=(
                f"Discovered {domain_count} hostnames from "
                f"{len(all_certs)} certificate record(s)"
            ),
        )


def _fetch_crtsh(
    domain: str,
    timeout: int,
    user_agent: str,
    proxy_url: str | None = None,
) -> list[dict]:
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    request = urllib.request.Request(
        f"https://crt.sh/?{query}",
        headers={
            "User-Agent": user_agent or "hydra/1.0",
            "Accept": "application/json",
        },
    )
    with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
        payload = response.read(20 * 1024 * 1024)
    data = json.loads(payload.decode("utf-8", errors="replace"))
    return data if isinstance(data, list) else []


def _extract_names(raw_names: object, root_domain: str) -> set[str]:
    names: set[str] = set()
    root = normalize_domain(root_domain)
    for raw_name in str(raw_names or "").splitlines():
        candidate = normalize_domain(raw_name.removeprefix("*."))
        if candidate == root or candidate.endswith(f".{root}"):
            names.add(candidate)
    return names

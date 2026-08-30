"""Soft-404 / catch-all HTTP canary check.

Before trusting that a URL "exists" because httpx returned 200, probe a
random nonexistent path on each live host. If the canary also returns 200
with a body substantially identical to the site root, the server does not
distinguish valid from invalid routes — status-code-based existence is
unreliable (common on misconfigured WordPress, catch-all CDNs/balancers).
"""

from __future__ import annotations

import asyncio
import random
import string
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.assets import normalize_domain
from core.exceptions import ValidationError
from core.http_probe import http_get
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from core.response_diff import bodies_near_identical, body_sha256
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.security import (
    atomic_write_text,
    relative_output_path,
    validate_output_path,
    validate_safe_filename,
)


class Soft404CheckPlugin(BaseToolPlugin):
    """Compare root vs random-path responses to detect soft-404 catch-alls."""

    name = "soft404_check"
    display_name = "Soft-404 Check"
    required = False
    external_dependency = False
    stage_order = 42
    produces = ("urls",)
    capability = "http_verify"
    active_collection = True
    strict_opsec_allowed = True
    cacheable = False

    def is_enabled(self) -> bool:
        return self.settings.enable_soft404_check

    def get_binary_path(self) -> Path:
        return Path("built-in")

    def get_install_hint(self) -> str:
        return "Built-in (stdlib urllib)"

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        from core.intel.scope import allows_active_collection, require_collection_scope

        scope = require_collection_scope(context)
        targets = [
            target
            for target in _alive_targets(context)[: self.settings.soft404_max_hosts]
            if allows_active_collection(str(target.get("host") or target.get("url") or ""), scope)
        ]
        if not targets:
            return self._skip("No live HTTP services to probe for soft-404")

        self.update_status(context, ToolStatus.RUNNING)
        semaphore = asyncio.Semaphore(self.settings.soft404_concurrency)
        records: list[dict[str, object]] = []

        # Route these urllib-based requests through Hydra's local confinement
        # proxy — same DNS-rebinding/TOCTOU reasoning as httpx/browser_probe
        # (core/collection/crawler_proxy.py): `allows_active_collection`
        # above validated a hostname string; without the proxy, urllib does
        # its own independent DNS resolution and connection when `_probe_host`
        # actually runs. See docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md.
        async with self._crawler_confinement(context) as confinement_proxy:
            # Always route through the confinement proxy — it chains to
            # `Settings.outbound_proxy_url` internally when configured
            # (`core/collection/crawler_proxy.py`), so this urllib request
            # never talks to the external proxy without Hydra's
            # authorization/SSRF check running first.
            proxy_url = confinement_proxy.proxy_url

            async def probe(target: dict[str, str]) -> dict[str, object]:
                async with semaphore:
                    return await asyncio.to_thread(self._probe_host, context, target, proxy_url)

            results = await asyncio.gather(
                *(probe(target) for target in targets),
                return_exceptions=True,
            )
        soft_hosts: list[str] = []
        for target, result in zip(targets, results, strict=False):
            if isinstance(result, Exception):
                records.append(
                    {
                        "host": target["host"],
                        "soft_404_detected": False,
                        "error": str(result)[:240],
                    }
                )
                continue
            records.append(result)
            if result.get("soft_404_detected"):
                soft_hosts.append(str(result["host"]))
                context.add_warning(
                    f"soft404_check: {result['host']} returned HTTP 200 for a "
                    "random nonexistent path with a body matching the site root — "
                    "URL existence inferred from status codes is unreliable"
                )

        output_path = self._output_path(context, "soft404_check.jsonl")
        count = write_jsonl(output_path, records, base_dir=context.output_dir)
        context.metadata["soft_404_detected_hosts"] = soft_hosts

        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=f"Soft-404 detected on {len(soft_hosts)}/{len(targets)} host(s)",
        )

    def _probe_host(
        self, context: PipelineContext, target: dict[str, str], proxy_url: str | None
    ) -> dict[str, object]:
        base_url = target["url"]
        canary_path = f"/zzqq-{_random_token()}-nonexistent-path-{random.randint(1000, 9999)}"  # nosec B311  # canary path, not cryptography
        canary_url = urljoin(base_url.rstrip("/") + "/", canary_path.lstrip("/"))
        timeout = self.settings.soft404_timeout

        root = http_get(base_url, timeout=timeout, proxy_url=proxy_url)
        canary = http_get(canary_url, timeout=timeout, proxy_url=proxy_url)
        detected = _is_soft_404(root.status_code, root.body, canary.status_code, canary.body)

        raw_artifact = self._write_raw_artifact(
            context,
            target["host"],
            base_url=base_url,
            canary_url=canary_url,
            root_status=root.status_code,
            canary_status=canary.status_code,
            root_hash=root.body_hash,
            canary_hash=canary.body_hash,
            root_len=root.body_length,
            canary_len=canary.body_length,
            root_err=root.error,
            canary_err=canary.error,
        )

        return {
            "host": target["host"],
            "base_url": base_url,
            "canary_url": canary_url,
            "root_status": root.status_code,
            "canary_status": canary.status_code,
            "root_body_hash": root.body_hash,
            "canary_body_hash": canary.body_hash,
            "root_body_length": root.body_length,
            "canary_body_length": canary.body_length,
            "soft_404_detected": detected,
            "raw_artifact": raw_artifact,
        }

    def _write_raw_artifact(
        self,
        context: PipelineContext,
        host: str,
        **details: object,
    ) -> str | None:
        try:
            filename = validate_safe_filename(f"{host}.txt")
        except ValidationError:
            filename = validate_safe_filename(f"host-{abs(hash(host))}.txt")
        raw_path = validate_output_path(
            context.output_dir / "soft404_check_raw" / filename, context.output_dir
        )
        lines = [f"{key}: {value}" for key, value in details.items()]
        try:
            atomic_write_text(raw_path, "\n".join(lines) + "\n")
        except OSError as exc:
            self.logger.warning("Failed to write soft-404 raw artifact for %s: %s", host, exc)
            return None
        return relative_output_path(raw_path, context.output_dir)


def _alive_targets(context: PipelineContext) -> list[dict[str, str]]:
    targets: dict[str, dict[str, str]] = {}
    for record in context.httpx_results:
        url = str(record.get("url") or record.get("input") or "")
        if not url:
            continue
        if "://" not in url:
            url = f"https://{url}"
        host = normalize_domain(urlparse(url).hostname or "")
        if not host:
            continue
        targets.setdefault(host, {"host": host, "url": url})
    # When httpx was served from the result cache it stores alive.txt (not
    # httpx.json) as the cached artifact, so httpx_results may be empty even
    # though we have live URLs — fall back to those.
    if not targets:
        for url in context.alive_urls:
            if "://" not in url:
                url = f"https://{url}"
            host = normalize_domain(urlparse(url).hostname or "")
            if host:
                targets.setdefault(host, {"host": host, "url": url})
    if not targets:
        alive_path = context.output_dir / "alive.txt"
        if alive_path.exists():
            from utils.files import read_lines

            for url in read_lines(alive_path):
                if "://" not in url:
                    url = f"https://{url}"
                host = normalize_domain(urlparse(url).hostname or "")
                if host:
                    targets.setdefault(host, {"host": host, "url": url})
    return [targets[host] for host in sorted(targets)]


def _random_token(length: int = 10) -> str:
    return "".join(
        random.choices(
            string.ascii_lowercase + string.digits, k=length
        )  # nosec B311  # canary token, not cryptography
    )


def _is_soft_404(
    root_status: int | None,
    root_body: bytes,
    canary_status: int | None,
    canary_body: bytes,
) -> bool:
    """True when a nonexistent path returns 200 with a root-like body."""
    if canary_status != 200:
        return False
    if not canary_body:
        return False
    if root_status == 200 and root_body:
        if body_sha256(root_body) == body_sha256(canary_body):
            return True
        if bodies_near_identical(root_body, canary_body):
            return True
        return False
    # Root itself wasn't a clean 200 — still flag a 200 on a nonsense path
    # when the body is non-trivial (catch-all serving a default page).
    return len(canary_body) >= 64

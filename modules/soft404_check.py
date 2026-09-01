"""Soft-404 / catch-all HTTP canary check.

Before trusting that a URL "exists" because httpx returned 200, probe a
random nonexistent path on each live host. If the canary also returns 200
with a body substantially identical to the site root, the server does not
distinguish valid from invalid routes — status-code-based existence is
unreliable (common on misconfigured WordPress, catch-all CDNs/balancers).

Retrofitted onto `core/collection/gateway.py:CollectionGateway` — the
demonstration call site for the structural pattern: `_probe_host` receives
`AuthorizedCollectionTarget` objects, not raw URL strings, for both the root
and the canary URL (the canary is derived from an authorized root by
appending a random path, but is independently re-authorized rather than
assumed safe by association).
"""

from __future__ import annotations

import asyncio
import random
import string
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.assets import normalize_domain
from core.collection.gateway import CollectionGateway
from core.collection.target import AuthorizedCollectionTarget
from core.exceptions import ValidationError
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from core.response_diff import ResponseSnapshot, bodies_near_identical, body_sha256
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
        from core.intel.scope import require_collection_scope

        scope = require_collection_scope(context)
        candidates = _alive_targets(context)[: self.settings.soft404_max_hosts]

        self.update_status(context, ToolStatus.RUNNING)
        semaphore = asyncio.Semaphore(self.settings.soft404_concurrency)
        records: list[dict[str, object]] = []

        # CollectionGateway (core/collection/gateway.py) owns authorization +
        # confinement-proxy lifecycle + the actual request together: `_probe_host`
        # below receives an AuthorizedCollectionTarget, never a bare URL string,
        # for both the root and the (separately re-authorized) canary URL.
        async with CollectionGateway(
            scope,
            capability=self.capability,
            context=context,
            upstream_proxy_url=self.settings.outbound_proxy_url or None,
            extra_headers=self.settings.merged_headers(),
            user_agent=self.settings.effective_user_agent(),
        ) as gateway:
            authorized: list[tuple[dict[str, str], AuthorizedCollectionTarget]] = []
            for candidate in candidates:
                target = gateway.authorize(candidate["url"], operation="soft404_root")
                if target is not None:
                    authorized.append((candidate, target))
            if not authorized:
                return self._skip("No live HTTP services to probe for soft-404")

            async def probe(
                candidate: dict[str, str], root_target: AuthorizedCollectionTarget
            ) -> dict[str, object]:
                async with semaphore:
                    return await self._probe_host(context, gateway, candidate, root_target)

            results = await asyncio.gather(
                *(probe(candidate, root_target) for candidate, root_target in authorized),
                return_exceptions=True,
            )
        soft_hosts: list[str] = []
        for (candidate, _root_target), result in zip(authorized, results, strict=False):
            if isinstance(result, Exception):
                records.append(
                    {
                        "host": candidate["host"],
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
            message=f"Soft-404 detected on {len(soft_hosts)}/{len(authorized)} host(s)",
        )

    async def _probe_host(
        self,
        context: PipelineContext,
        gateway: CollectionGateway,
        candidate: dict[str, str],
        root_target: AuthorizedCollectionTarget,
    ) -> dict[str, object]:
        base_url = root_target.raw
        canary_path = f"/zzqq-{_random_token()}-nonexistent-path-{random.randint(1000, 9999)}"  # nosec B311  # canary path, not cryptography
        canary_url = urljoin(base_url.rstrip("/") + "/", canary_path.lstrip("/"))
        timeout = self.settings.soft404_timeout

        # The canary is derived from an already-authorized root URL, but it
        # is a distinct URL and is independently re-authorized here rather
        # than assumed safe by association with `root_target` — in practice
        # this always passes (same hostname), but "the canary shares the
        # root's hostname" is a code-reading assumption, not something this
        # method should trust without checking.
        canary_target = gateway.authorize(canary_url, operation="soft404_canary")

        root = await gateway.http_get(root_target, timeout=timeout, operation="soft404_root")
        if canary_target is not None:
            canary = await gateway.http_get(
                canary_target, timeout=timeout, operation="soft404_canary"
            )
        else:  # pragma: no cover - same hostname as an already-authorized root
            canary = ResponseSnapshot(status_code=None, body=b"", error="canary_not_authorized")
        detected = _is_soft_404(root.status_code, root.body, canary.status_code, canary.body)

        raw_artifact = self._write_raw_artifact(
            context,
            candidate["host"],
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
            "host": candidate["host"],
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

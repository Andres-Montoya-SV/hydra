"""Cloud storage bucket name enumeration (opt-in active probe).

SECURITY / AUTHORIZATION
------------------------
This plugin sends unauthenticated HTTP GETs to S3 / GCS / Azure Blob endpoints
derived from the target brand. Disabled by default. Only enable with ownership
or explicit authorization.

It detects whether a candidate bucket *exists* and whether it is publicly
listable. It does **not** download object contents beyond observing a public
listing response, and never uploads or modifies anything.
"""

from __future__ import annotations

import asyncio
import random
import string
from pathlib import Path

from core.domain import parse_hostname
from core.http_probe import http_get
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from core.response_diff import ResponseSnapshot
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.security import atomic_write_text, relative_output_path, validate_output_path

_BUCKET_SUFFIXES: tuple[str, ...] = (
    "",
    "-backup",
    "-backups",
    "-dev",
    "-development",
    "-staging",
    "-stage",
    "-prod",
    "-production",
    "-assets",
    "-static",
    "-media",
    "-uploads",
    "-files",
    "-data",
    "-db",
    "-database",
    "-logs",
    "-test",
    "-tmp",
    "-temp",
    "-old",
    "-archive",
    "-public",
    "-private",
    "-internal",
    "-www",
)


class CloudBucketEnumPlugin(BaseToolPlugin):
    """Permute brand-like bucket names and check S3 / GCS / Azure existence."""

    name = "cloud_bucket_enum"
    display_name = "Cloud Bucket Enumeration"
    required = False
    external_dependency = False
    stage_order = 56
    cacheable = False
    produces = ("urls",)
    capability = "cloud_enum"
    active_collection = True
    strict_opsec_allowed = True

    def is_enabled(self) -> bool:
        return self.settings.enable_cloud_bucket_enum

    def get_binary_path(self) -> Path:
        return Path("built-in")

    def get_install_hint(self) -> str:
        return "Built-in (stdlib urllib) — opt-in active probe"

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        from core.intel.scope import require_collection_scope

        require_collection_scope(context)
        if not self.settings.cloud_bucket_enum_authorize_derived:
            return self._skip(
                "Cloud-derived endpoints (*.s3.amazonaws.com, storage.googleapis.com, "
                "*.blob.core.windows.net) are not seed-scoped. Set "
                "CLOUD_BUCKET_ENUM_AUTHORIZE_DERIVED=true to opt in to probing them. "
                "Discovery of a brand name does not authorize cloud infrastructure probes."
            )
        brands = _brand_labels(context)
        if not brands:
            return self._skip("No root domains available for bucket name permutation")

        context.add_warning(
            "Cloud Bucket Enumeration sends active unauthenticated HTTP requests to "
            "S3/GCS/Azure endpoints derived from the target brand. Enable only with "
            "ownership or explicit authorization. Existence/listing only — no object "
            "download beyond a public list response, no writes."
        )
        self.update_status(context, ToolStatus.RUNNING)

        delay = max(0, self.settings.cloud_bucket_enum_delay_ms) / 1000.0
        timeout = self.settings.cloud_bucket_enum_timeout
        raw_lines: list[str] = []

        # Route these urllib-based requests through Hydra's local confinement
        # proxy — same DNS-rebinding/TOCTOU reasoning as httpx/browser_probe/
        # soft404_check (core/collection/crawler_proxy.py): `authorize_active_
        # indicator` below validates a hostname string per candidate; without
        # the proxy, urllib does its own independent DNS resolution and
        # connection when the request actually runs.
        async with self._crawler_confinement(context) as confinement_proxy:
            return await self._run_probes(
                context, confinement_proxy.proxy_url, delay, timeout, raw_lines, brands
            )

    async def _run_probes(
        self,
        context: PipelineContext,
        confinement_proxy_url: str,
        delay: float,
        timeout: int,
        raw_lines: list[str],
        brands: list[str],
    ) -> PluginResult:
        from core.intel.authorize import authorize_active_indicator
        from core.intel.scope import require_collection_scope

        scope = require_collection_scope(context)
        # Always route through the confinement proxy — see the identical
        # comment in modules/soft404_check.py.
        proxy = confinement_proxy_url

        # Calibrate "does not exist" per provider with a random canary name.
        # Alphanumeric only, ≤24 chars: Azure storage-account labels reject
        # hyphens; keeping the label short also avoids intermittent S3
        # virtual-host DNS failures seen with long ``*.s3.amazonaws.com`` names.
        canary_name = f"reconprobe{_random_token(8)}"
        baselines: dict[str, str] = {}
        for provider in ("s3", "gcs", "azure"):
            url = _provider_url(provider, canary_name)
            decision = authorize_active_indicator(
                url, scope, "cloud_bucket_enum", "cloud_bucket_enum_canary"
            )
            if not decision.allowed:
                # Defense in depth: the entry check above already requires
                # cloud_bucket_enum_authorize_derived, but the request itself
                # must still be authorized against the actual CollectionScope
                # object per host, like every other active-collection plugin —
                # not just a Settings flag checked once at plugin entry.
                context.add_warning(
                    f"cloud_bucket_enum: canary for {provider} not authorized by "
                    f"CollectionScope ({decision.reason}); skipped"
                )
                baselines[provider] = "not_authorized"
                continue
            snap = await asyncio.to_thread(http_get, url, timeout=timeout, proxy_url=proxy)
            classification = _classify(provider, snap)
            # Provider-specific canary semantics:
            # - Azure: NXDOMAIN for a random account name is the normal
            #   "does not exist" signal (storage accounts are DNS labels).
            # - S3: *.s3.amazonaws.com usually has wildcard DNS, so a gaierror
            #   on the canary is an environment/resolver problem, not proof
            #   the bucket naming is wrong.
            # - GCS: fixed host — DNS failure means the network is broken.
            if _is_dns_failure(snap) and provider == "azure":
                baselines[provider] = "not_found"
                classification = "not_found"
            elif _is_dns_failure(snap):
                baselines[provider] = "dns_failure"
                context.add_warning(_canary_warning(provider, "dns_failure", snap))
            else:
                baselines[provider] = classification
                if classification != "not_found":
                    context.add_warning(_canary_warning(provider, classification, snap))
            raw_lines.append(
                f"CANARY provider={provider} bucket={canary_name} url={url}\n"
                f"  status={snap.status_code} class={baselines[provider]} "
                f"len={snap.body_length} err={snap.error}"
            )
            if delay:
                await asyncio.sleep(delay)

        candidates = _candidate_buckets(brands)
        hits: list[dict[str, object]] = []
        total_probes = 3  # canaries
        denied_probes = 0
        for bucket in candidates:
            for provider in ("s3", "gcs", "azure"):
                url = _provider_url(provider, bucket)
                decision = authorize_active_indicator(
                    url, scope, "cloud_bucket_enum", "cloud_bucket_enum_probe"
                )
                if not decision.allowed:
                    denied_probes += 1
                    continue
                snap = await asyncio.to_thread(http_get, url, timeout=timeout, proxy_url=proxy)
                total_probes += 1
                classification = _classify(provider, snap)
                raw_lines.append(
                    f"PROBE provider={provider} bucket={bucket} url={url}\n"
                    f"  status={snap.status_code} class={classification} "
                    f"len={snap.body_length} err={snap.error}"
                )
                if classification in {"exists_private", "public_listable"}:
                    hits.append(
                        {
                            "bucket": bucket,
                            "provider": provider,
                            "url": url,
                            "status_code": snap.status_code,
                            "classification": classification,
                            "exists": True,
                            "public_listable": classification == "public_listable",
                            "body_length": snap.body_length,
                            "body_hash": snap.body_hash,
                            "canary_baseline": baselines.get(provider),
                        }
                    )
                if delay:
                    await asyncio.sleep(delay)

        if denied_probes:
            context.add_warning(
                f"cloud_bucket_enum: {denied_probes} candidate probe(s) were not "
                "authorized by CollectionScope and were never requested"
            )

        raw_artifact = self._write_raw_artifact(context, "\n".join(raw_lines) + "\n")
        for row in hits:
            row["raw_artifact"] = raw_artifact

        output_path = self._output_path(context, "cloud_bucket_enum.jsonl")
        count = write_jsonl(output_path, hits, base_dir=context.output_dir)
        context.metadata["cloud_bucket_enum_probes"] = total_probes
        context.metadata["cloud_bucket_enum_denied_probes"] = denied_probes
        context.metadata["cloud_bucket_enum_candidates"] = len(candidates)
        context.metadata["cloud_bucket_enum_hits"] = count
        context.metadata["cloud_bucket_enum_brands"] = brands

        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=(
                f"Cloud bucket enum: {count} existing bucket(s) "
                f"({total_probes} requests, {len(candidates)} names × 3 providers)"
            ),
        )

    def _write_raw_artifact(self, context: PipelineContext, content: str) -> str | None:
        raw_path = validate_output_path(
            context.output_dir / "cloud_bucket_enum_raw.txt", context.output_dir
        )
        try:
            atomic_write_text(raw_path, content)
        except OSError as exc:
            self.logger.warning("Failed to write cloud_bucket_enum raw artifact: %s", exc)
            return None
        return relative_output_path(raw_path, context.output_dir)


def _brand_labels(context: PipelineContext) -> list[str]:
    labels: list[str] = []
    for target in context.targets:
        if not target.domain:
            continue
        root = parse_hostname(target.domain)[2] or target.domain
        # metaversejustice.com → metaversejustice
        brand = root.split(".")[0].lower().strip("-.")
        if brand and brand not in labels:
            labels.append(brand)
    return labels


def _candidate_buckets(brands: list[str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for brand in brands:
        for suffix in _BUCKET_SUFFIXES:
            for variant in (f"{brand}{suffix}", f"{brand}{suffix.replace('-', '.')}"):
                cleaned = variant.strip(".-").lower()
                if not cleaned or cleaned in seen:
                    continue
                # S3 bucket naming: 3–63 chars, lowercase, digits, dots, hyphens.
                if len(cleaned) < 3 or len(cleaned) > 63:
                    continue
                if ".." in cleaned or cleaned.startswith(".") or cleaned.endswith("."):
                    continue
                seen.add(cleaned)
                names.append(cleaned)
    return names


def _provider_url(provider: str, bucket: str) -> str:
    if provider == "s3":
        return f"https://{bucket}.s3.amazonaws.com/"
    if provider == "gcs":
        return f"https://storage.googleapis.com/{bucket}"
    if provider == "azure":
        return f"https://{bucket}.blob.core.windows.net/{bucket}?restype=container&comp=list"
    raise ValueError(f"unknown provider: {provider}")


def _is_dns_failure(snap: ResponseSnapshot) -> bool:
    err = (snap.error or "").lower()
    return snap.status_code is None and any(
        marker in err
        for marker in (
            "nodename",
            "name or service not known",
            "getaddrinfo",
            "nxdomain",
            "gaierror",
            "errno 8",
        )
    )


def _canary_warning(provider: str, classification: str, snap: ResponseSnapshot) -> str:
    """Explain canary calibration failures — especially DNS on virtual-hosted URLs."""
    base = (
        f"cloud_bucket_enum: canary against {provider} did not return "
        f"'not_found' (got {classification})"
    )
    if _is_dns_failure(snap):
        return (
            f"{base} — DNS resolution failure for a dynamic subdomain "
            f"({provider} uses '{{bucket}}.…' virtual-hosted URLs; GCS uses a "
            "fixed host). This often means the current network cannot resolve "
            "arbitrary cloud subdomains; results for this provider may be "
            "inconclusive — try running from a network with normal public DNS"
        )
    return f"{base} — results for this provider may be inconclusive"


def _classify(provider: str, snap: ResponseSnapshot) -> str:
    """Map provider response → not_found | exists_private | public_listable | unknown."""
    body = snap.body.decode("utf-8", errors="replace") if snap.body else ""
    status = snap.status_code
    lower = body.lower()
    err = (snap.error or "").lower()

    # DNS NXDOMAIN / resolution failure for a virtual-hosted bucket name almost
    # always means the account/bucket label does not exist (especially Azure).
    if status is None and any(
        marker in err
        for marker in ("nodename", "name or service not known", "getaddrinfo", "nxdomain")
    ):
        return "not_found"

    if snap.error and status is None:
        return "unknown"

    if provider == "s3":
        if "nosuchbucket" in lower.replace(" ", "") or "nosuchbucket" in lower:
            return "not_found"
        if "accessdenied" in lower.replace(" ", "") or "accessdenied" in lower:
            return "exists_private"
        if status == 200 and ("<listbucketresult" in lower or "<contents>" in lower):
            return "public_listable"
        if status == 404:
            return "not_found"
        if status in {301, 302, 307, 308} and "s3" in lower:
            # Redirect to regional endpoint often means the name exists.
            return "exists_private"
        return "unknown"

    if provider == "gcs":
        if "nosuchbucket" in lower.replace(" ", "") or '"code": 404' in lower:
            return "not_found"
        if status == 404:
            return "not_found"
        if "accessdenied" in lower.replace(" ", "") or status == 403:
            return "exists_private"
        if status == 200 and (
            "<listbucketresult" in lower or "<contents>" in lower or '"items"' in lower
        ):
            return "public_listable"
        return "unknown"

    if provider == "azure":
        if "containernotfound" in lower.replace(" ", "") or "resourcenotfound" in lower.replace(
            " ", ""
        ):
            return "not_found"
        if status == 404:
            return "not_found"
        if "authenticationfailed" in lower.replace(
            " ", ""
        ) or "authorizationfailure" in lower.replace(" ", ""):
            return "exists_private"
        if status == 403:
            return "exists_private"
        if status == 200 and (
            "<enumerationresults" in lower or "<blobs>" in lower or "<blob>" in lower
        ):
            return "public_listable"
        return "unknown"

    return "unknown"


def _random_token(length: int = 8) -> str:
    return "".join(
        random.choices(
            string.ascii_lowercase + string.digits, k=length
        )  # nosec B311  # canary bucket name, not cryptography
    )

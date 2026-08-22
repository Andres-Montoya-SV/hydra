"""httpx HTTP probing plugin."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.intel.model import CollectionStatus, ScopeStatus
from core.intel.scope import (
    CollectionScope,
    allows_active_collection,
    require_collection_scope,
    scope_status_for,
)
from core.models import PipelineContext
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_jsonl, write_jsonl, write_lines
from utils.security import atomic_write_text, validate_output_path

# httpx followed the redirect from an authorized input. That is observation,
# not permission to treat the destination as an active-collection target.
_REDIRECT_CONFIDENCE = 95


class HttpxPlugin(BaseToolPlugin):
    name = "httpx"
    display_name = "httpx"
    required = True
    stage_order = 40
    produces = ("urls", "certificates", "technologies", "ips")
    followup_kinds = ("domains",)
    capability = "http_probe"
    active_collection = True
    strict_opsec_allowed = True
    install_hint_macos = "brew install httpx"
    install_hint_linux = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

    def is_enabled(self) -> bool:
        return True

    def get_binary_path(self) -> Path:
        return self.settings.httpx_path

    def _build_args(
        self, context: PipelineContext, input_path: Path, json_output: Path
    ) -> list[str]:
        args = [
            str(self.resolved_binary(context)),
            "-l",
            str(input_path),
            "-silent",
            "-json",
            "-o",
            str(json_output),
            "-t",
            str(self.settings.httpx_threads),
            "-timeout",
            "10",
            "-follow-redirects",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-web-server",
            "-location",
            "-favicon",
            "-hash",
            "sha256",
            "-include-response-header",
            "-disable-update-check",
            "-no-stdin",
        ]

        if not self.settings.strict_opsec:
            args.extend(["-ip", "-cname", "-tls-probe", "-tls-grab"])
        elif self.settings.outbound_proxy_url:
            args.extend(["-proxy", self.settings.outbound_proxy_url])

        headers = self.settings.merged_headers()
        for key, value in headers.items():
            args.extend(["-H", f"{key}: {value}"])

        user_agent = self.settings.effective_user_agent()
        if user_agent:
            args.extend(["-H", f"User-Agent: {user_agent}"])

        return args

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        input_path = self._authorized_input(context, input_path)
        scope = require_collection_scope(context)
        suffix = str(context.metadata.get("httpx_output_suffix") or "")
        json_output = self._output_path(context, f"httpx{suffix}.json")
        alive_output = self._output_path(context, f"alive{suffix}.txt")
        csv_output = self._output_path(context, f"httpx{suffix}.csv")
        redirects_output = self._output_path(context, f"httpx_redirects{suffix}.jsonl")

        if not input_path.exists() or input_path.stat().st_size == 0:
            return PluginResult(success=False, message="No hosts to probe")

        args = self._build_args(context, input_path, json_output)
        # httpx writes JSONL via -o; must not capture stdout (would overwrite -o file)
        result = await self._execute_self_output(context, args, json_output, allow_empty=True)

        records = read_jsonl(json_output) if json_output.exists() else []
        annotated, alive_urls, redirect_obs = authorize_httpx_records(
            records, scope, raw_artifact=json_output.name
        )
        if annotated:
            write_jsonl(json_output, annotated, base_dir=context.output_dir)
        context.httpx_results = annotated

        write_lines(alive_output, alive_urls, base_dir=context.output_dir)
        context.alive_urls = alive_urls
        write_jsonl(redirects_output, redirect_obs, base_dir=context.output_dir)
        if redirect_obs:
            context.metadata.setdefault("http_redirects_out_of_scope", [])
            denied = context.metadata["http_redirects_out_of_scope"]
            if isinstance(denied, list):
                for item in redirect_obs:
                    dest = str(item.get("final_url") or "")
                    if dest and dest not in denied:
                        denied.append(dest)
            context.add_warning(
                f"httpx: recorded {len(redirect_obs)} HTTP redirect(s) out of scope "
                "(observation only — destination not added to alive.txt)"
            )

        if annotated:
            self._write_csv(csv_output, annotated, context)

        return PluginResult(
            success=result.success,
            output_path=json_output,
            lines_produced=len(alive_urls),
            message=f"Found {len(alive_urls)} live HTTP services",
            data={"records": len(annotated), "redirect_observations": len(redirect_obs)},
        )

    def _write_csv(self, path: Path, records: list[dict], context: PipelineContext) -> None:
        if not records:
            return
        path = validate_output_path(path, context.output_dir)
        fieldnames = sorted({key for rec in records for key in rec.keys()})
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            flat = {k: json.dumps(v) if isinstance(v, list | dict) else v for k, v in rec.items()}
            writer.writerow(flat)
        atomic_write_text(path, output.getvalue())


def httpx_input_url(record: dict) -> str:
    """Original request target. Prefer explicit input over the followed URL."""
    raw = str(record.get("input") or record.get("host") or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return raw
    final = str(record.get("url") or "").strip()
    scheme = urlparse(final).scheme if final else "https"
    if scheme not in {"http", "https"}:
        scheme = "https"
    return f"{scheme}://{raw}"


def httpx_final_url(record: dict) -> str:
    """Landing URL after httpx `-follow-redirects` (last hop, not the first)."""
    explicit = str(record.get("final_url") or record.get("url") or "").strip()
    if explicit:
        return explicit
    hops = httpx_redirect_chain(record)
    if hops:
        return hops[-1]
    return httpx_input_url(record)


def httpx_redirect_chain(record: dict) -> list[str]:
    """Ordered hop URLs. Last entry is the destination httpx actually fetched."""
    hops: list[str] = []
    origin = httpx_input_url(record)
    if origin:
        hops.append(origin)

    chain = record.get("chain") or record.get("redirect_chain") or []
    if isinstance(chain, list):
        for item in chain:
            url = ""
            if isinstance(item, dict):
                url = str(item.get("url") or item.get("location") or "").strip()
            else:
                url = str(item).strip()
            if url and "://" not in url and hops:
                url = urljoin(hops[-1], url)
            if url and url not in hops:
                hops.append(url)

    location = str(record.get("location") or "").strip()
    if location:
        base = hops[-1] if hops else origin
        loc = location if "://" in location else urljoin(base or location, location)
        if loc and loc not in hops:
            hops.append(loc)

    final = str(record.get("final_url") or record.get("url") or "").strip()
    if final and final not in hops:
        hops.append(final)
    return hops


def authorized_alive_url(record: dict, scope: CollectionScope) -> str | None:
    """URL that may be written to alive.txt / consumed by later active plugins.

    In-scope landing URLs stay active targets. Out-of-scope redirect
    destinations are never authorization, even when httpx followed them.
    """
    final = httpx_final_url(record)
    if final and allows_active_collection(final, scope):
        return final
    origin = httpx_input_url(record)
    if origin and allows_active_collection(origin, scope):
        # Keep the authorized origin as a crawl/scan target; never the OOS dest.
        return origin
    return None


def authorize_httpx_records(
    records: list[dict],
    scope: CollectionScope,
    *,
    raw_artifact: str = "httpx.json",
) -> tuple[list[dict], list[str], list[dict]]:
    """Annotate records, select authorized alive URLs, and record OOS redirects."""
    annotated: list[dict] = []
    alive: list[str] = []
    observations: list[dict] = []
    seen_alive: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        item = dict(record)
        origin = httpx_input_url(item)
        final = httpx_final_url(item)
        hops = httpx_redirect_chain(item)
        origin_status = scope_status_for(origin, scope) if origin else ScopeStatus.UNKNOWN
        final_status = scope_status_for(final, scope) if final else ScopeStatus.UNKNOWN
        item["input_scope_status"] = origin_status.value
        item["scope_status"] = final_status.value
        item["redirect_chain"] = hops
        annotated.append(item)

        left_scope = bool(final) and not allows_active_collection(final, scope)
        redirected = bool(origin and final and origin.rstrip("/") != final.rstrip("/"))
        if left_scope and (redirected or hops):
            observations.append(
                _redirect_observation(
                    origin=origin,
                    final=final,
                    hops=hops,
                    scope_status=final_status,
                    raw_artifact=raw_artifact,
                )
            )

        alive_url = authorized_alive_url(item, scope)
        if alive_url and alive_url not in seen_alive:
            seen_alive.add(alive_url)
            alive.append(alive_url)
    return annotated, alive, observations


def _redirect_observation(
    *,
    origin: str,
    final: str,
    hops: list[str],
    scope_status: ScopeStatus,
    raw_artifact: str,
) -> dict:
    return {
        "input": origin,
        "final_url": final,
        "redirect_chain": hops,
        "scope_status": scope_status.value,
        "collection_status": CollectionStatus.NOT_ALLOWED.value,
        "reason": "http_redirect_destination_not_authorized",
        "confidence_score": _REDIRECT_CONFIDENCE,
        "raw_artifact": raw_artifact,
    }

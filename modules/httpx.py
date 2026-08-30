"""httpx HTTP probing plugin."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.collection.audit import NetworkRequestRecord, append_network_request
from core.collection.target import AuthorizedCollectionTarget
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

# httpx observed the redirect Location header from an authorized input. That
# is observation, not permission to treat the destination as an
# active-collection target — it is never fetched unless authorized first.
_REDIRECT_CONFIDENCE = 95

# A redirect Location outside these schemes is never followed, regardless of
# what CollectionScope says about any hostname portion it might parse out —
# file:/ftp:/gopher:/data:/javascript:/blob: are not an HTTP follow-up hop.
_ALLOWED_REDIRECT_SCHEMES = frozenset({"http", "https"})


def _record_hop_decision(
    context: object,
    *,
    url: str,
    redirect_hop: int,
    allowed: bool,
    reason: str,
    completed: bool = False,
    resolved_ips: tuple[str, ...] = (),
) -> None:
    """Append one redirect-hop authorization decision to the durable
    `intel_network_requests` audit trail (core/collection/audit.py)."""
    from urllib.parse import urlparse as _urlparse

    parsed = _urlparse(url) if "://" in url else None
    append_network_request(
        context,
        NetworkRequestRecord(
            collector="httpx",
            capability="http_probe",
            method="GET",
            url=url,
            normalized_hostname=(parsed.hostname or "") if parsed else "",
            resolved_ip=resolved_ips[0] if resolved_ips else "",
            port=parsed.port if parsed else None,
            redirect_hop=redirect_hop,
            decision="ALLOW" if allowed else "DENY",
            reason=reason,
            network_attempted=allowed,
            network_completed=completed,
        ),
    )


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
        self,
        context: PipelineContext,
        input_path: Path | None,
        json_output: Path,
        *,
        target_url: str | None = None,
        confinement_proxy_url: str | None = None,
    ) -> list[str]:
        """Build httpx argv.

        Never pass `-follow-redirects`: httpx would fetch the redirect
        destination itself before Hydra gets a chance to authorize it. httpx
        only reports the `Location` header (`-location`); the caller decides,
        hop by hop, whether to issue a follow-up request via `target_url`.

        `confinement_proxy_url` (`ScopeEnforcingProxy.proxy_url`, started by
        the caller via `self._crawler_confinement(context)`) routes httpx's
        own DNS resolution and connection through Hydra's local proxy —
        without it, `AuthorizedCollectionTarget`'s destination-IP validation
        (`core/collection/ssrf.py`) checks one resolution while httpx
        performs a second, independent one when it actually connects, which
        is exactly the DNS-rebinding/TOCTOU gap the proxy closes for
        katana/hakrawler/nuclei already. See docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md.
        """
        args = [str(self.resolved_binary(context))]
        if target_url is not None:
            args.extend(["-u", target_url])
        else:
            args.extend(["-l", str(input_path)])
        args.extend(
            [
                "-silent",
                "-json",
                "-o",
                str(json_output),
                "-t",
                str(self.settings.httpx_threads),
                "-timeout",
                "10",
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
        )

        if not self.settings.strict_opsec:
            args.extend(["-ip", "-cname", "-tls-probe", "-tls-grab"])
            if confinement_proxy_url:
                args.extend(["-proxy", confinement_proxy_url])
        elif self.settings.outbound_proxy_url:
            # External OPSEC-hiding proxy takes priority over local
            # confinement here: chaining Hydra's local proxy in front of an
            # external proxy (so both the SSRF check AND the IP-hiding
            # guarantee hold at once) is out of scope this turn — the
            # DNS-rebinding/TOCTOU protection `confinement_proxy_url`
            # otherwise provides does not apply in this specific
            # configuration. Documented, not hidden — see
            # docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md.
            args.extend(["-proxy", self.settings.outbound_proxy_url])
        elif confinement_proxy_url:
            args.extend(["-proxy", confinement_proxy_url])

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

        # Route httpx's own DNS resolution and connections through Hydra's
        # local confinement proxy — the same mechanism already proven live
        # for katana/hakrawler/nuclei (core/collection/crawler_proxy.py).
        # Without this, `AuthorizedCollectionTarget`'s destination-IP check
        # validates one DNS answer while httpx independently resolves and
        # connects a second time — a DNS-rebinding/TOCTOU window. See
        # docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md.
        async with self._crawler_confinement(context) as proxy:
            args = self._build_args(
                context, input_path, json_output, confinement_proxy_url=proxy.proxy_url
            )
            # httpx writes JSONL via -o; must not capture stdout (would overwrite -o file)
            result = await self._execute_self_output(context, args, json_output, allow_empty=True)

            records = read_jsonl(json_output) if json_output.exists() else []
            resolved_records = [
                await self._resolve_authorized_redirects(
                    context, record, scope, suffix, index, proxy.proxy_url
                )
                for index, record in enumerate(records)
            ]
        annotated, alive_urls, redirect_obs = authorize_httpx_records(
            resolved_records, scope, raw_artifact=json_output.name
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

    async def _resolve_authorized_redirects(
        self,
        context: PipelineContext,
        record: dict,
        scope: CollectionScope,
        suffix: str,
        record_index: int,
        confinement_proxy_url: str = "",
    ) -> dict:
        """Walk a redirect chain hop by hop, authorizing each destination before
        httpx is allowed to request it.

        `record` is the result of the single request httpx already made to an
        authorized host (no `-follow-redirects`, so it never fetched past that
        first hop on its own). Every subsequent hop named by `Location` is
        checked against `scope` before Hydra issues the follow-up httpx
        request for it. The walk stops — without ever requesting the
        destination — at the first hop that is not authorized.
        """
        origin = httpx_input_url(record)
        visited: list[str] = [origin] if origin else []
        current = record
        current_url = str(current.get("url") or origin)
        if current_url and current_url not in visited:
            visited.append(current_url)

        blocked_target: str | None = None
        hop = 0
        max_hops = self.settings.httpx_max_redirect_hops
        while hop < max_hops:
            location = str(current.get("location") or "").strip()
            if not location:
                break
            next_url = location if "://" in location else urljoin(current_url, location)
            next_scheme = urlparse(next_url).scheme.lower() if "://" in next_url else ""
            if next_scheme and next_scheme not in _ALLOWED_REDIRECT_SCHEMES:
                # A redirect to file:/ftp:/gopher:/data:/javascript:/blob: is
                # never a same-capability HTTP follow-up hop, regardless of
                # what CollectionScope says about the hostname portion (which
                # may not even exist for these schemes).
                blocked_target = next_url
                _record_hop_decision(
                    context,
                    url=next_url,
                    redirect_hop=hop + 1,
                    allowed=False,
                    reason=f"blocked_scheme:{next_scheme}",
                )
                break
            target, deny_reason = AuthorizedCollectionTarget.authorize_verbose(
                next_url, scope, capability="http_probe", operation="httpx_redirect_hop"
            )
            if target is None:
                blocked_target = next_url
                _record_hop_decision(
                    context,
                    url=next_url,
                    redirect_hop=hop + 1,
                    allowed=False,
                    reason=deny_reason,
                )
                break
            hop += 1
            hop_record = await self._fetch_single_hop(
                context,
                target,
                suffix=suffix,
                record_index=record_index,
                hop=hop,
                confinement_proxy_url=confinement_proxy_url,
            )
            _record_hop_decision(
                context,
                url=next_url,
                redirect_hop=hop,
                allowed=True,
                reason="in_scope",
                completed=hop_record is not None,
                resolved_ips=target.resolved_ips,
            )
            if hop_record is None:
                # Follow-up request failed/produced nothing usable — stop where
                # we are; `current` already reflects the last hop we reached.
                break
            current = hop_record
            current_url = str(current.get("url") or next_url)
            if current_url not in visited:
                visited.append(current_url)

        # `input`/scope bookkeeping always tracks the original origin host, even
        # when `current` came from a later hop's own httpx response. `host`,
        # `url`, `tech`, `title`, etc. intentionally stay whatever `current`
        # (the last hop Hydra actually requested) reports — that data
        # describes that hop, not the original origin.
        merged = dict(current)
        merged["input"] = record.get("input", origin)
        merged["chain"] = [{"url": url} for url in visited]
        merged["final_url"] = blocked_target or current_url
        return merged

    async def _fetch_single_hop(
        self,
        context: PipelineContext,
        target: AuthorizedCollectionTarget,
        *,
        suffix: str,
        record_index: int,
        hop: int,
        confinement_proxy_url: str = "",
    ) -> dict | None:
        """Issue the httpx request for one already-authorized redirect hop.

        Takes the authorization proof itself, not a bare URL string — there
        is no way to call this with a destination that was not actually
        checked by `AuthorizedCollectionTarget.authorize()`. Routed through
        `confinement_proxy_url` for the same DNS-rebinding/TOCTOU reason as
        the initial request (`run()`) — the Python-level check above
        validates one DNS answer; the proxy independently resolves,
        validates, and pins the actual connection to that same answer.
        """
        hop_output = self._output_path(context, f"httpx_hop{suffix}_{record_index}_{hop}.json")
        args = self._build_args(
            context,
            None,
            hop_output,
            target_url=target.raw,
            confinement_proxy_url=confinement_proxy_url,
        )
        result = await self._execute_self_output(context, args, hop_output, allow_empty=True)
        records = read_jsonl(hop_output) if hop_output.exists() else []
        try:
            hop_output.unlink()
        except OSError:
            pass
        if not result.success or not records:
            return None
        return records[0]

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
    """Landing URL after hop-by-hop authorized redirect resolution (last hop, not the first).

    May be a hop that was never fetched — the destination of an
    unauthorized `Location` header, reported for observation only.
    """
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

"""Passive-DNS enrichment for out-of-scope certificate siblings.

Off-root certificate SANs discovered by `ctlogs` are recorded as
observations, never actively DNS-resolved — resolving a hostname is a
target-directed network operation, and a certificate sibling is
`OUT_OF_SCOPE`/`NOT_ALLOWED` by design (see `modules/ctlogs.py`,
`core/intel/engine.py::ingest_ct_records`). Hydra never opens a connection
whose destination is the sibling hostname.

The correct way to learn whether a sibling shares infrastructure is the
same shape already used for certificate SANs (crt.sh) and reputation
(URLhaus): ask a fixed third-party database what IPs it has already seen
the hostname resolve to, historically. The hostname is query *content*
sent to a fixed endpoint — Hydra's own connection always goes to the
passive-DNS provider, never to the sibling — the same FIXED_THIRD_PARTY /
THIRD_PARTY_OBSERVATION classification as `modules/ctlogs.py` and
`modules/threat_intel.py` (see `docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md`).

Two providers:

- Mnemonic PassiveDNS (`api.mnemonic.no`) — default, no API key. Public
  data is TLP-white only, rate-limited by the provider to 10 requests/min
  and 1000/day (verified against the current published API spec).
- SecurityTrails (`api.securitytrails.com`) — optional, additive. Only
  queried when `SECURITYTRAILS_API_KEY` is configured; silently skipped
  otherwise, same opt-in pattern as `WPSCAN_API_TOKEN`/`URLHAUS_API_KEY`.
  A SecurityTrails failure never erases a successful Mnemonic result.

Candidates are never arbitrary: only hostnames already observed this run
as out-of-scope certificate siblings (present in this run's `ctlogs.jsonl`
SAN set, but not authorized for active collection) are queried, capped at
`passive_dns_max_candidates`.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from modules.ctlogs import extract_all_names
from utils.files import read_jsonl, write_jsonl
from utils.network import open_url
from utils.security import atomic_write_text, relative_output_path, validate_output_path

_MNEMONIC_ENDPOINT = "https://api.mnemonic.no/pdns/v3/{query}"
_SECURITYTRAILS_ENDPOINT = "https://api.securitytrails.com/v1/history/{hostname}/dns/a"


class PassiveDnsPlugin(BaseToolPlugin):
    """Passive-DNS lookups for certificate siblings, never the siblings themselves."""

    name = "passive_dns"
    display_name = "Passive DNS (certificate siblings)"
    required = False
    external_dependency = False
    stage_order = 46
    produces = ("passive_dns",)
    capability = "passive_dns"
    strict_opsec_allowed = True

    def is_enabled(self) -> bool:
        return self.settings.enable_passive_dns

    def get_binary_path(self) -> Path:
        return Path("built-in")

    def get_install_hint(self) -> str:
        return "Built-in (Mnemonic PassiveDNS, no key; optional SECURITYTRAILS_API_KEY)"

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        candidates = _sibling_candidates(context, self.settings.passive_dns_max_candidates)
        if not candidates:
            return self._skip("No out-of-scope certificate siblings to query")

        self.update_status(context, ToolStatus.RUNNING)
        securitytrails_key = self.settings.securitytrails_api_key
        timeout = self.settings.passive_dns_timeout
        proxy_url = self.settings.outbound_proxy_url
        user_agent = self.settings.effective_user_agent()

        records: list[dict[str, object]] = []
        raw_chunks: list[str] = []
        errors: list[str] = []
        for index, host in enumerate(candidates):
            record, raw = await asyncio.to_thread(
                _query_host, host, securitytrails_key, timeout, user_agent, proxy_url
            )
            records.append(record)
            raw_chunks.append(raw)
            if record.get("query_status") == "error":
                errors.append(host)
            if index < len(candidates) - 1:
                await asyncio.sleep(self.settings.passive_dns_delay_seconds)

        raw_rel = self._write_raw(context, "\n".join(raw_chunks) + "\n")
        for record in records:
            record["raw_artifact"] = raw_rel

        output_path = self._output_path(context, "passive_dns.jsonl")
        count = write_jsonl(output_path, records, base_dir=context.output_dir)
        resolved = sum(1 for r in records if r.get("ip"))
        if errors:
            context.add_warning(f"Passive DNS: {len(errors)} lookup(s) failed")
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=(
                f"Passive DNS: {resolved}/{len(candidates)} certificate "
                "sibling(s) resolved historically"
            ),
        )

    def _write_raw(self, context: PipelineContext, content: str) -> str | None:
        raw_path = validate_output_path(
            context.output_dir / "passive_dns_raw.txt", context.output_dir
        )
        try:
            atomic_write_text(raw_path, content)
        except OSError:
            return None
        return relative_output_path(raw_path, context.output_dir)


def _sibling_candidates(context: PipelineContext, max_candidates: int) -> list[str]:
    """Out-of-scope certificate SANs observed this run — never arbitrary domains."""
    ct_path = context.output_dir / "ctlogs.jsonl"
    if not ct_path.exists():
        return []
    scope = getattr(context, "collection_scope", None)
    if scope is None:
        return []
    from core.intel.scope import allows_active_collection

    names: set[str] = set()
    for record in read_jsonl(ct_path):
        if not isinstance(record, dict):
            continue
        names.update(extract_all_names(record.get("name_value") or record.get("common_name")))

    siblings = sorted(name for name in names if name and not allows_active_collection(name, scope))
    return siblings[:max_candidates]


def _query_host(
    host: str,
    securitytrails_key: str | None,
    timeout: int,
    user_agent: str,
    proxy_url: str | None,
) -> tuple[dict[str, object], str]:
    raw_parts: list[str] = []
    try:
        ips, first_seen, last_seen, raw = _query_mnemonic(host, timeout, user_agent, proxy_url)
        raw_parts.append(raw)
    except Exception as exc:
        return (
            {
                "host": host,
                "ip": [],
                "collector": "passive_dns",
                "source": "passive_dns",
                "providers": [],
                "query_status": "error",
                "error": str(exc)[:240],
            },
            f"# {host} mnemonic error: {exc}",
        )

    providers = ["mnemonic"] if ips else []
    if securitytrails_key:
        try:
            st_ips, st_first, st_last, st_raw = _query_securitytrails(
                host, securitytrails_key, timeout, user_agent, proxy_url
            )
            raw_parts.append(st_raw)
            if st_ips:
                providers.append("securitytrails")
                ips = ips | st_ips
                first_seen = first_seen or st_first
                last_seen = last_seen or st_last
        except Exception as exc:
            # Optional, additive provider — a failure here must not erase a
            # successful Mnemonic result or fail the whole host lookup.
            raw_parts.append(f"# {host} securitytrails error: {exc}")

    record = {
        "host": host,
        "ip": sorted(ips),
        "collector": "passive_dns",
        "source": "passive_dns",
        "providers": providers,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "query_status": "ok" if ips else "empty",
    }
    return record, "\n".join(raw_parts)


def _query_mnemonic(
    host: str, timeout: int, user_agent: str, proxy_url: str | None
) -> tuple[set[str], str | None, str | None, str]:
    query = urllib.parse.quote(host, safe="")
    url = f"{_MNEMONIC_ENDPOINT.format(query=query)}?rrType=a&limit=50"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": user_agent or "hydra/1.0", "Accept": "application/json"},
    )
    with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
        payload = response.read(2 * 1024 * 1024)
    text = payload.decode("utf-8", errors="replace")
    parsed = json.loads(text)
    data = parsed.get("data") if isinstance(parsed, dict) else None
    ips: set[str] = set()
    first_seen: int | None = None
    last_seen: int | None = None
    for row in data or []:
        if not isinstance(row, dict) or row.get("rrtype") != "a" or row.get("tlp") != "white":
            continue
        answer = str(row.get("answer") or "").rstrip(".")
        if answer:
            ips.add(answer)
        fs, ls = row.get("firstSeenTimestamp"), row.get("lastSeenTimestamp")
        if isinstance(fs, int):
            first_seen = fs if first_seen is None else min(first_seen, fs)
        if isinstance(ls, int):
            last_seen = ls if last_seen is None else max(last_seen, ls)
    return (
        ips,
        str(first_seen) if first_seen is not None else None,
        str(last_seen) if last_seen is not None else None,
        f"# {host} mnemonic\n{text}",
    )


def _query_securitytrails(
    host: str, api_key: str, timeout: int, user_agent: str, proxy_url: str | None
) -> tuple[set[str], str | None, str | None, str]:
    url = _SECURITYTRAILS_ENDPOINT.format(hostname=urllib.parse.quote(host, safe=""))
    request = urllib.request.Request(
        url,
        headers={
            "APIKEY": api_key,
            "Accept": "application/json",
            "User-Agent": user_agent or "hydra/1.0",
        },
    )
    with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
        payload = response.read(2 * 1024 * 1024)
    text = payload.decode("utf-8", errors="replace")
    parsed = json.loads(text)
    rows = parsed.get("records") if isinstance(parsed, dict) else None
    ips: set[str] = set()
    first_seen: str | None = None
    last_seen: str | None = None
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        for value in row.get("values") or []:
            if isinstance(value, dict) and value.get("ip"):
                ips.add(str(value["ip"]))
        first_seen = first_seen or row.get("first_seen")
        last_seen = last_seen or row.get("last_seen")
    return ips, first_seen, last_seen, f"# {host} securitytrails\n{text}"

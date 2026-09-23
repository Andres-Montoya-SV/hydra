"""Subdomain takeover detection (opt-in, active, two-stage).

WHAT THIS DETECTS
------------------
A dangling DNS record — almost always a CNAME, sometimes an alias chain
through several hops — that points at a third-party service (cloud
storage, a PaaS app, a static-site host) the target organization no
longer controls. The service name is still resolvable (or, for some
providers, was simply never claimed), but nothing is provisioned there,
so anyone can register that name on the third-party service and start
serving content under the target's own subdomain.

FINGERPRINT DATABASE
---------------------
`modules/data/takeover_fingerprints.json` is a vendored, filtered
snapshot of the community-maintained `can-i-take-over-xyz` project
(https://github.com/EdOverflow/can-i-take-over-xyz), fetched and
filtered for real on 2026-09-23 — not reused from training data. Kept:
every entry marked `vulnerable: true` with at least one CNAME pattern
that is an actual hostname suffix (one entry, SmartJobBoard, had only a
bare IP literal as its "cname" and was dropped entirely; a bare IP
literal was also dropped from Worksites' pattern list, keeping its real
hostname pattern). See that file's own `_meta.refresh_instructions` for
how to pull a fresh snapshot.

**A real, confirmed-by-fetching-the-actual-current-file surprise**: the
upstream project's own current data lists `Github` (GitHub Pages) and
`Heroku` — the textbook example services in most takeover writeups —
with an **empty** `cname` array and `status: "Edge case"` /
`vulnerable: false`. The maintainers themselves no longer publish a
CNAME pattern reliable enough to auto-flag for these two (custom-domain
verification state on GitHub Pages and Heroku's app-naming model changed
enough that a bare CNAME match is not dependable evidence any more).
This module adds `github.io`/`herokuapp.com` back in as two clearly
separate `source: "hydra-supplementary"` entries (real, well-known
patterns) rather than silently dropping the two services everyone
expects to see here — but every finding built from a `status: "Edge
case"` entry gets a visibly lower confidence/severity than one built
from a `status: "Vulnerable"` entry, precisely because the upstream
project itself declined to call these certain. See `_SEVERITY_BY_STATUS`
below.

TWO-STAGE DETECTION
---------------------
Stage 1 (passive, cheap): for every subdomain dnsx already resolved this
run (read directly from `dnsx_records.jsonl`, the same file
`core/parsers/registry.py::DnsxParser` consumes — this plugin does not
re-run DNS lookups of its own), check whether any of its CNAME values
matches a known-vulnerable-service pattern. A Stage-1 match alone is
never a finding — most CNAMEs matching a pattern are legitimately
provisioned, not dangling.

Stage 2 (active, the actual confirmation) differs by signature type:

- **Fingerprint-type signatures** (most of the vendored list): send one
  real, safe, read-only GET to the *target's own subdomain itself*
  (never to the third-party CNAME target directly) through
  `core/collection/gateway.py::CollectionGateway` — the same
  authorize-then-request pattern `modules/param_fuzz.py`'s own docstring
  describes. The already-resolved subdomain is independently
  re-authorized as its own `AuthorizedCollectionTarget`, not assumed
  safe because dnsx already touched it. Confirmation requires the
  response body to match that service's specific fingerprint text.
- **NXDOMAIN-type signatures** (AWS/Elastic Beanstalk, Discourse,
  Microsoft Azure's whole CNAME family): these mean the CNAME's ultimate
  target does not resolve to anything at all — which also means the
  subdomain itself has no A/AAAA record, since CNAME resolution requires
  its target to resolve. This module deliberately does **not** send an
  HTTP probe for this category. Reading `core/collection/crawler_proxy.py
  ::ScopeEnforcingProxy._handle_connect` shows why that would be useless
  anyway: a CONNECT to a host that fails `dns_resolution_failed` gets the
  exact same synthetic `403 Forbidden` the proxy returns for an ordinary
  out-of-scope denial — indistinguishable from this plugin's side of the
  gateway. Instead, confirmation is dnsx's own already-collected
  observation for that exact host: a real CNAME record present, but zero
  A/AAAA records anywhere in the same `dnsx_records.jsonl` line. That is
  authoritative Hydra-own DNS data, not a guess, and it requires no
  additional network activity at all.

WILDCARD DNS INTERACTION
--------------------------
Consulted before reporting, not before detecting (`modules/
wildcard_check.py`'s own `context.metadata["wildcard_dns_roots"]` flag,
set upstream of this plugin in the pipeline). A wildcard-active root
means *any* name under it may show the same CNAME purely as a wildcard
artifact, not a deliberately provisioned record — but skipping every
subdomain under such a root silently would hide a real, and arguably
more severe, wildcard-level takeover (anyone could then claim the
service and serve content under literally any name on that root). This
module never skips a wildcard-affected root. Instead:

- If two or more *distinct* subdomains under the same wildcard-active
  root independently confirm the same signature, that corroboration is
  itself strong evidence of a genuine wildcard-level dangling record —
  they are collapsed into **one** finding scoped to the root domain
  (full confidence; listing the sample subdomains observed), rather than
  flooding a report with near-duplicate per-subdomain findings that are
  really the same misconfiguration.
- If only a single subdomain under a wildcard-active root confirms, it
  is still reported (never silently dropped) but at reduced confidence,
  with an explicit caveat in its description: this may be the wildcard
  itself rather than a deliberate, singular record, and a human should
  verify directly.

NEVER CLAIMS THE RESOURCE
----------------------------
This module detects and reports. It never registers the bucket/app/page
name it found dangling, even though that would be the traditional
human-researcher proof-of-concept step. Actually claiming a resource is
an out-of-band decision for whoever acts on the finding, made with the
target program's own explicit rules in view — never something this
automated pipeline does unattended.

NON-GOALS (explicitly out of scope, not deferred to a "later" inside
this module): actually claiming/registering anything; NS-delegation
takeovers (a dangling delegation to a nameserver the target no longer
controls — a real, structurally different case, noted here as a
follow-up); a live-fetched, always-current signature list (vendored and
periodically refreshed is the intended tradeoff).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from core.collection.gateway import CollectionGateway
from core.domain import parse_hostname
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl

_FINGERPRINTS_PATH = Path(__file__).resolve().parent / "data" / "takeover_fingerprints.json"

# can-i-take-over-xyz's own fingerprint field is consumed as a regex by that
# project's other downstream tools — confirmed directly from the fetched
# data, not assumed: several entries use `.*` as an intentional wildcard
# (ngrok: "Tunnel .*.ngrok.io not found") and one (Ghost) uses the
# HTML-escaped pipe `&#124;` for regex alternation. Unescaping that entity
# and compiling every fingerprint as a case-insensitive regex (rather than a
# plain substring) is required to match those entries correctly; it is a
# no-op for the many fingerprints that contain no regex metacharacters.
_HTML_PIPE = "&#124;"

# Confidence/severity depends on the vendored signature's own `status` field
# — "Vulnerable" entries come straight from can-i-take-over-xyz's own
# confirmed classification; "Edge case" entries (this module's own
# github.io/herokuapp.com additions) are a real, well-known pattern the
# upstream project itself declined to call certain — see module docstring.
_SEVERITY_BY_STATUS = {
    "Vulnerable": ("high", 95),
    "Edge case": ("medium", 65),
}
# A single, unconfirmed-by-corroboration subdomain under an active wildcard
# root is downgraded further still, regardless of the signature's own
# status — see the "WILDCARD DNS INTERACTION" section above.
_WILDCARD_SINGLE_CONFIDENCE_CAP = 60


@dataclass(frozen=True)
class TakeoverSignature:
    service: str
    cname_patterns: tuple[str, ...]
    fingerprint: str | None
    fingerprint_regex: re.Pattern[str] | None
    nxdomain: bool
    status: str
    source: str


def _compile_fingerprint(raw: str | None) -> re.Pattern[str] | None:
    if not raw or raw == "NXDOMAIN":
        return None
    unescaped = raw.replace(_HTML_PIPE, "|")
    try:
        return re.compile(unescaped, re.IGNORECASE)
    except re.error:
        # A handful of upstream fingerprints contain literal punctuation
        # that is not valid regex syntax when reused verbatim (unbalanced
        # parens/brackets in free-text sentences) — fall back to a literal
        # substring match rather than dropping the signature entirely.
        return re.compile(re.escape(unescaped), re.IGNORECASE)


def load_signatures(path: Path = _FINGERPRINTS_PATH) -> list[TakeoverSignature]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    signatures: list[TakeoverSignature] = []
    for entry in doc.get("signatures", []):
        fingerprint = entry.get("fingerprint")
        signatures.append(
            TakeoverSignature(
                service=str(entry["service"]),
                cname_patterns=tuple(str(p).lower().rstrip(".") for p in entry["cname_patterns"]),
                fingerprint=fingerprint,
                fingerprint_regex=_compile_fingerprint(fingerprint),
                nxdomain=bool(entry.get("nxdomain")),
                status=str(entry.get("status", "Vulnerable")),
                source=str(entry.get("source", "unknown")),
            )
        )
    return signatures


def match_signature(cname: str, signatures: list[TakeoverSignature]) -> TakeoverSignature | None:
    """First signature whose CNAME pattern is a suffix of ``cname``."""
    candidate = cname.lower().rstrip(".")
    for sig in signatures:
        for pattern in sig.cname_patterns:
            if candidate == pattern or candidate.endswith(f".{pattern}"):
                return sig
    return None


@dataclass
class _Candidate:
    host: str
    cname: str
    signature: TakeoverSignature
    has_address: bool


def _read_dnsx_records(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def find_candidates(
    dnsx_records: list[dict[str, object]], signatures: list[TakeoverSignature]
) -> list[_Candidate]:
    """Stage 1: CNAME-pattern matches, one candidate per (host, matched cname)."""
    candidates: list[_Candidate] = []
    for rec in dnsx_records:
        host = str(rec.get("host") or "").strip().rstrip(".").lower()
        if not host:
            continue
        has_address = bool(rec.get("a")) or bool(rec.get("aaaa"))
        for cname in rec.get("cname", []) or []:
            cname = str(cname).strip().rstrip(".")
            if not cname:
                continue
            sig = match_signature(cname, signatures)
            if sig is not None:
                candidates.append(
                    _Candidate(host=host, cname=cname, signature=sig, has_address=has_address)
                )
    return candidates


class SubTakeoverPlugin(BaseToolPlugin):
    """Two-stage subdomain takeover detector (CNAME pattern + live confirmation)."""

    name = "sub_takeover"
    display_name = "Subdomain Takeover Detection"
    required = False
    external_dependency = False
    stage_order = 44
    produces = ("takeover_findings",)
    capability = "sub_takeover"
    active_collection = True
    cacheable = False

    def is_enabled(self) -> bool:
        return self.settings.enable_sub_takeover

    def get_binary_path(self) -> Path:
        return Path("built-in")

    def get_install_hint(self) -> str:
        return "Built-in (stdlib urllib + vendored fingerprint database) — opt-in active probe"

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        from core.intel.scope import require_collection_scope

        scope = require_collection_scope(context)
        # This stage (order 44) always runs during the initial pass, before
        # any bounded follow-up collection re-invokes dnsx with its own
        # suffixed output file — read the seed dnsx_records.jsonl directly,
        # the same file core/parsers/registry.py::DnsxParser prefers.
        dnsx_records_path = context.output_dir / "dnsx_records.jsonl"
        dnsx_records = _read_dnsx_records(dnsx_records_path)
        if not dnsx_records:
            return self._skip("No dnsx records available to check for dangling CNAMEs")

        signatures = load_signatures()
        candidates = find_candidates(dnsx_records, signatures)
        if not candidates:
            return self._skip("No CNAME matched a known-vulnerable-service pattern")

        context.add_warning(
            "Subdomain Takeover Detection sends one safe, read-only GET per "
            "fingerprint-type candidate against the target's own already-"
            "resolved subdomain (never the third-party CNAME target directly). "
            "It never registers/claims any resource it finds dangling."
        )
        self.update_status(context, ToolStatus.RUNNING)

        wildcard_roots = {
            str(r).lower() for r in (context.metadata.get("wildcard_dns_roots") or [])
        }
        alive_by_host = _alive_urls_by_host(self._alive_urls(context))

        candidates_path = self._output_path(context, "sub_takeover_candidates.jsonl")
        write_jsonl(
            candidates_path,
            [
                {
                    "host": c.host,
                    "cname": c.cname,
                    "service": c.signature.service,
                    "signature_status": c.signature.status,
                    "has_address": c.has_address,
                }
                for c in candidates
            ],
            base_dir=context.output_dir,
        )

        confirmed: list[dict[str, object]] = []
        timeout = self.settings.sub_takeover_timeout

        async with CollectionGateway(
            scope,
            capability=self.capability,
            context=context,
            upstream_proxy_url=self.settings.outbound_proxy_url or None,
            extra_headers=self.settings.merged_headers(),
            user_agent=self.settings.effective_user_agent(),
        ) as gateway:
            for candidate in candidates:
                result = await self._confirm(gateway, candidate, alive_by_host, timeout)
                if result is not None:
                    confirmed.append(result)

        confirmed = _apply_wildcard_policy(confirmed, wildcard_roots)

        output_path = self._output_path(context, "sub_takeover.jsonl")
        count = write_jsonl(output_path, confirmed, base_dir=context.output_dir)
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=(
                f"Subdomain takeover: {count} confirmed finding(s) from "
                f"{len(candidates)} Stage-1 candidate(s)"
            ),
        )

    async def _confirm(
        self,
        gateway: CollectionGateway,
        candidate: _Candidate,
        alive_by_host: dict[str, str],
        timeout: int,
    ) -> dict[str, object] | None:
        sig = candidate.signature

        if sig.nxdomain:
            # See module docstring: an HTTP probe here would just hit the
            # confinement proxy's own dns_resolution_failed -> synthetic 403
            # path, indistinguishable from an ordinary scope denial. dnsx's
            # own has_address observation for this exact host is the real
            # confirmation and requires no network activity here at all.
            if candidate.has_address:
                return None
            return _finding_dict(candidate, sig, url=None, method="dns_nxdomain_confirmed")

        url = alive_by_host.get(candidate.host)
        if url is None:
            # Not in this run's httpx-confirmed-alive set — Stage 1 only,
            # never surfaced as a finding on its own.
            return None

        target = gateway.authorize(url, operation="sub_takeover_confirm")
        if target is None:
            return None
        response = await gateway.http_get(target, timeout=timeout, operation="sub_takeover_confirm")
        if sig.fingerprint_regex is None:
            return None
        body_text = response.body.decode("utf-8", errors="replace")
        if not sig.fingerprint_regex.search(body_text):
            return None
        return _finding_dict(candidate, sig, url=url, method="http_fingerprint")


def _alive_urls_by_host(urls: list[str]) -> dict[str, str]:
    from urllib.parse import urlparse

    by_host: dict[str, str] = {}
    for url in urls:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        if host and host not in by_host:
            by_host[host] = url
    return by_host


def _finding_dict(
    candidate: _Candidate,
    sig: TakeoverSignature,
    *,
    url: str | None,
    method: str,
) -> dict[str, object]:
    severity, confidence = _SEVERITY_BY_STATUS.get(sig.status, ("medium", 65))
    description = (
        f"{candidate.host} has a CNAME to {candidate.cname}, matching "
        f"{sig.service}'s known-dangling pattern. "
        + (
            f"Confirmed live: the response fingerprint for {sig.service}'s "
            "unclaimed state was present."
            if method == "http_fingerprint"
            else (
                f"Confirmed via DNS: {sig.service}'s CNAME target does not "
                "resolve at all (no A/AAAA record for this host), matching "
                f"{sig.service}'s known NXDOMAIN-dangling behavior."
            )
        )
    )
    if sig.status == "Edge case":
        description += (
            f" Note: {sig.service} is classified 'Edge case' in the vendored "
            "fingerprint database — the upstream signature source itself does "
            "not treat a fingerprint match here as guaranteed-claimable; "
            "verify manually before treating this as a certain takeover."
        )
    return {
        "host": candidate.host,
        "cname": candidate.cname,
        "service": sig.service,
        "template_id": "subdomain-takeover",
        "severity": severity,
        "name": f"Possible subdomain takeover via {sig.service}",
        "description": description,
        "confidence_score": confidence,
        "url": url,
        "confirmed_stage2": True,
        "stage2_method": method,
        "signature_status": sig.status,
        "wildcard_dns_active": False,
        "raw_artifact": "sub_takeover.jsonl",
    }


def _apply_wildcard_policy(
    findings: list[dict[str, object]], wildcard_roots: set[str]
) -> list[dict[str, object]]:
    """See module docstring, "WILDCARD DNS INTERACTION". Findings whose host's
    root is not wildcard-active pass through unchanged."""
    if not wildcard_roots:
        return findings

    by_root_and_service: dict[tuple[str, str], list[dict[str, object]]] = {}
    passthrough: list[dict[str, object]] = []
    for finding in findings:
        host = str(finding["host"])
        root = parse_hostname(host)[2]
        if root not in wildcard_roots:
            passthrough.append(finding)
            continue
        by_root_and_service.setdefault((root, str(finding["service"])), []).append(finding)

    result = list(passthrough)
    for (root, _service), group in by_root_and_service.items():
        distinct_hosts = sorted({str(f["host"]) for f in group})
        if len(distinct_hosts) >= 2:
            # Corroborated across independent subdomains -- almost certainly
            # the wildcard's own dangling record, not N separate mistakes.
            # Collapse into one root-scoped finding at full confidence.
            merged = dict(group[0])
            merged["host"] = root
            merged["wildcard_dns_active"] = True
            merged["wildcard_confirmed_subdomains"] = distinct_hosts
            merged["description"] = (
                str(merged["description"])
                + f" Wildcard DNS is active on {root}; the same pattern was "
                f"independently confirmed on {len(distinct_hosts)} distinct "
                f"subdomains ({', '.join(distinct_hosts[:5])}"
                + (", ..." if len(distinct_hosts) > 5 else "")
                + "), which corroborates a genuine wildcard-level dangling "
                "record rather than one isolated misconfiguration."
            )
            result.append(merged)
        else:
            single = dict(group[0])
            single["wildcard_dns_active"] = True
            current_confidence = int(single.get("confidence_score", 65))
            single["confidence_score"] = min(current_confidence, _WILDCARD_SINGLE_CONFIDENCE_CAP)
            single["description"] = (
                str(single["description"])
                + f" Wildcard DNS is active on {root}; this match could not be "
                "independently corroborated on a second subdomain, so it may "
                "reflect the wildcard's own generic answer rather than a "
                "deliberate, singular record for this specific name — verify "
                "directly before treating this as confirmed."
            )
            result.append(single)
    return result

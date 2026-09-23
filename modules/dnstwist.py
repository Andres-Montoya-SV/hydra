"""Domain permutation / typosquat monitoring (opt-in, brand-protection —
NOT a target-infrastructure vulnerability).

CONCEPTUALLY DIFFERENT FROM EVERY OTHER PLUGIN IN modules/
------------------------------------------------------------
Every other plugin either enumerates real subdomains of the target or
probes real, already-discovered hosts belonging to it. This one
GENERATES candidate domains that are explicitly NOT the target
(typosquats, homoglyphs, bit-flips of the target's own domain name) and
checks which ones are actually registered. A registered permutation is
evidence of a distinct, separate risk — potential phishing/brand-
impersonation infrastructure — not a vulnerability in the target's own
systems, and often not even malicious at all (plenty of registered
lookalikes are unrelated legitimate businesses that happen to share a
similar name). **This module never creates a `Host` and is never routed
through `core/parsers/registry.py`'s `PARSER_REGISTRY`** — see
`core/store.py`'s own `typosquat_candidates` table (a dedicated table,
never `hosts`/`findings`) and `core/runner.py::_finalize_to_store`'s
explicit, separate ingestion step for why. A report or downstream
consumer must never be able to mistake "someone registered a lookalike
of your domain" for "we found a new subdomain of yours."

WRAPPING `dnstwist`, NOT REIMPLEMENTING ITS PERMUTATION ALGORITHMS
------------------------------------------------------------------------
Confirmed against the real, current `dnstwist` 20250130 CLI, not assumed
(installed and run for real against `example.com` during this module's
own development):

- Real current top-level flags: `--format json`, `--registered` (only
  show domains that actually resolve — without it, the output is
  thousands of NXDOMAIN permutations, pure noise for this use case),
  `--all` (show every DNS record type per candidate, not just the
  first — needed to see MX records at all), `--whois` (creation
  date/registrar), `--threads`, `--useragent`.
- Real JSON shape per candidate: `{"domain", "fuzzer", "dns_a",
  "dns_aaaa", "dns_mx", "dns_ns", "whois_created", "whois_registrar"}`.
  `dns_mx` is simply ABSENT from the dict when a candidate has no MX
  record (confirmed: not `[]`, not present at all) — EXCEPT for the
  seed domain's own `"fuzzer": "*original"` echo-back row, which
  dnstwist represents as `"dns_mx": [""]` (a one-element list containing
  an empty string) — a real, confirmed inconsistency specific to that
  one row. Moot for this module either way: the `*original` row is the
  target's own domain re-reported by dnstwist itself and is always
  excluded — it is not a permutation candidate.
- `whois_created` is a plain `"YYYY-MM-DD"` string when present, parsed
  defensively regardless (a domain with privacy-redacted or unavailable
  WHOIS data simply omits the field, per real observed behavior).

WHICH OPTIONAL dnstwist FEATURES ARE ENABLED, AND WHY
----------------------------------------------------------
`dnstwist` can also probe each candidate far more aggressively:
`-b`/`--banners` (grabs live HTTP/SMTP service banners from the
candidate), `-p`/`--phash`/`--screenshots` (renders the candidate's web
page and does visual-similarity scoring), `--lsh` (fetches the
candidate's page content for fuzzy text-similarity scoring), and
`-m`/`--mxcheck` (actively connects to the candidate's own MX host to
test whether it can be used to intercept mail — not merely observing
that an MX record exists).

**None of these are enabled here.** Every one of them means `dnstwist`
itself — a separate external binary, not a piece of Hydra's own Python
process — makes a raw, unconfined network connection directly to a host
whose IP/hostname was chosen by that candidate's own DNS answers (a
completely separate, unrelated third party Hydra never verified or put
in any `SCOPE_FILE`). Checked directly against dnstwist's real, current
`--help`: **there is no `--proxy` flag at all** — unlike
`katana`/`hakrawler`/`nuclei` (which Hydra already routes through
`ScopeEnforcingProxy` via `modules/_base.py::_crawler_confinement`),
there is no way to make dnstwist's own outbound connections go through
Hydra's confinement layer. Enabling any of these flags would mean this
codebase making real outbound connections to attacker-influenceable
destinations with zero of Hydra's own SSRF/private-IP validation, zero
audit trail, and zero ability to refuse a connection — exactly the
discipline this project applies to every other outbound connection it
makes, regardless of whose domain is on the other end. Rather than
bending `AuthorizedCollectionTarget` (built entirely around "was this
in an operator's own `SCOPE_FILE`", which no candidate ever is by
definition) to cover this, the real call made here is simpler: this
module never does active content-fetching of a candidate at all. A
future, explicit content-fetching feature for this module would need
its own, new authorization concept — not sketched out here, since one
was not built.

What DOES touch the network, and why it's a materially different risk:
`dnstwist`'s own DNS resolution (to determine "is this candidate even
registered", and to read A/AAAA/MX/NS records with `--all`) and WHOIS
lookups (`--whois`) go to the operator's configured DNS resolver and to
well-known, fixed-per-TLD WHOIS registry servers respectively — never a
connection whose destination is chosen by the candidate's own DNS
answers. This is the same risk class `modules/ctlogs.py` (a fixed
third-party endpoint) and `core/collection/whois_client.py` (WHOIS for
the target's own domain) already carry in this codebase.

PRIORITIZATION — NOT EVERY REGISTERED PERMUTATION IS A FINDING
----------------------------------------------------------------
Dumping every resolvable permutation as an undifferentiated list would
be noise, not a finding — most registered lookalikes are unrelated,
harmless businesses. Two real signals available without active content-
fetching:

- **Has an MX record configured** (`--all`'s own DNS data, never
  `-m`/`--mxcheck`'s active SMTP probe) — the task's own framing, and
  this module's judgment too: the single strongest available phishing-
  risk signal. A lookalike domain set up to receive email is set up to
  either spoof the target in outbound phishing mail or receive
  misdirected mail intended for the target — `severity="high"`.
  Independent of MX: a registration younger than
  `Settings.dnstwist_fresh_registration_days` (default 90) is
  `severity="medium"` — suspicious timing, unconfirmed intent.
  Everything else registered is `severity="low"` — worth recording as
  brand-protection awareness, not worth escalating.

NON-GOALS
------------
Automatically reporting/taking down a discovered typosquat (a real
takedown is a legal/registrar process, entirely out of scope for an
unattended pipeline); continuous/scheduled re-monitoring to detect NEWLY
registered permutations since a prior scan (a real, valuable follow-up —
a bigger scheduling/diffing project, not half-built here — each run is
independent, `INSERT OR REPLACE` keyed on `(run_id, candidate_domain)`,
no cross-run diffing).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl

_ORIGINAL_FUZZER = "*original"


class DnstwistPlugin(BaseToolPlugin):
    """Registered domain-permutation (typosquat) monitoring via
    `dnstwist`. Brand-protection signal, never a target asset — see
    module docstring."""

    name = "dnstwist"
    display_name = "dnstwist (Typosquat Monitoring)"
    required = False
    stage_order = 18
    produces = ("typosquat_candidates",)
    capability = "typosquat_detection"
    active_collection = False
    install_hint_macos = "brew install dnstwist"
    install_hint_linux = "pip install dnstwist"

    def is_enabled(self) -> bool:
        return self.settings.enable_dnstwist

    def get_binary_path(self) -> Path:
        return self.settings.dnstwist_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        domains = [t.domain for t in context.targets]
        if not domains:
            return self._skip("No target domains")

        self.update_status(context, ToolStatus.RUNNING)
        all_candidates: list[dict[str, object]] = []
        any_success = False
        fresh_days = self.settings.dnstwist_fresh_registration_days

        for domain in domains:
            context.current_target = domain
            output_path = self._output_path(context, f"dnstwist_{_safe_stem(domain)}.json")
            args = [
                str(self.get_binary_path()),
                "--format",
                "json",
                "--registered",
                "--all",
                "--whois",
                "--threads",
                str(self.settings.dnstwist_threads),
                "--useragent",
                self.settings.effective_user_agent(),
                "--output",
                str(output_path),
                domain,
            ]
            return_code, stdout, stderr = await self._run_tool(
                context, args, timeout=self.settings.dnstwist_timeout
            )
            self._scan_telemetry(context, stdout, stderr)
            if return_code != 0:
                context.add_warning(
                    f"dnstwist: exit code {return_code} for {domain} — "
                    f"{(stderr or stdout).strip()[:200] or 'no output'}"
                )
                continue
            any_success = True

            rows = _read_dnstwist_json(output_path)
            for row in rows:
                candidate = _row_to_candidate(row, domain, fresh_days=fresh_days)
                if candidate is not None:
                    all_candidates.append(candidate)

        context.current_target = None
        findings_path = self._output_path(context, "dnstwist_findings.jsonl")
        count = write_jsonl(findings_path, all_candidates, base_dir=context.output_dir)

        if domains and not any_success:
            message = "dnstwist failed for all target domains"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, output_path=findings_path, message=message)

        high = sum(1 for c in all_candidates if c["severity"] == "high")
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=findings_path,
            lines_produced=count,
            message=(
                f"dnstwist: {count} registered permutation(s) found, {high} with an MX record"
            ),
        )


def _safe_stem(domain: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain)


def _read_dnstwist_json(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _has_real_mx(row: dict[str, object]) -> bool:
    mx = row.get("dns_mx")
    if not isinstance(mx, list):
        return False
    return any(str(m).strip() for m in mx)


def _is_freshly_registered(whois_created: str, *, fresh_days: int) -> bool:
    try:
        created = datetime.strptime(whois_created.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return False
    age_days = (datetime.now(timezone.utc) - created).days
    return 0 <= age_days <= fresh_days


def _row_to_candidate(
    row: dict[str, object], target_domain: str, *, fresh_days: int
) -> dict[str, object] | None:
    """Real dnstwist JSON row -> this module's own candidate record.
    Excludes the `*original` echo-back of the target's own domain —
    that row is dnstwist re-reporting the seed itself, never a
    permutation candidate."""
    fuzzer = str(row.get("fuzzer") or "")
    if fuzzer == _ORIGINAL_FUZZER:
        return None
    candidate_domain = str(row.get("domain") or "").strip().lower()
    if not candidate_domain:
        return None

    has_mx = _has_real_mx(row)
    whois_created = str(row.get("whois_created") or "").strip()
    fresh = bool(whois_created) and _is_freshly_registered(whois_created, fresh_days=fresh_days)

    if has_mx:
        severity = "high"
        risk_reason = "MX record configured — set up to send or receive email as this name"
        confidence = 80
    elif fresh:
        severity = "medium"
        risk_reason = f"registered within the last {fresh_days} days"
        confidence = 55
    else:
        severity = "low"
        risk_reason = "registered, no MX record, not recently created"
        confidence = 40

    return {
        "target_domain": target_domain,
        "candidate_domain": candidate_domain,
        "fuzzer": fuzzer,
        "dns_a": [str(ip) for ip in (row.get("dns_a") or [])],
        "dns_mx": [str(m) for m in (row.get("dns_mx") or []) if str(m).strip()],
        "has_mx": has_mx,
        "whois_created": whois_created or None,
        "whois_registrar": str(row.get("whois_registrar") or "") or None,
        "severity": severity,
        "risk_reason": risk_reason,
        "confidence_score": confidence,
    }

"""Continuous monitoring for verified domains — the two-speed model
("Hydra API — Continuous Monitoring for Verified Domains" task,
docs/PAID_API_DESIGN.md's dated monitoring section has the full
writeup). Pure functions/constants over plain data, no `ControlDB`/HTTP
concerns — the same "business logic factored out of the router/worker"
split `api/domain_verification.py` and `api/subscriptions.py` already
established, so every decision here is unit-testable without a database,
an event loop, or a running pipeline.

**Speed 1 (passive, daily, every opted-in tier)**: re-runs ONLY the
plugins this codebase itself already declares non-active
(`core.plugin_base.ReconPlugin.active_collection is False`) — genuine
OSINT/passive-source subdomain enumeration and cert-transparency/
historical lookups, never a probe the target's own infrastructure would
see as a new inbound connection beyond the baseline DNS resolution/
liveness check every scan (Speed 1 or Speed 2) already needs to turn a
subdomain list into anything reportable at all. This set is read
directly off each plugin's own class attribute below
(`PASSIVE_MONITORING_PLUGINS`), not hand-maintained separately, so it
can never silently drift from what the plugins themselves actually
declare.

**Speed 2 (active, weekly, Pro/Ultra only)**: the full existing pipeline,
unchanged — the same `_run_headless_pipeline` a manual `POST /scans`
already runs. No new "deep scan" mode is invented; Speed 2 IS an
ordinary scan, auto-triggered instead of client-triggered, tagged
`trigger_source='scheduled_active'` (api/control_db.py) purely so the
worker/orchestrator/client-facing history can tell why it exists.

**Why Speed 1 never consumes the monthly scan quota (Part B) and Speed 2
always does**: Part B's quota exists to bound Hydra's own infrastructure/
tool-execution cost per account per month. A passive-only run's cost is
a small, roughly-constant handful of API calls to public
OSINT sources — running it daily for every opted-in domain does not
meaningfully change the cost picture a manual/Speed-2 scan's quota was
designed to bound. Charging it against the same quota would also create
a perverse outcome the task's own "airtight quota interaction"
requirement rules out: an account running Speed 1 daily for a month
would silently exhaust an entire month's manual-scan quota (30+ runs)
doing nothing but the free background hygiene check the feature exists
to provide. Speed 2 is the full pipeline (naabu/httpx/nuclei/etc. against
real target infrastructure) — identical cost/risk profile to a manual
scan, so it consumes a real quota slot the same way.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

Speed = Literal["passive", "active"]


def _passive_monitoring_plugin_names() -> frozenset[str]:
    """Computed from the plugin registry itself, not a hand-written
    literal list — importing `modules` (which registers every plugin
    via `ReconPlugin.__init_subclass__`) is unavoidable to ask each
    plugin what it declares, but this function is called once, at
    worker-loop startup, never per-scan."""
    import modules  # noqa: F401 - registers every ReconPlugin subclass
    from core.plugin_base import ReconPlugin

    return frozenset(p.name for p in ReconPlugin.all_plugins() if not p.active_collection)


# Populated lazily (see `passive_monitoring_settings_overrides` below) —
# importing the full `modules` package at `api/monitoring.py` import time
# would pull in every external-tool plugin's own heavy import graph just
# to build this set, the same "deferred: heavy import graph" concern
# `api/scan_orchestrator.py` already documents for `import app`.
_PASSIVE_PLUGIN_NAMES_CACHE: frozenset[str] | None = None


def passive_monitoring_plugin_names() -> frozenset[str]:
    global _PASSIVE_PLUGIN_NAMES_CACHE
    if _PASSIVE_PLUGIN_NAMES_CACHE is None:
        _PASSIVE_PLUGIN_NAMES_CACHE = _passive_monitoring_plugin_names()
    return _PASSIVE_PLUGIN_NAMES_CACHE


def passive_monitoring_settings_overrides(all_enable_flags: dict[str, bool]) -> dict[str, bool]:
    """Given every `enable_<tool>` flag `config.settings.Settings`
    currently defines (introspected by the caller, `api/scan_orchestrator.py`,
    via `vars(settings)`), returns the subset that must be forced to
    `False` for a Speed 1 passive run — any enabled tool whose plugin
    name is NOT in `passive_monitoring_plugin_names()`. Returning only the
    flags that need to CHANGE (never the ones already correct) keeps this
    function's effect legible in a test/log: the returned dict is exactly
    "what Speed 1 turned off that this account normally has on."

    Deliberately never turns anything ON — an account that has, say,
    `enable_subfinder=False` for its own reasons (rare; most passive
    plugins default enabled) stays off for Speed 1 too. Monitoring
    narrows what a scan does; it never expands an account's own
    configured tool selection."""
    passive_names = passive_monitoring_plugin_names()
    overrides: dict[str, bool] = {}
    for attr, value in all_enable_flags.items():
        if not attr.startswith("enable_") or not value:
            continue
        plugin_name = attr[len("enable_") :]
        if plugin_name not in passive_names:
            overrides[attr] = False
    return overrides


def compute_asset_digest(hostnames: list[str]) -> str:
    """The lightweight diff key stored on `monitored_domains.last_asset_digest`
    — a single SHA-256 hex digest of the sorted, newline-joined hostname
    set, never the full Host/Finding rows. Comparing two digests is an
    O(1) string equality check regardless of whether the domain has 50 or
    50,000 hosts, which is what makes "did anything change" cheap enough
    to check on every scheduled cycle at real (300k+ monitored-domain)
    scale — the alternative (re-reading and diffing the full host list
    for every domain every cycle) is exactly the kind of per-cycle cost
    that would make the scale target impossible on a single worker
    process."""
    joined = "\n".join(sorted(hostnames))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AssetJumpClassification:
    needs_review: bool
    reason: str | None


def classify_asset_jump(
    *,
    previous_count: int | None,
    new_count: int,
    ceiling: int,
    wildcard_dns_detected: bool,
) -> AssetJumpClassification:
    """Part B's asset-count sanity ceiling. `previous_count is None`
    means this is the domain's first-ever monitored run — never flagged
    (there is no "jump" without a prior baseline to jump from), even if
    the first run's count already exceeds the ceiling on its own; the
    ceiling exists to catch a SUDDEN, likely-spurious explosion (a
    wildcard DNS record silently starting to resolve, a scope-config
    mistake), not to gate a domain that has always legitimately had a
    large attack surface.

    `wildcard_dns_detected` (read from the scan's own
    `context.metadata["wildcard_dns_detected"]`,
    `modules/wildcard_check.py`) short-circuits the ceiling: a real,
    already-detected wildcard DNS record is a KNOWN, already-explained
    cause of an inflated host count, not a sanity-check failure — flagging
    `needs_review` for something the pipeline's own wildcard-detection
    module already identified and is already suppressing false positives
    for elsewhere (`modules/soft404_check.py`'s consumer,
    `modules/ffuf.py`) would be double-counting the same signal as two
    different, contradictory kinds of alarm."""
    if previous_count is None:
        return AssetJumpClassification(needs_review=False, reason=None)
    if new_count <= ceiling:
        return AssetJumpClassification(needs_review=False, reason=None)
    if wildcard_dns_detected:
        return AssetJumpClassification(needs_review=False, reason=None)
    return AssetJumpClassification(
        needs_review=True,
        reason=(
            f"Asset count jumped from {previous_count} to {new_count}, past the "
            f"configured ceiling ({ceiling}), with no wildcard DNS detected to explain it."
        ),
    )


@dataclass(frozen=True)
class MonitoringRunOutcome:
    """What `api/monitoring_worker.py` needs to know after attempting one
    domain's scheduled scan, to build both the batched DB write and (if
    warranted) the account's notification-email content — kept as one
    small, serializable-shaped record rather than scattering these fields
    across several return values, since both consumers need all of them."""

    monitoring_id: str
    account_id: str
    domain: str
    speed: Speed
    scan_id: str
    hosts_added: list[str]
    hosts_removed: list[str]
    asset_count: int
    asset_digest: str
    needs_review: bool
    review_reason: str | None


# NOTE on hostname diffing: `monitored_domains` persists only a DIGEST
# per domain per cycle (`compute_asset_digest`), never the full hostname
# set — precisely so a 300k-row table never holds O(total hosts across
# every monitored domain) of state. The actual added/removed hostname
# list a notification email shows (`MonitoringRunOutcome.hosts_added/
# removed`) is computed by `api/monitoring_worker.py` directly from the
# two SCANS' own `recon.db` rows (this run's vs. the previous run's, both
# already durably stored there via `core.store.AssetStore.get_host_domains`)
# only for domains whose digest actually changed — never from this table.


def next_due_at(interval_hours: int, *, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return (now + timedelta(hours=interval_hours)).isoformat()


def significance_rank(outcome: MonitoringRunOutcome) -> tuple[int, str]:
    """Ordering for capped/summarized notification emails
    (`EmailSender.send_monitoring_alert`) — most significant first, so
    truncating a long list of changed domains to the configured cap
    (`APISettings.monitoring_max_domains_per_email`) drops the LEAST
    interesting ones, never an arbitrary/insertion-order cut. Documented
    ordering, most to least significant:

    1. `needs_review` (asset-count ceiling tripped — the one case that
       needs a human to look, not just FYI).
    2. New hosts appeared (a growing attack surface is more actionable
       than one that shrank).
    3. Hosts disappeared (still worth surfacing — decommissioned
       infrastructure, or a monitoring blind spot forming — but lower
       urgency than growth).
    4. No change (never actually included in a notification at all —
       `api/monitoring_worker.py` only calls this for domains WITH
       something to report; listed here only so the ordering rule is
       total and testable in isolation).

    The `str` component (domain name) is a stable tiebreaker within a
    rank, so the same input always produces the same email content —
    useful for the notification-cap tests and for anyone diffing two
    cycles' emails by eye."""
    if outcome.needs_review:
        rank = 0
    elif outcome.hosts_added:
        rank = 1
    elif outcome.hosts_removed:
        rank = 2
    else:
        rank = 3
    return rank, outcome.domain

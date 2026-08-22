"""Bounded follow-up planning. The queue is never trusted."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.assets import normalize_domain
from core.intel.correlate import registrable_domain
from core.intel.model import CollectReason, Indicator
from core.intel.scope import CollectionScope, allows_active_collection, indicator_hostname
from utils.files import read_jsonl

INDEPENDENT_REASONS = frozenset(
    {
        CollectReason.CERTIFICATE_SAN,
        CollectReason.SEED,
        CollectReason.SHARED_CERTIFICATE,
    }
)


@dataclass
class FollowUpDecision:
    hostname: str
    allowed: bool
    reason: str
    allow_dns: bool = False
    allow_http: bool = False


@dataclass
class FollowUpPlan:
    decisions: list[FollowUpDecision] = field(default_factory=list)
    dns_targets: list[str] = field(default_factory=list)
    http_targets: list[str] = field(default_factory=list)

    def rejected(self) -> list[FollowUpDecision]:
        return [item for item in self.decisions if not item.allowed]


def load_wildcard_roots(output_dir: Path, metadata: dict | None = None) -> set[str]:
    roots: set[str] = set()
    meta = metadata or {}
    for item in meta.get("wildcard_dns_roots") or []:
        root = normalize_domain(str(item))
        if root:
            roots.add(root)
    path = output_dir / "wildcard_check.jsonl"
    if path.exists():
        for record in read_jsonl(path):
            if not isinstance(record, dict) or not record.get("wildcard_dns_detected"):
                continue
            root = normalize_domain(str(record.get("root_domain") or ""))
            if root:
                roots.add(root)
    return roots


def wildcard_blocks_active_collection(
    hostname: str,
    wildcard_roots: set[str],
    reason: CollectReason,
) -> bool:
    """Block probes that exist only because a wildcard zone resolves them."""
    root = registrable_domain(hostname)
    if not root or root not in wildcard_roots:
        return False
    return reason not in INDEPENDENT_REASONS


def plan_followup_collection(
    *,
    candidates: list[Indicator],
    scope: CollectionScope,
    wildcard_roots: set[str],
    already_collected: set[str],
    dns_budget: int,
    http_budget: int,
) -> FollowUpPlan:
    """Normalize → scope → wildcard → authorize. Never trust queue status."""
    plan = FollowUpPlan()
    seen: set[str] = set()
    collected = {normalize_domain(name) for name in already_collected}
    for item in candidates:
        host = indicator_hostname(item.value) or normalize_domain(item.value)
        if not host:
            plan.decisions.append(FollowUpDecision(item.value, False, "invalid"))
            continue
        if host in seen:
            plan.decisions.append(FollowUpDecision(host, False, "duplicate"))
            continue
        seen.add(host)
        if host in collected:
            plan.decisions.append(FollowUpDecision(host, False, "already_collected"))
            continue
        if not allows_active_collection(host, scope):
            plan.decisions.append(FollowUpDecision(host, False, "out_of_scope"))
            continue
        if wildcard_blocks_active_collection(host, wildcard_roots, item.reason):
            plan.decisions.append(FollowUpDecision(host, False, "wildcard_unconfirmed"))
            continue
        allow_dns = len(plan.dns_targets) < max(0, dns_budget)
        allow_http = len(plan.http_targets) < max(0, http_budget)
        if not allow_dns and not allow_http:
            plan.decisions.append(FollowUpDecision(host, False, "budget_exhausted"))
            continue
        plan.decisions.append(
            FollowUpDecision(
                host,
                True,
                "authorized",
                allow_dns=allow_dns,
                allow_http=allow_http,
            )
        )
        if allow_dns:
            plan.dns_targets.append(host)
        if allow_http:
            plan.http_targets.append(host)
    return plan

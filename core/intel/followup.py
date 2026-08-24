"""Bounded follow-up planning. The queue is never trusted. Reasons are not evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from core.assets import normalize_domain
from core.intel.authorize import authorize_active_indicator
from core.intel.correlate import registrable_domain
from core.intel.model import (
    CollectReason,
    EntityType,
    Indicator,
    RelationshipType,
    entity_id,
)
from core.intel.scope import CollectionScope, indicator_hostname
from utils.files import read_jsonl

if TYPE_CHECKING:
    from core.intel.engine import IntelEngine

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


def load_certificate_backed_names(output_dir: Path) -> set[str]:
    """Names corroborated by CT artifacts (not plugin reason strings)."""
    from core.intel.tls import extract_certificate_names

    names: set[str] = set()
    path = output_dir / "ctlogs.jsonl"
    if not path.exists():
        return names
    for record in read_jsonl(path):
        if not isinstance(record, dict):
            continue
        for name in extract_certificate_names(
            record.get("name_value") or record.get("common_name")
        ):
            normalized = normalize_domain(name)
            if normalized:
                names.add(normalized)
    return names


def wildcard_blocks_active_collection(
    hostname: str,
    wildcard_roots: set[str],
    reason: CollectReason,
    *,
    evidence_ok: bool,
) -> bool:
    """Block probes that exist only because a wildcard zone resolves them."""
    root = registrable_domain(hostname)
    if not root or root not in wildcard_roots:
        return False
    if reason not in INDEPENDENT_REASONS:
        return True
    if reason is CollectReason.SEED:
        return False
    return not evidence_ok


def evidence_supports_certificate_followup(engine: IntelEngine | None, item: Indicator) -> bool:
    """CERTIFICATE_SAN / SHARED_CERTIFICATE require real evidence, not a reason string."""
    if engine is None:
        return False
    if not item.evidence_id:
        return False
    evidence = engine.evidence.get(item.evidence_id)
    if evidence is None:
        return False
    observation = next(
        (obs for obs in engine.observations if obs.observation_id == evidence.observation_id),
        None,
    )
    if observation is None:
        return False
    host = indicator_hostname(item.value) or normalize_domain(item.value)
    domain_eid = entity_id(EntityType.DOMAIN, host)
    cert_id = (
        str(observation.data.get("certificate") or "")
        or str(evidence.metadata.get("certificate") or "")
        or (observation.entity_id if observation.entity_id.startswith("certificate:") else "")
    )
    if not cert_id or cert_id not in engine.entities:
        return False
    if engine.entities[cert_id].entity_type is not EntityType.CERTIFICATE:
        return False
    if item.reason is CollectReason.CERTIFICATE_SAN:
        if str(observation.data.get("observed_as") or "") != "certificate_san":
            return False
        if str(observation.data.get("certificate") or "") != cert_id:
            return False
        return any(
            rel.relationship_type is RelationshipType.SAN_CONTAINS
            and rel.source_entity == cert_id
            and rel.target_entity == domain_eid
            and rel.evidence_id
            for rel in engine.relationships.values()
        )
    if item.reason is CollectReason.SHARED_CERTIFICATE:
        return any(
            rel.relationship_type
            in {RelationshipType.SAN_CONTAINS, RelationshipType.SHARES_CERTIFICATE}
            and rel.evidence_id
            and (
                rel.source_entity == cert_id
                or rel.target_entity == domain_eid
                or rel.source_entity == domain_eid
            )
            for rel in engine.relationships.values()
        )
    return False


def plan_followup_collection(
    *,
    candidates: list[Indicator],
    scope: CollectionScope,
    wildcard_roots: set[str],
    already_collected: set[str],
    dns_budget: int,
    http_budget: int,
    engine: IntelEngine | None = None,
) -> FollowUpPlan:
    """Normalize → evidence → scope → wildcard → authorize. Never trust queue status."""
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
        if item.reason in INDEPENDENT_REASONS and item.reason is not CollectReason.SEED:
            pass  # evidence checked after scope so OOS still reports out_of_scope
        decision = authorize_active_indicator(
            host, scope, "followup_collection", item.reason.value
        )
        if not decision.allowed:
            plan.decisions.append(
                FollowUpDecision(
                    host,
                    False,
                    "out_of_scope" if decision.decision.value == "DENY" else "unauthorized",
                )
            )
            continue
        if item.reason in INDEPENDENT_REASONS and item.reason is not CollectReason.SEED:
            if not evidence_supports_certificate_followup(engine, item):
                plan.decisions.append(
                    FollowUpDecision(host, False, "spoofed_or_missing_evidence")
                )
                continue
        evidence_ok = evidence_supports_certificate_followup(engine, item)
        if wildcard_blocks_active_collection(
            host, wildcard_roots, item.reason, evidence_ok=evidence_ok
        ):
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


def apply_wildcard_seed_dns_policy(
    names: list[str],
    *,
    seeds: list[str],
    wildcard_roots: set[str],
    certificate_backed: set[str],
    scope: CollectionScope,
) -> tuple[list[str], list[str]]:
    """DNS-only names under a wildcard root are not active DNS targets.

    Certificate-backed (CT SAN) names may still be resolved if authorized.
    ``subdomains.txt`` is not rewritten — this only filters collector input.
    """
    if not wildcard_roots:
        kept = [
            name
            for name in names
            if authorize_active_indicator(name, scope, "dnsx", "seed_dns").allowed
        ]
        return kept, []
    seed_set = {normalize_domain(item) for item in seeds if normalize_domain(item)}
    kept: list[str] = []
    withheld: list[str] = []
    for raw in names:
        host = indicator_hostname(raw) or normalize_domain(raw)
        if not host:
            continue
        decision = authorize_active_indicator(host, scope, "dnsx", "seed_dns")
        if not decision.allowed:
            withheld.append(host)
            continue
        root = registrable_domain(host)
        if root in wildcard_roots and host not in seed_set and host not in certificate_backed:
            withheld.append(host)
            continue
        kept.append(host)
    return kept, withheld

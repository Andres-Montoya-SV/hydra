"""Evidence-backed infrastructure correlation. No actor/owner inference."""

from __future__ import annotations

from collections import defaultdict

from core.domain import parse_hostname
from core.intel.cloud import cloud_provider_for_ip, is_ipv4, is_ipv6
from core.intel.model import ConfidenceBand, EntityType

# Named bands → integer scores used by clustering, graph, HTML, and CLI.
BAND_SCORE: dict[ConfidenceBand, int] = {
    ConfidenceBand.VERY_HIGH: 98,
    ConfidenceBand.HIGH: 88,
    ConfidenceBand.MEDIUM: 65,
    ConfidenceBand.LOW: 40,
}

IDENTIFIED_CERTIFICATE_KINDS = frozenset({"sha256", "serial_issuer"})


def band_score(band: ConfidenceBand) -> int:
    return BAND_SCORE[band]


def score_to_band(score: int) -> ConfidenceBand:
    if score >= 94:
        return ConfidenceBand.VERY_HIGH
    if score >= 80:
        return ConfidenceBand.HIGH
    if score >= 55:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW


# Domain-domain SHARES_* cliques above this size use hub edges only
# (domain → certificate/IP → domain). 16 members = 120 pairs.
MAX_PAIRWISE_SHARE_MEMBERS = 16


def pair_domains(members: list[str]) -> list[tuple[str, str]]:
    """Deterministic undirected pairs (sorted)."""
    unique = sorted(set(members))
    pairs: list[tuple[str, str]] = []
    for i, left in enumerate(unique):
        for right in unique[i + 1 :]:
            pairs.append((left, right))
    return pairs


def bounded_pairs(
    members: list[str], *, max_members: int = MAX_PAIRWISE_SHARE_MEMBERS
) -> list[tuple[str, str]]:
    """Pairwise share edges only for small member sets. Large sets stay hub-only."""
    unique = sorted(set(members))
    if len(unique) < 2 or len(unique) > max_members:
        return []
    return pair_domains(unique)


def registrable_domain(hostname: str) -> str:
    _, _, root = parse_hostname(hostname)
    return root


def ipv4_confidence(ip: str) -> tuple[ConfidenceBand, str]:
    """Shared IPv4 is MEDIUM on cloud tenancy, HIGH on non-cloud addresses."""
    provider = cloud_provider_for_ip(ip)
    if provider:
        return ConfidenceBand.MEDIUM, "shared_cloud_tenancy"
    return ConfidenceBand.HIGH, "shared_ipv4"


def ipv6_confidence(ip: str) -> tuple[ConfidenceBand, str]:
    provider = cloud_provider_for_ip(ip)
    if provider:
        return ConfidenceBand.MEDIUM, "shared_cloud_tenancy"
    return ConfidenceBand.HIGH, "shared_ipv6"


def shares_certificate_confidence(
    sans: list[str],
    *,
    identity_kind: str,
) -> tuple[ConfidenceBand, str] | None:
    """Domain-domain SHARES_CERTIFICATE decays with SAN / eTLD+1 diversity.

    SAN_CONTAINS stays independently VERY_HIGH. This function only qualifies
    the pairwise domain correlation. Unidentified certificates do not correlate.
    """
    if identity_kind not in IDENTIFIED_CERTIFICATE_KINDS:
        return None
    names = [name for name in sans if name]
    cardinality = len(set(names))
    diversity = len({registrable_domain(name) for name in names if registrable_domain(name)})
    if diversity >= 50 or cardinality >= 80:
        return ConfidenceBand.LOW, "shared_certificate_high_cardinality"
    if diversity >= 15 or cardinality >= 25:
        return ConfidenceBand.MEDIUM, "shared_certificate_diverse_san"
    return ConfidenceBand.HIGH, "shared_leaf_certificate"


def cluster_signal_confidence(
    cluster_type: str, signal: str, size: int
) -> tuple[ConfidenceBand, str]:
    """Map Host-view clusters onto the same named bands as IntelEngine."""
    if cluster_type == "ip":
        if is_ipv4(signal):
            return ipv4_confidence(signal)
        if is_ipv6(signal):
            return ipv6_confidence(signal)
        return ConfidenceBand.LOW, "unparseable_ip"
    if cluster_type == "favicon":
        return ConfidenceBand.MEDIUM, "shared_favicon"
    if cluster_type == "body_hash":
        return ConfidenceBand.MEDIUM, "shared_body_hash"
    if cluster_type == "certificate":
        if size >= 20:
            return ConfidenceBand.MEDIUM, "shared_certificate_diverse_san"
        return ConfidenceBand.HIGH, "shared_leaf_certificate"
    if cluster_type in {"cdn", "waf", "asn", "cidr"}:
        return ConfidenceBand.MEDIUM, f"shared_{cluster_type}"
    if cluster_type in {"title", "technology", "redirect", "webserver"}:
        return ConfidenceBand.LOW, f"shared_{cluster_type}"
    return ConfidenceBand.MEDIUM, f"shared_{cluster_type}"


def index_by_type(entities: dict) -> dict[EntityType, list]:
    grouped: dict[EntityType, list] = defaultdict(list)
    for entity in entities.values():
        grouped[entity.entity_type].append(entity)
    return grouped


def ip_version_label(ip: str) -> str | None:
    if is_ipv4(ip):
        return "ipv4"
    if is_ipv6(ip):
        return "ipv6"
    return None

"""First-class intelligence types. No actor/owner/campaign entities."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EntityType(str, Enum):
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    CERTIFICATE = "CERTIFICATE"
    ASN = "ASN"
    NAMESERVER = "NAMESERVER"
    URL = "URL"
    HTTP_SERVICE = "HTTP_SERVICE"
    TECHNOLOGY = "TECHNOLOGY"


class IndicatorKind(str, Enum):
    DOMAIN = "DOMAIN"
    IP = "IP"
    CERTIFICATE = "CERTIFICATE"
    URL = "URL"


class ScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class CollectionStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    ELIGIBLE = "ELIGIBLE"
    IN_FLIGHT = "IN_FLIGHT"
    COLLECTED = "COLLECTED"
    FAILED = "FAILED"
    NOT_ALLOWED = "NOT_ALLOWED"
    REJECTED = "REJECTED"
    # Entity projection: observed but not actively collected.
    NOT_COLLECTED = "NOT_COLLECTED"


class ConfidenceBand(str, Enum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RelationshipType(str, Enum):
    PRESENTS_CERTIFICATE = "PRESENTS_CERTIFICATE"
    SAN_CONTAINS = "SAN_CONTAINS"
    RESOLVES_TO = "RESOLVES_TO"
    PRESENTED_AT = "PRESENTED_AT"
    SHARES_CERTIFICATE = "SHARES_CERTIFICATE"
    SHARES_IPV4 = "SHARES_IPV4"
    SHARES_IPV6 = "SHARES_IPV6"
    SHARES_NAMESERVER = "SHARES_NAMESERVER"
    SHARES_ASN = "SHARES_ASN"
    SHARES_FAVICON = "SHARES_FAVICON"
    SHARES_BODY_HASH = "SHARES_BODY_HASH"
    SHARES_TLS_CHARACTERISTICS = "SHARES_TLS_CHARACTERISTICS"
    HAS_NAMESERVER = "HAS_NAMESERVER"
    IN_ASN = "IN_ASN"
    SERVES_HTTP = "SERVES_HTTP"
    RUNS_TECHNOLOGY = "RUNS_TECHNOLOGY"
    SEED_TARGET = "SEED_TARGET"


class CollectReason(str, Enum):
    SEED = "SEED"
    CERTIFICATE_SAN = "CERTIFICATE_SAN"
    DNS_RESOLUTION = "DNS_RESOLUTION"
    SHARED_CERTIFICATE = "SHARED_CERTIFICATE"
    SHARED_IPV4 = "SHARED_IPV4"
    PLUGIN = "PLUGIN"


def stable_id(*parts: str) -> str:
    """Deterministic identifier from canonical parts."""
    payload = "|".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


def normalize_fingerprint(value: str | None) -> str:
    """Return lowercase 64-char hex SHA-256 or empty string."""
    if not value:
        return ""
    hexpart = "".join(ch for ch in str(value).lower() if ch in "0123456789abcdef")
    return hexpart if len(hexpart) == 64 else ""


def entity_id(entity_type: EntityType, key: str) -> str:
    kind = entity_type.value.lower()
    return f"{kind}:{key}"


def certificate_entity_id(fingerprint_sha256: str | None, *, fallback: str = "") -> str:
    fp = normalize_fingerprint(fingerprint_sha256)
    if fp:
        return entity_id(EntityType.CERTIFICATE, fp)
    if fallback:
        return entity_id(EntityType.CERTIFICATE, fallback)
    raise ValueError("certificate identity requires SHA-256 fingerprint or explicit fallback")


@dataclass
class IntelEntity:
    entity_id: str
    entity_type: EntityType
    key: str
    data: dict[str, Any] = field(default_factory=dict)
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    collection_status: CollectionStatus = CollectionStatus.NOT_COLLECTED
    is_seed: bool = False
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "key": self.key,
            "data": self.data,
            "scope_status": self.scope_status.value,
            "collection_status": self.collection_status.value,
            "is_seed": self.is_seed,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class Observation:
    observation_id: str
    entity_id: str
    source: str
    collector: str
    run_id: str
    observed_at: str
    data: dict[str, Any] = field(default_factory=dict)
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "entity_id": self.entity_id,
            "source": self.source,
            "collector": self.collector,
            "run_id": self.run_id,
            "observed_at": self.observed_at,
            "data": self.data,
            "scope_status": self.scope_status.value,
        }


@dataclass
class Evidence:
    evidence_id: str
    source: str
    collector: str
    observation_id: str
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "collector": self.collector,
            "observation_id": self.observation_id,
            "reason": self.reason,
            "metadata": self.metadata,
            "observed_at": self.observed_at,
        }


@dataclass
class Relationship:
    relationship_id: str
    source_entity: str
    relationship_type: RelationshipType
    target_entity: str
    confidence: ConfidenceBand
    strength: str
    first_seen: str
    last_seen: str
    evidence_id: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "source_entity": self.source_entity,
            "relationship_type": self.relationship_type.value,
            "target_entity": self.target_entity,
            "confidence": self.confidence.value,
            "strength": self.strength,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "evidence_id": self.evidence_id,
            "data": self.data,
        }


@dataclass
class Indicator:
    indicator_id: str
    kind: IndicatorKind
    value: str
    depth: int
    parent_id: str | None
    reason: CollectReason
    scope_status: ScopeStatus
    collection_status: CollectionStatus
    evidence_id: str
    priority: int = 100
    discovered_from: str = ""
    normalized_value: str = ""
    source_entity_id: str = ""
    authorization_status: str = ""
    created_at: str = ""
    claimed_at: str = ""
    completed_at: str = ""
    failure_reason: str = ""
    collector: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "kind": self.kind.value,
            "value": self.value,
            "normalized_value": self.normalized_value or self.value,
            "source_entity_id": self.source_entity_id or self.discovered_from,
            "depth": self.depth,
            "parent_id": self.parent_id,
            "reason": self.reason.value,
            "scope_status": self.scope_status.value,
            "collection_status": self.collection_status.value,
            "authorization_status": self.authorization_status,
            "evidence_id": self.evidence_id,
            "priority": self.priority,
            "discovered_from": self.discovered_from,
            "created_at": self.created_at,
            "claimed_at": self.claimed_at,
            "completed_at": self.completed_at,
            "failure_reason": self.failure_reason,
            "collector": self.collector,
        }


def dump_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))

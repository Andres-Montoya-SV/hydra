"""Small structured-output contract for plugins.

Plugins keep subprocess isolation and artifact files. They MAY also attach
`PluginResult.data["intel"]` with a StructuredEmission so the intelligence
engine can ingest entities/relationships without a new parser class.

This is intentionally not a generic plugin framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.intel.model import (
    ConfidenceBand,
    EntityType,
    RelationshipType,
    normalize_fingerprint,
)

ALLOWED_ENTITY_PREFIXES = tuple(f"{item.value.lower()}:" for item in EntityType)
FORBIDDEN_ENTITY_PREFIXES = (
    "actor:",
    "owner:",
    "threat_group:",
    "threat-actor:",
    "threat_actor:",
    "campaign:",
    "attribution:",
    "person:",
)


def _entity_allowed(entity_ref: str) -> bool:
    text = (entity_ref or "").strip().lower()
    if not text or ":" not in text:
        return False
    if any(text.startswith(prefix) for prefix in FORBIDDEN_ENTITY_PREFIXES):
        return False
    return any(text.startswith(prefix) for prefix in ALLOWED_ENTITY_PREFIXES)


def _fingerprint_from_ref(entity_ref: str, metadata: dict[str, Any]) -> str:
    fp = normalize_fingerprint(str(metadata.get("fingerprint_sha256") or ""))
    if fp:
        return fp
    if entity_ref.startswith("certificate:"):
        return normalize_fingerprint(entity_ref.split(":", 1)[1])
    return ""


def validate_emitted_relationship(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Accept only typed, evidenced plugin relationships. No attribution entities."""
    try:
        rel_type = RelationshipType(str(raw.get("relationship_type") or raw.get("type") or ""))
    except ValueError:
        return None
    source = str(raw.get("source_entity") or "")
    target = str(raw.get("target_entity") or "")
    if not _entity_allowed(source) or not _entity_allowed(target):
        return None
    confidence_raw = str(raw.get("confidence") or "MEDIUM")
    try:
        band = ConfidenceBand(confidence_raw)
    except ValueError:
        return None
    metadata = dict(raw.get("metadata") or {})
    if rel_type is RelationshipType.SHARES_CERTIFICATE:
        fp = _fingerprint_from_ref(source, metadata) or _fingerprint_from_ref(target, metadata)
        serial = str(metadata.get("certificate_serial") or metadata.get("serial") or "")
        if not fp and not serial:
            return None
        if band is ConfidenceBand.VERY_HIGH:
            band = ConfidenceBand.HIGH
        if fp:
            metadata.setdefault("fingerprint_sha256", fp)
    if rel_type is RelationshipType.PRESENTS_CERTIFICATE:
        fp = _fingerprint_from_ref(source, metadata) or _fingerprint_from_ref(target, metadata)
        if band is ConfidenceBand.VERY_HIGH and not fp:
            return None
        if fp:
            metadata.setdefault("fingerprint_sha256", fp)
    return {
        "relationship_type": rel_type,
        "source_entity": source,
        "target_entity": target,
        "confidence": band,
        "reason": str(raw.get("reason") or "plugin_relationship"),
        "collector": str(raw.get("collector") or "plugin"),
        "metadata": metadata,
    }


@dataclass
class StructuredEmission:
    """Optional structured output a collector may emit alongside artifacts."""

    produces: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    certificates: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    followups: list[dict[str, Any]] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "produces": list(self.produces),
            "domains": list(self.domains),
            "ip_addresses": list(self.ip_addresses),
            "certificates": list(self.certificates),
            "relationships": list(self.relationships),
            "followups": list(self.followups),
            "observations": list(self.observations),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> StructuredEmission:
        if not raw:
            return cls()
        return cls(
            produces=list(raw.get("produces") or []),
            domains=[str(d) for d in (raw.get("domains") or [])],
            ip_addresses=[str(i) for i in (raw.get("ip_addresses") or [])],
            certificates=[dict(c) for c in (raw.get("certificates") or []) if isinstance(c, dict)],
            relationships=[
                dict(r) for r in (raw.get("relationships") or []) if isinstance(r, dict)
            ],
            followups=[dict(f) for f in (raw.get("followups") or []) if isinstance(f, dict)],
            observations=[dict(o) for o in (raw.get("observations") or []) if isinstance(o, dict)],
        )

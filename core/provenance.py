"""Structured provenance tracking for reconnaissance findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProvenanceRecord:
    """Single observation with full audit trail."""

    tool: str
    field: str
    value: str
    confidence: int  # 0-100
    discovered_at: str = field(default_factory=utc_now_iso)
    verified_by: list[str] = field(default_factory=list)
    artifact_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "field": self.field,
            "value": self.value,
            "confidence": self.confidence,
            "discovered_at": self.discovered_at,
            "verified_by": self.verified_by,
            "artifact_path": self.artifact_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceRecord:
        return cls(
            tool=str(data.get("tool", "")),
            field=str(data.get("field", "")),
            value=str(data.get("value", "")),
            confidence=int(data.get("confidence", 25)),
            discovered_at=str(data.get("discovered_at", utc_now_iso())),
            verified_by=list(data.get("verified_by") or []),
            artifact_path=data.get("artifact_path"),
        )


def record_observation(
    *,
    tool: str,
    field: str,
    value: str,
    confidence: int,
    verified_by: list[str] | None = None,
    artifact_path: str | None = None,
) -> ProvenanceRecord:
    """Create a provenance record with bounded confidence."""
    return ProvenanceRecord(
        tool=tool,
        field=field,
        value=value,
        confidence=max(0, min(100, confidence)),
        verified_by=verified_by or [],
        artifact_path=Path(artifact_path).name if artifact_path else None,
    )

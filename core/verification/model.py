"""Data model for the verification agent — see
docs/VERIFICATION_AGENT_DESIGN.md Part B.2/C for the design this implements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContradictionSeverity(str, Enum):
    """Deliberately two-valued, not a numeric scale (design Part B.2): a
    contradiction either means the original claim is simply wrong
    (INVALIDATES), or means a second source disagrees without either being
    proven wrong (DOWNGRADES_CONFIDENCE). Do not add a third value or widen
    this to a numeric scale without updating
    docs/VERIFICATION_AGENT_DESIGN.md first — the two-value design is a
    documented decision, not an oversight.
    """

    INVALIDATES = "INVALIDATES"
    DOWNGRADES_CONFIDENCE = "DOWNGRADES_CONFIDENCE"


class VerificationStatus(str, Enum):
    """CONFIRMED: the detector fired and the contradiction is real.
    DISMISSED: a human reviewed a CONFIRMED flag and rejected it (this
    package never sets DISMISSED itself — nothing here decides on its own
    that a contradiction doesn't matter). UNRESOLVED: no detector applies
    and no explanation is confirmed (catalog item 9's status — a
    phenomenon must never be silently dropped for lack of a detector)."""

    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class VerificationFinding:
    """One contradiction between an interpreted claim and the raw evidence
    that either backs or contradicts it. See
    docs/VERIFICATION_AGENT_DESIGN.md Part B.2 for the exact shape this
    mirrors.
    """

    claim: str
    evidence: str
    raw_artifact: str | None
    severity: ContradictionSeverity
    detector: str
    host: str | None = None
    status: VerificationStatus = VerificationStatus.CONFIRMED
    related_table: str | None = None
    related_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "evidence": self.evidence,
            "raw_artifact": self.raw_artifact,
            "severity": self.severity.value,
            "detector": self.detector,
            "host": self.host,
            "status": self.status.value,
            "related_table": self.related_table,
            "related_id": self.related_id,
            "metadata": self.metadata,
        }

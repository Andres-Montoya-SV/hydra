"""Fase 10 (EASM roadmap): external observation sources, confidence
classes, and deterministic precedence reconciliation. Pure module — no
database access, no `datetime.now()`, no LLM, no probabilistic scoring —
same discipline as `api/change_detection.py`.

**Reused, not reinvented**: Fase 04 already has a real, tested
Observation/Evidence model (`api/observation_identity.py`,
`api/control_db.py`'s `observations`/`evidence` tables). Fase 10 does not
build a second, parallel observation pipeline for external data — it
extends the existing one with the two things it didn't need until now:
which SOURCE CLASS produced a fact (Hydra's own scan vs. an imported
Nmap/RDAP/customer feed) and which CONFIDENCE CLASS that source class
implies. `EvidenceContent.confidence_class` (added in
`api/observation_identity.py`) carries this straight through the exact
same `find_or_create_evidence`/`record_observation` methods every other
phase already uses.

**The core rule, stated once, enforced by one pure function**: `Observed
!= Owned`, and imported data is never authorization — anything imported
that does not already correspond to a real, existing `assets` row is
routed to `candidate_assets` (Fase 06), never inserted into `assets`
directly (see `api/external_observation_ingest.py`, the I/O layer built
on top of this module).

**Precedence never deletes or downgrades anything already stored** — a
third-party import and a Hydra direct observation for the same fact are
BOTH kept, forever, as separate `evidence` rows (they already have
different `source` values, so they were never going to collide in
storage). `reconcile_precedence` only answers a QUERY-time question —
"which of these already-stored candidates should a caller currently
trust" — and does so by a fixed, documented rank, never by simply
picking whichever arrived most recently.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ObservationSource(str, Enum):
    """Only the source types this phase's own scope actually names as
    implemented — no speculative source ahead of a real importer that
    needs it (Fase 10's own "no implementar ningún [provider] todavía"
    instruction)."""

    HYDRA = "HYDRA"
    NMAP = "NMAP"
    MASSCAN = "MASSCAN"
    CUSTOMER_IMPORT = "CUSTOMER_IMPORT"
    RDAP = "RDAP"
    CERTIFICATE_TRANSPARENCY = "CERTIFICATE_TRANSPARENCY"
    CLOUD_PROVIDER = "CLOUD_PROVIDER"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"


class ObservationConfidenceClass(str, Enum):
    """Deliberately NOT a universal numeric score — a small, named set of
    classes, each with one clear meaning, per the phase's own "sin un
    score universal arbitrario" instruction."""

    DIRECT_CURRENT = "DIRECT_CURRENT"
    HISTORICAL = "HISTORICAL"
    THIRD_PARTY_CURRENT = "THIRD_PARTY_CURRENT"
    CUSTOMER_SUPPLIED = "CUSTOMER_SUPPLIED"
    INFERRED_RELATIONSHIP = "INFERRED_RELATIONSHIP"


# Higher wins. A live Hydra observation always outranks any external
# source, however recent that external source is — this is the concrete
# rule behind "una observación vieja de terceros nunca sobrescribe una
# observación directa más fresca de Hydra": DIRECT_CURRENT's rank is not
# just higher than THIRD_PARTY_CURRENT/HISTORICAL, it is higher
# regardless of timestamp, because `reconcile_precedence` below only
# consults `last_seen_at` to break a tie WITHIN the same class, never to
# let a lower class outrank a higher one. Customer-supplied data is
# trusted more than an arbitrary third-party feed (the customer is
# asserting first-hand knowledge of their own infrastructure) but still
# less than Hydra's own direct, current look. Inferred relationships
# (e.g. "this SAN implies a related domain") are the weakest class — a
# derived guess, not even a first-hand external observation.
CONFIDENCE_CLASS_RANK: dict[ObservationConfidenceClass, int] = {
    ObservationConfidenceClass.DIRECT_CURRENT: 100,
    ObservationConfidenceClass.CUSTOMER_SUPPLIED: 80,
    ObservationConfidenceClass.THIRD_PARTY_CURRENT: 60,
    ObservationConfidenceClass.INFERRED_RELATIONSHIP: 40,
    ObservationConfidenceClass.HISTORICAL: 20,
}

DEFAULT_SOURCE_CONFIDENCE_CLASS: dict[ObservationSource, ObservationConfidenceClass] = {
    ObservationSource.HYDRA: ObservationConfidenceClass.DIRECT_CURRENT,
    ObservationSource.NMAP: ObservationConfidenceClass.THIRD_PARTY_CURRENT,
    ObservationSource.MASSCAN: ObservationConfidenceClass.THIRD_PARTY_CURRENT,
    ObservationSource.CUSTOMER_IMPORT: ObservationConfidenceClass.CUSTOMER_SUPPLIED,
    ObservationSource.RDAP: ObservationConfidenceClass.THIRD_PARTY_CURRENT,
    ObservationSource.CERTIFICATE_TRANSPARENCY: ObservationConfidenceClass.THIRD_PARTY_CURRENT,
    ObservationSource.CLOUD_PROVIDER: ObservationConfidenceClass.THIRD_PARTY_CURRENT,
    ObservationSource.EXTERNAL_INTELLIGENCE: ObservationConfidenceClass.THIRD_PARTY_CURRENT,
}


@dataclass(frozen=True)
class PrecedenceCandidate:
    """The minimal, DB-free shape `reconcile_precedence` needs to rank
    one already-stored evidence row against others for the same fact —
    never a live DB handle, keeping this function pure."""

    evidence_id: str
    confidence_class: ObservationConfidenceClass
    last_seen_at: str


def reconcile_precedence(candidates: list[PrecedenceCandidate]) -> PrecedenceCandidate | None:
    """Deterministic: the same list, in any order, always returns the
    same winner. Ranked by `CONFIDENCE_CLASS_RANK` first (a class never
    loses to a lower class no matter how old it is), `last_seen_at`
    second (breaks a tie within the same class by recency only), and
    `evidence_id` last (a final, arbitrary but STABLE tiebreaker so two
    candidates identical in every other way still resolve
    deterministically rather than depending on dict/list ordering)."""
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda c: (CONFIDENCE_CLASS_RANK[c.confidence_class], c.last_seen_at, c.evidence_id),
    )


@dataclass(frozen=True)
class ExternalObservationDraft:
    """One fact one external batch reported about one candidate asset
    identity — the shape `api/external_observation_ingest.py` consumes.
    `candidate_type`/`normalized_value` reuse `api/candidate_assets.py`'s
    own vocabulary and normalization exactly (`IndicatorKind`-shaped),
    never a second identity scheme for the same concept."""

    candidate_type: str
    normalized_value: str
    display_value: str
    observation_type: str
    detail: str
    source: ObservationSource
    confidence_class: ObservationConfidenceClass

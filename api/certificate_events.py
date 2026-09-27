"""Fase 12 (EASM roadmap): deterministic classification of what changed
between two consecutive certificate observations Hydra recorded for the
SAME domain asset. Pure module — no database access, no `datetime.now()`
— same discipline as `api/change_detection.py`.

**Why a separate "Certificate" asset type was NOT built** (the phase's
own "si el modelo actual no basta" qualifier — build one only if the
current model doesn't already suffice): `core/intel/engine.py` already
emits `PRESENTS_CERTIFICATE`/`SAN_CONTAINS`/`SHARES_CERTIFICATE`
relationships from real TLS observations, and Fase 07's relationship
backfill already persists ALL `intel_relationships` rows regardless of
type into the EASM relationship graph unchanged — a certificate shared
across domains is therefore ALREADY visible as a `SHARES_CERTIFICATE`
relationship, never as asset ownership, with zero new code. A genuinely
new `certificates` table would also break Fase 03's "one asset, one
host" assumption the moment a certificate is shared across domains
(`host_for_asset` has no single answer for "which domain does this
certificate belong to").

What was genuinely missing was per-domain change classification —
"did the certificate THIS domain presents get renewed, or actually
replaced by a different issuer, or gain/lose a SAN" — which this module
provides. It rides entirely on Fase 04's existing Evidence model: a
certificate's full shape (fingerprint, subject, issuer, validity window,
SANs) is carried, verbatim, as one canonical string in
`EvidenceContent.detail` for the domain's own
`OBSERVATION_TYPE_CERTIFICATE_PRESENT` observation
(`api/observation_identity.py`) — this module only parses that string
back into a `CertificateSnapshot` and compares two of them. No new
observation/evidence pipeline, no new asset type.

**The observation time / validity time distinction the phase requires**
("el tiempo de observación se mantiene separado del tiempo de validez"):
`not_before`/`not_after` here are the certificate's OWN validity window,
carried as opaque strings never interpreted as "when Hydra saw this" —
that is `Observation.observed_at`/`Evidence.first_seen_at`/`last_seen_at`,
a completely separate pair of timestamps this module never touches.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

_FIELD_SEP = "|"
_SAN_SEP = ","
_KV_SEP = "="


class CertificateEventType(str, Enum):
    FIRST_SEEN = "CERTIFICATE_FIRST_SEEN"
    RENEWED = "CERTIFICATE_RENEWED"
    CHANGED = "CERTIFICATE_CHANGED"
    SAN_ADDED = "SAN_ADDED"
    SAN_REMOVED = "SAN_REMOVED"


@dataclass(frozen=True)
class CertificateSnapshot:
    fingerprint_sha256: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    sans: tuple[str, ...]


@dataclass(frozen=True)
class CertificateEvent:
    event_type: CertificateEventType
    reason: str


def certificate_snapshot_detail(
    *,
    fingerprint_sha256: str,
    subject: str | None,
    issuer: str | None,
    not_before: str | None,
    not_after: str | None,
    sans: Iterable[str],
) -> str:
    """The single canonical serialization
    `api/observation_identity.py::observations_for_host` writes into
    `EvidenceContent.detail` and `parse_certificate_snapshot` below reads
    back — kept in exact lockstep on purpose, one format, one place,
    never re-derived independently on either side."""
    sorted_sans = _SAN_SEP.join(sorted(set(sans)))
    return _FIELD_SEP.join(
        [
            f"fingerprint{_KV_SEP}{fingerprint_sha256}",
            f"subject{_KV_SEP}{subject or ''}",
            f"issuer{_KV_SEP}{issuer or ''}",
            f"not_before{_KV_SEP}{not_before or ''}",
            f"not_after{_KV_SEP}{not_after or ''}",
            f"sans{_KV_SEP}{sorted_sans}",
        ]
    )


def parse_certificate_snapshot(detail: str) -> CertificateSnapshot | None:
    """Returns `None` for anything that isn't this module's own
    serialization format (defensive against a stray non-certificate
    evidence row ending up in the wrong caller by mistake — never raises
    on unexpected input)."""
    fields: dict[str, str] = {}
    for part in detail.split(_FIELD_SEP):
        key, sep, value = part.partition(_KV_SEP)
        if not sep:
            continue
        fields[key] = value
    fingerprint = fields.get("fingerprint", "")
    if not fingerprint:
        return None
    sans_raw = fields.get("sans", "")
    sans = tuple(s for s in sans_raw.split(_SAN_SEP) if s)
    return CertificateSnapshot(
        fingerprint_sha256=fingerprint,
        subject=fields.get("subject", ""),
        issuer=fields.get("issuer", ""),
        not_before=fields.get("not_before", ""),
        not_after=fields.get("not_after", ""),
        sans=sans,
    )


def classify_certificate_transition(
    *, previous: CertificateSnapshot | None, current: CertificateSnapshot
) -> list[CertificateEvent]:
    """Deterministic and explainable — every returned event cites the
    concrete before/after values that produced it, never a bare label.
    Can return MORE than one event for a single transition: a renewal
    that also drops a SAN is both a RENEWED and a SAN_REMOVED event,
    reported as two separately citable facts rather than one lossy
    label."""
    if previous is None:
        return [
            CertificateEvent(
                CertificateEventType.FIRST_SEEN,
                f"first certificate observed for this domain: fingerprint {current.fingerprint_sha256}",
            )
        ]
    if previous.fingerprint_sha256 == current.fingerprint_sha256:
        return []  # identical fact -- Fase 04's own evidence dedup already collapsed this

    events: list[CertificateEvent] = []
    same_identity = previous.subject == current.subject and previous.issuer == current.issuer
    if same_identity:
        events.append(
            CertificateEvent(
                CertificateEventType.RENEWED,
                f"same subject/issuer, new fingerprint ({previous.fingerprint_sha256} -> "
                f"{current.fingerprint_sha256}), validity {previous.not_after!r} -> {current.not_after!r}",
            )
        )
    else:
        events.append(
            CertificateEvent(
                CertificateEventType.CHANGED,
                f"issuer/subject changed ({previous.issuer!r}/{previous.subject!r} -> "
                f"{current.issuer!r}/{current.subject!r})",
            )
        )

    previous_sans = set(previous.sans)
    current_sans = set(current.sans)
    added = sorted(current_sans - previous_sans)
    removed = sorted(previous_sans - current_sans)
    if added:
        events.append(
            CertificateEvent(CertificateEventType.SAN_ADDED, f"SANs added: {', '.join(added)}")
        )
    if removed:
        events.append(
            CertificateEvent(
                CertificateEventType.SAN_REMOVED, f"SANs removed: {', '.join(removed)}"
            )
        )
    return events

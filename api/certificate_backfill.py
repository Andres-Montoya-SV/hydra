"""Fase 12 (EASM roadmap): walks each domain asset's own
`OBSERVATION_TYPE_CERTIFICATE_PRESENT` evidence history (already
recorded by Fase 04 from real `Host.tls` captures — no new collection)
and records the deterministic certificate events
`api/certificate_events.py::classify_certificate_transition` decides
between each consecutive distinct certificate.

A separate pass from `api/change_backfill.py`, same reasoning as that
module's own separation from `api/asset_backfill.py`:
`change_backfill` answers "did ANY fact about this asset change";
this answers the specific, richer question "how, exactly, did the
certificate change (renewed / replaced / SAN added or removed)" — reusing
the exact same Evidence/Observation rows, never a second collection or a
new asset type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.certificate_events import (
    CertificateSnapshot,
    classify_certificate_transition,
    parse_certificate_snapshot,
)
from api.observation_identity import OBSERVATION_TYPE_CERTIFICATE_PRESENT

if TYPE_CHECKING:
    from api.control_db import ControlDB


@dataclass(frozen=True)
class CertificateBackfillSummary:
    domain_assets_processed: int
    certificate_transitions_seen: int
    events_recorded: int
    events_already_present: int
    unparseable_evidence_skipped: int


def detect_certificate_events_for_organization(
    *, control_db: ControlDB, organization_id: str
) -> CertificateBackfillSummary:
    """Idempotent: `record_certificate_event`'s own
    `UNIQUE(asset_id, run_id, event_type, reason)` constraint means
    running this twice over the same organization's data produces zero
    duplicate rows — every event on the second pass lands in
    `events_already_present` instead."""
    domain_assets = control_db.list_assets_for_organization(organization_id, asset_type="domain")

    domain_assets_processed = 0
    certificate_transitions_seen = 0
    events_recorded = 0
    events_already_present = 0
    unparseable_evidence_skipped = 0

    for asset in domain_assets:
        observations = [
            entry
            for entry in control_db.list_observations_for_asset(asset.asset_id)
            if entry.observation.observation_type == OBSERVATION_TYPE_CERTIFICATE_PRESENT
        ]
        if not observations:
            continue
        domain_assets_processed += 1

        # Chronological by (observed_at, evidence_id) -- evidence_id is
        # the final, stable tiebreaker for observations recorded in the
        # same instant, the same determinism discipline
        # api/change_detection.py's own digest comparison already relies
        # on.
        observations.sort(
            key=lambda entry: (entry.observation.observed_at, entry.evidence.evidence_id)
        )

        previous_snapshot: CertificateSnapshot | None = None
        previous_evidence_id: str | None = None
        for entry in observations:
            if entry.evidence.evidence_id == previous_evidence_id:
                continue  # the exact same fact re-observed by a later run -- not a transition

            snapshot = parse_certificate_snapshot(entry.evidence.detail)
            if snapshot is None:
                unparseable_evidence_skipped += 1
                continue

            certificate_transitions_seen += 1
            for event in classify_certificate_transition(
                previous=previous_snapshot, current=snapshot
            ):
                result = control_db.record_certificate_event(
                    organization_id=organization_id,
                    asset_id=asset.asset_id,
                    run_id=entry.observation.run_id,
                    event_type=event.event_type.value,
                    reason=event.reason,
                    previous_fingerprint=(
                        previous_snapshot.fingerprint_sha256
                        if previous_snapshot is not None
                        else None
                    ),
                    new_fingerprint=snapshot.fingerprint_sha256,
                    detected_at=entry.observation.observed_at,
                )
                if result is not None:
                    events_recorded += 1
                else:
                    events_already_present += 1

            previous_snapshot = snapshot
            previous_evidence_id = entry.evidence.evidence_id

    return CertificateBackfillSummary(
        domain_assets_processed=domain_assets_processed,
        certificate_transitions_seen=certificate_transitions_seen,
        events_recorded=events_recorded,
        events_already_present=events_already_present,
        unparseable_evidence_skipped=unparseable_evidence_skipped,
    )

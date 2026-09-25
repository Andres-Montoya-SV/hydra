"""Fase 05 (EASM roadmap): runs the pure state machine in
`api/change_detection.py` against an organization's REAL, already-
recorded assets/observations (Fases 03/04) and persists the resulting
`change_events`.

Deliberately a SEPARATE pass from `api/asset_backfill.py`, not a third
thing bolted into that same per-host loop: Fase 03/04's backfill
computes things PER HOST PER RUN (as each run's data streams past);
change detection is fundamentally PER ASSET ACROSS ALL ITS RELEVANT
RUNS — it needs the full picture before it can decide anything, so it
runs as its own pass, after `api/asset_backfill.py` has already
populated `assets`/`observations`/`evidence` for the organization.

**Which runs are "relevant" to a given asset — a real, deliberate
scoping decision, not an oversight**: a naive "every completed scan in
this organization is a check for every asset in this organization" would
be wrong the moment an organization monitors more than one distinct
domain — a scan of `other-target.example` would then count as a "missed
run" for an asset that only ever lived under `example.com`, and enough
of those would eventually misfire a false `DISAPPEARED` for an asset
nothing ever tried to check. `api/change_detection.py::host_for_asset`
extracts the real underlying host from each asset's own identity, and
`api.domain_verification.domain_is_covered` (the SAME subdomain-aware
coverage check `POST /scans`'s own verified-domain gate already uses,
reused rather than reinvented) decides whether a given scan's target
domain actually covers that host before that scan counts as a check for
that asset at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.change_detection import (
    DEFAULT_MISSED_RUN_THRESHOLD,
    RunObservationOutcome,
    compute_asset_state_transitions,
    host_for_asset,
    observation_digest,
)
from api.domain_verification import domain_is_covered

if TYPE_CHECKING:
    from api.control_db import ControlDB


@dataclass(frozen=True)
class ChangeDetectionSummary:
    assets_processed: int
    relevant_run_checks: int
    change_events_recorded: int
    change_events_already_present: int


def detect_and_record_changes_for_organization(
    *,
    control_db: ControlDB,
    organization_id: str,
    missed_run_threshold: int = DEFAULT_MISSED_RUN_THRESHOLD,
) -> ChangeDetectionSummary:
    """For every asset this organization has, walks every completed scan
    that is actually relevant to that asset's own host (oldest first),
    building the exact `RunObservationOutcome` sequence
    `compute_asset_state_transitions` needs, then persists whichever
    `ChangeEvent`s that pure function decided. Idempotent — replaying
    this against the same, unchanged history records zero new rows the
    second time (`ControlDB.record_change_event`'s own `INSERT OR
    IGNORE` on `UNIQUE(asset_id, run_id)`)."""
    scans = [
        s
        for s in control_db.list_scans_for_organization(organization_id)
        if s.status == "completed"
    ]
    scans.sort(key=lambda s: s.created_at)

    assets_processed = 0
    relevant_run_checks = 0
    change_events_recorded = 0
    change_events_already_present = 0

    for asset in control_db.list_assets_for_organization(organization_id):
        assets_processed += 1
        host = host_for_asset(asset_type=asset.asset_type, identity_key=asset.identity_key)
        relevant_scans = [s for s in scans if domain_is_covered(host, s.domain)]

        run_outcomes = []
        for scan in relevant_scans:
            relevant_run_checks += 1
            facts = control_db.observation_digest_input_for_run(
                asset_id=asset.asset_id, run_id=scan.scan_id
            )
            observed = bool(facts)
            run_outcomes.append(
                RunObservationOutcome(
                    run_id=scan.scan_id,
                    observed=observed,
                    observation_digest=observation_digest(facts) if observed else None,
                )
            )

        events = compute_asset_state_transitions(
            run_outcomes=run_outcomes, missed_run_threshold=missed_run_threshold
        )
        for event in events:
            change_event_id = control_db.record_change_event(
                organization_id=organization_id,
                asset_id=asset.asset_id,
                run_id=event.run_id,
                previous_state=event.previous_state.value if event.previous_state else None,
                new_state=event.new_state.value,
                reason=event.reason,
                previous_digest=event.previous_digest,
                new_digest=event.new_digest,
            )
            if change_event_id is not None:
                change_events_recorded += 1
            else:
                change_events_already_present += 1

    return ChangeDetectionSummary(
        assets_processed=assets_processed,
        relevant_run_checks=relevant_run_checks,
        change_events_recorded=change_events_recorded,
        change_events_already_present=change_events_already_present,
    )

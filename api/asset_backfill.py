"""Fase 03 (asset identity) and Fase 04 (observations/evidence) of the
EASM roadmap: runs the pure reconciliation logic in
`api/asset_identity.py`/`api/observation_identity.py` against an
organization's REAL, already-existing run history — never against the
live scan-completion path.

Deliberately NOT wired into `api/scan_orchestrator.py`/
`api/monitoring_worker.py` — both phases' own prompts are explicit that
this is about "qué pasa DESPUÉS de que el scan ya corrió y guardó sus
resultados crudos," never the scanning flow itself. Live,
per-scan-completion wiring is deferred to whichever later phase actually
needs it triggered automatically rather than backfilled on demand.

Fase 04 extends this SAME backfill pass (rather than a second, separate
walk through run history) to also derive and persist observations/
evidence for each host it reconciles into an asset — the two phases
share one loop over the same `Host` rows because Fase 04's observations
need the asset_id Fase 03's reconciliation just resolved for that exact
host, in that exact run.

One backfill call is scoped to ONE organization — every `ScanRecord`
`list_scans_for_organization` returns carries its own `account_id`
(different scans under one organization are not guaranteed to share an
account_id in the general case — a future multi-owner-account
organization — so each scan's OWN account is used to open the right
`AssetStore` file, never an account assumed from the organization or
from a prior scan in the same loop).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.asset_identity import (
    ExistingAsset,
    cloud_storage_observation,
    reconcile_host_observations,
    reconcile_observation,
)
from api.observation_identity import EvidenceContent, observations_for_host
from api.tenancy import account_db_path
from core.store import AssetStore

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings


@dataclass(frozen=True)
class BackfillSummary:
    scans_processed: int
    hosts_processed: int
    assets_created: int
    assets_touched: int
    observations_recorded: int
    observations_already_present: int
    evidence_created_or_touched: int


def backfill_assets_for_organization(
    *, control_db: ControlDB, api_settings: APISettings, organization_id: str
) -> BackfillSummary:
    """Replays every `'completed'` scan this organization has ever had,
    oldest first, reconciling each scan's `Host` rows (read back from
    that scan's OWN account's `AssetStore` — never mutated, never
    deleted, per Fase 03's "no destructive migration of run_id-scoped
    tables" rule) into the organization's `assets`/`asset_identifiers`
    tables, THEN (Fase 04) deriving and persisting every observation/
    evidence pair that same `Host` implies, attached to the asset just
    reconciled.

    The in-memory `existing` map is seeded once from every asset already
    persisted for this organization, then updated as this SAME call
    mints new ones — so a host observed for the first time in an early
    scan and seen again in a later scan within this one backfill run
    correctly reconciles to the same asset, not two, without needing a
    round trip to the database between scans. Observations resolve their
    own asset_id from this exact same map, immediately after Fase 03's
    reconciliation updates it for the current host — never a second,
    independent identity computation."""
    scans = [
        s
        for s in control_db.list_scans_for_organization(organization_id)
        if s.status == "completed"
    ]
    scans.sort(key=lambda s: s.created_at)

    existing = control_db.existing_assets_for_organization(organization_id)
    scans_processed = 0
    hosts_processed = 0
    assets_created = 0
    assets_touched = 0
    observations_recorded = 0
    observations_already_present = 0
    evidence_created_or_touched = 0

    for scan in scans:
        store = AssetStore(account_db_path(api_settings, scan.account_id))
        hosts = store.get_hosts(scan.scan_id)
        scans_processed += 1
        observed_at = scan.updated_at or scan.created_at
        for host in hosts:
            hosts_processed += 1
            decisions = reconcile_host_observations(
                host=host,
                existing_by_identity_key=existing,
                new_asset_id=lambda: secrets.token_hex(16),
            )
            control_db.apply_asset_reconciliation(
                organization_id=organization_id,
                run_id=scan.scan_id,
                decisions=decisions,
                observed_at=observed_at,
            )
            for decision in decisions:
                if decision.is_new:
                    assets_created += 1
                else:
                    assets_touched += 1
                existing[decision.identity_key] = ExistingAsset(
                    asset_id=decision.asset_id,
                    asset_type=decision.asset_type,
                    identity_key=decision.identity_key,
                )

            for draft in observations_for_host(host):
                asset = existing.get(draft.identity_key)
                if asset is None:
                    # Unreachable in practice: every identity_key an
                    # observation draft carries is one of the SAME
                    # identity_key values reconcile_host_observations
                    # (above, this same host) just resolved into
                    # `existing`. Skipped defensively rather than raising
                    # — one malformed observation must never abort the
                    # rest of this host's, or this run's, backfill.
                    continue
                evidence_id = control_db.find_or_create_evidence(
                    organization_id=organization_id,
                    asset_id=asset.asset_id,
                    content=draft.evidence,
                    run_id=scan.scan_id,
                    observed_at=observed_at,
                )
                evidence_created_or_touched += 1
                observation_id = control_db.record_observation(
                    organization_id=organization_id,
                    asset_id=asset.asset_id,
                    run_id=scan.scan_id,
                    account_id=scan.account_id,
                    observation_type=draft.observation_type,
                    evidence_id=evidence_id,
                    observed_at=observed_at,
                )
                if observation_id is not None:
                    observations_recorded += 1
                else:
                    observations_already_present += 1

        for resource in store.get_cloud_resources(scan.scan_id):
            resource_name = str(resource.get("resource_name") or "").strip()
            if not resource_name:
                continue
            cloud_observation = cloud_storage_observation(resource)
            decision = reconcile_observation(
                observation=cloud_observation,
                existing_by_identity_key=existing,
                new_asset_id=lambda: secrets.token_hex(16),
            )
            control_db.apply_asset_reconciliation(
                organization_id=organization_id,
                run_id=scan.scan_id,
                decisions=[decision],
                observed_at=observed_at,
            )
            if decision.is_new:
                assets_created += 1
            else:
                assets_touched += 1
            existing[decision.identity_key] = ExistingAsset(
                asset_id=decision.asset_id,
                asset_type=decision.asset_type,
                identity_key=decision.identity_key,
            )

            evidence_id = control_db.find_or_create_evidence(
                organization_id=organization_id,
                asset_id=decision.asset_id,
                content=EvidenceContent(
                    source="cloud_bucket_enum",
                    detail=(
                        f"classification={resource.get('classification') or 'unknown'};"
                        f"public_listable={bool(resource.get('public_listable'))};"
                        f"url={resource.get('url') or ''}"
                    ),
                    confidence_score=int(resource.get("confidence_score") or 70),
                ),
                run_id=scan.scan_id,
                observed_at=observed_at,
            )
            evidence_created_or_touched += 1
            observation_id = control_db.record_observation(
                organization_id=organization_id,
                asset_id=decision.asset_id,
                run_id=scan.scan_id,
                account_id=scan.account_id,
                observation_type="cloud_storage_observed",
                evidence_id=evidence_id,
                observed_at=observed_at,
            )
            if observation_id is not None:
                observations_recorded += 1
            else:
                observations_already_present += 1

    return BackfillSummary(
        scans_processed=scans_processed,
        hosts_processed=hosts_processed,
        assets_created=assets_created,
        assets_touched=assets_touched,
        observations_recorded=observations_recorded,
        observations_already_present=observations_already_present,
        evidence_created_or_touched=evidence_created_or_touched,
    )

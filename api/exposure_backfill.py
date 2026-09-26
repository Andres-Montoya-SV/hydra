"""Fase 08 — backfill durable Exposures from completed run Findings.

This pass reads already-persisted run-scoped findings. It performs no network
collection and never mutates the original AssetStore rows.

A missing finding in a later run is deliberately NOT treated as remediation:
Hydra's current durable run schema does not prove that the responsible detector
executed successfully for that asset. False resolution is worse than a stale
open exposure, so resolution remains explicit until provider execution outcome
is persisted in a later phase.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.asset_identity import domain_identity_key
from api.exposure_identity import exposure_from_finding
from api.tenancy import account_db_path
from core.store import AssetStore
from core.verification.grounding import partition_verification_flags_by_host

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings


@dataclass(frozen=True)
class ExposureBackfillSummary:
    scans_processed: int
    findings_seen: int
    exposures_created: int
    exposures_reobserved: int
    evidence_created: int
    findings_ignored_info: int
    findings_ignored_invalidated: int
    findings_ignored_without_asset: int


def backfill_exposures_for_organization(
    *, control_db: ControlDB, api_settings: APISettings, organization_id: str
) -> ExposureBackfillSummary:
    """Replay completed scans oldest-first into durable Exposure identity."""
    scans = [
        scan
        for scan in control_db.list_scans_for_organization(organization_id)
        if scan.status == "completed"
    ]
    scans.sort(key=lambda scan: scan.created_at)
    assets = control_db.existing_assets_for_organization(organization_id)

    scans_processed = 0
    findings_seen = 0
    exposures_created = 0
    exposures_reobserved = 0
    evidence_created = 0
    findings_ignored_info = 0
    findings_ignored_invalidated = 0
    findings_ignored_without_asset = 0

    for scan in scans:
        store = AssetStore(account_db_path(api_settings, scan.account_id))
        invalidated_hosts, _ = partition_verification_flags_by_host(
            store.get_verification_flags(scan.scan_id)
        )
        findings = store.get_findings(scan.scan_id)
        scans_processed += 1
        observed_at = scan.updated_at or scan.created_at

        for finding in findings:
            findings_seen += 1
            host = str(finding.get("host") or "").strip().lower().rstrip(".")
            if host in invalidated_hosts:
                findings_ignored_invalidated += 1
                continue

            asset = assets.get(domain_identity_key(host)) if host else None
            if asset is None:
                findings_ignored_without_asset += 1
                continue

            draft = exposure_from_finding(finding, asset_id=asset.asset_id)
            if draft is None:
                findings_ignored_info += 1
                continue

            finding_id = finding.get("id")
            if not isinstance(finding_id, int):
                # The source row must be traceable. A detector result without
                # the real persisted finding id is not strong enough to become
                # durable Exposure evidence.
                findings_ignored_without_asset += 1
                continue

            _, created, evidence_was_created = control_db.upsert_exposure(
                organization_id=organization_id,
                account_id=scan.account_id,
                run_id=scan.scan_id,
                finding_id=finding_id,
                draft=draft,
                observed_at=observed_at,
            )
            if created:
                exposures_created += 1
            else:
                exposures_reobserved += 1
            if evidence_was_created:
                evidence_created += 1

    return ExposureBackfillSummary(
        scans_processed=scans_processed,
        findings_seen=findings_seen,
        exposures_created=exposures_created,
        exposures_reobserved=exposures_reobserved,
        evidence_created=evidence_created,
        findings_ignored_info=findings_ignored_info,
        findings_ignored_invalidated=findings_ignored_invalidated,
        findings_ignored_without_asset=findings_ignored_without_asset,
    )

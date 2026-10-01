"""Productization Phase 11c: an organization's data as one archive.

`GET /organizations/{id}/export` (owners) and `python -m api.tenants
export-organization` (operators, no size limit) build a ZIP:

    manifest.json     format, organization, time, and per dataset: rows and SHA-256
    <dataset>.json    the rows, one JSON array per dataset

The datasets are every control-plane table holding the organization's
rows (its inventory, observations, exposures, remediation, integrations,
scans, settings, members and its security audit log).
`tests/test_tenant_lifecycle.py` pins the list to the schema, so a new
table can't be silently left out.

**Never exported:**
- webhook signing secrets, integration credentials and API-key hashes
  (those columns are dropped);
- any sealed value that reaches a row anyway, which is masked.

The raw scan results stay where they are (the per-account `recon.db`)
and are available as each scan's report.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from typing import IO, Any

from api.control_db import ControlDB
from api.secrets_box import SEALED_PREFIX

FORMAT = "hydra-organization-export/1"

# Each dataset with its literal read (the organization's rows only).
ORGANIZATION_DATASETS: dict[str, str] = {
    "organizations": "SELECT * FROM organizations WHERE organization_id = ?",
    "account_organization_roles": "SELECT * FROM account_organization_roles WHERE organization_id = ?",
    "assets": "SELECT * FROM assets WHERE organization_id = ?",
    "asset_identifiers": "SELECT * FROM asset_identifiers WHERE organization_id = ?",
    "asset_business_context": "SELECT * FROM asset_business_context WHERE organization_id = ?",
    "asset_business_context_audit": "SELECT * FROM asset_business_context_audit WHERE organization_id = ?",
    "candidate_assets": "SELECT * FROM candidate_assets WHERE organization_id = ?",
    "candidate_asset_reviews": "SELECT * FROM candidate_asset_reviews WHERE organization_id = ?",
    "observation_batches": "SELECT * FROM observation_batches WHERE organization_id = ?",
    "evidence": "SELECT * FROM evidence WHERE organization_id = ?",
    "observations": "SELECT * FROM observations WHERE organization_id = ?",
    "certificate_events": "SELECT * FROM certificate_events WHERE organization_id = ?",
    "change_events": "SELECT * FROM change_events WHERE organization_id = ?",
    "technology_events": "SELECT * FROM technology_events WHERE organization_id = ?",
    "relationships": "SELECT * FROM relationships WHERE organization_id = ?",
    "relationship_evidence": "SELECT * FROM relationship_evidence WHERE organization_id = ?",
    "exposures": "SELECT * FROM exposures WHERE organization_id = ?",
    "exposure_evidence": "SELECT * FROM exposure_evidence WHERE organization_id = ?",
    "exposure_history": "SELECT * FROM exposure_history WHERE organization_id = ?",
    "exposure_risk_snapshots": "SELECT * FROM exposure_risk_snapshots WHERE organization_id = ?",
    "exposure_remediation": "SELECT * FROM exposure_remediation WHERE organization_id = ?",
    "remediation_events": "SELECT * FROM remediation_events WHERE organization_id = ?",
    "ticketing_integrations": "SELECT * FROM ticketing_integrations WHERE organization_id = ?",
    "ticketing_links": "SELECT * FROM ticketing_links WHERE organization_id = ?",
    "webhooks": "SELECT * FROM webhooks WHERE organization_id = ?",
    "integration_events": "SELECT * FROM integration_events WHERE organization_id = ?",
    "scans": "SELECT * FROM scans WHERE organization_id = ?",
    "provider_run_outcomes": "SELECT * FROM provider_run_outcomes WHERE organization_id = ?",
    "monitored_domains": "SELECT * FROM monitored_domains WHERE organization_id = ?",
    "domain_verifications": "SELECT * FROM domain_verifications WHERE organization_id = ?",
    "organization_scope_exclusions": "SELECT * FROM organization_scope_exclusions WHERE organization_id = ?",
    "organization_collection_settings": "SELECT * FROM organization_collection_settings WHERE organization_id = ?",
    "capability_audit_log": "SELECT * FROM capability_audit_log WHERE organization_id = ?",
    "security_audit_log": "SELECT * FROM security_audit_log WHERE organization_id = ?",
    "integration_deliveries": (
        "SELECT * FROM integration_deliveries WHERE event_id IN "
        "(SELECT event_id FROM integration_events WHERE organization_id = ?)"
    ),
}

# Columns that hold secrets or their hashes: never exported.
_SECRET_COLUMNS = frozenset({"secret", "credential", "lookup_hash", "verify_hash", "raw_body"})


class ExportTooLargeError(RuntimeError):
    """The archive passed the size limit; nothing usable was produced."""


def _clean(row: Any) -> dict[str, Any]:
    cleaned = {}
    for key in row.keys():
        if key in _SECRET_COLUMNS:
            continue
        value = row[key]
        if isinstance(value, str) and value.startswith(SEALED_PREFIX):
            value = "[sealed]"
        cleaned[key] = value
    return cleaned


def _dataset_rows(db: ControlDB, statement: str, organization_id: str) -> list[dict[str, Any]]:
    with db.backend.connect() as conn:
        return [_clean(row) for row in conn.execute(statement, (organization_id,)).fetchall()]


def write_organization_export(
    db: ControlDB, organization_id: str, out: IO[bytes], *, max_bytes: int | None = None
) -> dict[str, Any]:
    """Writes the archive to `out` and returns its manifest. Raises
    ExportTooLargeError once the archive passes `max_bytes`."""
    datasets = []
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, statement in ORGANIZATION_DATASETS.items():
            rows = _dataset_rows(db, statement, organization_id)
            data = json.dumps(rows, sort_keys=True, default=str).encode()
            archive.writestr(f"{name}.json", data)
            datasets.append(
                {"name": name, "rows": len(rows), "sha256": hashlib.sha256(data).hexdigest()}
            )
            if max_bytes is not None and out.tell() > max_bytes:
                raise ExportTooLargeError(f"the export passed {max_bytes} bytes")
        manifest = {
            "format": FORMAT,
            "organization_id": organization_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "datasets": datasets,
        }
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
    return manifest

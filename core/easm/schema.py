"""SQLite schema for Hydra's additive persistent EASM layer."""

from __future__ import annotations

import sqlite3

EASM_SCHEMA = """
CREATE TABLE IF NOT EXISTS easm_organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS easm_assets (
    asset_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    canonical_key TEXT NOT NULL,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    ownership_state TEXT NOT NULL DEFAULT 'unknown',
    ownership_confidence INTEGER NOT NULL DEFAULT 0
        CHECK (ownership_confidence BETWEEN 0 AND 100),
    criticality TEXT NOT NULL DEFAULT 'unknown',
    environment TEXT NOT NULL DEFAULT 'unknown',
    business_unit TEXT,
    owner_team TEXT,
    internet_expected INTEGER,
    data_classification TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(organization_id, asset_type, canonical_key),
    FOREIGN KEY(organization_id) REFERENCES easm_organizations(organization_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS easm_asset_observations (
    observation_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    run_id TEXT,
    source TEXT NOT NULL,
    collector TEXT,
    observed_at TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 50
        CHECK (confidence BETWEEN 0 AND 100),
    fingerprint TEXT,
    data_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(asset_id) REFERENCES easm_assets(asset_id) ON DELETE CASCADE,
    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS easm_asset_events (
    event_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    detected_at TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 50
        CHECK (confidence BETWEEN 0 AND 100),
    source_observation_id TEXT,
    previous_state_json TEXT,
    current_state_json TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(organization_id) REFERENCES easm_organizations(organization_id)
        ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES easm_assets(asset_id) ON DELETE CASCADE,
    FOREIGN KEY(source_observation_id)
        REFERENCES easm_asset_observations(observation_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS easm_ownership_evidence (
    evidence_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    family TEXT NOT NULL,
    signal TEXT NOT NULL,
    direction TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 50
        CHECK (confidence BETWEEN 0 AND 100),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(asset_id) REFERENCES easm_assets(asset_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS easm_exposures (
    exposure_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    exposure_key TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    confidence INTEGER NOT NULL DEFAULT 50
        CHECK (confidence BETWEEN 0 AND 100),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    reopened_count INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    source_finding_id INTEGER,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(organization_id, asset_id, exposure_key),
    FOREIGN KEY(organization_id) REFERENCES easm_organizations(organization_id)
        ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES easm_assets(asset_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_easm_assets_org
    ON easm_assets(organization_id, status, asset_type);
CREATE INDEX IF NOT EXISTS idx_easm_assets_key
    ON easm_assets(organization_id, canonical_key);
CREATE INDEX IF NOT EXISTS idx_easm_assets_seen
    ON easm_assets(organization_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_easm_observations_asset
    ON easm_asset_observations(asset_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_easm_observations_run
    ON easm_asset_observations(run_id);
CREATE INDEX IF NOT EXISTS idx_easm_events_org
    ON easm_asset_events(organization_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_easm_events_asset
    ON easm_asset_events(asset_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_easm_ownership_asset
    ON easm_ownership_evidence(asset_id, family);
CREATE INDEX IF NOT EXISTS idx_easm_exposures_org
    ON easm_exposures(organization_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_easm_exposures_asset
    ON easm_exposures(asset_id, status);
"""


def ensure_easm_schema(conn: sqlite3.Connection) -> None:
    """Create EASM tables on an existing Hydra SQLite connection.

    The caller is responsible for enabling ``PRAGMA foreign_keys=ON`` before
    invoking this helper, matching ``core.store.configure_sqlite``.
    """

    conn.executescript(EASM_SCHEMA)

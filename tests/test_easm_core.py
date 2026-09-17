from __future__ import annotations

import json
import sqlite3

from core.easm.model import AssetType
from core.easm.store import EasmStore


def _connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("CREATE TABLE runs (run_id TEXT PRIMARY KEY)")
    return conn


def test_asset_identity_survives_repeated_observations() -> None:
    conn = _connection()
    store = EasmStore(conn)
    org_id = store.ensure_organization(name="Acme", slug="acme")

    first_id, created = store.upsert_asset(
        organization_id=org_id,
        asset_type=AssetType.HOSTNAME,
        canonical_key="API.Example.COM.",
        seen_at="2026-09-17T10:00:00+00:00",
    )
    second_id, created_again = store.upsert_asset(
        organization_id=org_id,
        asset_type=AssetType.HOSTNAME,
        canonical_key="api.example.com",
        seen_at="2026-09-17T11:00:00+00:00",
    )

    assert first_id == second_id
    assert created is True
    assert created_again is False

    row = conn.execute(
        "SELECT canonical_key, first_seen, last_seen FROM easm_assets WHERE asset_id = ?",
        (first_id,),
    ).fetchone()
    assert row is not None
    assert row["canonical_key"] == "api.example.com"
    assert row["first_seen"] == "2026-09-17T10:00:00+00:00"
    assert row["last_seen"] == "2026-09-17T11:00:00+00:00"

    event_count = conn.execute(
        "SELECT COUNT(*) FROM easm_asset_events WHERE asset_id = ? AND event_type = 'new_asset'",
        (first_id,),
    ).fetchone()[0]
    assert event_count == 1


def test_observations_are_additive_and_keep_run_provenance() -> None:
    conn = _connection()
    conn.execute("INSERT INTO runs(run_id) VALUES ('run-1')")
    conn.execute("INSERT INTO runs(run_id) VALUES ('run-2')")
    store = EasmStore(conn)
    org_id = store.ensure_organization(name="Acme", slug="acme")
    asset_id, _ = store.upsert_asset(
        organization_id=org_id,
        asset_type=AssetType.HOSTNAME,
        canonical_key="api.example.com",
    )

    store.record_observation(
        asset_id=asset_id,
        run_id="run-1",
        source="dnsx",
        collector="dnsx",
        confidence=90,
        data={"ips": ["203.0.113.10"]},
        observed_at="2026-09-17T10:00:00+00:00",
    )
    store.record_observation(
        asset_id=asset_id,
        run_id="run-2",
        source="dnsx",
        collector="dnsx",
        confidence=90,
        data={"ips": ["203.0.113.11"]},
        observed_at="2026-09-18T10:00:00+00:00",
    )

    rows = conn.execute(
        """
        SELECT run_id, data_json FROM easm_asset_observations
        WHERE asset_id = ? ORDER BY observed_at
        """,
        (asset_id,),
    ).fetchall()
    assert [row["run_id"] for row in rows] == ["run-1", "run-2"]
    assert json.loads(rows[0]["data_json"])["ips"] == ["203.0.113.10"]
    assert json.loads(rows[1]["data_json"])["ips"] == ["203.0.113.11"]


def test_same_key_in_two_organizations_is_two_assets() -> None:
    conn = _connection()
    store = EasmStore(conn)
    org_a = store.ensure_organization(name="Acme", slug="acme")
    org_b = store.ensure_organization(name="Example Holdings", slug="example-holdings")

    asset_a, _ = store.upsert_asset(
        organization_id=org_a,
        asset_type=AssetType.DOMAIN,
        canonical_key="example.com",
    )
    asset_b, _ = store.upsert_asset(
        organization_id=org_b,
        asset_type=AssetType.DOMAIN,
        canonical_key="example.com",
    )

    assert asset_a != asset_b

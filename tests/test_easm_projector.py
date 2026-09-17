from __future__ import annotations

import json
import sqlite3

from core.assets import Host, HttpService, Port, TechnologyFinding, TlsCertificate
from core.easm.projector import project_hosts
from core.easm.store import EasmStore


def _connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("CREATE TABLE runs (run_id TEXT PRIMARY KEY)")
    return conn


def _host(
    *,
    timestamp: str,
    ip: str,
    ports: list[int],
    technology: str,
    cert_fingerprint: str,
) -> Host:
    host = Host(
        domain="api.example.com",
        ips=[ip],
        ports=[
            Port(
                host="api.example.com",
                port=port,
                protocol="tcp",
                confidence_score=95,
                validated=True,
            )
            for port in ports
        ],
        http_services=[
            HttpService(
                url="https://api.example.com/",
                host="api.example.com",
                status_code=200,
                title="Example API",
                technologies=[
                    TechnologyFinding(
                        name=technology,
                        source="httpx",
                        confidence=90,
                    )
                ],
                response_fingerprint=f"body-{technology.lower()}",
            )
        ],
        tls=TlsCertificate(
            host="api.example.com",
            fingerprint_sha256=cert_fingerprint,
            issuer="Example CA",
            sans=["api.example.com"],
        ),
        confidence_score=95,
        scan_timestamp=timestamp,
        first_seen=timestamp,
        last_seen=timestamp,
    )
    return host


def test_projector_turns_two_runs_into_one_asset_and_change_events() -> None:
    conn = _connection()
    conn.execute("INSERT INTO runs(run_id) VALUES ('run-1')")
    conn.execute("INSERT INTO runs(run_id) VALUES ('run-2')")
    store = EasmStore(conn)
    org_id = store.ensure_organization(name="Acme", slug="acme")

    first = _host(
        timestamp="2026-09-17T10:00:00+00:00",
        ip="203.0.113.10",
        ports=[443, 8443],
        technology="nginx",
        cert_fingerprint="cert-old",
    )
    second = _host(
        timestamp="2026-09-18T10:00:00+00:00",
        ip="203.0.113.25",
        ports=[443, 6379],
        technology="caddy",
        cert_fingerprint="cert-new",
    )

    result_one = project_hosts(
        conn, organization_id=org_id, run_id="run-1", hosts=[first]
    )
    result_two = project_hosts(
        conn, organization_id=org_id, run_id="run-2", hosts=[second]
    )

    assert result_one.assets_seen == 1
    assert result_one.events_written == 1  # NEW_ASSET
    assert result_two.assets_seen == 1

    assets = conn.execute("SELECT * FROM easm_assets").fetchall()
    assert len(assets) == 1
    assert assets[0]["canonical_key"] == "api.example.com"
    assert assets[0]["first_seen"] == "2026-09-17T10:00:00+00:00"
    assert assets[0]["last_seen"] == "2026-09-18T10:00:00+00:00"

    observations = conn.execute(
        "SELECT run_id, data_json FROM easm_asset_observations ORDER BY observed_at"
    ).fetchall()
    assert [row["run_id"] for row in observations] == ["run-1", "run-2"]
    assert json.loads(observations[1]["data_json"])["ips"] == ["203.0.113.25"]

    event_types = [
        row["event_type"]
        for row in conn.execute(
            "SELECT event_type FROM easm_asset_events ORDER BY detected_at, event_type"
        ).fetchall()
    ]
    assert event_types.count("new_asset") == 1
    assert "ip_changed" in event_types
    assert "port_opened" in event_types
    assert "port_closed" in event_types
    assert "technology_changed" in event_types
    assert "http_changed" in event_types
    assert "certificate_changed" in event_types

    port_events = conn.execute(
        """
        SELECT event_type, previous_state_json, current_state_json
        FROM easm_asset_events
        WHERE event_type IN ('port_opened', 'port_closed')
        ORDER BY event_type
        """
    ).fetchall()
    assert len(port_events) == 2
    blobs = " ".join(
        f"{row['previous_state_json']} {row['current_state_json']}" for row in port_events
    )
    assert "6379/tcp" in blobs
    assert "8443/tcp" in blobs


def test_projecting_same_run_twice_is_idempotent() -> None:
    conn = _connection()
    conn.execute("INSERT INTO runs(run_id) VALUES ('run-1')")
    store = EasmStore(conn)
    org_id = store.ensure_organization(name="Acme", slug="acme")
    host = _host(
        timestamp="2026-09-17T10:00:00+00:00",
        ip="203.0.113.10",
        ports=[443],
        technology="nginx",
        cert_fingerprint="cert-one",
    )

    first = project_hosts(conn, organization_id=org_id, run_id="run-1", hosts=[host])
    second = project_hosts(conn, organization_id=org_id, run_id="run-1", hosts=[host])

    assert first.skipped is False
    assert second.skipped is True
    assert conn.execute("SELECT COUNT(*) FROM easm_assets").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM easm_asset_observations").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM easm_asset_events").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM easm_run_projections").fetchone()[0] == 1


def test_historical_backfill_is_stored_without_false_transition_against_future() -> None:
    conn = _connection()
    conn.execute("INSERT INTO runs(run_id) VALUES ('run-old')")
    conn.execute("INSERT INTO runs(run_id) VALUES ('run-new')")
    store = EasmStore(conn)
    org_id = store.ensure_organization(name="Acme", slug="acme")

    newer = _host(
        timestamp="2026-09-18T10:00:00+00:00",
        ip="203.0.113.25",
        ports=[443, 6379],
        technology="caddy",
        cert_fingerprint="cert-new",
    )
    older = _host(
        timestamp="2026-09-17T10:00:00+00:00",
        ip="203.0.113.10",
        ports=[443],
        technology="nginx",
        cert_fingerprint="cert-old",
    )

    project_hosts(conn, organization_id=org_id, run_id="run-new", hosts=[newer])
    before = conn.execute("SELECT COUNT(*) FROM easm_asset_events").fetchone()[0]
    project_hosts(conn, organization_id=org_id, run_id="run-old", hosts=[older])
    after = conn.execute("SELECT COUNT(*) FROM easm_asset_events").fetchone()[0]

    # The historical observation is valuable, but it must not be compared to
    # a future state and turned into a backwards IP/port/certificate change.
    assert after == before
    assert conn.execute("SELECT COUNT(*) FROM easm_asset_observations").fetchone()[0] == 2

    asset = conn.execute("SELECT first_seen, last_seen FROM easm_assets").fetchone()
    assert asset["first_seen"] == "2026-09-17T10:00:00+00:00"
    assert asset["last_seen"] == "2026-09-18T10:00:00+00:00"

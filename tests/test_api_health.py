"""`GET /health` (docs/PAID_API_DESIGN.md's "Basic observability"
section) — tested against a genuinely broken dependency, not just the
happy path: a real corrupted `control.db` file, and a real stale
heartbeat timestamp, not simulated by reasoning about the code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from api.control_db import ControlDB  # noqa: E402
from api.health import LoopHeartbeats, check_health  # noqa: E402
from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


class TestHealthEndpointHappyPath:
    def test_a_freshly_started_real_app_reports_healthy(self, api_settings: APISettings) -> None:
        with TestClient(create_app(api_settings)) as client:
            resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["checks"]["control_db"] == "ok"
        assert body["checks"]["scan_worker"] == "ok"
        assert body["checks"]["reconciliation"] == "ok"
        assert body["checks"]["backup"] == "ok"
        assert body["checks"]["monitoring"] == "ok"

    def test_health_requires_no_api_key(self, api_settings: APISettings) -> None:
        with TestClient(create_app(api_settings)) as client:
            # Deliberately no X-API-Key header — an uptime monitor
            # cannot authenticate.
            resp = client.get("/health")
        assert resp.status_code == 200


class TestHealthCheckPureFunction:
    """Exercises `check_health` directly against a genuinely broken
    control_db — a real corrupted SQLite file, not a mock standing in
    for "unreachable"."""

    def test_a_genuinely_corrupted_control_db_reports_503_with_a_real_reason(
        self, tmp_path: Path, api_settings: APISettings
    ) -> None:
        control_db = ControlDB(api_settings.control_db_path)
        control_db.ping()  # sane before corruption — confirms the setup itself is valid

        # Real corruption: overwrite the actual file AND its WAL/SHM
        # sidecars with non-SQLite bytes. Corrupting only the main file
        # is not enough to prove anything — found the hard way while
        # writing this test: WAL mode (core.store.connect_sqlite's own
        # default) can transparently recover real data from an intact
        # `-wal` file even when the main `.db` file is garbage, silently
        # masking the exact corruption this test means to simulate.
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{api_settings.control_db_path}{suffix}")
            path.write_bytes(b"not a real sqlite file at all")

        heartbeats = LoopHeartbeats()
        heartbeats.mark_alive("scan_worker")
        heartbeats.mark_alive("reconciliation")
        heartbeats.mark_alive("backup")
        heartbeats.mark_alive("monitoring")

        healthy, checks = check_health(
            control_db=control_db, heartbeats=heartbeats, api_settings=api_settings
        )

        assert healthy is False
        assert "unreachable" in checks["control_db"]

    def test_a_stale_loop_reports_503_with_a_real_reason(self, api_settings: APISettings) -> None:
        control_db = ControlDB(api_settings.control_db_path)
        heartbeats = LoopHeartbeats()
        heartbeats.mark_alive("reconciliation")
        heartbeats.mark_alive("backup")
        heartbeats.mark_alive("monitoring")
        # scan_worker: backdated far past its threshold
        # (max(scan_poll_interval_seconds * 2, 60) — default settings
        # give a 60s floor) — a real elapsed-time comparison, not a
        # mocked "is stale" flag.
        heartbeats.timestamps["scan_worker"] = heartbeats.timestamps["reconciliation"] - 999.0

        healthy, checks = check_health(
            control_db=control_db, heartbeats=heartbeats, api_settings=api_settings
        )

        assert healthy is False
        assert "stale" in checks["scan_worker"]
        assert checks["reconciliation"] == "ok"
        assert checks["backup"] == "ok"
        assert checks["monitoring"] == "ok"

    def test_a_loop_that_never_reported_in_is_never_treated_as_healthy_by_default(
        self, api_settings: APISettings
    ) -> None:
        control_db = ControlDB(api_settings.control_db_path)
        heartbeats = LoopHeartbeats()  # nothing ever marked alive

        healthy, checks = check_health(
            control_db=control_db, heartbeats=heartbeats, api_settings=api_settings
        )

        assert healthy is False
        assert checks["scan_worker"] == "never reported alive"
        assert checks["reconciliation"] == "never reported alive"
        assert checks["backup"] == "never reported alive"
        assert checks["monitoring"] == "never reported alive"

    def test_everything_alive_and_recent_is_healthy(self, api_settings: APISettings) -> None:
        control_db = ControlDB(api_settings.control_db_path)
        heartbeats = LoopHeartbeats()
        for name in ("scan_worker", "reconciliation", "backup", "monitoring"):
            heartbeats.mark_alive(name)

        healthy, checks = check_health(
            control_db=control_db, heartbeats=heartbeats, api_settings=api_settings
        )

        assert healthy is True
        assert all(v == "ok" for v in checks.values())

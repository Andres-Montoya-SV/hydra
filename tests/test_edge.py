"""Productization Phase 11a: request ids, body limits, security headers,
CORS and readiness (api/edge.py)."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from api.control_db import ControlDB
from api.edge import EdgeMiddleware, RequestIdFilter, current_request_id
from api.main import create_app
from api.observability import JsonFormatter
from api.settings import APISettings, load_api_settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as test_client:
        yield test_client


def _mini_app(**limits: int) -> FastAPI:
    app = FastAPI()
    logger = logging.getLogger("hydra.test.edge")

    @app.get("/whoami")
    def whoami() -> dict[str, str]:
        logger.info("inside the request")
        return {"request_id": current_request_id()}

    @app.get("/cached")
    def cached() -> JSONResponse:
        return JSONResponse({}, headers={"Cache-Control": "max-age=60"})

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"received": len(await request.body())}

    @app.post("/organizations/o1/imports/nmap")
    async def import_(request: Request) -> dict[str, int]:
        return {"received": len(await request.body())}

    settings = {"max_body_bytes": 1024, "max_import_bytes": 4096, "hsts_seconds": 0, **limits}
    app.add_middleware(EdgeMiddleware, **settings)
    return app


class TestSecurityHeaders:
    @pytest.mark.parametrize("path", ["/health", "/does-not-exist", "/organizations"])
    def test_every_response_carries_them(self, client: TestClient, path: str) -> None:
        response = client.get(path)  # 200, 404, 401
        headers = response.headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["cache-control"] == "no-store"
        assert headers["content-security-policy"].startswith("default-src 'none'")
        assert "strict-transport-security" not in headers  # off by default

    def test_the_docs_page_can_load_its_assets(self, client: TestClient) -> None:
        response = client.get("/docs")
        assert response.status_code == 200
        assert "content-security-policy" not in response.headers
        assert response.headers["x-frame-options"] == "DENY"

    def test_hsts_when_configured(self, tmp_path: Path) -> None:
        settings = APISettings(data_dir=tmp_path / "api", hsts_seconds=31536000)
        with TestClient(create_app(settings)) as hsts_client:
            header = hsts_client.get("/health").headers["strict-transport-security"]
        assert header == "max-age=31536000; includeSubDomains"

    def test_a_route_s_own_header_wins(self) -> None:
        response = TestClient(_mini_app()).get("/cached")
        assert response.headers["cache-control"] == "max-age=60"


class TestRequestId:
    def test_generated_and_visible_inside_the_request(self) -> None:
        response = TestClient(_mini_app()).get("/whoami")
        request_id = response.headers["x-request-id"]
        assert len(request_id) == 32 and response.json()["request_id"] == request_id

    def test_a_safe_incoming_id_is_kept(self) -> None:
        response = TestClient(_mini_app()).get(
            "/whoami", headers={"X-Request-ID": "lb-7f3a9c1e-0001"}
        )
        assert response.headers["x-request-id"] == "lb-7f3a9c1e-0001"

    @pytest.mark.parametrize("incoming", ["short", "x" * 65, "has space inside", 'a"<script>'])
    def test_an_unsafe_incoming_id_is_replaced(self, incoming: str) -> None:
        response = TestClient(_mini_app()).get("/whoami", headers={"X-Request-ID": incoming})
        assert response.headers["x-request-id"] != incoming
        assert len(response.headers["x-request-id"]) == 32

    def test_log_records_carry_it(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.handler.addFilter(RequestIdFilter())
        with caplog.at_level(logging.INFO, logger="hydra.test.edge"):
            response = TestClient(_mini_app()).get("/whoami")
        record = next(r for r in caplog.records if r.getMessage() == "inside the request")
        assert getattr(record, "request_id", None) == response.headers["x-request-id"]
        payload = json.loads(JsonFormatter().format(record))
        assert payload["request_id"] == response.headers["x-request-id"]

    def test_outside_a_request_it_is_a_dash(self) -> None:
        assert current_request_id() == "-"


class TestBodyLimit:
    def test_declared_oversize_is_refused_before_the_route(self, client: TestClient) -> None:
        response = client.post(
            "/accounts",
            content=b"x" * (1024 * 1024 + 1),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "x-request-id" in response.headers

    def test_streamed_oversize_is_refused_too(self) -> None:
        def chunks() -> Iterator[bytes]:  # no Content-Length: chunked
            for _ in range(4):
                yield b"x" * 512

        response = TestClient(_mini_app()).post("/echo", content=chunks())
        assert response.status_code == 413

    def test_streamed_oversize_on_a_real_endpoint_is_a_413(self, client: TestClient) -> None:
        def chunks() -> Iterator[bytes]:
            for _ in range(5):
                yield b" " * (256 * 1024)

        response = client.post(
            "/accounts", content=chunks(), headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 413
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_within_the_limit_passes(self) -> None:
        response = TestClient(_mini_app()).post("/echo", content=b"x" * 1000)
        assert response.status_code == 200 and response.json() == {"received": 1000}

    def test_imports_get_the_importer_s_larger_limit(self) -> None:
        mini = TestClient(_mini_app())
        assert mini.post("/organizations/o1/imports/nmap", content=b"x" * 3000).status_code == 200
        assert mini.post("/organizations/o1/imports/nmap", content=b"x" * 5000).status_code == 413
        assert mini.post("/echo", content=b"x" * 3000).status_code == 413


class TestCors:
    def test_none_by_default(self, client: TestClient) -> None:
        response = client.get("/health", headers={"Origin": "https://app.example.com"})
        assert "access-control-allow-origin" not in response.headers

    def test_only_listed_origins(self, tmp_path: Path) -> None:
        settings = APISettings(data_dir=tmp_path / "api", cors_origins=("https://app.example.com",))
        with TestClient(create_app(settings)) as cors_client:
            preflight = {"Access-Control-Request-Method": "GET"}
            allowed = cors_client.options(
                "/organizations", headers={"Origin": "https://app.example.com", **preflight}
            )
            other = cors_client.options(
                "/organizations", headers={"Origin": "https://evil.example", **preflight}
            )
        assert allowed.headers["access-control-allow-origin"] == "https://app.example.com"
        assert "access-control-allow-credentials" not in allowed.headers
        assert "access-control-allow-origin" not in other.headers
        assert "x-request-id" in allowed.headers  # the edge wraps CORS too


class TestEdgeSettings:
    @pytest.fixture(autouse=True)
    def _clean(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("CORS_ORIGINS", "MAX_BODY_BYTES", "HSTS_SECONDS"):
            monkeypatch.delenv(f"HYDRA_API_{name}", raising=False)

    def test_defaults(self) -> None:
        settings = load_api_settings()
        assert (settings.max_body_bytes, settings.cors_origins, settings.hsts_seconds) == (
            1024 * 1024,
            (),
            0,
        )

    def test_origins_are_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "HYDRA_API_CORS_ORIGINS", "https://App.example.com/, http://localhost:3000"
        )
        assert load_api_settings().cors_origins == (
            "https://app.example.com",
            "http://localhost:3000",
        )

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("CORS_ORIGINS", "*"),
            ("CORS_ORIGINS", "http://app.example.com"),
            ("CORS_ORIGINS", "https://app.example.com/path"),
            ("MAX_BODY_BYTES", "10"),
            ("HSTS_SECONDS", "-1"),
        ],
    )
    def test_unsafe_values_stop_startup(
        self, monkeypatch: pytest.MonkeyPatch, name: str, value: str
    ) -> None:
        monkeypatch.setenv(f"HYDRA_API_{name}", value)
        with pytest.raises(ValueError):
            load_api_settings()


class TestReadiness:
    def test_ready_when_the_database_answers(self, client: TestClient) -> None:
        response = client.get("/ready")
        assert response.status_code == 200 and response.json() == {"status": "ready"}

    def test_not_ready_when_it_does_not(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def down(self: ControlDB) -> None:
            raise OSError("database unreachable")

        monkeypatch.setattr(ControlDB, "ping", down)
        response = client.get("/ready")
        assert response.status_code == 503 and response.json() == {"status": "not ready"}

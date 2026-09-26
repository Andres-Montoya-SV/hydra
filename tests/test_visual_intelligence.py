"""Visual Asset Intelligence regression tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from core.assets import Host, HttpService
from core.models import DomainTarget, PipelineContext
from core.parsers.registry import BrowserProbeParser
from core.store import AssetStore, ScanRun
from modules.browser_probe import _capture_visual_artifacts
from utils.files import write_jsonl


class FakePage:
    async def content(self) -> str:
        return "<html><head><title>Hydra</title></head><body>hello</body></html>"

    async def title(self) -> str:
        return "Hydra Console"

    async def screenshot(self, *, full_page: bool, type: str) -> bytes:
        assert full_page is False
        assert type == "png"
        return b"fake-png-bytes"


@pytest.mark.asyncio
async def test_visual_capture_persists_relative_artifacts_and_hashes(tmp_path: Path) -> None:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain="example.com")],
        output_dir=output_dir,
    )

    metadata = await _capture_visual_artifacts(
        context,
        "example.com",
        FakePage(),
        "https://example.com/",
    )

    assert metadata["raw_artifact"] == "browser_probe_raw/example.com.html"
    assert metadata["screenshot_path"] == "browser_probe_screenshots/example.com.png"
    assert metadata["title"] == "Hydra Console"
    assert metadata["screenshot_sha256"] == hashlib.sha256(b"fake-png-bytes").hexdigest()
    assert isinstance(metadata["rendered_html_sha256"], str)
    assert (output_dir / str(metadata["raw_artifact"])).exists()
    screenshot = output_dir / str(metadata["screenshot_path"])
    assert screenshot.read_bytes() == b"fake-png-bytes"
    assert screenshot.stat().st_mode & 0o777 == 0o600


def test_browser_parser_keeps_visual_metadata_without_cloaking(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "browser_probe.jsonl",
        [
            {
                "host": "app.example.com",
                "httpx_final_url": "https://app.example.com/",
                "browser_final_url": "https://app.example.com/",
                "redirect_chain": ["https://app.example.com/"],
                "cloaking_suspected": False,
                "raw_artifact": "browser_probe_raw/app.example.com.html",
                "screenshot_path": "browser_probe_screenshots/app.example.com.png",
                "screenshot_sha256": "a" * 64,
                "rendered_html_sha256": "b" * 64,
                "title": "Example App",
            }
        ],
    )

    hosts, warnings = BrowserProbeParser().parse(tmp_path)

    assert warnings == []
    assert len(hosts) == 1
    assert hosts[0].findings == []
    assert len(hosts[0].http_services) == 1
    service = hosts[0].http_services[0]
    assert service.url == "https://app.example.com/"
    assert service.title == "Example App"
    assert service.body_hash == "b" * 64
    assert service.response_fingerprint == "a" * 64
    assert service.screenshot_path == "browser_probe_screenshots/app.example.com.png"
    assert service.source == "browser_probe"


def test_failed_probe_without_visual_evidence_does_not_create_empty_service(
    tmp_path: Path,
) -> None:
    write_jsonl(
        tmp_path / "browser_probe.jsonl",
        [
            {
                "host": "app.example.com",
                "httpx_final_url": "https://app.example.com/",
                "browser_final_url": None,
                "redirect_chain": [],
                "cloaking_suspected": False,
                "raw_artifact": None,
                "error": "browser failed",
            }
        ],
    )

    hosts, _ = BrowserProbeParser().parse(tmp_path)

    assert hosts == []


def test_visual_provider_enriches_existing_http_service() -> None:
    canonical = Host(
        domain="example.com",
        http_services=[
            HttpService(
                url="https://example.com/",
                host="example.com",
                status_code=200,
                title="httpx title",
                source="httpx",
            )
        ],
    )
    visual = Host(
        domain="example.com",
        http_services=[
            HttpService(
                url="https://example.com/",
                host="example.com",
                title="Rendered title",
                body_hash="b" * 64,
                response_fingerprint="a" * 64,
                screenshot_path="browser_probe_screenshots/example.com.png",
                source="browser_probe",
            )
        ],
    )

    canonical.merge_from(visual)

    assert len(canonical.http_services) == 1
    service = canonical.http_services[0]
    assert service.status_code == 200
    assert service.title == "Rendered title"
    assert service.body_hash == "b" * 64
    assert service.response_fingerprint == "a" * 64
    assert service.screenshot_path == "browser_probe_screenshots/example.com.png"


def test_visual_artifact_path_round_trips_through_sqlite(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "recon.db")
    run_id = "visual-roundtrip"
    store.create_run(ScanRun(run_id=run_id, started_at="2026-09-26T00:00:00+00:00"))
    host = Host(
        domain="example.com",
        http_services=[
            HttpService(
                url="https://example.com/",
                host="example.com",
                title="Rendered title",
                body_hash="b" * 64,
                response_fingerprint="a" * 64,
                screenshot_path="browser_probe_screenshots/example.com.png",
                source="browser_probe",
            )
        ],
    )

    store.persist_registry(run_id, {host.domain: host})
    loaded = store.get_hosts(run_id)[0].http_services[0]

    assert loaded.screenshot_path == "browser_probe_screenshots/example.com.png"
    assert loaded.body_hash == "b" * 64
    assert loaded.response_fingerprint == "a" * 64

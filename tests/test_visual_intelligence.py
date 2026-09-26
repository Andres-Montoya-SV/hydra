"""Fase 07 Visual Asset Intelligence regression tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from core.models import DomainTarget, PipelineContext
from core.parsers.registry import BrowserProbeParser
from modules.browser_probe import _capture_visual_artifacts
from utils.files import write_jsonl


class FakePage:
    async def content(self) -> str:
        return "<html><head><title>Hydra</title></head><body>hello</body></html>"

    async def title(self) -> str:
        return "Hydra Console"

    async def screenshot(self, *, full_page: bool, type: str) -> bytes:
        assert full_page is True
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
    assert (output_dir / str(metadata["screenshot_path"])).read_bytes() == b"fake-png-bytes"


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

    assert len(hosts) == 1
    assert hosts[0].http_services == []

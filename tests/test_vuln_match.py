"""modules/vuln_match.py — the hardening round fix: a source query that
fails (invalid/missing WPSCAN_API_TOKEN, network error, rate limit, bad
JSON) must never be indistinguishable from "queried and found clean".
Confirmed with real evidence before this fix: WPScan returning 404 for an
invalid token made a detected technology (Bookly:28.0) silently vanish
from the report, looking identical to a genuine clean result.
"""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import PipelineContext
from core.parsers.registry import VulnMatchParser
from modules.vuln_match import VulnMatchPlugin
from utils.files import read_jsonl

SEED = "www.metaversejustice.com"


def _context(tmp_path: Path, *, techs: list[str]) -> PipelineContext:
    output_dir = tmp_path / "output" / "run1"
    output_dir.mkdir(parents=True)
    context = PipelineContext(
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([SEED, "metaversejustice.com"]),
    )
    context.httpx_results = [
        {
            "host": SEED,
            "input": SEED,
            "url": f"https://{SEED}/",
            "tech": techs,
        }
    ]
    return context


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, _n: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _osv_empty_body() -> bytes:
    return json.dumps({"vulns": []}).encode()


def _wpscan_404() -> Exception:
    return urllib.error.HTTPError(
        "https://wpscan.com/api/v3/plugins/bookly", 404, "Not Found", {}, None
    )


def _wpscan_401() -> Exception:
    return urllib.error.HTTPError(
        "https://wpscan.com/api/v3/plugins/bookly", 401, "Unauthorized", {}, None
    )


def _osv_or_wpscan(
    request, *, osv_body: bytes | None = None, wpscan_error: Exception | None = None
):
    """Router for a single `open_url` patch target: OSV requests are POSTs
    to api.osv.dev, WPScan requests are GETs to wpscan.com — dispatch on
    the request URL like the real two endpoints would."""
    url = request.full_url if hasattr(request, "full_url") else str(request)
    if "wpscan.com" in url:
        if wpscan_error is not None:
            raise wpscan_error
        return _FakeResp(json.dumps({"vulnerabilities": {}}).encode())
    return _FakeResp(osv_body if osv_body is not None else _osv_empty_body())


@pytest.mark.asyncio
class TestWpscanCheckFailedNeverBecomesClean:
    async def test_404_marks_check_failed_not_checked_clean(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = "invalid-or-expired-token"
        context = _context(tmp_path, techs=["Bookly:28.0"])

        with patch(
            "modules.vuln_match.open_url",
            side_effect=lambda req, **kw: _osv_or_wpscan(req, wpscan_error=_wpscan_404()),
        ):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        assert rows
        check_failed = [r for r in rows if r["check_status"] == "check_failed"]
        assert check_failed, "a 404 from WPScan must produce a check_failed row"
        assert check_failed[0]["source"] == "wpscan"
        assert check_failed[0]["technology"] == "Bookly"
        assert check_failed[0]["identifier"] is None
        assert not any(r["check_status"] == "checked_vulnerable" for r in rows)
        # Never silently absent: this is the entire bug — a failed check
        # must not look like "queried, nothing found" (zero rows at all).
        assert len(rows) >= 1

    async def test_401_also_marks_check_failed(self, settings: Settings, tmp_path: Path) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = "invalid-token"
        context = _context(tmp_path, techs=["Bookly:28.0"])

        with patch(
            "modules.vuln_match.open_url",
            side_effect=lambda req, **kw: _osv_or_wpscan(req, wpscan_error=_wpscan_401()),
        ):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        check_failed = [r for r in rows if r["check_status"] == "check_failed"]
        assert check_failed and check_failed[0]["source"] == "wpscan"

    async def test_timeout_also_marks_check_failed(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = "sk-real-looking-token"
        context = _context(tmp_path, techs=["Bookly:28.0"])

        with patch(
            "modules.vuln_match.open_url",
            side_effect=lambda req, **kw: _osv_or_wpscan(
                req, wpscan_error=TimeoutError("timed out")
            ),
        ):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        check_failed = [r for r in rows if r["check_status"] == "check_failed"]
        assert check_failed and check_failed[0]["source"] == "wpscan"
        assert "timed out" in check_failed[0]["summary"]

    async def test_missing_token_on_a_wordpress_family_tech_is_also_check_failed(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        """WPSCAN_API_TOKEN entirely absent — a WordPress-family plugin
        detected without ever attempting the one source that actually
        covers it must be flagged too, not silently skipped."""
        settings.enable_vuln_match = True
        settings.wpscan_api_token = None
        context = _context(tmp_path, techs=["Bookly:28.0"])

        with patch("modules.vuln_match.open_url", return_value=_FakeResp(_osv_empty_body())):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        check_failed = [r for r in rows if r["check_status"] == "check_failed"]
        assert check_failed and check_failed[0]["source"] == "wpscan"
        assert "no WPSCAN_API_TOKEN" in check_failed[0]["summary"]

    async def test_check_failed_is_surfaced_as_a_run_warning(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = "invalid-token"
        context = _context(tmp_path, techs=["Bookly:28.0"])

        with patch(
            "modules.vuln_match.open_url",
            side_effect=lambda req, **kw: _osv_or_wpscan(req, wpscan_error=_wpscan_404()),
        ):
            await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert any("Bookly:28.0" in w and "wpscan" in w for w in context.warnings)
        assert any("vulnerabilidad no descartada" in w for w in context.warnings)

    async def test_check_failed_is_recorded_in_metadata_for_downstream_reporting(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = "invalid-token"
        context = _context(tmp_path, techs=["Bookly:28.0"])

        with patch(
            "modules.vuln_match.open_url",
            side_effect=lambda req, **kw: _osv_or_wpscan(req, wpscan_error=_wpscan_404()),
        ):
            await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        failed = context.metadata.get("vuln_match_check_failed")
        assert failed
        assert failed[0]["technology"] == "Bookly"
        assert failed[0]["version"] == "28.0"
        assert failed[0]["source"] == "wpscan"

    async def test_check_failed_produces_an_info_finding_via_the_parser(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = "invalid-token"
        context = _context(tmp_path, techs=["Bookly:28.0"])

        with patch(
            "modules.vuln_match.open_url",
            side_effect=lambda req, **kw: _osv_or_wpscan(req, wpscan_error=_wpscan_404()),
        ):
            await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        hosts, _ = VulnMatchParser().parse(context.output_dir)
        failed_findings = [
            f for h in hosts for f in h.findings if f.template_id == "vuln-check-failed"
        ]
        assert failed_findings
        assert failed_findings[0].severity == "info"
        assert "Bookly" in failed_findings[0].name


@pytest.mark.asyncio
class TestOsvFailureAlsoMarksCheckFailed:
    async def test_osv_network_error_marks_check_failed_not_clean(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = None
        context = _context(tmp_path, techs=["Nicepage:8.6.23"])

        with patch("modules.vuln_match.open_url", side_effect=ConnectionError("network down")):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        check_failed = [r for r in rows if r["check_status"] == "check_failed"]
        assert check_failed and check_failed[0]["source"] == "osv.dev"
        assert not any(r["check_status"] == "checked_vulnerable" for r in rows)

    async def test_osv_invalid_json_marks_check_failed(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = None
        context = _context(tmp_path, techs=["Nicepage:8.6.23"])

        with patch("modules.vuln_match.open_url", return_value=_FakeResp(b"not valid json{{{")):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        check_failed = [r for r in rows if r["check_status"] == "check_failed"]
        assert check_failed and check_failed[0]["source"] == "osv.dev"
        assert "invalid JSON" in check_failed[0]["summary"]


@pytest.mark.asyncio
class TestVulnerabilityMatchStillWorks:
    """The fix must not change behavior for the success paths: a real
    vulnerability match still round-trips exactly as before."""

    async def test_osv_match_still_produces_checked_vulnerable(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = None
        context = _context(tmp_path, techs=["Bookly:27.8"])
        osv_body = json.dumps(
            {
                "vulns": [
                    {
                        "id": "GHSA-bookly-demo",
                        "aliases": ["CVE-2026-13395"],
                        "summary": "Bookly 27.8 advisory from fixture",
                        "severity": [{"type": "CVSS_V3", "score": "8.1"}],
                    }
                ]
            }
        ).encode()

        with patch("modules.vuln_match.open_url", return_value=_FakeResp(osv_body)):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        vulnerable = [r for r in rows if r["check_status"] == "checked_vulnerable"]
        assert vulnerable
        assert vulnerable[0]["identifier"] == "CVE-2026-13395"
        # OSV's own successful-but-no-token-for-wpscan branch still marks
        # the WPScan side as check_failed (no token) — both states coexist
        # honestly on the same technology.
        failed = [r for r in rows if r["check_status"] == "check_failed"]
        assert failed and failed[0]["source"] == "wpscan"

    async def test_wpscan_match_still_produces_checked_vulnerable(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = "sk-real-token"
        context = _context(tmp_path, techs=["Bookly:27.8"])
        wpscan_body = json.dumps(
            {
                "vulnerabilities": {
                    "Bookly < 27.9 - SQLi": {
                        "id": "12345",
                        "references": {"cve": ["2026-99999"]},
                    }
                }
            }
        ).encode()

        with patch(
            "modules.vuln_match.open_url",
            side_effect=lambda req, **kw: (
                _osv_or_wpscan(req, osv_body=_osv_empty_body())
                if "osv.dev" in (req.full_url if hasattr(req, "full_url") else str(req))
                else _FakeResp(wpscan_body)
            ),
        ):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        vulnerable = [r for r in rows if r["check_status"] == "checked_vulnerable"]
        assert vulnerable
        assert vulnerable[0]["identifier"] == "CVE-2026-99999"
        assert vulnerable[0]["source"] == "wpscan"
        assert not any(r["check_status"] == "check_failed" for r in rows)

    async def test_genuinely_clean_technology_produces_zero_rows(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        """The one thing that must NOT change: a technology that is
        actually checked clean across every applicable source still
        produces no rows at all — this fix only adds visibility for
        FAILURES, it never adds noise for real clean results."""
        settings.enable_vuln_match = True
        settings.wpscan_api_token = None
        context = _context(tmp_path, techs=["jQuery:3.6.0"])

        with patch("modules.vuln_match.open_url", return_value=_FakeResp(_osv_empty_body())):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        assert rows == []


@pytest.mark.asyncio
class TestRealWorldRegressionFixtureBookly28:
    """The exact real-world case this round was fixed from: Bookly:28.0
    detected on metaversejustice.com, WPSCAN_API_TOKEN present but
    rejected by the API with a plain 404 — verified against the actual
    raw log this produced in production:
    'WPScan bookly error: HTTP Error 404: Not Found'.
    """

    async def test_bookly_28_with_rejected_token_is_never_silently_clean(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        settings.enable_vuln_match = True
        settings.wpscan_api_token = "expired-production-token"
        context = _context(tmp_path, techs=["Bookly:28.0", "WordPress"])

        with patch(
            "modules.vuln_match.open_url",
            side_effect=lambda req, **kw: _osv_or_wpscan(req, wpscan_error=_wpscan_404()),
        ):
            result = await VulnMatchPlugin(settings).run(context, context.output_dir / "alive.txt")

        assert result.success
        rows = read_jsonl(context.output_dir / "vuln_match.jsonl")
        assert len(rows) == 1
        row = rows[0]
        assert row["check_status"] == "check_failed"
        assert row["technology"] == "Bookly"
        assert row["version"] == "28.0"
        assert row["source"] == "wpscan"
        assert "404" in row["summary"]

        hosts, _ = VulnMatchParser().parse(context.output_dir)
        findings = [f for h in hosts for f in h.findings]
        assert len(findings) == 1
        assert findings[0].template_id == "vuln-check-failed"
        assert "Bookly:28.0" in findings[0].name

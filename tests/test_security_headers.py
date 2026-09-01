"""`modules/security_headers.py`: raw-evidence capture and the real
`creator.stripchat.com` underscore/hyphen header-key bug.

`security_headers` never makes its own request — it re-evaluates
`context.httpx_results` (httpx's own `header` JSON object, already captured
by `modules/httpx.py`'s real subprocess run). httpx's JSON encoder renames
every hyphenated header name to use underscores (`X-Frame-Options` ->
`x_frame_options`) — before this fix, `normalize_header_map` only
lowercased keys, never folded underscores back to hyphens, so a lookup
against `CHECKED_HEADERS` (all hyphenated) silently always failed for any
of the 6 checked headers that were genuinely present. This is what a real
scan against `creator.stripchat.com` hit: `x-frame-options` and
`strict-transport-security` were both present in httpx's own capture (and
in a manual `curl -sI` against the same host, run repeatedly, with no
intermittency across different Cloudflare edge nodes) but were reported
missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.security_headers import (
    CHECKED_HEADERS,
    SecurityHeadersPlugin,
    missing_security_headers,
    normalize_header_map,
    score_from_missing,
)
from utils.files import read_jsonl

# Exact shape of the real header dict httpx.json captured for
# creator.stripchat.com in an actual run — underscored keys, as httpx's own
# JSON encoder produces them, not the real wire-format hyphenated names.
STRIPCHAT_REAL_HTTPX_HEADER = {
    "alt_svc": 'h3=":443"; ma=86400',
    "cache_control": "no-cache",
    "cf_cache_status": "DYNAMIC",
    "cf_ray": "a34625811bed8b47-TPA",
    "content_type": "text/html; charset=utf-8",
    "date": "Tue, 01 Sep 2026 17:55:32 GMT",
    "expires": "Thu, 01 Jan 1970 00:00:01 GMT",
    "last_modified": "Tue, 01 Sep 2026 14:01:27 GMT",
    "server": "cloudflare",
    "set_cookie": "__cf_bm=redacted; HttpOnly; SameSite=None; Secure; Path=/",
    "strict_transport_security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "x_backend": "india-static-models-fw-66d555ff8c-nc6v6",
    "x_frame_options": "deny",
}


def _context(tmp_path: Path) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(
        targets=[DomainTarget(domain="stripchat.com")],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(
            ["stripchat.com"], patterns=["*.stripchat.com"]
        ),
    )


def test_normalize_header_map_folds_httpx_underscores_to_hyphens() -> None:
    normalized = normalize_header_map(STRIPCHAT_REAL_HTTPX_HEADER)
    assert normalized["x-frame-options"] == "deny"
    assert normalized["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "x_frame_options" not in normalized


def test_stripchat_real_capture_no_longer_produces_false_missing() -> None:
    """The exact regression: httpx's real capture for creator.stripchat.com
    already had x-frame-options and strict-transport-security. Before the
    fix this returned both as missing (score 0); it must not anymore."""
    normalized = normalize_header_map(STRIPCHAT_REAL_HTTPX_HEADER)
    missing = missing_security_headers(normalized)
    assert "x-frame-options" not in missing
    assert "strict-transport-security" not in missing
    # The other 4 genuinely are absent from this real response — real
    # findings, not false positives, must still be reported.
    assert set(missing) == {
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    }
    assert score_from_missing(missing) == 33


@pytest.mark.asyncio
async def test_raw_artifact_records_every_header_verbatim_when_all_present(
    tmp_path: Path,
) -> None:
    """Fixture with all 6 evaluated headers present: the raw artifact must
    record the literal header text and missing=[]."""
    settings = Settings(project_root=tmp_path, enable_security_headers=True)
    context = _context(tmp_path)
    context.httpx_results = [
        {
            "host": "complete.stripchat.com",
            "url": "https://complete.stripchat.com/",
            "method": "GET",
            "status_code": 200,
            "timestamp": "2026-09-01T18:03:12Z",
            "header": {
                "strict_transport_security": "max-age=63072000",
                "content_security_policy": "default-src 'self'",
                "x_content_type_options": "nosniff",
                "x_frame_options": "deny",
                "referrer_policy": "no-referrer",
                "permissions_policy": "geolocation=()",
                "server": "cloudflare",
            },
        }
    ]

    result = await SecurityHeadersPlugin(settings).run(context, tmp_path / "unused")
    assert result.success

    rows = read_jsonl(context.output_dir / "security_headers.jsonl")
    assert len(rows) == 1
    assert rows[0]["missing"] is False
    assert rows[0]["security_headers_score"] == 100
    raw_path = context.output_dir / rows[0]["raw_artifact"]
    assert raw_path.exists()
    raw_text = raw_path.read_text()

    assert "HOST complete.stripchat.com" in raw_text
    assert "REQUEST GET https://complete.stripchat.com/ HTTP/1.1" in raw_text
    assert "TIMESTAMP 2026-09-01T18:03:12Z" in raw_text
    assert "RESPONSE STATUS 200" in raw_text
    # Real, literal header text — hyphenated (folded from httpx's encoding),
    # not the missing=[...] summary alone.
    assert "x-frame-options: deny" in raw_text
    assert "strict-transport-security: max-age=63072000" in raw_text
    assert "server: cloudflare" in raw_text
    assert "missing=[]" in raw_text


@pytest.mark.asyncio
async def test_raw_artifact_reflects_exactly_what_arrived_when_headers_missing(
    tmp_path: Path,
) -> None:
    """Fixture with genuinely missing headers: the raw artifact must show
    exactly what arrived — no invented headers, no silently dropped ones
    the module itself doesn't evaluate (e.g. `server`)."""
    settings = Settings(project_root=tmp_path, enable_security_headers=True)
    context = _context(tmp_path)
    context.httpx_results = [
        {
            "host": "bare.stripchat.com",
            "url": "https://bare.stripchat.com/",
            "method": "GET",
            "status_code": 200,
            "timestamp": "2026-09-01T18:04:00Z",
            "header": {"server": "nginx", "content_type": "text/html"},
        }
    ]

    await SecurityHeadersPlugin(settings).run(context, tmp_path / "unused")

    rows = read_jsonl(context.output_dir / "security_headers.jsonl")
    assert {r["header_key"] for r in rows} == set(CHECKED_HEADERS)
    assert all(r["missing"] for r in rows)
    raw_path = context.output_dir / rows[0]["raw_artifact"]
    raw_text = raw_path.read_text()
    header_block = raw_text.split("RESPONSE HEADERS")[1].split("EVALUATED")[0]

    # Real headers that arrived, even ones not evaluated, are present.
    assert "server: nginx" in header_block
    assert "content-type: text/html" in header_block
    # None of the 6 evaluated headers were sent — must not be fabricated
    # into the header block just because the module checks for them.
    for name in CHECKED_HEADERS:
        assert f"\n  {name}: " not in header_block


@pytest.mark.asyncio
async def test_raw_artifact_is_one_file_per_host_not_a_shared_file(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, enable_security_headers=True)
    context = _context(tmp_path)
    context.httpx_results = [
        {
            "host": "one.stripchat.com",
            "url": "https://one.stripchat.com/",
            "header": {"server": "nginx"},
        },
        {
            "host": "two.stripchat.com",
            "url": "https://two.stripchat.com/",
            "header": {"server": "cloudflare"},
        },
    ]

    await SecurityHeadersPlugin(settings).run(context, tmp_path / "unused")

    rows = read_jsonl(context.output_dir / "security_headers.jsonl")
    by_host = {r["host"]: r["raw_artifact"] for r in rows}
    assert by_host["one.stripchat.com"] == "security_headers_raw/one.stripchat.com.txt"
    assert by_host["two.stripchat.com"] == "security_headers_raw/two.stripchat.com.txt"
    assert (context.output_dir / "security_headers_raw" / "one.stripchat.com.txt").exists()
    assert (context.output_dir / "security_headers_raw" / "two.stripchat.com.txt").exists()


@pytest.mark.asyncio
async def test_stripchat_end_to_end_matches_the_real_archived_run(tmp_path: Path) -> None:
    """End-to-end regression using the real header shape from the archived
    creator.stripchat.com run: drives the actual plugin, not just the pure
    functions, and confirms the fixed jsonl/raw output."""
    settings = Settings(project_root=tmp_path, enable_security_headers=True)
    context = _context(tmp_path)
    context.httpx_results = [
        {
            "host": "creator.stripchat.com",
            "url": "https://creator.stripchat.com",
            "method": "GET",
            "status_code": 200,
            "timestamp": "2026-09-01T11:55:33.392656-06:00",
            "header": STRIPCHAT_REAL_HTTPX_HEADER,
        }
    ]

    await SecurityHeadersPlugin(settings).run(context, tmp_path / "unused")

    rows = read_jsonl(context.output_dir / "security_headers.jsonl")
    missing_keys = {r["header_key"] for r in rows if r["missing"]}
    assert "x-frame-options" not in missing_keys
    assert "strict-transport-security" not in missing_keys
    assert rows[0]["security_headers_score"] == 33

    raw_path = context.output_dir / "security_headers_raw" / "creator.stripchat.com.txt"
    raw_text = raw_path.read_text()
    assert "x-frame-options: deny" in raw_text
    assert "strict-transport-security: max-age=31536000; includeSubDomains" in raw_text
